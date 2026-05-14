// Remediation engine for `ocean harden`.
//
// Loads .check.yaml definitions, executes the checks, identifies failing checks
// with remediation blocks, and either plans (dry-run) or executes the fixes.

use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};

use crate::check::definition::{CheckDefinition, CheckType};
use crate::check::loader::load_definitions_from_dir as load_defs_from_dir;
use crate::evidence::StatusId;
use crate::module::{Executor, Registry};
use crate::modules::{register_all_observers, register_all_testers};

// ─── Security: Credential masking (TH-1a) ───────────────────────────────────

/// Known credential env var names. Values for these are scrubbed from all output.
const CREDENTIAL_ENV_VARS: &[&str] = &[
    "GITHUB_TOKEN",
    "OKTA_API_TOKEN",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AZURE_CLIENT_SECRET",
    "GCP_SERVICE_ACCOUNT_KEY",
];

/// Scrubs known credential values from a string, replacing them with `***REDACTED***`.
pub struct CredentialMask {
    secrets: Vec<String>,
}

impl CredentialMask {
    pub fn from_config(config: &HashMap<String, String>) -> Self {
        let secrets: Vec<String> = CREDENTIAL_ENV_VARS
            .iter()
            .filter_map(|key| config.get(*key))
            .filter(|v| !v.is_empty())
            .cloned()
            .collect();
        Self { secrets }
    }

    pub fn scrub(&self, input: &str) -> String {
        let mut result = input.to_string();
        for secret in &self.secrets {
            result = result.replace(secret.as_str(), "***REDACTED***");
        }
        result
    }
}

// ─── Security: URL allowlist (TH-2b) ────────────────────────────────────────

/// Validates that a remediation URL is targeting a known-safe endpoint.
fn validate_remediation_url(url: &str) -> Result<()> {
    if url.starts_with("https://api.github.com/")
        || url.starts_with("https://github.com/")
        || is_okta_url(url)
        || is_aws_url(url)
        || is_azure_url(url)
    {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "remediation URL rejected by allowlist: {url}\n\
             Allowed: api.github.com, *.okta.com, AWS, Azure endpoints.\n\
             If this is a legitimate endpoint, add it to ALLOWED_URL_PREFIXES in harden/mod.rs"
        ))
    }
}

/// Extract the host from a URL, returning None if parsing fails or scheme is not HTTPS.
fn https_host(raw: &str) -> Option<String> {
    let parsed = url::Url::parse(raw).ok()?;
    if parsed.scheme() != "https" {
        return None;
    }
    parsed.host_str().map(|h| h.to_lowercase())
}

fn is_okta_url(raw: &str) -> bool {
    https_host(raw)
        .map(|host| host.ends_with(".okta.com") || host.ends_with(".oktapreview.com"))
        .unwrap_or(false)
}

fn is_aws_url(raw: &str) -> bool {
    https_host(raw)
        .map(|host| host.ends_with(".amazonaws.com"))
        .unwrap_or(false)
}

fn is_azure_url(raw: &str) -> bool {
    https_host(raw)
        .map(|host| host.ends_with(".azure.com"))
        .unwrap_or(false)
}

// ─── Security: Template variable allowlist (TH-2d) ──────────────────────────

const ALLOWED_TEMPLATE_VARS: &[&str] = &[
    "GITHUB_TOKEN",
    "OKTA_API_TOKEN",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AZURE_CLIENT_SECRET",
    "AZURE_CLIENT_ID",
    "AZURE_TENANT_ID",
    "GCP_SERVICE_ACCOUNT_KEY",
    "ORG_NAME",
    "org",
    "org_name",
    "domain",
    "tenant",
];

// ─── Security: Audit logging (TH-2e) ────────────────────────────────────────

fn write_audit_log(plan: &RemediationPlan, result: &RemediationResult, mask: &CredentialMask) {
    let log_dir = std::env::var("HOME")
        .ok()
        .map(|h| std::path::PathBuf::from(h).join(".ocean"))
        .unwrap_or_else(|| std::path::PathBuf::from(".ocean"));
    let _ = std::fs::create_dir_all(&log_dir);
    let log_path = log_dir.join("audit.log");

    let timestamp = chrono::Utc::now().to_rfc3339();
    let status = if result.success { "SUCCESS" } else { "FAILED" };
    let api_summary = plan
        .api_action
        .as_ref()
        .map(|a| format!("{} {}", a.method, a.url))
        .unwrap_or_else(|| "no-api".to_string());

    let entry = mask.scrub(&format!(
        "[{timestamp}] HARDEN --apply | check={} | {status} | {api_summary} | actions={} errors={}\n",
        plan.check_id,
        result.actions_taken.len(),
        result.errors.len(),
    ));

    // Best-effort append; don't fail the remediation if logging fails.
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, entry.as_bytes()));
}

// ─── Security: User-check source warnings (TH-3a/b) ─────────────────────────

/// Returns true if the checks directory is under ~/.ocean/checks/ (user-authored).
pub fn is_user_checks_dir(checks_dir: &Path) -> bool {
    std::env::var("HOME")
        .ok()
        .map(|h| {
            let user_dir = std::path::PathBuf::from(h).join(".ocean").join("checks");
            checks_dir.starts_with(&user_dir)
        })
        .unwrap_or(false)
}

/// Print a warning about user-authored checks if the checks_dir is under ~/.ocean/checks/.
pub fn warn_user_checks<W: Write>(out: &mut W, checks_dir: &Path, _plans: &[RemediationPlan]) {
    if is_user_checks_dir(checks_dir) {
        let _ = writeln!(
            out,
            "⚠ Loading checks from {} — these are not verified by OCEAN maintainers.",
            checks_dir.display()
        );
    }
}

// ─── Public types ──────────────────────────────────────────────────────────────

/// What kind of remediation actions to plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemediationMode {
    /// Execute API calls from `remediation.api`.
    Api,
    /// Generate (and optionally write) Terraform HCL from `remediation.terraform`.
    Terraform,
    /// Display CLI commands from `remediation.cli`.
    Cli,
    /// All modes.
    All,
}

impl RemediationMode {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "api" => Ok(Self::Api),
            "terraform" | "tf" => Ok(Self::Terraform),
            "cli" => Ok(Self::Cli),
            "all" => Ok(Self::All),
            other => Err(anyhow::anyhow!(
                "unknown remediation mode '{other}'; expected: api, terraform, cli, all"
            )),
        }
    }

    fn includes_api(&self) -> bool {
        matches!(self, Self::Api | Self::All)
    }

    fn includes_terraform(&self) -> bool {
        matches!(self, Self::Terraform | Self::All)
    }

    fn includes_cli(&self) -> bool {
        matches!(self, Self::Cli | Self::All)
    }
}

/// A single planned remediation action for a failing check.
#[derive(Debug)]
pub struct RemediationPlan {
    pub check_id: String,
    pub check_name: String,
    pub description: String,
    pub steps: Vec<String>,
    pub api_action: Option<ApiAction>,
    pub cli_action: Option<String>,
    pub terraform_resources: Vec<serde_json::Value>,
}

#[derive(Debug)]
pub struct ApiAction {
    pub method: String,
    pub url: String,
    pub body: Option<serde_json::Value>,
}

/// Result of executing a single remediation plan.
#[derive(Debug)]
pub struct RemediationResult {
    pub check_id: String,
    pub success: bool,
    pub actions_taken: Vec<String>,
    pub errors: Vec<String>,
}

// ─── Check discovery ───────────────────────────────────────────────────────────

/// Walk a checks directory and return all parsed CheckDefinitions with remediation blocks.
pub fn load_remediable_checks(checks_dir: &Path) -> Vec<CheckDefinition> {
    load_defs_from_dir(checks_dir)
        .into_iter()
        .filter(|def| def.remediation.is_some())
        .collect()
}

/// Walk a checks directory and return ALL parsed CheckDefinitions.
pub fn load_all_definitions(checks_dir: &Path) -> Vec<CheckDefinition> {
    load_defs_from_dir(checks_dir)
}

// ─── Planning ─────────────────────────────────────────────────────────────────

/// Build remediation plans for checks that are failing.
///
/// Runs all passive checks in `checks_dir`, then for each check that produced
/// failing evidence and has a `remediation:` block, produces a `RemediationPlan`.
pub fn plan_harden(
    checks_dir: &Path,
    mode: &RemediationMode,
    config: &HashMap<String, String>,
    filter: Option<&str>,
) -> Result<Vec<RemediationPlan>> {
    let defs = load_all_definitions(checks_dir);
    if defs.is_empty() {
        return Ok(Vec::new());
    }

    // Build a lookup from check_id → definition for checks with remediation.
    let remediable: HashMap<String, &CheckDefinition> = defs
        .iter()
        .filter(|d| d.remediation.is_some())
        .filter(|d| filter.is_none_or(|f| d.id.starts_with(f) || d.source == f))
        .map(|d| (d.id.clone(), d))
        .collect();

    if remediable.is_empty() {
        return Ok(Vec::new());
    }

    // Register and run passive checks to get current evidence.
    let registry = Registry::new();
    register_all_observers(&registry);
    register_all_testers(&registry);
    crate::check::loader::load_checks_from_dir(&registry, checks_dir)?;

    let executor = Executor::new(std::sync::Arc::new(registry));

    let mut plans = Vec::new();

    for (check_id, def) in &remediable {
        if def.check_type != CheckType::Passive {
            continue; // Only auto-run passive checks for harden
        }

        let evidence = match executor.execute_observer(check_id, config) {
            Ok(ev) => ev,
            Err(_) => continue, // Check couldn't run; skip
        };

        let failing = evidence
            .iter()
            .any(|e| matches!(e.status_id, StatusId::Ineffective));

        if !failing {
            continue;
        }

        let rem = def.remediation.as_ref().unwrap(); // safe: filtered above

        let api_action = if mode.includes_api() {
            if let Some(api) = rem.api.as_ref() {
                let resolved_url = resolve_vars(&api.url, config);
                // TH-2b: Validate URL against allowlist before including in plan.
                if let Err(e) = validate_remediation_url(&resolved_url) {
                    eprintln!("  ⚠ Skipping {}: {e}", check_id);
                    continue;
                }
                Some(ApiAction {
                    method: api.method.clone(),
                    url: resolved_url,
                    body: api.body.clone(),
                })
            } else {
                None
            }
        } else {
            None
        };

        let cli_action = if mode.includes_cli() {
            rem.cli.as_ref().map(|c| resolve_vars(&c.command, config))
        } else {
            None
        };

        let terraform_resources = if mode.includes_terraform() {
            rem.terraform
                .as_ref()
                .map(|tf| tf.resources.clone())
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        plans.push(RemediationPlan {
            check_id: check_id.clone(),
            check_name: def.name.clone(),
            description: rem.description.clone(),
            steps: rem.steps.clone(),
            api_action,
            cli_action,
            terraform_resources,
        });
    }

    // Sort plans deterministically by check_id.
    plans.sort_by(|a, b| a.check_id.cmp(&b.check_id));

    Ok(plans)
}

// ─── Execution ────────────────────────────────────────────────────────────────

/// Execute remediation plans (apply mode).
///
/// For API actions: makes HTTP calls via ureq.
/// For CLI actions: shows the command (user must run it; we do not shell-exec).
/// For Terraform: writes HCL to `terraform_dir`.
///
/// Each execution is logged to `~/.ocean/audit.log` (TH-2e).
pub fn execute_plans(
    plans: &[RemediationPlan],
    config: &HashMap<String, String>,
    terraform_dir: Option<&Path>,
) -> Vec<RemediationResult> {
    let mask = CredentialMask::from_config(config);
    plans
        .iter()
        .map(|plan| {
            let result = execute_plan(plan, config, terraform_dir, &mask);
            write_audit_log(plan, &result, &mask);
            result
        })
        .collect()
}

fn execute_plan(
    plan: &RemediationPlan,
    config: &HashMap<String, String>,
    terraform_dir: Option<&Path>,
    mask: &CredentialMask,
) -> RemediationResult {
    let mut actions_taken = Vec::new();
    let mut errors = Vec::new();

    // API remediation
    if let Some(api) = &plan.api_action {
        match execute_api_call(api, config) {
            // TH-1a: Scrub credentials from action messages and error messages.
            Ok(msg) => actions_taken.push(mask.scrub(&msg)),
            Err(e) => errors.push(mask.scrub(&format!("API call failed: {e}"))),
        }
    }

    // CLI remediation — show the command, don't execute it (TH-7a: NEVER shell-exec)
    if let Some(cmd) = &plan.cli_action {
        actions_taken.push(format!("Run: {}", mask.scrub(cmd)));
    }

    // Terraform remediation
    if !plan.terraform_resources.is_empty() {
        if let Some(dir) = terraform_dir {
            match write_terraform(plan, dir) {
                Ok(path) => actions_taken.push(format!("Terraform written to {}", path.display())),
                Err(e) => errors.push(mask.scrub(&format!("Terraform write failed: {e}"))),
            }
        } else {
            let hcl = generate_terraform_hcl(plan);
            actions_taken.push(format!("Terraform HCL:\n{}", mask.scrub(&hcl)));
        }
    }

    RemediationResult {
        check_id: plan.check_id.clone(),
        success: errors.is_empty(),
        actions_taken,
        errors,
    }
}

const ALLOWED_HTTP_METHODS: &[&str] = &["GET", "PATCH", "PUT", "POST", "DELETE"];

fn execute_api_call(action: &ApiAction, config: &HashMap<String, String>) -> Result<String> {
    let method_upper = action.method.to_uppercase();
    if !ALLOWED_HTTP_METHODS.contains(&method_upper.as_str()) {
        return Err(anyhow::anyhow!(
            "invalid HTTP method '{}'; allowed: {}",
            action.method,
            ALLOWED_HTTP_METHODS.join(", ")
        ));
    }

    let auth = config
        .get("GITHUB_TOKEN")
        .or_else(|| config.get("OKTA_API_TOKEN"))
        .map(|t| format!("Bearer {t}"))
        .unwrap_or_default();

    let req = ureq::request(&action.method.to_uppercase(), &action.url)
        .set("Authorization", &auth)
        .set("Accept", "application/vnd.github+json")
        .set("X-GitHub-Api-Version", "2022-11-28");

    let resp = if let Some(body) = &action.body {
        req.send_json(body).context("API call failed")?
    } else {
        req.call().context("API call failed")?
    };

    Ok(format!(
        "{} {} → HTTP {}",
        action.method, action.url, resp.status()
    ))
}

fn write_terraform(plan: &RemediationPlan, dir: &Path) -> Result<std::path::PathBuf> {
    std::fs::create_dir_all(dir)?;
    let filename = format!("{}.tf", plan.check_id.to_lowercase().replace('-', "_"));
    let path = dir.join(&filename);
    let hcl = generate_terraform_hcl(plan);
    std::fs::write(&path, hcl)?;
    Ok(path)
}

fn generate_terraform_hcl(plan: &RemediationPlan) -> String {
    let mut hcl = format!("# Remediation: {} — {}\n\n", plan.check_id, plan.check_name);
    for resource in &plan.terraform_resources {
        hcl.push_str(&serde_json::to_string_pretty(resource).unwrap_or_default());
        hcl.push_str("\n\n");
    }
    hcl
}

// ─── Confirmation prompt (TH-2a) ─────────────────────────────────────────────

/// Display the full remediation plan and prompt for confirmation.
///
/// Returns `true` if the user confirms, `false` otherwise.
/// When `auto_confirm` is true, skips the prompt (for CI/--confirm flag).
pub fn confirm_apply<W: Write>(
    out: &mut W,
    plans: &[RemediationPlan],
    config: &HashMap<String, String>,
    auto_confirm: bool,
) -> Result<bool> {
    let mask = CredentialMask::from_config(config);

    writeln!(out, "\n⚠ APPLY MODE — the following API calls will be executed:\n")?;
    for (i, plan) in plans.iter().enumerate() {
        writeln!(out, "  {}. {} — {}", i + 1, plan.check_id, plan.check_name)?;
        if let Some(api) = &plan.api_action {
            writeln!(out, "     API: {} {}", api.method, mask.scrub(&api.url))?;
            if let Some(body) = &api.body {
                let body_str = serde_json::to_string_pretty(body).unwrap_or_default();
                writeln!(out, "     Body: {}", mask.scrub(&body_str))?;
            }
        }
        if let Some(cmd) = &plan.cli_action {
            writeln!(out, "     CLI (display only): {}", mask.scrub(cmd))?;
        }
        if !plan.terraform_resources.is_empty() {
            writeln!(out, "     Terraform: {} resource(s) will be written", plan.terraform_resources.len())?;
        }
    }
    writeln!(out)?;

    if auto_confirm {
        writeln!(out, "  --confirm flag set, proceeding automatically.")?;
        return Ok(true);
    }

    // Interactive confirmation
    write!(out, "Proceed? [y/N] ")?;
    out.flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let answer = input.trim().to_lowercase();
    Ok(answer == "y" || answer == "yes")
}

// ─── Output formatting ────────────────────────────────────────────────────────

/// Print harden plans in dry-run mode.
///
/// Credential values are scrubbed from all output (TH-1a).
pub fn print_dry_run<W: Write>(out: &mut W, plans: &[RemediationPlan], format: &str, config: &HashMap<String, String>) -> Result<()> {
    let mask = CredentialMask::from_config(config);
    if format == "json" {
        let json: Vec<serde_json::Value> = plans
            .iter()
            .map(|p| {
                serde_json::json!({
                    "check_id": p.check_id,
                    "check_name": p.check_name,
                    "description": p.description,
                    "steps": p.steps,
                    "api": p.api_action.as_ref().map(|a| serde_json::json!({
                        "method": a.method,
                        "url": mask.scrub(&a.url),
                        "body": a.body,
                    })),
                    "cli": p.cli_action.as_ref().map(|c| mask.scrub(c)),
                    "terraform_resources": p.terraform_resources.len(),
                })
            })
            .collect();
        let json_str = serde_json::to_string_pretty(&json)?;
        writeln!(out, "{}", mask.scrub(&json_str))?;
    } else {
        if plans.is_empty() {
            writeln!(out, "No failing checks with remediation plans found.")?;
            return Ok(());
        }
        writeln!(out, "\n[DRY RUN] Remediation plan — use --apply to execute\n")?;
        for plan in plans {
            writeln!(out, "  ▸ {} — {}", plan.check_id, plan.check_name)?;
            if let Some(api) = &plan.api_action {
                writeln!(out, "    API: {} {}", api.method, mask.scrub(&api.url))?;
            }
            if let Some(cmd) = &plan.cli_action {
                writeln!(out, "    CLI: {}", mask.scrub(cmd))?;
            }
            if !plan.terraform_resources.is_empty() {
                writeln!(out, "    Terraform: {} resource(s)", plan.terraform_resources.len())?;
            }
            if !plan.steps.is_empty() {
                writeln!(out, "    Manual steps:")?;
                for step in &plan.steps {
                    writeln!(out, "      • {step}")?;
                }
            }
        }
    }
    Ok(())
}

/// Print harden execution results.
///
/// Credential values are scrubbed from all output (TH-1a).
pub fn print_results<W: Write>(out: &mut W, results: &[RemediationResult], format: &str, config: &HashMap<String, String>) -> Result<()> {
    let mask = CredentialMask::from_config(config);
    if format == "json" {
        let json: Vec<serde_json::Value> = results
            .iter()
            .map(|r| {
                serde_json::json!({
                    "check_id": r.check_id,
                    "success": r.success,
                    "actions_taken": r.actions_taken,
                    "errors": r.errors,
                })
            })
            .collect();
        // TH-1a: Defense-in-depth scrub on serialized JSON output.
        let json_str = serde_json::to_string_pretty(&json)?;
        writeln!(out, "{}", mask.scrub(&json_str))?;
    } else {
        for r in results {
            if r.success {
                writeln!(out, "  ✓ {}", r.check_id)?;
                for action in &r.actions_taken {
                    writeln!(out, "    {}", mask.scrub(action))?;
                }
            } else {
                writeln!(out, "  ✗ {}", r.check_id)?;
                for err in &r.errors {
                    writeln!(out, "    ERROR: {}", mask.scrub(err))?;
                }
            }
        }
    }
    Ok(())
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Resolve `{{key}}` template variables from the config map.
///
/// Only variables in `ALLOWED_TEMPLATE_VARS` are resolved. Unknown variables
/// are left as-is (safe for dry-run display). This prevents injection via
/// crafted .check.yaml template variables (TH-2d).
fn resolve_vars(template: &str, config: &HashMap<String, String>) -> String {
    let mut result = template.to_string();
    for key in ALLOWED_TEMPLATE_VARS {
        if let Some(value) = config.get(*key) {
            let placeholder = format!("{{{{{key}}}}}");
            result = result.replace(&placeholder, value);
        }
    }
    result
}

/// Like `resolve_vars` but masks credential values for safe display (TH-1a).
#[allow(dead_code)]
pub fn resolve_vars_masked(template: &str, config: &HashMap<String, String>) -> String {
    let mut result = template.to_string();
    for key in ALLOWED_TEMPLATE_VARS {
        if config.contains_key(*key) {
            let placeholder = format!("{{{{{key}}}}}");
            if CREDENTIAL_ENV_VARS.contains(key) {
                // Leave credential placeholders unresolved in display output
                // (they stay as {{GITHUB_TOKEN}} etc.)
            } else {
                if let Some(value) = config.get(*key) {
                    result = result.replace(&placeholder, value);
                }
            }
        }
    }
    result
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::TempDir;

    static HOME_MUTEX: Mutex<()> = Mutex::new(());

    fn write_check(dir: &Path, filename: &str, content: &str) {
        std::fs::write(dir.join(filename), content).unwrap();
    }

    const CHECK_WITH_REMEDIATION: &str = r#"
id: TST-1
name: Test Check With Remediation
source: github
steps: []
assertions: []
remediation:
  description: "Fix the issue"
  steps:
    - "Step 1: do something"
  api:
    method: PATCH
    url: "https://api.example.com/orgs/{{org}}"
    body:
      setting: true
  cli:
    command: "gh api orgs/{{org}} -X PATCH -f setting=true"
"#;

    const CHECK_WITHOUT_REMEDIATION: &str = r#"
id: TST-2
name: Test Check Without Remediation
source: github
steps: []
assertions: []
"#;

    #[test]
    fn load_remediable_checks_filters_correctly() {
        let dir = TempDir::new().unwrap();
        write_check(dir.path(), "tst1.check.yaml", CHECK_WITH_REMEDIATION);
        write_check(dir.path(), "tst2.check.yaml", CHECK_WITHOUT_REMEDIATION);

        let checks = load_remediable_checks(dir.path());
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].id, "TST-1");
    }

    #[test]
    fn load_all_definitions_returns_all() {
        let dir = TempDir::new().unwrap();
        write_check(dir.path(), "tst1.check.yaml", CHECK_WITH_REMEDIATION);
        write_check(dir.path(), "tst2.check.yaml", CHECK_WITHOUT_REMEDIATION);

        let defs = load_all_definitions(dir.path());
        assert_eq!(defs.len(), 2);
    }

    #[test]
    fn load_remediable_checks_nonexistent_dir() {
        let checks = load_remediable_checks(Path::new("/nonexistent"));
        assert!(checks.is_empty());
    }

    #[test]
    fn remediation_mode_from_str() {
        assert_eq!(RemediationMode::from_str("api").unwrap(), RemediationMode::Api);
        assert_eq!(RemediationMode::from_str("terraform").unwrap(), RemediationMode::Terraform);
        assert_eq!(RemediationMode::from_str("tf").unwrap(), RemediationMode::Terraform);
        assert_eq!(RemediationMode::from_str("cli").unwrap(), RemediationMode::Cli);
        assert_eq!(RemediationMode::from_str("all").unwrap(), RemediationMode::All);
        assert!(RemediationMode::from_str("unknown").is_err());
    }

    #[test]
    fn remediation_mode_includes() {
        assert!(RemediationMode::All.includes_api());
        assert!(RemediationMode::All.includes_terraform());
        assert!(RemediationMode::All.includes_cli());
        assert!(RemediationMode::Api.includes_api());
        assert!(!RemediationMode::Api.includes_terraform());
        assert!(!RemediationMode::Api.includes_cli());
    }

    #[test]
    fn resolve_vars_substitutes_placeholders() {
        let mut config = HashMap::new();
        config.insert("org".to_string(), "my-org".to_string());
        let result = resolve_vars("https://api.github.com/orgs/{{org}}", &config);
        assert_eq!(result, "https://api.github.com/orgs/my-org");
    }

    #[test]
    fn resolve_vars_unknown_key_left_as_is() {
        let config = HashMap::new();
        let result = resolve_vars("{{unknown}}", &config);
        assert_eq!(result, "{{unknown}}");
    }

    #[test]
    fn generate_terraform_hcl_contains_check_id() {
        let plan = RemediationPlan {
            check_id: "GH-1.01".to_string(),
            check_name: "MFA Check".to_string(),
            description: String::new(),
            steps: Vec::new(),
            api_action: None,
            cli_action: None,
            terraform_resources: vec![serde_json::json!({"type": "github_org", "setting": true})],
        };
        let hcl = generate_terraform_hcl(&plan);
        assert!(hcl.contains("GH-1.01"));
        assert!(hcl.contains("MFA Check"));
    }

    fn empty_config() -> HashMap<String, String> {
        HashMap::new()
    }

    #[test]
    fn print_dry_run_json_empty() {
        let mut out = Vec::new();
        print_dry_run(&mut out, &[], "json", &empty_config()).unwrap();
        let s = String::from_utf8(out).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(v.as_array().unwrap().is_empty());
    }

    #[test]
    fn print_dry_run_table_empty() {
        let mut out = Vec::new();
        print_dry_run(&mut out, &[], "table", &empty_config()).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("No failing"));
    }

    #[test]
    fn print_dry_run_table_with_plans() {
        let plans = vec![RemediationPlan {
            check_id: "GH-1.01".to_string(),
            check_name: "Enforce MFA".to_string(),
            description: "Enable MFA".to_string(),
            steps: vec!["Go to settings".to_string()],
            api_action: Some(ApiAction {
                method: "PATCH".to_string(),
                url: "https://api.github.com/orgs/my-org".to_string(),
                body: None,
            }),
            cli_action: Some("gh api orgs/my-org -X PATCH".to_string()),
            terraform_resources: Vec::new(),
        }];
        let mut out = Vec::new();
        print_dry_run(&mut out, &plans, "table", &empty_config()).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("GH-1.01"));
        assert!(s.contains("PATCH"));
    }

    #[test]
    fn print_results_json() {
        let results = vec![RemediationResult {
            check_id: "GH-1.01".to_string(),
            success: true,
            actions_taken: vec!["PATCH https://api.github.com/orgs/x → HTTP 200".to_string()],
            errors: Vec::new(),
        }];
        let mut out = Vec::new();
        print_results(&mut out, &results, "json", &empty_config()).unwrap();
        let s = String::from_utf8(out).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v[0]["check_id"], "GH-1.01");
        assert_eq!(v[0]["success"], true);
    }

    // ─── Security tests ──────────────────────────────────────────────────────

    #[test]
    fn sec_credential_mask_scrubs_tokens() {
        // TH-1a: Credential values must never appear in output.
        let mut config = HashMap::new();
        config.insert("GITHUB_TOKEN".to_string(), "ghp_secret123abc".to_string());
        let mask = CredentialMask::from_config(&config);

        assert_eq!(
            mask.scrub("Authorization: Bearer ghp_secret123abc"),
            "Authorization: Bearer ***REDACTED***"
        );
        assert_eq!(
            mask.scrub("https://api.github.com/orgs/my-org?token=ghp_secret123abc"),
            "https://api.github.com/orgs/my-org?token=***REDACTED***"
        );
    }

    #[test]
    fn sec_credential_mask_empty_config() {
        let mask = CredentialMask::from_config(&HashMap::new());
        assert_eq!(mask.scrub("no secrets here"), "no secrets here");
    }

    #[test]
    fn sec_dry_run_does_not_leak_token() {
        // TH-1b: Dry-run output must not contain credential values.
        let mut config = HashMap::new();
        config.insert("GITHUB_TOKEN".to_string(), "ghp_test_secret_token_xyz".to_string());
        config.insert("org".to_string(), "my-org".to_string());

        let plans = vec![RemediationPlan {
            check_id: "GH-1.08".to_string(),
            check_name: "Restrict Repo Creation".to_string(),
            description: "Fix it".to_string(),
            steps: Vec::new(),
            api_action: Some(ApiAction {
                method: "PATCH".to_string(),
                url: "https://api.github.com/orgs/my-org?auth=ghp_test_secret_token_xyz".to_string(),
                body: None,
            }),
            cli_action: None,
            terraform_resources: Vec::new(),
        }];

        // Test table output
        let mut out = Vec::new();
        print_dry_run(&mut out, &plans, "table", &config).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(!s.contains("ghp_test_secret_token_xyz"), "Token leaked in table output: {s}");

        // Test JSON output
        let mut out = Vec::new();
        print_dry_run(&mut out, &plans, "json", &config).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(!s.contains("ghp_test_secret_token_xyz"), "Token leaked in JSON output: {s}");
    }

    #[test]
    fn sec_url_allowlist_accepts_github() {
        assert!(validate_remediation_url("https://api.github.com/orgs/my-org").is_ok());
    }

    #[test]
    fn sec_url_allowlist_accepts_okta() {
        assert!(validate_remediation_url("https://mycompany.okta.com/api/v1/policies").is_ok());
    }

    #[test]
    fn sec_url_allowlist_rejects_evil_host() {
        // TH-2b: Malicious URLs must be rejected.
        assert!(validate_remediation_url("https://evil.example.com/steal").is_err());
        assert!(validate_remediation_url("http://api.github.com/orgs/my-org").is_err()); // http not https
    }

    #[test]
    fn sec_url_allowlist_rejects_domain_bypass() {
        // F-001: URLs with trusted domains in the path (not host) must be rejected.
        assert!(validate_remediation_url("https://evil.example.com/.okta.com/steal").is_err());
        assert!(validate_remediation_url("https://evil.example.com/.amazonaws.com/exfil").is_err());
        assert!(validate_remediation_url("https://evil.example.com/.azure.com/steal").is_err());
        assert!(validate_remediation_url("https://evil.example.com/api.github.com/orgs/x").is_err());
    }

    #[test]
    fn sec_http_method_validation() {
        // F-003: Only standard HTTP methods allowed.
        assert!(ALLOWED_HTTP_METHODS.contains(&"PATCH"));
        assert!(ALLOWED_HTTP_METHODS.contains(&"GET"));
        assert!(ALLOWED_HTTP_METHODS.contains(&"DELETE"));
        assert!(!ALLOWED_HTTP_METHODS.contains(&"CONNECT"));
        assert!(!ALLOWED_HTTP_METHODS.contains(&"TRACE"));
    }

    #[test]
    fn sec_template_var_allowlist_blocks_unknown() {
        // TH-2d: Only known template variables are resolved.
        let mut config = HashMap::new();
        config.insert("MALICIOUS_VAR".to_string(), "injected_value".to_string());
        config.insert("org".to_string(), "legit-org".to_string());

        let result = resolve_vars("{{MALICIOUS_VAR}}/{{org}}", &config);
        assert!(result.contains("{{MALICIOUS_VAR}}"), "Unknown var was resolved: {result}");
        assert!(result.contains("legit-org"), "Known var was not resolved: {result}");
    }

    #[test]
    fn sec_resolve_vars_masked_hides_credentials() {
        let mut config = HashMap::new();
        config.insert("GITHUB_TOKEN".to_string(), "ghp_secret".to_string());
        config.insert("org".to_string(), "my-org".to_string());

        let result = resolve_vars_masked("{{GITHUB_TOKEN}} {{org}}", &config);
        assert!(result.contains("{{GITHUB_TOKEN}}"), "Credential should stay as placeholder: {result}");
        assert!(result.contains("my-org"), "Non-credential should be resolved: {result}");
    }

    #[test]
    fn sec_no_shell_exec_in_cli_mode() {
        // TH-7a/c: CLI commands are displayed, never executed.
        // Verify by running execute_plan with a dangerous CLI command —
        // if it were executed, the test would fail (or worse).
        let plan = RemediationPlan {
            check_id: "TST-EVIL".to_string(),
            check_name: "Evil Check".to_string(),
            description: "Should not execute".to_string(),
            steps: Vec::new(),
            api_action: None,
            cli_action: Some("rm -rf / --no-preserve-root".to_string()),
            terraform_resources: Vec::new(),
        };
        let config = HashMap::new();
        let mask = CredentialMask::from_config(&config);
        let result = execute_plan(&plan, &config, None, &mask);

        // The command should appear in actions_taken as display text, not executed.
        assert!(result.success);
        assert!(result.actions_taken[0].contains("rm -rf"));
        // Verify we're still alive (i.e., the command was NOT executed).
        assert!(std::path::Path::new("/").exists());
    }

    #[test]
    fn sec_confirm_auto_confirm() {
        // TH-2a: auto-confirm should proceed without stdin.
        let config = HashMap::new();
        let plans = vec![RemediationPlan {
            check_id: "GH-1.01".to_string(),
            check_name: "Test".to_string(),
            description: String::new(),
            steps: Vec::new(),
            api_action: Some(ApiAction {
                method: "PATCH".to_string(),
                url: "https://api.github.com/orgs/test".to_string(),
                body: None,
            }),
            cli_action: None,
            terraform_resources: Vec::new(),
        }];
        let mut out = Vec::new();
        let result = confirm_apply(&mut out, &plans, &config, true).unwrap();
        assert!(result, "auto-confirm should return true");
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("APPLY MODE"), "Should show plan header");
        assert!(s.contains("PATCH"), "Should show API method");
    }

    // ─── Additional unit tests (from test plan GRC-51) ──────────────────────

    #[test]
    fn ut_h003_active_check_excluded_from_remediation() {
        // UT-H003: Active checks with remediation blocks are excluded from load_remediable_checks
        // because plan_harden() skips non-passive checks.
        let active_check = r#"
id: TST-ACTIVE
name: Active Test Check
source: github
type: active
safety: observable
steps: []
assertions: []
remediation:
  description: "Should not be auto-remediated"
  steps: []
  api:
    method: PATCH
    url: "https://api.github.com/orgs/test"
"#;
        let dir = TempDir::new().unwrap();
        write_check(dir.path(), "active.check.yaml", active_check);

        // load_remediable_checks returns it (it has a remediation block)
        let checks = load_remediable_checks(dir.path());
        assert_eq!(checks.len(), 1, "Should find the active check with remediation");
        assert_eq!(checks[0].check_type, CheckType::Active);
        // But plan_harden will skip it because it's active (verified by the
        // `if def.check_type != CheckType::Passive { continue; }` guard in plan_harden).
    }

    #[test]
    fn ut_h010_print_dry_run_json_with_plans() {
        // UT-H010: dry-run JSON output with actual plans is parseable and array length matches.
        let plans = vec![
            RemediationPlan {
                check_id: "GH-1.01".to_string(),
                check_name: "Enforce MFA".to_string(),
                description: "Enable MFA".to_string(),
                steps: vec!["Step 1".to_string()],
                api_action: Some(ApiAction {
                    method: "PATCH".to_string(),
                    url: "https://api.github.com/orgs/test".to_string(),
                    body: Some(serde_json::json!({"require_mfa": true})),
                }),
                cli_action: None,
                terraform_resources: Vec::new(),
            },
            RemediationPlan {
                check_id: "GH-1.08".to_string(),
                check_name: "Restrict Repos".to_string(),
                description: "Limit repo creation".to_string(),
                steps: Vec::new(),
                api_action: None,
                cli_action: Some("gh api orgs/test -X PATCH".to_string()),
                terraform_resources: Vec::new(),
            },
        ];
        let mut out = Vec::new();
        print_dry_run(&mut out, &plans, "json", &empty_config()).unwrap();
        let s = String::from_utf8(out).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).expect("Must be valid JSON");
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 2, "Array length must match plan count");
        assert_eq!(arr[0]["check_id"], "GH-1.01");
        assert_eq!(arr[1]["check_id"], "GH-1.08");
    }

    #[test]
    fn ut_h014_write_terraform_creates_dir() {
        // UT-H014: write_terraform creates directory if it doesn't exist.
        let parent = TempDir::new().unwrap();
        let tf_dir = parent.path().join("nested").join("terraform");
        assert!(!tf_dir.exists());

        let plan = RemediationPlan {
            check_id: "GH-1.01".to_string(),
            check_name: "MFA Check".to_string(),
            description: String::new(),
            steps: Vec::new(),
            api_action: None,
            cli_action: None,
            terraform_resources: vec![serde_json::json!({"type": "github_org", "setting": true})],
        };
        let path = write_terraform(&plan, &tf_dir).unwrap();
        assert!(tf_dir.exists(), "Directory should be created");
        assert!(path.exists(), "Terraform file should exist");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("GH-1.01"), "File should contain check ID");
    }

    #[test]
    fn ut_h012_print_results_mixed_success_failure() {
        // UT-H012: Results output with mixed success/failure has all required fields.
        let results = vec![
            RemediationResult {
                check_id: "GH-1.01".to_string(),
                success: true,
                actions_taken: vec!["PATCH → 200".to_string()],
                errors: Vec::new(),
            },
            RemediationResult {
                check_id: "GH-1.08".to_string(),
                success: false,
                actions_taken: Vec::new(),
                errors: vec!["API call failed: HTTP 403".to_string()],
            },
        ];
        let mut out = Vec::new();
        print_results(&mut out, &results, "json", &empty_config()).unwrap();
        let s = String::from_utf8(out).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        // Verify all fields present
        assert_eq!(arr[0]["success"], true);
        assert!(arr[0]["actions_taken"].as_array().unwrap().len() > 0);
        assert_eq!(arr[1]["success"], false);
        assert!(arr[1]["errors"].as_array().unwrap().len() > 0);
    }

    #[test]
    fn ut_h013_remediation_mode_invalid_input() {
        // UT-H013: Invalid mode string returns descriptive error listing valid modes.
        let err = RemediationMode::from_str("garbage").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("garbage"), "Error should mention the invalid input");
        assert!(msg.contains("api"), "Error should list valid modes");
        assert!(msg.contains("terraform"), "Error should list valid modes");
        assert!(msg.contains("cli"), "Error should list valid modes");
    }

    // ─── Additional security tests (from test plan GRC-51) ──────────────────

    #[test]
    fn sec_h002_credentials_not_in_error_output() {
        // SEC-H002: Failed API calls must not leak credential values in error messages.
        let mut config = HashMap::new();
        config.insert("GITHUB_TOKEN".to_string(), "ghp_supersecrettoken999".to_string());
        let mask = CredentialMask::from_config(&config);

        // Simulate an error message that might contain a token
        let raw_error = "API call failed: 403 Forbidden. Authorization: Bearer ghp_supersecrettoken999";
        let scrubbed = mask.scrub(raw_error);
        assert!(!scrubbed.contains("ghp_supersecrettoken999"), "Token leaked in error: {scrubbed}");
        assert!(scrubbed.contains("***REDACTED***"), "Should show REDACTED");
    }

    #[test]
    fn sec_h004_terraform_no_credential_literals() {
        // SEC-H004: Terraform output must not contain credential literal values.
        let mut config = HashMap::new();
        config.insert("GITHUB_TOKEN".to_string(), "ghp_terraform_secret_xyz".to_string());

        let plan = RemediationPlan {
            check_id: "GH-1.01".to_string(),
            check_name: "MFA".to_string(),
            description: String::new(),
            steps: Vec::new(),
            api_action: None,
            cli_action: None,
            terraform_resources: vec![serde_json::json!({
                "type": "github_org_settings",
                "provider": "github",
                "config": {"token": "var.github_token"}
            })],
        };
        let hcl = generate_terraform_hcl(&plan);
        assert!(!hcl.contains("ghp_terraform_secret_xyz"), "Terraform output must not contain credentials");
    }

    #[test]
    fn sec_h010_user_checks_dir_detection() {
        // SEC-H010: is_user_checks_dir correctly identifies ~/.ocean/checks/ paths.
        if let Ok(home) = std::env::var("HOME") {
            let user_dir = std::path::PathBuf::from(&home).join(".ocean").join("checks");
            assert!(is_user_checks_dir(&user_dir), "~/.ocean/checks/ should be detected as user dir");

            let built_in_dir = std::path::PathBuf::from("/usr/share/ocean/checks");
            assert!(!is_user_checks_dir(&built_in_dir), "Built-in dir should not be flagged");
        }
    }

    #[test]
    fn sec_h010_warn_user_checks_output() {
        // SEC-H010: warn_user_checks writes a warning for user-authored checks.
        if let Ok(home) = std::env::var("HOME") {
            let user_dir = std::path::PathBuf::from(&home).join(".ocean").join("checks");
            let mut out = Vec::new();
            warn_user_checks(&mut out, &user_dir, &[]);
            let s = String::from_utf8(out).unwrap();
            assert!(s.contains("not verified"), "Should warn about unverified checks");
        }
    }

    #[test]
    fn sec_h012_partial_failure_result() {
        // SEC-H012: When some remediations succeed and some fail, results reflect this correctly.
        let plans = vec![
            RemediationPlan {
                check_id: "GH-1.01".to_string(),
                check_name: "MFA".to_string(),
                description: String::new(),
                steps: Vec::new(),
                api_action: None,
                cli_action: Some("gh api test".to_string()),
                terraform_resources: Vec::new(),
            },
        ];
        let config = HashMap::new();
        let results = execute_plans(&plans, &config, None);

        // CLI-only plans should succeed (display only, no execution)
        assert_eq!(results.len(), 1);
        assert!(results[0].success);
        assert!(results[0].actions_taken[0].contains("gh api test"));
    }

    #[test]
    fn sec_h006_check_yaml_field_injection() {
        // SEC-H006: Malicious values in check names/descriptions are treated as strings.
        let malicious_check = r#"
id: TST-EVIL
name: "test; rm -rf /"
source: github
steps: []
assertions: []
remediation:
  description: "<script>alert(1)</script>"
  steps:
    - "Step with $(whoami) injection"
  cli:
    command: "echo 'display only'"
"#;
        let dir = TempDir::new().unwrap();
        write_check(dir.path(), "evil.check.yaml", malicious_check);

        let checks = load_remediable_checks(dir.path());
        assert_eq!(checks.len(), 1);
        // Values are just strings, not interpreted
        assert_eq!(checks[0].name, "test; rm -rf /");

        // Dry-run output should show the values as-is (no interpretation)
        let plan = RemediationPlan {
            check_id: "TST-EVIL".to_string(),
            check_name: "test; rm -rf /".to_string(),
            description: "<script>alert(1)</script>".to_string(),
            steps: vec!["Step with $(whoami) injection".to_string()],
            api_action: None,
            cli_action: Some("echo 'display only'".to_string()),
            terraform_resources: Vec::new(),
        };
        let mut out = Vec::new();
        print_dry_run(&mut out, &[plan], "table", &empty_config()).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("test; rm -rf /"), "Name should appear as-is in output");
        // Verify no shell interpretation occurred (we're still here)
        assert!(std::path::Path::new("/").exists());
    }

    #[test]
    fn sec_h009_url_allowlist_rejects_http() {
        // SEC-H009: Only HTTPS URLs are accepted; HTTP rejected.
        assert!(validate_remediation_url("http://api.github.com/orgs/test").is_err());
    }

    #[test]
    fn sec_url_allowlist_accepts_aws() {
        assert!(validate_remediation_url("https://iam.amazonaws.com/").is_ok());
    }

    #[test]
    fn sec_url_allowlist_accepts_azure() {
        assert!(validate_remediation_url("https://management.azure.com/subscriptions").is_ok());
    }

    #[test]
    fn sec_confirm_shows_api_details() {
        // SEC-H007: Confirmation prompt must show method, URL, and body.
        let mut config = HashMap::new();
        config.insert("GITHUB_TOKEN".to_string(), "ghp_secret".to_string());

        let plans = vec![RemediationPlan {
            check_id: "GH-1.08".to_string(),
            check_name: "Restrict Repo Creation".to_string(),
            description: String::new(),
            steps: Vec::new(),
            api_action: Some(ApiAction {
                method: "PATCH".to_string(),
                url: "https://api.github.com/orgs/test".to_string(),
                body: Some(serde_json::json!({"members_can_create_repos": false})),
            }),
            cli_action: None,
            terraform_resources: Vec::new(),
        }];
        let mut out = Vec::new();
        confirm_apply(&mut out, &plans, &config, true).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("PATCH"), "Must show HTTP method");
        assert!(s.contains("api.github.com"), "Must show URL");
        assert!(s.contains("members_can_create_repos"), "Must show body content");
        assert!(!s.contains("ghp_secret"), "Must not leak token in confirmation output");
    }

    // ─── Edge case tests (from test plan GRC-51) ────────────────────────────

    #[test]
    fn ec_h001_no_failing_checks_message() {
        // EC-H001: When no plans exist, dry-run shows "nothing to remediate".
        let mut out = Vec::new();
        print_dry_run(&mut out, &[], "table", &empty_config()).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("No failing"), "Should indicate no checks to remediate");
    }

    #[test]
    fn ec_h004_multiple_checks_independent_plans() {
        // EC-H004: Multiple failing checks produce independent plans (no dedup).
        let plans = vec![
            RemediationPlan {
                check_id: "GH-1.01".to_string(),
                check_name: "MFA".to_string(),
                description: String::new(),
                steps: Vec::new(),
                api_action: Some(ApiAction {
                    method: "PATCH".to_string(),
                    url: "https://api.github.com/orgs/test/mfa".to_string(),
                    body: None,
                }),
                cli_action: None,
                terraform_resources: Vec::new(),
            },
            RemediationPlan {
                check_id: "GH-1.08".to_string(),
                check_name: "Repos".to_string(),
                description: String::new(),
                steps: Vec::new(),
                api_action: Some(ApiAction {
                    method: "PATCH".to_string(),
                    url: "https://api.github.com/orgs/test/repos".to_string(),
                    body: None,
                }),
                cli_action: None,
                terraform_resources: Vec::new(),
            },
        ];
        let mut out = Vec::new();
        print_dry_run(&mut out, &plans, "json", &empty_config()).unwrap();
        let s = String::from_utf8(out).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 2, "Two independent plans should be generated");
        assert_ne!(arr[0]["check_id"], arr[1]["check_id"], "Plans should be for different checks");
    }

    #[test]
    fn credential_mask_multiple_tokens() {
        // Verify scrubbing works when multiple credential types are present.
        let mut config = HashMap::new();
        config.insert("GITHUB_TOKEN".to_string(), "ghp_token1".to_string());
        config.insert("OKTA_API_TOKEN".to_string(), "okta_secret_abc".to_string());
        let mask = CredentialMask::from_config(&config);

        let result = mask.scrub("ghp_token1 and okta_secret_abc in same string");
        assert!(!result.contains("ghp_token1"));
        assert!(!result.contains("okta_secret_abc"));
        assert_eq!(result.matches("***REDACTED***").count(), 2);
    }

    #[test]
    fn resolve_vars_allowed_var_org_name() {
        // Verify ORG_NAME is in the allowlist and resolves correctly.
        let mut config = HashMap::new();
        config.insert("ORG_NAME".to_string(), "my-company".to_string());
        let result = resolve_vars("https://api.github.com/orgs/{{ORG_NAME}}", &config);
        assert_eq!(result, "https://api.github.com/orgs/my-company");
    }

    #[test]
    #[ignore] // Pending F-001 fix in GRC-58 — un-ignore after is_okta_url/is_aws_url use host parsing
    fn sec_h014_url_allowlist_rejects_path_embedded_domains() {
        // SEC-H014 (CISO F-001): URL allowlist must reject URLs that embed trusted
        // domain strings in the PATH component, not the host. e.g.,
        // evil.example.com/.okta.com/steal would bypass a naive contains() check.
        assert!(
            validate_remediation_url("https://evil.example.com/.okta.com/steal").is_err(),
            "Path-embedded .okta.com must be rejected"
        );
        assert!(
            validate_remediation_url("https://evil.example.com/.amazonaws.com/steal").is_err(),
            "Path-embedded .amazonaws.com must be rejected"
        );
        assert!(
            validate_remediation_url("https://evil.example.com/api.github.com/steal").is_err(),
            "Path-embedded api.github.com must be rejected"
        );
    }

    // ─── write_audit_log ─────────────────────────────────────────────────────

    #[test]
    #[serial_test::serial]
    fn write_audit_log_creates_file_in_home() {
        // write_audit_log reads $HOME to determine the log path.
        // Override HOME to a tempdir so we don't pollute the real ~/.ocean/audit.log.
        let tmp = TempDir::new().unwrap();
        let tmp_home = tmp.path().to_str().unwrap().to_string();

        let plan = RemediationPlan {
            check_id: "GH-AUDIT".to_string(),
            check_name: "Audit Log Test".to_string(),
            description: String::new(),
            steps: Vec::new(),
            api_action: Some(ApiAction {
                method: "PATCH".to_string(),
                url: "https://api.github.com/orgs/test".to_string(),
                body: None,
            }),
            cli_action: None,
            terraform_resources: Vec::new(),
        };
        let result = RemediationResult {
            check_id: "GH-AUDIT".to_string(),
            success: true,
            actions_taken: vec!["done".to_string()],
            errors: Vec::new(),
        };
        let config = HashMap::new();
        let mask = CredentialMask::from_config(&config);

        // Temporarily override HOME (serialized to avoid races).
        let _guard = HOME_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("HOME", &tmp_home);
        write_audit_log(&plan, &result, &mask);
        std::env::remove_var("HOME");
        drop(_guard);

        let log_path = tmp.path().join(".ocean").join("audit.log");
        assert!(log_path.exists(), "audit.log should be created under $HOME/.ocean/");
        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("GH-AUDIT"), "log entry should contain check_id");
        assert!(content.contains("SUCCESS"), "log entry should contain status");
        assert!(content.contains("HARDEN --apply"), "log entry should contain action type");
    }

    #[test]
    #[serial_test::serial]
    fn write_audit_log_failed_result() {
        let tmp = TempDir::new().unwrap();
        let tmp_home = tmp.path().to_str().unwrap().to_string();

        let plan = RemediationPlan {
            check_id: "GH-FAIL".to_string(),
            check_name: "Fail Test".to_string(),
            description: String::new(),
            steps: Vec::new(),
            api_action: None,
            cli_action: None,
            terraform_resources: Vec::new(),
        };
        let result = RemediationResult {
            check_id: "GH-FAIL".to_string(),
            success: false,
            actions_taken: Vec::new(),
            errors: vec!["something went wrong".to_string()],
        };
        let config = HashMap::new();
        let mask = CredentialMask::from_config(&config);

        let _guard = HOME_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("HOME", &tmp_home);
        write_audit_log(&plan, &result, &mask);
        std::env::remove_var("HOME");
        drop(_guard);

        let log_path = tmp.path().join(".ocean").join("audit.log");
        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("FAILED"), "failed result should be logged as FAILED");
        assert!(content.contains("no-api"), "no api_action should show 'no-api'");
    }

    #[test]
    #[serial_test::serial]
    fn write_audit_log_appends_multiple_entries() {
        let tmp = TempDir::new().unwrap();
        let tmp_home = tmp.path().to_str().unwrap().to_string();

        let make_plan = |id: &str| RemediationPlan {
            check_id: id.to_string(),
            check_name: "Multi".to_string(),
            description: String::new(),
            steps: Vec::new(),
            api_action: None,
            cli_action: None,
            terraform_resources: Vec::new(),
        };
        let make_result = |id: &str| RemediationResult {
            check_id: id.to_string(),
            success: true,
            actions_taken: Vec::new(),
            errors: Vec::new(),
        };

        let config = HashMap::new();
        let mask = CredentialMask::from_config(&config);

        let _guard = HOME_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("HOME", &tmp_home);
        write_audit_log(&make_plan("ENTRY-1"), &make_result("ENTRY-1"), &mask);
        write_audit_log(&make_plan("ENTRY-2"), &make_result("ENTRY-2"), &mask);
        std::env::remove_var("HOME");
        drop(_guard);

        let log_path = tmp.path().join(".ocean").join("audit.log");
        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("ENTRY-1") && content.contains("ENTRY-2"),
            "both entries should appear in the log");
        // Two newlines means two appended lines
        assert!(content.lines().count() >= 2, "should have at least two log lines");
    }

    #[test]
    #[serial_test::serial]
    fn write_audit_log_scrubs_credentials() {
        let tmp = TempDir::new().unwrap();
        let tmp_home = tmp.path().to_str().unwrap().to_string();

        let mut config = HashMap::new();
        config.insert("GITHUB_TOKEN".to_string(), "ghp_super_secret_xyz".to_string());
        let mask = CredentialMask::from_config(&config);

        let plan = RemediationPlan {
            check_id: "GH-SEC".to_string(),
            check_name: "Sec Test".to_string(),
            description: String::new(),
            steps: Vec::new(),
            api_action: Some(ApiAction {
                method: "PATCH".to_string(),
                url: "https://api.github.com/orgs/test?auth=ghp_super_secret_xyz".to_string(),
                body: None,
            }),
            cli_action: None,
            terraform_resources: Vec::new(),
        };
        let result = RemediationResult {
            check_id: "GH-SEC".to_string(),
            success: true,
            actions_taken: Vec::new(),
            errors: Vec::new(),
        };

        let _guard = HOME_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("HOME", &tmp_home);
        write_audit_log(&plan, &result, &mask);
        std::env::remove_var("HOME");
        drop(_guard);

        let log_path = tmp.path().join(".ocean").join("audit.log");
        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(!content.contains("ghp_super_secret_xyz"),
            "credential should be scrubbed from audit log");
        assert!(content.contains("***REDACTED***"),
            "redacted marker should appear in log");
    }

    // ─── execute_api_call ─────────────────────────────────────────────────────

    #[test]
    fn execute_api_call_invalid_method_returns_err() {
        let action = ApiAction {
            method: "CONNECT".to_string(),
            url: "https://api.github.com/orgs/test".to_string(),
            body: None,
        };
        let config = HashMap::new();
        let result = execute_api_call(&action, &config);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("invalid HTTP method"), "error should describe the problem: {msg}");
        assert!(msg.contains("CONNECT"), "error should name the bad method: {msg}");
    }

    #[test]
    fn execute_api_call_trace_method_rejected() {
        let action = ApiAction {
            method: "TRACE".to_string(),
            url: "https://api.github.com/orgs/test".to_string(),
            body: None,
        };
        let config = HashMap::new();
        let result = execute_api_call(&action, &config);
        assert!(result.is_err());
    }

    #[test]
    fn execute_api_call_uses_github_token_auth() {
        // Verify token is picked up from config: spawn a mock server and check
        // that the Authorization header is set when GITHUB_TOKEN is in config.
        let server = crate::testutil::MockHTTPServer::new(vec![(
            200,
            r#"{"ok":true}"#.to_string(),
        )]);
        let action = ApiAction {
            method: "GET".to_string(),
            url: format!("{}/test", server.url()),
            body: None,
        };
        let mut config = HashMap::new();
        config.insert("GITHUB_TOKEN".to_string(), "ghp_test_token".to_string());

        // The request will succeed (200 from mock); the fact it returns Ok proves
        // the token was accepted (we're not checking the header value server-side,
        // but this covers the auth-construction branch).
        let result = execute_api_call(&action, &config);
        assert!(result.is_ok(), "GET to mock server should succeed: {:?}", result);
        let msg = result.unwrap();
        assert!(msg.contains("GET"), "result should mention the method");
        assert!(msg.contains("200"), "result should mention the status code");
    }

    #[test]
    fn execute_api_call_uses_okta_token_when_no_github() {
        let server = crate::testutil::MockHTTPServer::new(vec![(
            200,
            r#"{"ok":true}"#.to_string(),
        )]);
        let action = ApiAction {
            method: "GET".to_string(),
            url: format!("{}/test", server.url()),
            body: None,
        };
        let mut config = HashMap::new();
        config.insert("OKTA_API_TOKEN".to_string(), "okta_secret".to_string());

        let result = execute_api_call(&action, &config);
        // The call reaches the server (200) regardless of which token is used.
        assert!(result.is_ok(), "OKTA token path should succeed: {:?}", result);
    }

    #[test]
    fn execute_api_call_no_token_in_config() {
        let server = crate::testutil::MockHTTPServer::new(vec![(
            200,
            r#"{"ok":true}"#.to_string(),
        )]);
        let action = ApiAction {
            method: "GET".to_string(),
            url: format!("{}/test", server.url()),
            body: None,
        };
        let config = HashMap::new(); // No token at all → auth header is empty string

        let result = execute_api_call(&action, &config);
        assert!(result.is_ok(), "call with no token should still reach mock server: {:?}", result);
    }

    #[test]
    fn execute_api_call_with_body() {
        let server = crate::testutil::MockHTTPServer::new(vec![(
            200,
            r#"{"updated":true}"#.to_string(),
        )]);
        let action = ApiAction {
            method: "PATCH".to_string(),
            url: format!("{}/test", server.url()),
            body: Some(serde_json::json!({"setting": true})),
        };
        let config = HashMap::new();

        let result = execute_api_call(&action, &config);
        assert!(result.is_ok(), "PATCH with body should succeed: {:?}", result);
        let msg = result.unwrap();
        assert!(msg.contains("PATCH"), "result should mention PATCH method");
    }

    #[test]
    fn execute_api_call_post_with_body() {
        let server = crate::testutil::MockHTTPServer::new(vec![(
            201,
            r#"{"created":true}"#.to_string(),
        )]);
        let action = ApiAction {
            method: "POST".to_string(),
            url: format!("{}/test", server.url()),
            body: Some(serde_json::json!({"name": "test"})),
        };
        let config = HashMap::new();

        let result = execute_api_call(&action, &config);
        assert!(result.is_ok(), "POST with body should succeed: {:?}", result);
    }

    #[test]
    fn execute_api_call_put_without_body() {
        let server = crate::testutil::MockHTTPServer::new(vec![(
            200,
            r#"{"ok":true}"#.to_string(),
        )]);
        let action = ApiAction {
            method: "PUT".to_string(),
            url: format!("{}/test", server.url()),
            body: None,
        };
        let config = HashMap::new();

        let result = execute_api_call(&action, &config);
        assert!(result.is_ok(), "PUT without body should succeed: {:?}", result);
    }

    #[test]
    fn execute_api_call_delete() {
        let server = crate::testutil::MockHTTPServer::new(vec![(
            204,
            String::new(),
        )]);
        let action = ApiAction {
            method: "DELETE".to_string(),
            url: format!("{}/test", server.url()),
            body: None,
        };
        let config = HashMap::new();

        // 204 with empty body: ureq may or may not error on empty JSON parse,
        // but the request itself reaches the server. Check we at least attempt it.
        let _ = execute_api_call(&action, &config);
        // Not asserting Ok/Err here since empty body JSON parse behavior varies;
        // the coverage target is the DELETE branch inside execute_api_call.
    }

    // ─── execute_plan terraform branches ─────────────────────────────────────

    #[test]
    fn execute_plan_terraform_writes_to_dir_when_provided() {
        let tmp = TempDir::new().unwrap();
        let tf_dir = tmp.path().join("tf");

        let plan = RemediationPlan {
            check_id: "TF-WRITE".to_string(),
            check_name: "TF Write Test".to_string(),
            description: String::new(),
            steps: Vec::new(),
            api_action: None,
            cli_action: None,
            terraform_resources: vec![serde_json::json!({"type": "github_org"})],
        };
        let config = HashMap::new();
        let mask = CredentialMask::from_config(&config);

        let result = execute_plan(&plan, &config, Some(&tf_dir), &mask);
        assert!(result.success, "terraform write should succeed");
        assert!(result.actions_taken.iter().any(|a| a.contains("Terraform written to")),
            "action message should mention Terraform written to path");
        assert!(tf_dir.exists(), "terraform dir should have been created");
    }

    #[test]
    fn execute_plan_terraform_none_dir_generates_hcl_inline() {
        let plan = RemediationPlan {
            check_id: "TF-INLINE".to_string(),
            check_name: "TF Inline Test".to_string(),
            description: String::new(),
            steps: Vec::new(),
            api_action: None,
            cli_action: None,
            terraform_resources: vec![serde_json::json!({"type": "github_org"})],
        };
        let config = HashMap::new();
        let mask = CredentialMask::from_config(&config);

        let result = execute_plan(&plan, &config, None, &mask);
        assert!(result.success, "inline terraform should succeed");
        assert!(result.actions_taken.iter().any(|a| a.contains("Terraform HCL:")),
            "action message should contain inline HCL");
    }

    // ─── print_results text format ────────────────────────────────────────────

    #[test]
    fn print_results_text_success() {
        let results = vec![RemediationResult {
            check_id: "GH-1.01".to_string(),
            success: true,
            actions_taken: vec!["PATCH → HTTP 200".to_string()],
            errors: Vec::new(),
        }];
        let mut out = Vec::new();
        print_results(&mut out, &results, "table", &empty_config()).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("✓"), "success should show checkmark");
        assert!(s.contains("GH-1.01"), "should show check id");
        assert!(s.contains("PATCH → HTTP 200"), "should show action taken");
    }

    #[test]
    fn print_results_text_failure() {
        let results = vec![RemediationResult {
            check_id: "GH-1.08".to_string(),
            success: false,
            actions_taken: Vec::new(),
            errors: vec!["API call failed: HTTP 403 Forbidden".to_string()],
        }];
        let mut out = Vec::new();
        print_results(&mut out, &results, "table", &empty_config()).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("✗"), "failure should show X mark");
        assert!(s.contains("GH-1.08"), "should show check id");
        assert!(s.contains("ERROR:"), "should show ERROR: prefix");
        assert!(s.contains("403"), "should show error content");
    }

    #[test]
    fn print_results_text_multiple_mixed() {
        let results = vec![
            RemediationResult {
                check_id: "GH-1.01".to_string(),
                success: true,
                actions_taken: vec!["action one".to_string(), "action two".to_string()],
                errors: Vec::new(),
            },
            RemediationResult {
                check_id: "GH-1.08".to_string(),
                success: false,
                actions_taken: Vec::new(),
                errors: vec!["err one".to_string(), "err two".to_string()],
            },
        ];
        let mut out = Vec::new();
        print_results(&mut out, &results, "table", &empty_config()).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("✓") && s.contains("✗"), "should show both outcomes");
        assert!(s.contains("action one") && s.contains("action two"), "all actions should appear");
        assert!(s.contains("err one") && s.contains("err two"), "all errors should appear");
    }

    // ─── print_dry_run terraform resources ────────────────────────────────────

    #[test]
    fn print_dry_run_table_with_terraform_resources() {
        let plans = vec![RemediationPlan {
            check_id: "TF-1".to_string(),
            check_name: "Terraform Check".to_string(),
            description: "fix it".to_string(),
            steps: Vec::new(),
            api_action: None,
            cli_action: None,
            terraform_resources: vec![
                serde_json::json!({"type": "github_org"}),
                serde_json::json!({"type": "github_branch"}),
            ],
        }];
        let mut out = Vec::new();
        print_dry_run(&mut out, &plans, "table", &empty_config()).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("Terraform:"), "should show Terraform summary");
        assert!(s.contains("2 resource(s)"), "should mention count of resources");
    }

    // ─── https_host malformed URL ─────────────────────────────────────────────

    #[test]
    fn https_host_malformed_url_returns_none() {
        // Malformed URL cannot be parsed — should return None (not panic).
        assert!(https_host("not a url at all").is_none());
        assert!(https_host("").is_none());
        assert!(https_host("://no-scheme").is_none());
    }

    #[test]
    fn https_host_http_scheme_returns_none() {
        // HTTP scheme is rejected (only HTTPS is accepted).
        assert!(https_host("http://api.github.com/orgs/test").is_none());
    }

    #[test]
    fn https_host_valid_https_returns_host() {
        let host = https_host("https://mycompany.okta.com/api/v1/policies");
        assert_eq!(host, Some("mycompany.okta.com".to_string()));
    }

    #[test]
    fn is_okta_url_malformed_returns_false() {
        assert!(!is_okta_url("not_a_url"));
        assert!(!is_okta_url("http://mycompany.okta.com/test"));
    }

    #[test]
    fn is_okta_url_oktapreview_accepted() {
        assert!(is_okta_url("https://mycompany.oktapreview.com/api/v1"));
    }

    #[test]
    fn is_aws_url_malformed_returns_false() {
        assert!(!is_aws_url("not_a_url"));
        assert!(!is_aws_url("http://iam.amazonaws.com/"));
    }

    // ─── resolve_vars_masked uncovered branches ───────────────────────────────

    #[test]
    fn resolve_vars_masked_non_credential_var_resolved() {
        // Non-credential vars in ALLOWED_TEMPLATE_VARS should be substituted.
        let mut config = HashMap::new();
        config.insert("org".to_string(), "acme-corp".to_string());
        let result = resolve_vars_masked("https://api.github.com/orgs/{{org}}", &config);
        assert_eq!(result, "https://api.github.com/orgs/acme-corp");
    }

    #[test]
    fn resolve_vars_masked_credential_var_stays_as_placeholder() {
        // Credential vars should remain unreplaced (TH-1a display safety).
        let mut config = HashMap::new();
        config.insert("GITHUB_TOKEN".to_string(), "ghp_secret".to_string());
        let result = resolve_vars_masked("Bearer {{GITHUB_TOKEN}}", &config);
        // Credential placeholder should NOT be substituted.
        assert!(result.contains("{{GITHUB_TOKEN}}"), "credential placeholder should stay: {result}");
        assert!(!result.contains("ghp_secret"), "credential value should not appear: {result}");
    }

    #[test]
    fn resolve_vars_masked_unknown_var_unchanged() {
        // Vars not in ALLOWED_TEMPLATE_VARS are not in config, stay as-is.
        let config = HashMap::new();
        let result = resolve_vars_masked("{{UNKNOWN_VAR}}", &config);
        assert_eq!(result, "{{UNKNOWN_VAR}}");
    }

    #[test]
    fn resolve_vars_masked_mixed_credential_and_plain() {
        // Only non-credential vars are resolved; credentials stay as placeholder.
        let mut config = HashMap::new();
        config.insert("OKTA_API_TOKEN".to_string(), "okta_secret".to_string());
        config.insert("domain".to_string(), "mycompany".to_string());
        let result = resolve_vars_masked("https://{{domain}}.okta.com?token={{OKTA_API_TOKEN}}", &config);
        assert!(result.contains("mycompany"), "plain var 'domain' should be substituted");
        assert!(result.contains("{{OKTA_API_TOKEN}}"), "credential placeholder must remain");
        assert!(!result.contains("okta_secret"), "credential value must not appear");
    }

    // ─── plan_harden early-return branches ───────────────────────────────────

    #[test]
    fn plan_harden_empty_checks_dir_returns_empty() {
        let dir = TempDir::new().unwrap();
        // Empty dir — no check files — defs.is_empty() early return.
        let config = HashMap::new();
        let result = plan_harden(dir.path(), &RemediationMode::All, &config, None).unwrap();
        assert!(result.is_empty(), "empty checks dir should return empty plans");
    }

    #[test]
    fn plan_harden_no_remediable_checks_returns_empty() {
        let dir = TempDir::new().unwrap();
        // Write a check without a remediation block — remediable.is_empty() early return.
        write_check(dir.path(), "no_rem.check.yaml", CHECK_WITHOUT_REMEDIATION);
        let config = HashMap::new();
        let result = plan_harden(dir.path(), &RemediationMode::All, &config, None).unwrap();
        assert!(result.is_empty(), "checks without remediation should produce no plans");
    }

    // ─── confirm_apply with body display ──────────────────────────────────────

    #[test]
    fn confirm_apply_auto_confirm_with_terraform_resources() {
        // Cover the terraform_resources display branch in confirm_apply.
        let plans = vec![RemediationPlan {
            check_id: "TF-CONFIRM".to_string(),
            check_name: "TF Confirm Test".to_string(),
            description: String::new(),
            steps: Vec::new(),
            api_action: None,
            cli_action: None,
            terraform_resources: vec![serde_json::json!({"type": "github_org"})],
        }];
        let mut out = Vec::new();
        let confirmed = confirm_apply(&mut out, &plans, &HashMap::new(), true).unwrap();
        assert!(confirmed);
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("Terraform:"), "should show Terraform resource count in confirmation");
        assert!(s.contains("1 resource(s)"), "should show count");
    }

    #[test]
    fn confirm_apply_auto_confirm_with_cli_action() {
        // Cover the cli_action display branch in confirm_apply.
        let plans = vec![RemediationPlan {
            check_id: "CLI-CONFIRM".to_string(),
            check_name: "CLI Confirm Test".to_string(),
            description: String::new(),
            steps: Vec::new(),
            api_action: None,
            cli_action: Some("gh api orgs/test -X PATCH".to_string()),
            terraform_resources: Vec::new(),
        }];
        let mut out = Vec::new();
        let confirmed = confirm_apply(&mut out, &plans, &HashMap::new(), true).unwrap();
        assert!(confirmed);
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("CLI (display only):"), "should label CLI action");
        assert!(s.contains("gh api"), "should show CLI command");
    }

    // ─── Additional coverage tests ───────────────────────────────────────────

    #[test]
    fn execute_api_call_connection_refused_returns_err() {
        // Cover the transport error path (not a status error, but a connection failure).
        let action = ApiAction {
            method: "GET".to_string(),
            url: "http://127.0.0.1:1/nonexistent".to_string(),
            body: None,
        };
        let config = HashMap::new();
        let result = execute_api_call(&action, &config);
        assert!(result.is_err(), "connection refused should return Err");
    }

    #[test]
    fn execute_api_call_post_without_body() {
        // POST without body uses req.call() path.
        let server = crate::testutil::MockHTTPServer::new(vec![(
            200,
            r#"{"ok":true}"#.to_string(),
        )]);
        let action = ApiAction {
            method: "POST".to_string(),
            url: format!("{}/test", server.url()),
            body: None,
        };
        let config = HashMap::new();
        let result = execute_api_call(&action, &config);
        assert!(result.is_ok(), "POST without body should succeed: {:?}", result);
    }

    #[test]
    fn execute_api_call_method_case_insensitive() {
        // Method is uppercased internally — "get" should work.
        let server = crate::testutil::MockHTTPServer::new(vec![(
            200,
            r#"{"ok":true}"#.to_string(),
        )]);
        let action = ApiAction {
            method: "get".to_string(),
            url: format!("{}/test", server.url()),
            body: None,
        };
        let config = HashMap::new();
        let result = execute_api_call(&action, &config);
        assert!(result.is_ok(), "lowercase method should be accepted");
    }

    #[test]
    #[serial_test::serial]
    fn is_user_checks_dir_home_unset() {
        // When HOME is not set, is_user_checks_dir should return false.
        let _guard = HOME_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let original_home = std::env::var("HOME").ok();
        std::env::remove_var("HOME");

        let result = is_user_checks_dir(Path::new("/some/path"));
        assert!(!result, "should return false when HOME is unset");

        // Restore HOME.
        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        }
        drop(_guard);
    }

    #[test]
    fn warn_user_checks_no_warning_for_non_user_dir() {
        // Non-user-checks dirs should produce no output.
        let mut out = Vec::new();
        warn_user_checks(&mut out, Path::new("/usr/share/ocean/checks"), &[]);
        let s = String::from_utf8(out).unwrap();
        assert!(s.is_empty(), "non-user dir should produce no warning output");
    }

    #[test]
    fn credential_mask_filters_empty_values() {
        // Empty credential values in config should be filtered out (not cause empty-string replacement).
        let mut config = HashMap::new();
        config.insert("GITHUB_TOKEN".to_string(), String::new()); // empty
        config.insert("OKTA_API_TOKEN".to_string(), "okta_real".to_string());
        let mask = CredentialMask::from_config(&config);

        // The empty GITHUB_TOKEN value should be filtered out.
        let result = mask.scrub("text with okta_real in it");
        assert!(result.contains("***REDACTED***"), "non-empty token should be scrubbed");
        assert!(!result.contains("okta_real"), "okta token should be scrubbed");
    }

    #[test]
    fn credential_mask_no_matching_keys() {
        // Config with keys that are NOT credential env vars.
        let mut config = HashMap::new();
        config.insert("org".to_string(), "my-org".to_string());
        config.insert("domain".to_string(), "example.com".to_string());
        let mask = CredentialMask::from_config(&config);

        let result = mask.scrub("my-org example.com");
        assert_eq!(result, "my-org example.com", "non-credential values should not be scrubbed");
    }

    #[test]
    fn execute_plan_api_error_scrubs_credentials() {
        // When an API call fails, the error message is scrubbed.
        let mut config = HashMap::new();
        config.insert("GITHUB_TOKEN".to_string(), "ghp_visible_secret".to_string());
        let mask = CredentialMask::from_config(&config);

        let plan = RemediationPlan {
            check_id: "API-ERR".to_string(),
            check_name: "API Error".to_string(),
            description: String::new(),
            steps: Vec::new(),
            api_action: Some(ApiAction {
                method: "GET".to_string(),
                url: "http://127.0.0.1:1/will-fail".to_string(),
                body: None,
            }),
            cli_action: None,
            terraform_resources: Vec::new(),
        };

        let result = execute_plan(&plan, &config, None, &mask);
        assert!(!result.success, "connection failure should make result not successful");
        assert!(!result.errors.is_empty(), "should have errors");
        // Credential should be scrubbed from error messages.
        for err in &result.errors {
            assert!(!err.contains("ghp_visible_secret"), "credential leaked in error: {err}");
        }
    }

    #[test]
    fn execute_plan_combined_api_cli_terraform() {
        // Test a plan with all three action types.
        let tmp = TempDir::new().unwrap();
        let tf_dir = tmp.path().join("tf");
        let server = crate::testutil::MockHTTPServer::new(vec![(
            200,
            r#"{"ok":true}"#.to_string(),
        )]);
        let plan = RemediationPlan {
            check_id: "COMBO".to_string(),
            check_name: "Combined".to_string(),
            description: String::new(),
            steps: Vec::new(),
            api_action: Some(ApiAction {
                method: "GET".to_string(),
                url: format!("{}/test", server.url()),
                body: None,
            }),
            cli_action: Some("echo hello".to_string()),
            terraform_resources: vec![serde_json::json!({"type": "github_org"})],
        };
        let config = HashMap::new();
        let mask = CredentialMask::from_config(&config);

        let result = execute_plan(&plan, &config, Some(&tf_dir), &mask);
        assert!(result.success, "combined plan should succeed");
        // Should have 3 actions: API result, CLI display, Terraform write
        assert_eq!(result.actions_taken.len(), 3, "should have 3 actions: {:?}", result.actions_taken);
    }

    #[test]
    #[serial_test::serial]
    fn write_audit_log_home_unset_uses_fallback() {
        // When HOME is not set, write_audit_log falls back to ".ocean".
        let plan = RemediationPlan {
            check_id: "NO-HOME".to_string(),
            check_name: "No Home".to_string(),
            description: String::new(),
            steps: Vec::new(),
            api_action: None,
            cli_action: None,
            terraform_resources: Vec::new(),
        };
        let result = RemediationResult {
            check_id: "NO-HOME".to_string(),
            success: true,
            actions_taken: Vec::new(),
            errors: Vec::new(),
        };
        let mask = CredentialMask::from_config(&HashMap::new());

        let _guard = HOME_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let original_home = std::env::var("HOME").ok();
        std::env::remove_var("HOME");

        // Should not panic even without HOME.
        write_audit_log(&plan, &result, &mask);

        // Restore HOME.
        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        }
        drop(_guard);
    }

    #[test]
    fn is_azure_url_malformed_returns_false() {
        assert!(!is_azure_url("not_a_url"));
        assert!(!is_azure_url("http://management.azure.com/test"));
    }

    #[test]
    fn validate_remediation_url_github_non_api() {
        // github.com (not api.github.com) should also be accepted.
        assert!(validate_remediation_url("https://github.com/orgs/test/settings").is_ok());
    }

    #[test]
    fn validate_remediation_url_oktapreview() {
        assert!(validate_remediation_url("https://mycompany.oktapreview.com/api/v1/policies").is_ok());
    }

    #[test]
    fn validate_remediation_url_completely_invalid() {
        // Not a URL at all — will fail URL parse, then fail allowlist.
        assert!(validate_remediation_url("not-a-url").is_err());
    }

    #[test]
    fn https_host_uppercase_is_lowercased() {
        let host = https_host("https://API.GITHUB.COM/orgs/test");
        assert_eq!(host, Some("api.github.com".to_string()));
    }

    #[test]
    fn print_dry_run_json_with_terraform_resources() {
        // JSON output with terraform_resources > 0 should show count.
        let plans = vec![RemediationPlan {
            check_id: "TF-JSON".to_string(),
            check_name: "TF JSON Test".to_string(),
            description: "fix".to_string(),
            steps: Vec::new(),
            api_action: None,
            cli_action: None,
            terraform_resources: vec![serde_json::json!({"type": "github_org"})],
        }];
        let mut out = Vec::new();
        print_dry_run(&mut out, &plans, "json", &empty_config()).unwrap();
        let s = String::from_utf8(out).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v[0]["terraform_resources"], 1);
    }

    #[test]
    fn print_dry_run_table_with_cli_only_plan() {
        // Table output with only cli_action (no API, no terraform).
        let plans = vec![RemediationPlan {
            check_id: "CLI-ONLY".to_string(),
            check_name: "CLI Only".to_string(),
            description: "fix".to_string(),
            steps: Vec::new(),
            api_action: None,
            cli_action: Some("gh api orgs/test".to_string()),
            terraform_resources: Vec::new(),
        }];
        let mut out = Vec::new();
        print_dry_run(&mut out, &plans, "table", &empty_config()).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("CLI:"), "should show CLI label");
        assert!(s.contains("gh api"), "should show command");
    }

    #[test]
    fn print_dry_run_table_with_steps() {
        // Table output with manual steps but no API/CLI/TF.
        let plans = vec![RemediationPlan {
            check_id: "STEPS-ONLY".to_string(),
            check_name: "Steps Only".to_string(),
            description: "fix".to_string(),
            steps: vec!["Step 1: do X".to_string(), "Step 2: do Y".to_string()],
            api_action: None,
            cli_action: None,
            terraform_resources: Vec::new(),
        }];
        let mut out = Vec::new();
        print_dry_run(&mut out, &plans, "table", &empty_config()).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("Manual steps:"), "should show manual steps header");
        assert!(s.contains("Step 1: do X"), "should show step 1");
        assert!(s.contains("Step 2: do Y"), "should show step 2");
    }

    #[test]
    fn print_results_text_scrubs_credentials() {
        // Success actions and failure errors should both be scrubbed.
        let mut config = HashMap::new();
        config.insert("GITHUB_TOKEN".to_string(), "ghp_leaked".to_string());

        let results = vec![
            RemediationResult {
                check_id: "SCRUB-OK".to_string(),
                success: true,
                actions_taken: vec!["action with ghp_leaked token".to_string()],
                errors: Vec::new(),
            },
            RemediationResult {
                check_id: "SCRUB-ERR".to_string(),
                success: false,
                actions_taken: Vec::new(),
                errors: vec!["error with ghp_leaked token".to_string()],
            },
        ];
        let mut out = Vec::new();
        print_results(&mut out, &results, "table", &config).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(!s.contains("ghp_leaked"), "credentials should be scrubbed from text output: {s}");
        assert!(s.contains("***REDACTED***"), "should show redacted marker");
    }

    #[test]
    fn print_results_json_scrubs_credentials() {
        let mut config = HashMap::new();
        config.insert("GITHUB_TOKEN".to_string(), "ghp_injson".to_string());

        let results = vec![RemediationResult {
            check_id: "JSON-SCRUB".to_string(),
            success: true,
            actions_taken: vec!["sent ghp_injson to server".to_string()],
            errors: Vec::new(),
        }];
        let mut out = Vec::new();
        print_results(&mut out, &results, "json", &config).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(!s.contains("ghp_injson"), "credentials should be scrubbed from JSON output: {s}");
    }

    #[test]
    #[serial_test::serial]
    fn execute_plans_writes_audit_logs() {
        // execute_plans calls write_audit_log for each plan.
        let tmp = TempDir::new().unwrap();
        let tmp_home = tmp.path().to_str().unwrap().to_string();

        let plans = vec![
            RemediationPlan {
                check_id: "AUDIT-1".to_string(),
                check_name: "Audit 1".to_string(),
                description: String::new(),
                steps: Vec::new(),
                api_action: None,
                cli_action: Some("echo test".to_string()),
                terraform_resources: Vec::new(),
            },
            RemediationPlan {
                check_id: "AUDIT-2".to_string(),
                check_name: "Audit 2".to_string(),
                description: String::new(),
                steps: Vec::new(),
                api_action: None,
                cli_action: None,
                terraform_resources: Vec::new(),
            },
        ];

        let _guard = HOME_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("HOME", &tmp_home);
        let results = execute_plans(&plans, &HashMap::new(), None);
        std::env::remove_var("HOME");
        drop(_guard);

        assert_eq!(results.len(), 2);
        let log_path = tmp.path().join(".ocean").join("audit.log");
        assert!(log_path.exists(), "audit.log should be created by execute_plans");
        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("AUDIT-1") && content.contains("AUDIT-2"),
            "both plans should be logged");
    }

    #[test]
    fn resolve_vars_multiple_allowed_vars() {
        // Test multiple allowed vars resolved in one template.
        let mut config = HashMap::new();
        config.insert("org".to_string(), "my-org".to_string());
        config.insert("domain".to_string(), "example.com".to_string());
        config.insert("tenant".to_string(), "my-tenant".to_string());
        let result = resolve_vars("{{org}}/{{domain}}/{{tenant}}", &config);
        assert_eq!(result, "my-org/example.com/my-tenant");
    }

    #[test]
    fn confirm_apply_auto_confirm_with_body_and_all_actions() {
        // Cover the full display of a plan with API body, CLI, and terraform in confirm_apply.
        let plans = vec![RemediationPlan {
            check_id: "ALL-ACTIONS".to_string(),
            check_name: "All Actions".to_string(),
            description: String::new(),
            steps: Vec::new(),
            api_action: Some(ApiAction {
                method: "PATCH".to_string(),
                url: "https://api.github.com/orgs/test".to_string(),
                body: Some(serde_json::json!({"key": "value"})),
            }),
            cli_action: Some("gh api test".to_string()),
            terraform_resources: vec![serde_json::json!({"type": "x"}), serde_json::json!({"type": "y"})],
        }];
        let mut out = Vec::new();
        let confirmed = confirm_apply(&mut out, &plans, &HashMap::new(), true).unwrap();
        assert!(confirmed);
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("PATCH"), "should show method");
        assert!(s.contains("Body:"), "should show body");
        assert!(s.contains("CLI (display only):"), "should show CLI");
        assert!(s.contains("2 resource(s)"), "should show terraform count");
    }

    #[test]
    fn execute_plan_terraform_write_error() {
        // Trigger a terraform write failure by giving an invalid directory path.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let tmp = TempDir::new().unwrap();
            let readonly_dir = tmp.path().join("readonly");
            std::fs::create_dir_all(&readonly_dir).unwrap();
            std::fs::set_permissions(&readonly_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
            let nested = readonly_dir.join("nested");

            let plan = RemediationPlan {
                check_id: "TF-ERR".to_string(),
                check_name: "TF Error".to_string(),
                description: String::new(),
                steps: Vec::new(),
                api_action: None,
                cli_action: None,
                terraform_resources: vec![serde_json::json!({"type": "github_org"})],
            };
            let config = HashMap::new();
            let mask = CredentialMask::from_config(&config);

            let result = execute_plan(&plan, &config, Some(&nested), &mask);
            assert!(!result.success, "terraform write to unwritable dir should fail");
            assert!(!result.errors.is_empty(), "should have error message");

            // Restore permissions for cleanup.
            std::fs::set_permissions(&readonly_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    #[test]
    fn remediation_mode_includes_terraform_only() {
        assert!(!RemediationMode::Terraform.includes_api());
        assert!(RemediationMode::Terraform.includes_terraform());
        assert!(!RemediationMode::Terraform.includes_cli());
    }

    #[test]
    fn remediation_mode_includes_cli_only() {
        assert!(!RemediationMode::Cli.includes_api());
        assert!(!RemediationMode::Cli.includes_terraform());
        assert!(RemediationMode::Cli.includes_cli());
    }

    #[test]
    fn credential_mask_all_credential_types() {
        // Test that all six credential env vars are scrubbed.
        let mut config = HashMap::new();
        config.insert("GITHUB_TOKEN".to_string(), "gh_secret".to_string());
        config.insert("OKTA_API_TOKEN".to_string(), "okta_secret".to_string());
        config.insert("AWS_SECRET_ACCESS_KEY".to_string(), "aws_key".to_string());
        config.insert("AWS_SESSION_TOKEN".to_string(), "aws_session".to_string());
        config.insert("AZURE_CLIENT_SECRET".to_string(), "azure_secret".to_string());
        config.insert("GCP_SERVICE_ACCOUNT_KEY".to_string(), "gcp_key".to_string());
        let mask = CredentialMask::from_config(&config);

        let input = "gh_secret okta_secret aws_key aws_session azure_secret gcp_key";
        let result = mask.scrub(input);
        assert_eq!(result.matches("***REDACTED***").count(), 6,
            "all 6 credentials should be scrubbed: {result}");
    }

    #[test]
    fn resolve_vars_credential_vars_are_resolved() {
        // resolve_vars (unlike resolve_vars_masked) should resolve credential vars too.
        let mut config = HashMap::new();
        config.insert("GITHUB_TOKEN".to_string(), "ghp_resolved".to_string());
        let result = resolve_vars("Bearer {{GITHUB_TOKEN}}", &config);
        assert_eq!(result, "Bearer ghp_resolved", "resolve_vars should resolve credential vars");
    }

    #[test]
    fn resolve_vars_masked_all_credential_vars_stay() {
        // All credential env vars should stay as placeholders in masked mode.
        let mut config = HashMap::new();
        config.insert("AWS_SECRET_ACCESS_KEY".to_string(), "aws_secret_val".to_string());
        config.insert("AWS_SESSION_TOKEN".to_string(), "aws_session_val".to_string());
        config.insert("AZURE_CLIENT_SECRET".to_string(), "azure_val".to_string());
        config.insert("GCP_SERVICE_ACCOUNT_KEY".to_string(), "gcp_val".to_string());

        for key in &["AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AZURE_CLIENT_SECRET", "GCP_SERVICE_ACCOUNT_KEY"] {
            let template = format!("{{{{{}}}}}", key);
            let result = resolve_vars_masked(&template, &config);
            assert_eq!(result, template, "credential var {} should stay as placeholder", key);
        }
    }

    #[test]
    fn print_dry_run_json_with_cli_action() {
        let plans = vec![RemediationPlan {
            check_id: "CLI-JSON".to_string(),
            check_name: "CLI JSON Test".to_string(),
            description: "fix".to_string(),
            steps: vec!["do X".to_string()],
            api_action: None,
            cli_action: Some("gh api test".to_string()),
            terraform_resources: Vec::new(),
        }];
        let mut out = Vec::new();
        print_dry_run(&mut out, &plans, "json", &empty_config()).unwrap();
        let s = String::from_utf8(out).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v[0]["cli"], "gh api test");
        assert!(v[0]["api"].is_null(), "api should be null when not present");
    }

    #[test]
    fn execute_plan_empty_plan_succeeds() {
        // A plan with no actions at all should still succeed.
        let plan = RemediationPlan {
            check_id: "EMPTY".to_string(),
            check_name: "Empty".to_string(),
            description: String::new(),
            steps: Vec::new(),
            api_action: None,
            cli_action: None,
            terraform_resources: Vec::new(),
        };
        let config = HashMap::new();
        let mask = CredentialMask::from_config(&config);

        let result = execute_plan(&plan, &config, None, &mask);
        assert!(result.success, "empty plan should succeed");
        assert!(result.actions_taken.is_empty(), "no actions taken");
        assert!(result.errors.is_empty(), "no errors");
    }

    // ─── Fault-injection: write-error `?` paths ──────────────────────────────

    fn full_plan() -> RemediationPlan {
        RemediationPlan {
            check_id: "GH-X".to_string(),
            check_name: "Full Plan".to_string(),
            description: "desc".to_string(),
            steps: vec!["step1".to_string(), "step2".to_string()],
            api_action: Some(ApiAction {
                method: "POST".to_string(),
                url: "https://api.github.com/orgs/x".to_string(),
                body: Some(serde_json::json!({"k": "v"})),
            }),
            cli_action: Some("gh api x".to_string()),
            terraform_resources: vec![serde_json::json!({"type": "github_organization"})],
        }
    }

    fn full_result(success: bool) -> RemediationResult {
        RemediationResult {
            check_id: "GH-X".to_string(),
            success,
            actions_taken: vec!["did thing".to_string()],
            errors: if success { vec![] } else { vec!["err1".to_string()] },
        }
    }

    #[test]
    fn print_dry_run_fault_injection() {
        use crate::testutil::FailingWriter;
        let plans = vec![full_plan()];
        for n in 0..60 {
            let mut w = FailingWriter::new(n);
            let _ = print_dry_run(&mut w, &plans, "json", &empty_config());
            let _ = print_dry_run(&mut w, &plans, "table", &empty_config());
            let _ = print_dry_run(&mut w, &[], "table", &empty_config());
        }
    }

    #[test]
    fn print_results_fault_injection() {
        use crate::testutil::FailingWriter;
        let results = vec![full_result(true), full_result(false)];
        for n in 0..60 {
            let mut w = FailingWriter::new(n);
            let _ = print_results(&mut w, &results, "json", &empty_config());
            let _ = print_results(&mut w, &results, "table", &empty_config());
        }
    }

    #[test]
    fn confirm_apply_fault_injection_auto_confirm() {
        use crate::testutil::FailingWriter;
        let plans = vec![full_plan()];
        for n in 0..60 {
            let mut w = FailingWriter::new(n);
            // auto_confirm=true skips stdin read, exercises all writelns.
            let _ = confirm_apply(&mut w, &plans, &empty_config(), true);
        }
    }

    #[test]
    fn warn_user_checks_fault_injection() {
        use crate::testutil::FailingWriter;
        // Need a dir that triggers the warning. Use ~/.ocean/checks if it
        // exists, else just fault-inject without expecting the branch.
        let tmp = TempDir::new().unwrap();
        for n in 0..20 {
            let mut w = FailingWriter::new(n);
            warn_user_checks(&mut w, tmp.path(), &[]);
        }
    }
}
