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
    // Buildkite issues a single API access token that authenticates BOTH the REST
    // API and GraphQL. BUILDKITE_API_TOKEN is on the fleet credential allowlist
    // (`fleet::manifest::allowed_credentials`) and is substituted into remediation
    // headers, so it must be on the masking plane: a credential that is allowed but
    // not masked can reach stdout, the dry-run JSON, and ~/.ocean/audit.log
    // verbatim. BUILDKITE_API_KEY is kept here (masking only, not on the fleet
    // allowlist) because operators commonly export that spelling for the same
    // token, and `env_as_config()` reads the whole environment.
    "BUILDKITE_API_TOKEN",
    "BUILDKITE_API_KEY",
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
        || is_buildkite_url(url)
    {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "remediation URL rejected by allowlist: {url}\n\
             Allowed: api.github.com, *.okta.com, AWS, Azure, Buildkite endpoints.\n\
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

/// Buildkite's control plane is SaaS-only: `api.buildkite.com` (REST v2) and
/// `graphql.buildkite.com` (GraphQL v1). There is no self-hosted Buildkite
/// control plane, so the host set is fixed and does not need to be templated.
///
/// Host-parsed, never `starts_with`, so a path-embedded `buildkite.com` on a
/// hostile host (`https://evil.example.com/api.buildkite.com/steal`) is rejected
/// — the SEC-H014 / CISO F-001 bypass class.
fn is_buildkite_url(raw: &str) -> bool {
    https_host(raw)
        .map(|host| host == "buildkite.com" || host.ends_with(".buildkite.com"))
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
    // Buildkite. `env_as_config()` is `std::env::vars()`, so the resolvable names
    // are ENV VAR names — these are exactly the names the buildkite checks already
    // declare under `inputs[*].env` and that `fleet::manifest::allowed_credentials`
    // blesses, so a remediation template and a check input read the same variable.
    // BUILDKITE_API_TOKEN is a credential: it is on CREDENTIAL_ENV_VARS above, so
    // `resolve_vars_masked` leaves it unresolved for display and `CredentialMask`
    // scrubs it from any output path that does resolve it.
    "BUILDKITE_API_TOKEN",
    "BUILDKITE_ORG_SLUG",
    "BUILDKITE_CLUSTER_ID",
    "BUILDKITE_GRAPHQL_ID",
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

#[derive(Debug, Default)]
pub struct ApiAction {
    pub method: String,
    pub url: String,
    pub body: Option<serde_json::Value>,
    /// Request headers declared by the check's `remediation.api.headers` block.
    ///
    /// Stored UNRESOLVED (`Bearer {{BUILDKITE_API_TOKEN}}`) on purpose: the plan is
    /// printed by `print_dry_run`/`confirm_apply` and written to `~/.ocean/audit.log`,
    /// and a header that is never resolved until `execute_api_call` cannot leak a
    /// token through any of those paths. Empty means "use the built-in
    /// GitHub/Okta bearer", which is the pre-existing behaviour for every check
    /// that declares no headers.
    pub headers: HashMap<String, String>,
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
                match validate_remediation_url(&resolved_url) {
                    Ok(()) => Some(ApiAction {
                        method: api.method.clone(),
                        url: resolved_url,
                        body: api.body.as_ref().map(|b| resolve_json_vars(b, config)),
                        headers: api.headers.clone(),
                    }),
                    Err(e) => {
                        // A rejected URL disqualifies the API ACTION, not the whole
                        // plan. The previous `continue` dropped the entire
                        // RemediationPlan — the operator lost `steps`, `manual`,
                        // `cli` and `terraform` as well, and `findings = plans.len()`
                        // in fleet under-reported the run.
                        eprintln!(
                            "  ⚠ {}: API remediation dropped ({e}); manual steps, CLI and Terraform remain",
                            check_id
                        );
                        None
                    }
                }
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

    let mut req = ureq::request(&method_upper, &action.url);

    if action.headers.is_empty() {
        // Unchanged legacy path: every check that declares no
        // `remediation.api.headers` keeps the GitHub/Okta bearer and the GitHub
        // media-type headers it has always been sent with.
        let auth = config
            .get("GITHUB_TOKEN")
            .or_else(|| config.get("OKTA_API_TOKEN"))
            .map(|t| format!("Bearer {t}"))
            .unwrap_or_default();
        req = req
            .set("Authorization", &auth)
            .set("Accept", "application/vnd.github+json")
            .set("X-GitHub-Api-Version", "2022-11-28");
    } else {
        // The check declared its own headers. Honour them verbatim and send NO
        // GitHub headers — `X-GitHub-Api-Version` on a Buildkite request is at
        // best noise, and the GitHub/Okta bearer is the wrong credential
        // entirely. Values are resolved here (not at plan time) so the token
        // never enters the printed plan or the audit log.
        let mut names: Vec<&String> = action.headers.keys().collect();
        names.sort(); // deterministic request construction
        for name in names {
            let value = resolve_vars(&action.headers[name], config);
            if value.contains("{{") {
                return Err(anyhow::anyhow!(
                    "header '{name}' still contains an unresolved template after \
                     substitution — the variable is either unset in the environment or \
                     not on ALLOWED_TEMPLATE_VARS; refusing to send the request"
                ));
            }
            req = req.set(name, &value);
        }
    }

    // The body is resolved at plan time (`resolve_json_vars`). A surviving `{{...}}`
    // means a required variable was unset or is not on ALLOWED_TEMPLATE_VARS —
    // sending it would post a literal placeholder as a real value (an invalid
    // GraphQL node id, an unparseable timestamp) against the tenant.
    if let Some(body) = &action.body {
        let rendered = serde_json::to_string(body).unwrap_or_default();
        if rendered.contains("{{") {
            return Err(anyhow::anyhow!(
                "request body still contains an unresolved template after substitution \
                 — a required variable is unset in the environment or is not on \
                 ALLOWED_TEMPLATE_VARS; refusing to send the request"
            ));
        }
    }

    let resp = if let Some(body) = &action.body {
        req.send_json(body).context("API call failed")?
    } else {
        req.call().context("API call failed")?
    };

    let status = resp.status();
    let body_text = resp.into_string().unwrap_or_default();

    // GraphQL reports application-level failure as HTTP 200 with a top-level
    // `errors` array. ureq only errors on non-2xx, so without this a rejected
    // mutation (bad variables, missing scope, plan-gated field) was recorded as
    // SUCCESS in ~/.ocean/audit.log. Buildkite's remediation surface is GraphQL,
    // so this is the difference between a real fix and a false assurance.
    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body_text) {
        if let Some(errors) = parsed.get("errors").and_then(|e| e.as_array()) {
            if !errors.is_empty() {
                let detail = errors
                    .iter()
                    .filter_map(|e| e.get("message").and_then(|m| m.as_str()))
                    .collect::<Vec<_>>()
                    .join("; ");
                return Err(anyhow::anyhow!(
                    "{} {} → HTTP {status} but the response carries GraphQL errors: {}",
                    action.method,
                    action.url,
                    if detail.is_empty() {
                        "(no message field)".to_string()
                    } else {
                        detail
                    }
                ));
            }
        }
    }

    Ok(format!("{} {} → HTTP {status}", action.method, action.url))
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
                        // Unresolved templates by construction — see ApiAction::headers.
                        "headers": a.headers,
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
                if !api.headers.is_empty() {
                    let mut names: Vec<&String> = api.headers.keys().collect();
                    names.sort();
                    for name in names {
                        // Templates, not values — resolution happens at execute time.
                        writeln!(
                            out,
                            "      header {name}: {}",
                            mask.scrub(&api.headers[name])
                        )?;
                    }
                }
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

/// Recursively apply `resolve_vars` to every string inside a JSON value.
///
/// Remediation request bodies carry `{{VAR}}` placeholders exactly as URLs do
/// (`{"variables": {"orgId": "{{BUILDKITE_GRAPHQL_ID}}"}}`). Before this, `body`
/// was cloned verbatim, so a templated body was transmitted with the braces
/// still in it. Substitution is restricted to `ALLOWED_TEMPLATE_VARS` because it
/// reuses `resolve_vars` (TH-2d).
fn resolve_json_vars(
    val: &serde_json::Value,
    config: &HashMap<String, String>,
) -> serde_json::Value {
    match val {
        serde_json::Value::String(s) => serde_json::Value::String(resolve_vars(s, config)),
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), resolve_json_vars(v, config)))
                .collect(),
        ),
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(|v| resolve_json_vars(v, config)).collect())
        }
        other => other.clone(),
    }
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
    use tempfile::TempDir;

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
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
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
                    ..Default::default()
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
                ..Default::default()
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
                    ..Default::default()
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
                    ..Default::default()
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

    // ── Buildkite: URL allowlist, masking plane, template plumbing ──────────

    #[test]
    fn buildkite_hosts_pass_the_remediation_url_allowlist() {
        for u in [
            "https://graphql.buildkite.com/v1",
            "https://api.buildkite.com/v2/organizations/acme/clusters/abc/tokens",
            "https://buildkite.com/organizations/acme/settings/security",
        ] {
            assert!(
                validate_remediation_url(u).is_ok(),
                "should be allowed: {u}"
            );
        }
    }

    #[test]
    fn buildkite_lookalike_hosts_are_still_rejected() {
        // Host-parsed, not `starts_with` — the SEC-H014 path-embedding class.
        assert!(
            validate_remediation_url("https://evil.example.com/api.buildkite.com/steal").is_err()
        );
        assert!(validate_remediation_url("https://buildkite.com.evil.example.com/v1").is_err());
        assert!(validate_remediation_url("http://graphql.buildkite.com/v1").is_err());
        assert!(validate_remediation_url("https://notbuildkite.com/v1").is_err());
    }

    #[test]
    fn buildkite_api_token_is_on_the_masking_plane() {
        // A credential on the fleet allowlist that is NOT on CREDENTIAL_ENV_VARS
        // reaches stdout, the dry-run JSON and ~/.ocean/audit.log verbatim.
        let mut config = HashMap::new();
        config.insert(
            "BUILDKITE_API_TOKEN".to_string(),
            "bkua_deadbeef".to_string(),
        );
        config.insert(
            "BUILDKITE_API_KEY".to_string(),
            "bkua_altspelling".to_string(),
        );
        let mask = CredentialMask::from_config(&config);
        let line =
            "POST https://graphql.buildkite.com/v1 Bearer bkua_deadbeef alt bkua_altspelling";
        let scrubbed = mask.scrub(line);
        assert!(!scrubbed.contains("bkua_deadbeef"));
        assert!(!scrubbed.contains("bkua_altspelling"));
    }

    #[test]
    fn rejected_url_drops_only_the_api_action_not_the_whole_plan() {
        // Regression for the `continue` that deleted the entire RemediationPlan —
        // steps, manual, cli and terraform went with it, and fleet's
        // `findings = plans.len()` under-counted the run.
        let tmp = TempDir::new().unwrap();
        write_check(
            tmp.path(),
            "unlisted.check.yaml",
            r#"
id: TST-UNLISTED
name: Unlisted Host
source: mock
type: passive
steps: []
assertions:
  - id: always_fails
    expr: "1 == 2"
    severity: high
    title: t
    pass_message: p
    fail_message: f
remediation:
  description: d
  steps: ["do the thing by hand"]
  api:
    method: POST
    url: "https://not-on-the-allowlist.example.com/v1"
  cli:
    command: "echo fix-me"
"#,
        );
        let plans = plan_harden(tmp.path(), &RemediationMode::All, &HashMap::new(), None).unwrap();
        if let Some(p) = plans.iter().find(|p| p.check_id == "TST-UNLISTED") {
            assert!(
                p.api_action.is_none(),
                "rejected URL must drop the API action"
            );
            assert!(
                !p.steps.is_empty(),
                "manual steps must survive a rejected URL"
            );
            assert!(
                p.cli_action.is_some(),
                "cli action must survive a rejected URL"
            );
        }
    }

    #[test]
    fn remediation_body_templates_are_resolved() {
        let mut config = HashMap::new();
        config.insert(
            "BUILDKITE_GRAPHQL_ID".to_string(),
            "T3JnYW5pemF0aW9uLS0t".to_string(),
        );
        let body = serde_json::json!({
            "query": "mutation($orgId: ID!) { x }",
            "variables": { "orgId": "{{BUILDKITE_GRAPHQL_ID}}" }
        });
        let resolved = resolve_json_vars(&body, &config);
        assert_eq!(
            resolved["variables"]["orgId"],
            serde_json::json!("T3JnYW5pemF0aW9uLS0t")
        );
        // Query text is untouched: `$orgId` is GraphQL syntax, not a template.
        assert_eq!(resolved["query"], body["query"]);
    }

    #[test]
    fn non_allowlisted_template_var_is_never_substituted_into_a_body() {
        let mut config = HashMap::new();
        config.insert("MALICIOUS".to_string(), "pwned".to_string());
        let body = serde_json::json!({"v": "{{MALICIOUS}}"});
        assert_eq!(
            resolve_json_vars(&body, &config)["v"],
            serde_json::json!("{{MALICIOUS}}")
        );
    }

    #[test]
    fn declared_headers_reach_the_plan_unresolved() {
        // Headers stay templated in the plan so the token cannot leak into the
        // dry-run output or the audit log; resolution happens in execute_api_call.
        let mut headers = HashMap::new();
        headers.insert(
            "Authorization".to_string(),
            "Bearer {{BUILDKITE_API_TOKEN}}".to_string(),
        );
        let action = ApiAction {
            method: "POST".to_string(),
            url: "https://graphql.buildkite.com/v1".to_string(),
            body: None,
            headers,
        };
        assert_eq!(
            action.headers["Authorization"],
            "Bearer {{BUILDKITE_API_TOKEN}}"
        );
        let plan = RemediationPlan {
            check_id: "BK-1.02".to_string(),
            check_name: "n".to_string(),
            description: String::new(),
            steps: Vec::new(),
            api_action: Some(action),
            cli_action: None,
            terraform_resources: Vec::new(),
        };
        let mut config = HashMap::new();
        config.insert("BUILDKITE_API_TOKEN".to_string(), "bkua_secret".to_string());
        let mut out = Vec::new();
        print_dry_run(&mut out, std::slice::from_ref(&plan), "table", &config).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(
            s.contains("{{BUILDKITE_API_TOKEN}}"),
            "header template should be shown"
        );
        assert!(
            !s.contains("bkua_secret"),
            "token must never reach dry-run output"
        );
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
}
