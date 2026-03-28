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
            rem.api.as_ref().map(|api| ApiAction {
                method: api.method.clone(),
                url: resolve_vars(&api.url, config),
                body: api.body.clone(),
            })
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
pub fn execute_plans(
    plans: &[RemediationPlan],
    config: &HashMap<String, String>,
    terraform_dir: Option<&Path>,
) -> Vec<RemediationResult> {
    plans.iter().map(|plan| execute_plan(plan, config, terraform_dir)).collect()
}

fn execute_plan(
    plan: &RemediationPlan,
    config: &HashMap<String, String>,
    terraform_dir: Option<&Path>,
) -> RemediationResult {
    let mut actions_taken = Vec::new();
    let mut errors = Vec::new();

    // API remediation
    if let Some(api) = &plan.api_action {
        match execute_api_call(api, config) {
            Ok(msg) => actions_taken.push(msg),
            Err(e) => errors.push(format!("API call failed: {e}")),
        }
    }

    // CLI remediation — show the command, don't execute it
    if let Some(cmd) = &plan.cli_action {
        actions_taken.push(format!("Run: {cmd}"));
    }

    // Terraform remediation
    if !plan.terraform_resources.is_empty() {
        if let Some(dir) = terraform_dir {
            match write_terraform(plan, dir) {
                Ok(path) => actions_taken.push(format!("Terraform written to {}", path.display())),
                Err(e) => errors.push(format!("Terraform write failed: {e}")),
            }
        } else {
            let hcl = generate_terraform_hcl(plan);
            actions_taken.push(format!("Terraform HCL:\n{hcl}"));
        }
    }

    RemediationResult {
        check_id: plan.check_id.clone(),
        success: errors.is_empty(),
        actions_taken,
        errors,
    }
}

fn execute_api_call(action: &ApiAction, config: &HashMap<String, String>) -> Result<String> {
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

// ─── Output formatting ────────────────────────────────────────────────────────

/// Print harden plans in dry-run mode.
pub fn print_dry_run<W: Write>(out: &mut W, plans: &[RemediationPlan], format: &str) -> Result<()> {
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
                        "url": a.url,
                        "body": a.body,
                    })),
                    "cli": p.cli_action,
                    "terraform_resources": p.terraform_resources.len(),
                })
            })
            .collect();
        writeln!(out, "{}", serde_json::to_string_pretty(&json)?)?;
    } else {
        if plans.is_empty() {
            writeln!(out, "No failing checks with remediation plans found.")?;
            return Ok(());
        }
        writeln!(out, "\n[DRY RUN] Remediation plan — use --apply to execute\n")?;
        for plan in plans {
            writeln!(out, "  ▸ {} — {}", plan.check_id, plan.check_name)?;
            if let Some(api) = &plan.api_action {
                writeln!(out, "    API: {} {}", api.method, api.url)?;
            }
            if let Some(cmd) = &plan.cli_action {
                writeln!(out, "    CLI: {cmd}")?;
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
pub fn print_results<W: Write>(out: &mut W, results: &[RemediationResult], format: &str) -> Result<()> {
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
        writeln!(out, "{}", serde_json::to_string_pretty(&json)?)?;
    } else {
        for r in results {
            if r.success {
                writeln!(out, "  ✓ {}", r.check_id)?;
                for action in &r.actions_taken {
                    writeln!(out, "    {action}")?;
                }
            } else {
                writeln!(out, "  ✗ {}", r.check_id)?;
                for err in &r.errors {
                    writeln!(out, "    ERROR: {err}")?;
                }
            }
        }
    }
    Ok(())
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Resolve `{{key}}` template variables from the config map.
fn resolve_vars(template: &str, config: &HashMap<String, String>) -> String {
    let mut result = template.to_string();
    for (key, value) in config {
        let placeholder = format!("{{{{{key}}}}}");
        result = result.replace(&placeholder, value);
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

    #[test]
    fn print_dry_run_json_empty() {
        let mut out = Vec::new();
        print_dry_run(&mut out, &[], "json").unwrap();
        let s = String::from_utf8(out).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(v.as_array().unwrap().is_empty());
    }

    #[test]
    fn print_dry_run_table_empty() {
        let mut out = Vec::new();
        print_dry_run(&mut out, &[], "table").unwrap();
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
        print_dry_run(&mut out, &plans, "table").unwrap();
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
        print_results(&mut out, &results, "json").unwrap();
        let s = String::from_utf8(out).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v[0]["check_id"], "GH-1.01");
        assert_eq!(v[0]["success"], true);
    }
}
