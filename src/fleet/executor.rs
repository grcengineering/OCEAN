// Parallel fleet target execution via tokio.
//
// Security mitigations: F22 (no set_var), F23 (owned HashMap per task),
// F24 (config param pattern), F25 (credential lifetime), F26 (scrub errors),
// F27 (per-target ureq::Agent), F28 (output dir permissions).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use tokio::sync::Semaphore;

use crate::harden::{execute_plans, plan_harden, CredentialMask, RemediationMode};

use super::manifest::FleetManifest;

// ─── Result Types ───────────────────────────────────────────────────────────

/// Status of a single fleet target's execution.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetStatus {
    Completed,
    Failed,
    Skipped,
}

/// Result from executing a single fleet target.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TargetResult {
    pub id: String,
    pub source: String,
    pub status: TargetStatus,
    pub checks_run: usize,
    pub findings: usize,
    pub changes_applied: usize,
    pub error: Option<String>,
    pub results_file: PathBuf,
}

/// Aggregated result from fleet execution.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FleetResult {
    pub fleet_name: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub total_targets: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub checks_run: usize,
    pub findings: usize,
    pub targets: Vec<TargetResult>,
}

// ─── Execution Configuration ────────────────────────────────────────────────

/// Options for fleet execution.
pub struct FleetExecOptions {
    pub checks_dir: String,
    pub mode: RemediationMode,
    pub apply: bool,
    pub concurrency: u8,
    pub continue_on_error: bool,
    pub output_dir: PathBuf,
    pub terraform_dir: String,
}

// ─── Executor ───────────────────────────────────────────────────────────────

/// Execute a fleet manifest with parallel target processing.
///
/// Each target gets its own:
/// - Credential context (owned HashMap) [F23]
/// - HTTP client (ureq::Agent) [F27]
/// - Output file [F14]
///
/// Returns the aggregated fleet result.
pub async fn execute_fleet(
    manifest: &FleetManifest,
    opts: &FleetExecOptions,
) -> Result<FleetResult> {
    let started_at = Utc::now();

    // F28: Create output directory with restricted permissions
    create_output_dir(&opts.output_dir)?;

    let semaphore = Arc::new(Semaphore::new(opts.concurrency as usize));
    let mut handles = Vec::new();

    for target in &manifest.targets {
        let permit = semaphore.clone().acquire_owned().await.unwrap();

        // F23: Each target gets an owned copy of its credential HashMap.
        // This HashMap is moved into the tokio task — no shared mutable state.
        let target_config = target.credentials.clone();
        let target_id = target.id.clone();
        let target_source = target.source.clone();
        let checks_dir = opts.checks_dir.clone();
        let mode = opts.mode.clone();
        let apply = opts.apply;
        let terraform_dir = opts.terraform_dir.clone();
        let output_dir = opts.output_dir.clone();

        let handle = tokio::task::spawn_blocking(move || {
            // F25: target_config is owned by this closure. It will be dropped
            // when this task completes — no credential caching or pooling.
            let result = execute_single_target(SingleTargetParams {
                target_id: &target_id,
                target_source: &target_source,
                config: &target_config,
                checks_dir: &checks_dir,
                mode: &mode,
                apply,
                terraform_dir: &terraform_dir,
                output_dir: &output_dir,
            });
            drop(permit); // Release semaphore permit
            result
        });

        handles.push(handle);
    }

    // Collect results
    let mut target_results = Vec::new();
    let mut abort = false;

    for handle in handles {
        let result = handle.await.context("fleet target task panicked")?;
        let failed = matches!(result.status, TargetStatus::Failed);
        target_results.push(result);

        if failed && !opts.continue_on_error {
            abort = true;
            break;
        }
    }

    let completed_at = Utc::now();

    let succeeded = target_results
        .iter()
        .filter(|r| matches!(r.status, TargetStatus::Completed))
        .count();
    let failed = target_results
        .iter()
        .filter(|r| matches!(r.status, TargetStatus::Failed))
        .count();
    let total_checks: usize = target_results.iter().map(|r| r.checks_run).sum();
    let total_findings: usize = target_results.iter().map(|r| r.findings).sum();

    let fleet_result = FleetResult {
        fleet_name: manifest.fleet.name.clone(),
        started_at,
        completed_at,
        total_targets: target_results.len(),
        succeeded,
        failed,
        checks_run: total_checks,
        findings: total_findings,
        targets: target_results.clone(),
    };

    // Write fleet summary to output dir
    write_fleet_summary(&fleet_result, &opts.output_dir)?;

    // Write fleet audit log entry
    write_fleet_audit_log(&fleet_result);

    if abort {
        anyhow::bail!(
            "fleet execution aborted: target failed (use --continue-on-error to skip failures)"
        );
    }

    Ok(fleet_result)
}

/// Bundled parameters for [`execute_single_target`] (keeps the function's
/// argument count within clippy's `too_many_arguments` threshold).
struct SingleTargetParams<'a> {
    target_id: &'a str,
    target_source: &'a str,
    config: &'a HashMap<String, String>,
    checks_dir: &'a str,
    mode: &'a RemediationMode,
    apply: bool,
    terraform_dir: &'a str,
    output_dir: &'a Path,
}

/// Execute a single fleet target (runs in a blocking tokio task).
///
/// F22: Does NOT call std::env::set_var(). Uses the config HashMap directly.
/// F27: Creates its own ureq::Agent (via harden's execute_api_call which
///      creates a fresh request per call).
fn execute_single_target(params: SingleTargetParams) -> TargetResult {
    let SingleTargetParams {
        target_id,
        target_source,
        config,
        checks_dir,
        mode,
        apply,
        terraform_dir,
        output_dir,
    } = params;

    // F26: Create credential mask for scrubbing errors
    let mask = CredentialMask::from_config(config);

    let result_file = output_dir.join(format!("{}.json", target_id));

    // Plan remediation using the target's own credential context
    let plans = match plan_harden(Path::new(checks_dir), mode, config, Some(target_source)) {
        Ok(plans) => plans,
        Err(e) => {
            let error_msg = mask.scrub(&format!("{e:#}"));
            let result = TargetResult {
                id: target_id.to_string(),
                source: target_source.to_string(),
                status: TargetStatus::Failed,
                checks_run: 0,
                findings: 0,
                changes_applied: 0,
                error: Some(error_msg),
                results_file: result_file.clone(),
            };
            // F18: Write result file even for failures
            let _ = write_target_result(&result, &result_file);
            return result;
        }
    };

    let findings = plans.len();

    if !apply || plans.is_empty() {
        let result = TargetResult {
            id: target_id.to_string(),
            source: target_source.to_string(),
            status: TargetStatus::Completed,
            checks_run: findings,
            findings,
            changes_applied: 0,
            error: None,
            results_file: result_file.clone(),
        };
        let _ = write_target_result(&result, &result_file);
        return result;
    }

    // Execute remediation plans with the target's own config
    let results = execute_plans(&plans, config, Some(Path::new(terraform_dir)));

    let changes_applied = results.iter().filter(|r| r.success).count();
    let errors: Vec<String> = results
        .iter()
        .filter(|r| !r.success)
        .flat_map(|r| r.errors.iter().map(|e| mask.scrub(e)))
        .collect();

    let status = if errors.is_empty() {
        TargetStatus::Completed
    } else {
        TargetStatus::Failed
    };

    let error = if errors.is_empty() {
        None
    } else {
        Some(errors.join("; "))
    };

    let result = TargetResult {
        id: target_id.to_string(),
        source: target_source.to_string(),
        status,
        checks_run: findings,
        findings,
        changes_applied,
        error,
        results_file: result_file.clone(),
    };

    // F14: Write per-target result to disk immediately
    let _ = write_target_result(&result, &result_file);

    result
}

// ─── Output Helpers ─────────────────────────────────────────────────────────

/// Create the output directory with 0700 permissions. [F28]
fn create_output_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)
        .with_context(|| format!("cannot create output directory: {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(path, perms)
            .with_context(|| format!("cannot set permissions on {}", path.display()))?;
    }

    Ok(())
}

/// Write a per-target result file with 0600 permissions. [F28]
fn write_target_result(result: &TargetResult, path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(result).context("failed to serialize target result")?;
    std::fs::write(path, json)
        .with_context(|| format!("cannot write result file: {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }

    Ok(())
}

/// Write the aggregated fleet summary JSON. [F19]
fn write_fleet_summary(result: &FleetResult, output_dir: &Path) -> Result<()> {
    let path = output_dir.join("fleet-summary.json");
    let json = serde_json::to_string_pretty(result).context("failed to serialize fleet summary")?;
    std::fs::write(&path, json)
        .with_context(|| format!("cannot write fleet summary: {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&path, perms)?;
    }

    Ok(())
}

/// Write fleet-level audit log entry. [AC-16, F4]
fn write_fleet_audit_log(result: &FleetResult) {
    let log_dir = std::env::var("HOME")
        .ok()
        .map(|h| std::path::PathBuf::from(h).join(".ocean"))
        .unwrap_or_else(|| std::path::PathBuf::from(".ocean"));
    let _ = std::fs::create_dir_all(&log_dir);
    let log_path = log_dir.join("audit.log");

    let run_id = uuid::Uuid::new_v4();
    let timestamp = result.started_at.to_rfc3339();
    let completed = result.completed_at.to_rfc3339();

    // F4: Log only counts and IDs, never credential values
    let target_ids: Vec<&str> = result.targets.iter().map(|t| t.id.as_str()).collect();
    let failed_ids: Vec<&str> = result
        .targets
        .iter()
        .filter(|t| matches!(t.status, TargetStatus::Failed))
        .map(|t| t.id.as_str())
        .collect();

    let entry = format!(
        "[{timestamp}] FLEET run={run_id} | fleet=\"{}\" | started={timestamp} completed={completed} | \
         targets={} succeeded={} failed={} | checks={} findings={} | \
         target_ids=[{}] failed_ids=[{}]\n",
        result.fleet_name,
        result.total_targets,
        result.succeeded,
        result.failed,
        result.checks_run,
        result.findings,
        target_ids.join(","),
        failed_ids.join(","),
    );

    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, entry.as_bytes()));
}

/// Compute the fleet exit code per spec: 0 = all pass, 1 = some fail, 2 = all fail. [F17]
pub fn fleet_exit_code(result: &FleetResult) -> i32 {
    if result.failed == 0 {
        0
    } else if result.failed == result.total_targets {
        2
    } else {
        1
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // UT-030: Fleet summary counts match
    #[test]
    fn fleet_exit_code_all_pass() {
        let result = FleetResult {
            fleet_name: "test".to_string(),
            started_at: Utc::now(),
            completed_at: Utc::now(),
            total_targets: 3,
            succeeded: 3,
            failed: 0,
            checks_run: 10,
            findings: 2,
            targets: vec![],
        };
        assert_eq!(fleet_exit_code(&result), 0);
    }

    #[test]
    fn fleet_exit_code_some_fail() {
        let result = FleetResult {
            fleet_name: "test".to_string(),
            started_at: Utc::now(),
            completed_at: Utc::now(),
            total_targets: 3,
            succeeded: 2,
            failed: 1,
            checks_run: 10,
            findings: 2,
            targets: vec![],
        };
        assert_eq!(fleet_exit_code(&result), 1);
    }

    #[test]
    fn fleet_exit_code_all_fail() {
        let result = FleetResult {
            fleet_name: "test".to_string(),
            started_at: Utc::now(),
            completed_at: Utc::now(),
            total_targets: 3,
            succeeded: 0,
            failed: 3,
            checks_run: 0,
            findings: 0,
            targets: vec![],
        };
        assert_eq!(fleet_exit_code(&result), 2);
    }

    #[test]
    fn output_dir_creation() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("fleet-out");
        create_output_dir(&dir).unwrap();
        assert!(dir.is_dir());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&dir).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o700);
        }
    }

    #[test]
    fn target_result_serialization() {
        let result = TargetResult {
            id: "github-main".to_string(),
            source: "github".to_string(),
            status: TargetStatus::Completed,
            checks_run: 10,
            findings: 3,
            changes_applied: 2,
            error: None,
            results_file: PathBuf::from("fleet-results/github-main.json"),
        };
        let json = serde_json::to_string_pretty(&result).unwrap();
        assert!(json.contains("\"status\": \"completed\""));
        assert!(json.contains("\"checks_run\": 10"));
    }
}
