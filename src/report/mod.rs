// Compliance reporting engine for `ocean report`.
//
// Maps check results to compliance framework controls (SOC2, NIST 800-53,
// ISO 27001, PCI DSS, DISA STIG) and generates posture reports.

use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

use anyhow::Result;
use serde::Serialize;

use crate::check::definition::{CheckDefinition, CheckType};
use crate::check::loader::load_definitions_from_dir;
use crate::evidence::StatusId;
use crate::module::{Executor, Registry};
use crate::modules::{register_all_observers, register_all_testers};

// ─── Public types ────────────────────────────────────────────────────────────

/// Status of a single compliance control based on its mapped check results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlStatus {
    Pass,
    Fail,
    Partial,
    NoData,
}

/// A single check result mapped to a framework control.
#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub check_id: String,
    pub check_name: String,
    pub source: String,
    pub profile: String,
    pub passed: bool,
    pub severity: String,
    pub evidence_summary: String,
}

/// A single framework control with its mapped check results.
#[derive(Debug, Clone, Serialize)]
pub struct ControlReport {
    pub framework: String,
    pub control_id: String,
    pub control_title: String,
    pub mapped_checks: Vec<CheckResult>,
    pub status: ControlStatus,
}

/// Aggregate summary of a compliance report.
#[derive(Debug, Clone, Serialize)]
pub struct ReportSummary {
    pub total_controls: usize,
    pub passing: usize,
    pub failing: usize,
    pub partial: usize,
    pub no_data: usize,
    pub pass_percentage: f64,
}

/// Full compliance report for a single framework.
#[derive(Debug, Clone, Serialize)]
pub struct ComplianceReport {
    pub framework: String,
    pub generated_at: String,
    pub ocean_version: String,
    pub source_filter: Option<String>,
    pub profile_filter: Option<String>,
    pub controls: Vec<ControlReport>,
    pub summary: ReportSummary,
}

// ─── Framework names ─────────────────────────────────────────────────────────

pub const SUPPORTED_FRAMEWORKS: &[&str] = &["soc2", "nist", "iso27001", "pci_dss", "disa_stig"];

pub fn validate_framework(name: &str) -> Result<()> {
    if name == "all" || SUPPORTED_FRAMEWORKS.contains(&name) {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "unknown framework '{}'; supported: {}",
            name,
            SUPPORTED_FRAMEWORKS.join(", ")
        ))
    }
}

// ─── Framework control catalog ───────────────────────────────────────────────

/// Static metadata for a compliance framework control.
pub struct FrameworkControl {
    pub framework: &'static str,
    pub control_id: &'static str,
    pub title: &'static str,
}

/// Returns the static control catalog. Covers controls referenced by existing checks.
fn control_catalog() -> Vec<FrameworkControl> {
    vec![
        // SOC2 Trust Services Criteria
        FrameworkControl { framework: "soc2", control_id: "CC6.1", title: "Logical and Physical Access Controls" },
        FrameworkControl { framework: "soc2", control_id: "CC6.2", title: "System Access Authentication" },
        FrameworkControl { framework: "soc2", control_id: "CC6.3", title: "Role-Based Access and Least Privilege" },
        FrameworkControl { framework: "soc2", control_id: "CC6.6", title: "External Threat Protection" },
        FrameworkControl { framework: "soc2", control_id: "CC6.7", title: "Data Transmission Protection" },
        FrameworkControl { framework: "soc2", control_id: "CC6.8", title: "Unauthorized Software Prevention" },
        FrameworkControl { framework: "soc2", control_id: "CC7.1", title: "Vulnerability Management" },
        FrameworkControl { framework: "soc2", control_id: "CC7.2", title: "Security Event Monitoring" },
        FrameworkControl { framework: "soc2", control_id: "CC7.3", title: "Security Incident Response" },
        FrameworkControl { framework: "soc2", control_id: "CC8.1", title: "Change Management" },
        // NIST 800-53
        FrameworkControl { framework: "nist", control_id: "AC-2", title: "Account Management" },
        FrameworkControl { framework: "nist", control_id: "AC-6", title: "Least Privilege" },
        FrameworkControl { framework: "nist", control_id: "AU-2", title: "Event Logging" },
        FrameworkControl { framework: "nist", control_id: "AU-6", title: "Audit Record Review" },
        FrameworkControl { framework: "nist", control_id: "CM-2", title: "Baseline Configuration" },
        FrameworkControl { framework: "nist", control_id: "CM-7", title: "Least Functionality" },
        FrameworkControl { framework: "nist", control_id: "IA-2", title: "Identification and Authentication" },
        FrameworkControl { framework: "nist", control_id: "IA-2(1)", title: "Multi-Factor Authentication" },
        FrameworkControl { framework: "nist", control_id: "RA-5", title: "Vulnerability Monitoring and Scanning" },
        FrameworkControl { framework: "nist", control_id: "SA-11", title: "Developer Testing and Evaluation" },
        FrameworkControl { framework: "nist", control_id: "SC-7", title: "Boundary Protection" },
        FrameworkControl { framework: "nist", control_id: "SC-8", title: "Transmission Confidentiality" },
        FrameworkControl { framework: "nist", control_id: "SI-2", title: "Flaw Remediation" },
        FrameworkControl { framework: "nist", control_id: "SI-4", title: "System Monitoring" },
        // ISO 27001 Annex A
        FrameworkControl { framework: "iso27001", control_id: "A.5.15", title: "Access Control" },
        FrameworkControl { framework: "iso27001", control_id: "A.5.17", title: "Authentication Information" },
        FrameworkControl { framework: "iso27001", control_id: "A.8.3", title: "Information Access Restriction" },
        FrameworkControl { framework: "iso27001", control_id: "A.8.8", title: "Management of Technical Vulnerabilities" },
        FrameworkControl { framework: "iso27001", control_id: "A.8.9", title: "Configuration Management" },
        FrameworkControl { framework: "iso27001", control_id: "A.8.15", title: "Logging" },
        FrameworkControl { framework: "iso27001", control_id: "A.8.16", title: "Monitoring Activities" },
        FrameworkControl { framework: "iso27001", control_id: "A.8.25", title: "Secure Development Lifecycle" },
        // PCI DSS
        FrameworkControl { framework: "pci_dss", control_id: "2.2", title: "System Configuration Standards" },
        FrameworkControl { framework: "pci_dss", control_id: "6.2", title: "Bespoke and Custom Software Security" },
        FrameworkControl { framework: "pci_dss", control_id: "6.3", title: "Security Vulnerabilities Identified and Addressed" },
        FrameworkControl { framework: "pci_dss", control_id: "7.2", title: "Access to System Components Appropriately Defined" },
        FrameworkControl { framework: "pci_dss", control_id: "8.3", title: "Strong Authentication Established" },
        FrameworkControl { framework: "pci_dss", control_id: "10.2", title: "Audit Logs Implemented" },
        FrameworkControl { framework: "pci_dss", control_id: "11.3", title: "Vulnerabilities Identified and Addressed" },
        // DISA STIG
        FrameworkControl { framework: "disa_stig", control_id: "V-222400", title: "MFA for Privileged Accounts" },
        FrameworkControl { framework: "disa_stig", control_id: "V-222401", title: "Account Management" },
        FrameworkControl { framework: "disa_stig", control_id: "V-222425", title: "Audit Log Configuration" },
        FrameworkControl { framework: "disa_stig", control_id: "V-222542", title: "Vulnerability Scanning" },
        FrameworkControl { framework: "disa_stig", control_id: "V-222577", title: "Configuration Management" },
    ]
}

/// Get the title for a framework control. Returns the control_id as fallback.
fn control_title(framework: &str, control_id: &str) -> String {
    control_catalog()
        .iter()
        .find(|c| c.framework == framework && c.control_id == control_id)
        .map(|c| c.title.to_string())
        .unwrap_or_else(|| control_id.to_string())
}

// ─── Report generation ───────────────────────────────────────────────────────

/// Extract framework references from a check definition as (framework, control_id) pairs.
fn extract_references(def: &CheckDefinition) -> Vec<(String, String)> {
    let mut refs = Vec::new();
    for id in def.references.soc2.as_vec() {
        refs.push(("soc2".to_string(), id));
    }
    for id in def.references.nist.as_vec() {
        refs.push(("nist".to_string(), id));
    }
    for id in def.references.iso27001.as_vec() {
        refs.push(("iso27001".to_string(), id));
    }
    for id in def.references.pci_dss.as_vec() {
        refs.push(("pci_dss".to_string(), id));
    }
    for id in def.references.disa_stig.as_vec() {
        refs.push(("disa_stig".to_string(), id));
    }
    refs
}

/// Generate a compliance report for a single framework.
///
/// Loads all check definitions, runs passive checks, and maps results to
/// framework controls via the `references:` block in each `.check.yaml`.
pub fn generate_report(
    checks_dir: &Path,
    framework: &str,
    config: &HashMap<String, String>,
    source_filter: Option<&str>,
    profile_filter: Option<&str>,
) -> Result<ComplianceReport> {
    let defs = load_definitions_from_dir(checks_dir);

    // Filter definitions by source and profile if specified.
    let filtered_defs: Vec<&CheckDefinition> = defs
        .iter()
        .filter(|d| source_filter.is_none_or(|s| d.source == s))
        .filter(|d| profile_filter.is_none_or(|p| profile_matches(&d.profile, p)))
        .collect();

    // Register and run passive checks.
    let registry = Registry::new();
    register_all_observers(&registry);
    register_all_testers(&registry);
    crate::check::loader::load_checks_from_dir(&registry, checks_dir)?;
    let executor = Executor::new(std::sync::Arc::new(registry));

    // Run each passive check and collect results.
    let mut check_results: HashMap<String, bool> = HashMap::new();
    for def in &filtered_defs {
        if def.check_type != CheckType::Passive {
            continue;
        }
        match executor.execute_observer(&def.id, config) {
            Ok(evidence) => {
                let passed = !evidence
                    .iter()
                    .any(|e| matches!(e.status_id, StatusId::Ineffective));
                check_results.insert(def.id.clone(), passed);
            }
            Err(_) => {
                // Check couldn't run (missing creds, etc.) — exclude from report.
            }
        }
    }

    // Build control → check result mappings.
    let mut control_map: HashMap<String, Vec<CheckResult>> = HashMap::new();

    for def in &filtered_defs {
        let passed = check_results.get(&def.id);
        if passed.is_none() {
            continue; // Check didn't run.
        }
        let passed = *passed.unwrap();

        for (fw, control_id) in extract_references(def) {
            if fw != framework {
                continue;
            }
            control_map
                .entry(control_id.clone())
                .or_default()
                .push(CheckResult {
                    check_id: def.id.clone(),
                    check_name: def.name.clone(),
                    source: def.source.clone(),
                    profile: def.profile.clone(),
                    passed,
                    severity: def.severity.clone(),
                    evidence_summary: if passed {
                        "Pass".to_string()
                    } else {
                        "Fail".to_string()
                    },
                });
        }
    }

    // Also include catalog controls that have no mapped checks (NoData).
    for cat in control_catalog() {
        if cat.framework == framework && !control_map.contains_key(cat.control_id) {
            control_map.insert(cat.control_id.to_string(), Vec::new());
        }
    }

    // Build ControlReport entries.
    let mut controls: Vec<ControlReport> = control_map
        .into_iter()
        .map(|(control_id, checks)| {
            let status = compute_control_status(&checks);
            ControlReport {
                framework: framework.to_string(),
                control_id: control_id.clone(),
                control_title: control_title(framework, &control_id),
                mapped_checks: checks,
                status,
            }
        })
        .collect();

    // Sort by control ID for deterministic output.
    controls.sort_by(|a, b| a.control_id.cmp(&b.control_id));

    let summary = compute_summary(&controls);

    Ok(ComplianceReport {
        framework: framework.to_string(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        ocean_version: env!("CARGO_PKG_VERSION").to_string(),
        source_filter: source_filter.map(|s| s.to_string()),
        profile_filter: profile_filter.map(|p| p.to_string()),
        controls,
        summary,
    })
}

fn compute_control_status(checks: &[CheckResult]) -> ControlStatus {
    if checks.is_empty() {
        return ControlStatus::NoData;
    }
    let all_pass = checks.iter().all(|c| c.passed);
    let all_fail = checks.iter().all(|c| !c.passed);
    if all_pass {
        ControlStatus::Pass
    } else if all_fail {
        ControlStatus::Fail
    } else {
        ControlStatus::Partial
    }
}

fn compute_summary(controls: &[ControlReport]) -> ReportSummary {
    let total = controls.len();
    let passing = controls.iter().filter(|c| c.status == ControlStatus::Pass).count();
    let failing = controls.iter().filter(|c| c.status == ControlStatus::Fail).count();
    let partial = controls.iter().filter(|c| c.status == ControlStatus::Partial).count();
    let no_data = controls.iter().filter(|c| c.status == ControlStatus::NoData).count();
    let assessed = total - no_data;
    let pass_pct = if assessed > 0 {
        (passing as f64 / assessed as f64) * 100.0
    } else {
        0.0
    };
    ReportSummary {
        total_controls: total,
        passing,
        failing,
        partial,
        no_data,
        pass_percentage: (pass_pct * 10.0).round() / 10.0, // round to 1 decimal
    }
}

/// Check if a check's profile matches the filter (includes that tier and below).
fn profile_matches(check_profile: &str, filter: &str) -> bool {
    let tier = |p: &str| -> u8 {
        match p.to_uppercase().as_str() {
            "L1" => 1,
            "L2" => 2,
            "L3" => 3,
            _ => 0,
        }
    };
    let check_tier = tier(check_profile);
    let filter_tier = tier(filter);
    if check_tier == 0 || filter_tier == 0 {
        return true; // Unknown profile, include by default.
    }
    check_tier <= filter_tier
}

// ─── Output formatting ───────────────────────────────────────────────────────

/// Print a compliance report in the specified format.
pub fn print_report<W: Write>(out: &mut W, report: &ComplianceReport, format: &str) -> Result<()> {
    match format {
        "json" => print_report_json(out, report),
        "csv" => print_report_csv(out, report),
        "table" | _ => print_report_table(out, report),
    }
}

fn print_report_table<W: Write>(out: &mut W, report: &ComplianceReport) -> Result<()> {
    writeln!(out, "\n═══ {} Compliance Report ═══", report.framework.to_uppercase())?;
    writeln!(out, "Generated: {}", report.generated_at)?;
    writeln!(out, "OCEAN version: {}", report.ocean_version)?;
    if let Some(ref src) = report.source_filter {
        writeln!(out, "Source filter: {src}")?;
    }
    if let Some(ref prof) = report.profile_filter {
        writeln!(out, "Profile filter: {prof}")?;
    }
    writeln!(out)?;

    // Header
    writeln!(out, "  {:<12} {:<40} {:<10} Checks", "Control", "Title", "Status")?;
    writeln!(out, "  {}", "─".repeat(75))?;

    for ctrl in &report.controls {
        let status_str = match ctrl.status {
            ControlStatus::Pass => "✓ Pass",
            ControlStatus::Fail => "✗ Fail",
            ControlStatus::Partial => "◐ Partial",
            ControlStatus::NoData => "— No data",
        };
        let check_count = ctrl.mapped_checks.len();
        let title = if ctrl.control_title.len() > 38 {
            format!("{}…", &ctrl.control_title[..37])
        } else {
            ctrl.control_title.clone()
        };
        writeln!(
            out,
            "  {:<12} {:<40} {:<10} {}",
            ctrl.control_id, title, status_str, check_count
        )?;
    }

    writeln!(out)?;
    let s = &report.summary;
    writeln!(
        out,
        "  Summary: {}/{} controls passing ({:.1}%), {} failing, {} partial, {} no data",
        s.passing,
        s.total_controls,
        s.pass_percentage,
        s.failing,
        s.partial,
        s.no_data,
    )?;
    writeln!(out)?;
    Ok(())
}

fn print_report_json<W: Write>(out: &mut W, report: &ComplianceReport) -> Result<()> {
    let json = serde_json::to_string_pretty(report)?;
    writeln!(out, "{json}")?;
    Ok(())
}

fn print_report_csv<W: Write>(out: &mut W, report: &ComplianceReport) -> Result<()> {
    writeln!(out, "framework,control_id,control_title,status,check_id,check_name,passed,severity")?;
    for ctrl in &report.controls {
        if ctrl.mapped_checks.is_empty() {
            writeln!(
                out,
                "{},{},{},{},,,",
                report.framework,
                csv_escape(&ctrl.control_id),
                csv_escape(&ctrl.control_title),
                status_csv(&ctrl.status),
            )?;
        } else {
            for check in &ctrl.mapped_checks {
                writeln!(
                    out,
                    "{},{},{},{},{},{},{},{}",
                    report.framework,
                    csv_escape(&ctrl.control_id),
                    csv_escape(&ctrl.control_title),
                    status_csv(&ctrl.status),
                    csv_escape(&check.check_id),
                    csv_escape(&check.check_name),
                    check.passed,
                    csv_escape(&check.severity),
                )?;
            }
        }
    }
    Ok(())
}

/// CSV-escape a field: quote if it contains comma/quote/newline.
/// Also prevent CSV injection (TH-4a) by prefixing cells starting with
/// =, +, -, @, tab, or carriage return with a single quote.
fn csv_escape(field: &str) -> String {
    let mut s = field.to_string();

    // TH-4a: CSV injection prevention.
    if s.starts_with('=') || s.starts_with('+') || s.starts_with('-')
        || s.starts_with('@') || s.starts_with('\t') || s.starts_with('\r')
    {
        s = format!("'{s}");
    }

    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

fn status_csv(status: &ControlStatus) -> &'static str {
    match status {
        ControlStatus::Pass => "pass",
        ControlStatus::Fail => "fail",
        ControlStatus::Partial => "partial",
        ControlStatus::NoData => "no_data",
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_framework_accepts_known() {
        assert!(validate_framework("soc2").is_ok());
        assert!(validate_framework("nist").is_ok());
        assert!(validate_framework("iso27001").is_ok());
        assert!(validate_framework("pci_dss").is_ok());
        assert!(validate_framework("disa_stig").is_ok());
        assert!(validate_framework("all").is_ok());
    }

    #[test]
    fn validate_framework_rejects_unknown() {
        assert!(validate_framework("hipaa").is_err());
        assert!(validate_framework("").is_err());
    }

    #[test]
    fn control_status_all_pass() {
        let checks = vec![
            CheckResult { check_id: "A".into(), check_name: "A".into(), source: "github".into(), profile: "L1".into(), passed: true, severity: "high".into(), evidence_summary: "Pass".into() },
            CheckResult { check_id: "B".into(), check_name: "B".into(), source: "github".into(), profile: "L1".into(), passed: true, severity: "high".into(), evidence_summary: "Pass".into() },
        ];
        assert_eq!(compute_control_status(&checks), ControlStatus::Pass);
    }

    #[test]
    fn control_status_all_fail() {
        let checks = vec![
            CheckResult { check_id: "A".into(), check_name: "A".into(), source: "github".into(), profile: "L1".into(), passed: false, severity: "high".into(), evidence_summary: "Fail".into() },
        ];
        assert_eq!(compute_control_status(&checks), ControlStatus::Fail);
    }

    #[test]
    fn control_status_partial() {
        let checks = vec![
            CheckResult { check_id: "A".into(), check_name: "A".into(), source: "github".into(), profile: "L1".into(), passed: true, severity: "high".into(), evidence_summary: "Pass".into() },
            CheckResult { check_id: "B".into(), check_name: "B".into(), source: "github".into(), profile: "L1".into(), passed: false, severity: "high".into(), evidence_summary: "Fail".into() },
        ];
        assert_eq!(compute_control_status(&checks), ControlStatus::Partial);
    }

    #[test]
    fn control_status_no_data() {
        assert_eq!(compute_control_status(&[]), ControlStatus::NoData);
    }

    #[test]
    fn summary_computation() {
        let controls = vec![
            ControlReport { framework: "soc2".into(), control_id: "CC6.1".into(), control_title: "Access".into(), mapped_checks: vec![
                CheckResult { check_id: "A".into(), check_name: "A".into(), source: "github".into(), profile: "L1".into(), passed: true, severity: "high".into(), evidence_summary: "Pass".into() },
            ], status: ControlStatus::Pass },
            ControlReport { framework: "soc2".into(), control_id: "CC6.2".into(), control_title: "Auth".into(), mapped_checks: vec![
                CheckResult { check_id: "B".into(), check_name: "B".into(), source: "github".into(), profile: "L1".into(), passed: false, severity: "high".into(), evidence_summary: "Fail".into() },
            ], status: ControlStatus::Fail },
            ControlReport { framework: "soc2".into(), control_id: "CC6.3".into(), control_title: "RBAC".into(), mapped_checks: vec![], status: ControlStatus::NoData },
        ];
        let s = compute_summary(&controls);
        assert_eq!(s.total_controls, 3);
        assert_eq!(s.passing, 1);
        assert_eq!(s.failing, 1);
        assert_eq!(s.no_data, 1);
        assert_eq!(s.pass_percentage, 50.0);
    }

    #[test]
    fn profile_filter_l1_includes_l1_only() {
        assert!(profile_matches("L1", "L1"));
        assert!(!profile_matches("L2", "L1"));
        assert!(!profile_matches("L3", "L1"));
    }

    #[test]
    fn profile_filter_l2_includes_l1_and_l2() {
        assert!(profile_matches("L1", "L2"));
        assert!(profile_matches("L2", "L2"));
        assert!(!profile_matches("L3", "L2"));
    }

    #[test]
    fn profile_filter_unknown_includes_all() {
        assert!(profile_matches("", "L1"));
        assert!(profile_matches("L1", ""));
    }

    #[test]
    fn csv_escape_plain() {
        assert_eq!(csv_escape("hello"), "hello");
    }

    #[test]
    fn csv_escape_with_comma() {
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
    }

    #[test]
    fn csv_escape_with_quotes() {
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn sec_csv_injection_prevention() {
        // TH-4a: Formula injection characters are prefixed with single quote.
        assert!(csv_escape("=cmd|'/C calc'!A1").starts_with("'="));
        assert!(csv_escape("+cmd").starts_with("'+"));
        assert!(csv_escape("-cmd").starts_with("'-"));
        assert!(csv_escape("@SUM(A1)").starts_with("'@"));
    }

    #[test]
    fn control_title_lookup_known() {
        let title = control_title("soc2", "CC6.1");
        assert_eq!(title, "Logical and Physical Access Controls");
    }

    #[test]
    fn control_title_lookup_unknown_returns_id() {
        let title = control_title("soc2", "CC99.99");
        assert_eq!(title, "CC99.99");
    }

    #[test]
    fn print_report_json_valid() {
        let report = ComplianceReport {
            framework: "soc2".into(),
            generated_at: "2026-03-28T00:00:00Z".into(),
            ocean_version: "0.1.0".into(),
            source_filter: None,
            profile_filter: None,
            controls: vec![],
            summary: ReportSummary {
                total_controls: 0,
                passing: 0,
                failing: 0,
                partial: 0,
                no_data: 0,
                pass_percentage: 0.0,
            },
        };
        let mut out = Vec::new();
        print_report_json(&mut out, &report).unwrap();
        let s = String::from_utf8(out).unwrap();
        let _: serde_json::Value = serde_json::from_str(&s).unwrap();
    }

    #[test]
    fn print_report_csv_header() {
        let report = ComplianceReport {
            framework: "soc2".into(),
            generated_at: "2026-03-28T00:00:00Z".into(),
            ocean_version: "0.1.0".into(),
            source_filter: None,
            profile_filter: None,
            controls: vec![],
            summary: ReportSummary {
                total_controls: 0,
                passing: 0,
                failing: 0,
                partial: 0,
                no_data: 0,
                pass_percentage: 0.0,
            },
        };
        let mut out = Vec::new();
        print_report_csv(&mut out, &report).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("framework,control_id,"));
    }

    #[test]
    fn print_report_table_format() {
        let report = ComplianceReport {
            framework: "nist".into(),
            generated_at: "2026-03-28T00:00:00Z".into(),
            ocean_version: "0.1.0".into(),
            source_filter: Some("github".into()),
            profile_filter: None,
            controls: vec![
                ControlReport {
                    framework: "nist".into(),
                    control_id: "IA-2".into(),
                    control_title: "Identification and Authentication".into(),
                    mapped_checks: vec![
                        CheckResult { check_id: "GH-1.01".into(), check_name: "MFA".into(), source: "github".into(), profile: "L1".into(), passed: true, severity: "critical".into(), evidence_summary: "Pass".into() },
                    ],
                    status: ControlStatus::Pass,
                },
            ],
            summary: ReportSummary {
                total_controls: 1,
                passing: 1,
                failing: 0,
                partial: 0,
                no_data: 0,
                pass_percentage: 100.0,
            },
        };
        let mut out = Vec::new();
        print_report_table(&mut out, &report).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("NIST"));
        assert!(s.contains("IA-2"));
        assert!(s.contains("Pass"));
        assert!(s.contains("1/1"));
    }

    #[test]
    fn extract_references_multi_framework() {
        let yaml = r#"
id: TST-REF
name: Multi Ref Check
source: github
steps: []
assertions: []
references:
  soc2: ["CC6.1", "CC7.1"]
  nist: "IA-2"
  iso27001: []
  pci_dss: "8.3"
  disa_stig: []
"#;
        let def: CheckDefinition = serde_yaml::from_str(yaml).unwrap();
        let refs = extract_references(&def);
        assert_eq!(refs.len(), 4); // 2 soc2 + 1 nist + 1 pci_dss
        assert!(refs.iter().any(|(fw, id)| fw == "soc2" && id == "CC6.1"));
        assert!(refs.iter().any(|(fw, id)| fw == "nist" && id == "IA-2"));
        assert!(refs.iter().any(|(fw, id)| fw == "pci_dss" && id == "8.3"));
    }
}
