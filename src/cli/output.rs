use anyhow::Result;
use serde::Serialize;
use std::io::Write;

// ---------------------------------------------------------------------------
// Pipeline evaluation output types
// ---------------------------------------------------------------------------

/// Result of running a single module during an evaluate/test pipeline.
pub struct ModuleRunResult {
    pub module_id: String,
    /// "observe" or "test"
    pub module_type: &'static str,
    /// "OK", "PASS", "FAIL", "ERROR"
    pub status: String,
    pub error: Option<String>,
}

/// Aggregated result of an evaluate-path pipeline for one control.
pub struct EvaluationResult {
    pub control_id: String,
    pub control_name: String,
    pub target: String,
    pub status: String,
    pub confidence: String,
    /// First framework mapping, e.g. "soc2 CC6.1"
    pub framework: String,
    pub module_runs: Vec<ModuleRunResult>,
    /// Non-empty when status is not "effective"
    pub findings: Vec<String>,
}

/// Print a human-readable evaluation table to the writer.
pub fn print_evaluation_table<W: Write>(w: &mut W, results: &[EvaluationResult]) -> Result<()> {
    // Header
    writeln!(
        w,
        "{:<44} {:<8} {:<12} {:<10} Framework",
        "Control", "Target", "Status", "Confidence"
    )?;
    writeln!(w, "{}", "─".repeat(88))?;

    for result in results {
        let status_upper = result.status.to_uppercase();
        let label = if result.control_name.is_empty() {
            result.control_id.clone()
        } else {
            format!("{} ({})", result.control_id, result.control_name)
        };
        writeln!(
            w,
            "{:<44} {:<8} {:<12} {:<10} {}",
            label,
            result.target,
            status_upper,
            result.confidence.to_uppercase(),
            result.framework,
        )?;
        for run in &result.module_runs {
            let status_col = match run.status.as_str() {
                "OK" | "PASS" => run.status.as_str(),
                _ => &run.status,
            };
            writeln!(
                w,
                "  ↳ [{:<7}] {:<38} {}",
                run.module_type, run.module_id, status_col,
            )?;
            if let Some(err) = &run.error {
                writeln!(w, "             error: {err}")?;
            }
        }
        if !result.findings.is_empty() {
            writeln!(w)?;
            writeln!(w, "  FINDINGS for {}:", result.control_id)?;
            for f in &result.findings {
                writeln!(w, "    • {f}")?;
            }
        }
        writeln!(w)?;
    }
    Ok(())
}

/// Output format for CLI commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    Yaml,
}

impl From<&str> for OutputFormat {
    /// Lenient, infallible parse: anything that is not YAML is JSON.
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "yaml" | "yml" => Self::Yaml,
            _ => Self::Json,
        }
    }
}

/// Write serializable data to the given writer in the requested format.
pub fn print_output<W: Write, T: Serialize>(
    writer: &mut W,
    data: &T,
    format: OutputFormat,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            let s = serde_json::to_string_pretty(data)?;
            writeln!(writer, "{s}")?;
        }
        OutputFormat::Yaml => {
            // Round-trip through JSON value to avoid serde_yaml's direct serialization quirks.
            let v = serde_json::to_value(data)?;
            let s = serde_yaml::to_string(&v)?;
            write!(writer, "{s}")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_output_pretty_printed() {
        let mut buf = Vec::new();
        print_output(&mut buf, &json!({"key": "value"}), OutputFormat::Json).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("\"key\""));
        assert!(s.contains("\"value\""));
        // pretty-printed JSON has newlines
        assert!(s.contains('\n'));
    }

    #[test]
    fn yaml_output_contains_key() {
        let mut buf = Vec::new();
        print_output(&mut buf, &json!({"alpha": "beta"}), OutputFormat::Yaml).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("alpha"));
        assert!(s.contains("beta"));
    }

    #[test]
    fn format_from_str_json_variants() {
        assert_eq!(OutputFormat::from("json"), OutputFormat::Json);
        assert_eq!(OutputFormat::from("JSON"), OutputFormat::Json);
        assert_eq!(OutputFormat::from("unknown"), OutputFormat::Json);
        assert_eq!(OutputFormat::from(""), OutputFormat::Json);
    }

    #[test]
    fn format_from_str_yaml_variants() {
        assert_eq!(OutputFormat::from("yaml"), OutputFormat::Yaml);
        assert_eq!(OutputFormat::from("yml"), OutputFormat::Yaml);
        assert_eq!(OutputFormat::from("YAML"), OutputFormat::Yaml);
        assert_eq!(OutputFormat::from("YML"), OutputFormat::Yaml);
    }

    #[test]
    fn json_array_output() {
        let mut buf = Vec::new();
        print_output(&mut buf, &json!([1, 2, 3]), OutputFormat::Json).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("1"));
        assert!(s.contains("2"));
        assert!(s.contains("3"));
    }

    #[test]
    fn yaml_array_output() {
        let mut buf = Vec::new();
        print_output(&mut buf, &json!([1, 2]), OutputFormat::Yaml).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("1"));
        assert!(s.contains("2"));
    }

    // --- print_evaluation_table ---
    fn make_module_run(id: &str, status: &str, err: Option<&str>) -> ModuleRunResult {
        ModuleRunResult {
            module_id: id.to_string(),
            module_type: "observe",
            status: status.to_string(),
            error: err.map(String::from),
        }
    }

    #[test]
    fn print_evaluation_table_fault_injection_covers_write_errors() {
        // Drive every `?` continuation in print_evaluation_table by failing
        // at write N for N = 0..50. Each invocation exits via a different ?.
        use crate::testutil::FailingWriter;
        let results = vec![EvaluationResult {
            control_id: "iam.full".to_string(),
            control_name: "Full".to_string(),
            target: "github".to_string(),
            status: "ineffective".to_string(),
            confidence: "high".to_string(),
            framework: "soc2 CC6.1".to_string(),
            module_runs: vec![
                make_module_run("a.run", "OK", Some("disk full")),
                make_module_run("b.fail", "FAIL", None),
            ],
            findings: vec!["bad config".to_string(), "another finding".to_string()],
        }];
        // n=0 should fail immediately at the header writeln.
        let mut w0 = FailingWriter::new(0);
        let r0 = print_evaluation_table(&mut w0, &results);
        assert!(r0.is_err(), "expected Err when writer fails on first write");
        // n=1..50: succeed through some prefix, then fail.
        for n in 1..50 {
            let mut w = FailingWriter::new(n);
            let _ = print_evaluation_table(&mut w, &results);
        }
    }

    #[test]
    fn print_output_fault_injection_covers_write_errors() {
        use crate::testutil::FailingWriter;
        for n in 0..20 {
            let mut w = FailingWriter::new(n);
            let _ = print_output(&mut w, &serde_json::json!({"k": "v"}), OutputFormat::Json);
        }
        for n in 0..20 {
            let mut w = FailingWriter::new(n);
            let _ = print_output(&mut w, &serde_json::json!({"k": "v"}), OutputFormat::Yaml);
        }
    }

    #[test]
    fn print_evaluation_table_empty() {
        let mut buf = Vec::new();
        print_evaluation_table(&mut buf, &[]).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Control"));
        assert!(s.contains("Status"));
    }

    #[test]
    fn print_evaluation_table_with_named_control() {
        let mut buf = Vec::new();
        let results = vec![EvaluationResult {
            control_id: "iam.test".to_string(),
            control_name: "Test Control".to_string(),
            target: "github".to_string(),
            status: "effective".to_string(),
            confidence: "high".to_string(),
            framework: "soc2 CC6.1".to_string(),
            module_runs: vec![make_module_run("mock.test", "OK", None)],
            findings: vec![],
        }];
        print_evaluation_table(&mut buf, &results).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("iam.test"));
        assert!(s.contains("Test Control"));
        assert!(s.contains("EFFECTIVE"));
        assert!(s.contains("HIGH"));
        assert!(s.contains("soc2 CC6.1"));
        assert!(s.contains("mock.test"));
    }

    #[test]
    fn print_evaluation_table_empty_control_name() {
        let mut buf = Vec::new();
        let results = vec![EvaluationResult {
            control_id: "iam.bare".to_string(),
            control_name: String::new(),
            target: "okta".to_string(),
            status: "ineffective".to_string(),
            confidence: "medium".to_string(),
            framework: String::new(),
            module_runs: vec![],
            findings: vec![],
        }];
        print_evaluation_table(&mut buf, &results).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("iam.bare"));
        assert!(s.contains("INEFFECTIVE"));
    }

    #[test]
    fn print_evaluation_table_with_findings() {
        let mut buf = Vec::new();
        let results = vec![EvaluationResult {
            control_id: "iam.audit".to_string(),
            control_name: "Audit".to_string(),
            target: "aws".to_string(),
            status: "ineffective".to_string(),
            confidence: "high".to_string(),
            framework: "iso27001 A.9.2".to_string(),
            module_runs: vec![make_module_run(
                "aws.iam_users",
                "FAIL",
                Some("token expired"),
            )],
            findings: vec![
                "user alice has admin without MFA".to_string(),
                "policy too permissive".to_string(),
            ],
        }];
        print_evaluation_table(&mut buf, &results).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("FINDINGS for iam.audit"));
        assert!(s.contains("user alice has admin"));
        assert!(s.contains("policy too permissive"));
        assert!(s.contains("token expired"));
    }

    #[test]
    fn print_evaluation_table_module_status_passes_through() {
        let mut buf = Vec::new();
        let results = vec![EvaluationResult {
            control_id: "iam.pass".to_string(),
            control_name: "X".to_string(),
            target: "*".to_string(),
            status: "effective".to_string(),
            confidence: "high".to_string(),
            framework: String::new(),
            module_runs: vec![
                make_module_run("a.ok", "OK", None),
                make_module_run("b.pass", "PASS", None),
                make_module_run("c.weird", "WEIRD", None),
            ],
            findings: vec![],
        }];
        print_evaluation_table(&mut buf, &results).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("a.ok"));
        assert!(s.contains("b.pass"));
        assert!(s.contains("c.weird"));
        assert!(s.contains("WEIRD"));
    }
}
