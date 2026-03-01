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

impl OutputFormat {
    pub fn from_str(s: &str) -> Self {
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
        assert_eq!(OutputFormat::from_str("json"), OutputFormat::Json);
        assert_eq!(OutputFormat::from_str("JSON"), OutputFormat::Json);
        assert_eq!(OutputFormat::from_str("unknown"), OutputFormat::Json);
        assert_eq!(OutputFormat::from_str(""), OutputFormat::Json);
    }

    #[test]
    fn format_from_str_yaml_variants() {
        assert_eq!(OutputFormat::from_str("yaml"), OutputFormat::Yaml);
        assert_eq!(OutputFormat::from_str("yml"), OutputFormat::Yaml);
        assert_eq!(OutputFormat::from_str("YAML"), OutputFormat::Yaml);
        assert_eq!(OutputFormat::from_str("YML"), OutputFormat::Yaml);
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
}
