use anyhow::Result;
use serde::Serialize;
use std::io::Write;

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
