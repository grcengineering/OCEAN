use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// A compliance framework (e.g., SOC 2, ISO 27001) with its list of requirements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Framework {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub version: String,
    pub controls: Vec<FrameworkControl>,
}

/// A single requirement within a compliance framework.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkControl {
    /// The framework-specific reference (e.g., "CC6.1").
    #[serde(rename = "ref")]
    pub ref_id: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    /// OCEAN control IDs that satisfy this requirement.
    #[serde(default)]
    pub ocean_control_ids: Vec<String>,
}

impl Framework {
    /// Load a Framework from a YAML string (matches the controls/frameworks/*.yaml format).
    pub fn load_yaml(yaml: &str) -> Result<Self> {
        serde_yaml::from_str(yaml).context("parsing framework YAML")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOC2_YAML: &str = r#"
id: soc2
name: SOC 2 Type II
version: "2017"
controls:
  - ref: CC6.1
    title: Logical and Physical Access Controls
    description: The entity implements logical access security.
    ocean_control_ids:
      - iam.mfa_enforcement
  - ref: CC6.6
    title: System Boundary Protection
    description: System boundary protection controls.
    ocean_control_ids:
      - network.waf_protection
  - ref: CC7.2
    title: Security Event Monitoring
    description: ""
    ocean_control_ids: []
"#;

    #[test]
    fn framework_load_yaml_parses_id_and_name() {
        let fw = Framework::load_yaml(SOC2_YAML).unwrap();
        assert_eq!(fw.id, "soc2");
        assert_eq!(fw.name, "SOC 2 Type II");
        assert_eq!(fw.version, "2017");
    }

    #[test]
    fn framework_load_yaml_parses_controls_count() {
        let fw = Framework::load_yaml(SOC2_YAML).unwrap();
        assert_eq!(fw.controls.len(), 3);
    }

    #[test]
    fn framework_load_yaml_first_control_has_ocean_ids() {
        let fw = Framework::load_yaml(SOC2_YAML).unwrap();
        assert_eq!(fw.controls[0].ref_id, "CC6.1");
        assert_eq!(fw.controls[0].title, "Logical and Physical Access Controls");
        assert_eq!(fw.controls[0].ocean_control_ids, vec!["iam.mfa_enforcement"]);
    }

    #[test]
    fn framework_load_yaml_empty_ocean_ids() {
        let fw = Framework::load_yaml(SOC2_YAML).unwrap();
        assert!(fw.controls[2].ocean_control_ids.is_empty());
    }

    #[test]
    fn framework_load_yaml_invalid_returns_error() {
        let bad = Framework::load_yaml("- just a list item");
        assert!(bad.is_err());
    }

    #[test]
    fn framework_serde_round_trip() {
        let fw = Framework::load_yaml(SOC2_YAML).unwrap();
        let json = serde_json::to_string(&fw).unwrap();
        let decoded: Framework = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id, fw.id);
        assert_eq!(decoded.controls.len(), fw.controls.len());
        assert_eq!(decoded.controls[0].ref_id, "CC6.1");
    }

    #[test]
    fn framework_without_version_defaults_empty() {
        let yaml = r#"
id: iso27001
name: ISO 27001
controls: []
"#;
        let fw = Framework::load_yaml(yaml).unwrap();
        assert_eq!(fw.version, "");
        assert!(fw.controls.is_empty());
    }
}
