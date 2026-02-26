use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A YAML-defined control that specifies what to monitor and how to evaluate it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Control {
    pub id: String,
    pub name: String,
    pub description: String,
    pub evaluation_logic: EvaluationLogic,
    #[serde(default)]
    pub framework_mappings: Vec<FrameworkMapping>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub component_controls: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub evaluation_expression_hash: String,
}

/// Defines how a control is evaluated — either via CEL expression or named preset.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EvaluationLogic {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cel_expression: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub preset: String,
}

/// Maps a control to a specific framework requirement (e.g., SOC 2 CC6.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkMapping {
    pub framework: String,
    pub requirement_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

/// The evaluated state of a control at a point in time.
/// Derived from one or more evidence records by the evaluation pipeline.
/// Note: EvaluationAttestationRef removed — Corsair handles provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlStatus {
    pub id: Uuid,
    pub control_id: String,
    pub timestamp: DateTime<Utc>,
    /// "effective", "ineffective", "unknown", "partial"
    pub status: String,
    /// "high", "medium", "low"
    pub confidence: String,
    pub evidence_ids: Vec<Uuid>,
    pub evaluation_details: String,
}

/// Result of an uptime calculation over a time range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UptimeResult {
    pub control_id: String,
    pub from_time: DateTime<Utc>,
    pub to_time: DateTime<Utc>,
    pub total_buckets: i32,
    pub effective_buckets: i32,
    pub ineffective_buckets: i32,
    pub gap_buckets: i32,
    pub uptime_percent: f64,
}

// ---------------------------------------------------------------------------
// YAML loading (from the controls/*.yaml file format)
// ---------------------------------------------------------------------------

/// Intermediate struct matching the YAML file format for controls.
/// The file format uses `evaluation.cel` / `evaluation.preset` and
/// `framework_mappings[].control` rather than `requirement_id`.
#[derive(Debug, Deserialize)]
struct ControlYaml {
    id: String,
    name: String,
    description: String,
    #[serde(default)]
    framework_mappings: Vec<FrameworkMappingYaml>,
    #[serde(default)]
    evaluation: EvaluationYaml,
    #[serde(default)]
    component_controls: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
struct EvaluationYaml {
    #[serde(default)]
    cel: String,
    #[serde(default)]
    preset: String,
}

#[derive(Debug, Deserialize)]
struct FrameworkMappingYaml {
    framework: String,
    /// Accepts both "control" (file format) and "requirement_id" (SDK format).
    #[serde(alias = "requirement_id")]
    control: String,
    #[serde(default)]
    description: String,
}

impl Control {
    /// Load a Control from a YAML string (matches the controls/**/*.yaml file format).
    pub fn load_yaml(yaml: &str) -> Result<Self> {
        let raw: ControlYaml = serde_yaml::from_str(yaml)
            .context("parsing control YAML")?;

        Ok(Control {
            id: raw.id,
            name: raw.name,
            description: raw.description,
            evaluation_logic: EvaluationLogic {
                cel_expression: raw.evaluation.cel,
                preset: raw.evaluation.preset,
            },
            framework_mappings: raw.framework_mappings
                .into_iter()
                .map(|m| FrameworkMapping {
                    framework: m.framework,
                    requirement_id: m.control,
                    description: m.description,
                })
                .collect(),
            component_controls: raw.component_controls,
            evaluation_expression_hash: String::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_control_status() -> ControlStatus {
        ControlStatus {
            id: Uuid::new_v4(),
            control_id: "cc6.1".to_string(),
            timestamp: Utc::now(),
            status: "effective".to_string(),
            confidence: "high".to_string(),
            evidence_ids: vec![Uuid::new_v4()],
            evaluation_details: "all evidence effective".to_string(),
        }
    }

    #[test]
    fn control_status_serde_round_trip() {
        let cs = make_control_status();
        let json = serde_json::to_string(&cs).unwrap();
        let decoded: ControlStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id, cs.id);
        assert_eq!(decoded.control_id, cs.control_id);
        assert_eq!(decoded.status, cs.status);
        assert_eq!(decoded.evidence_ids.len(), cs.evidence_ids.len());
    }

    #[test]
    fn evaluation_logic_default_empty() {
        let logic = EvaluationLogic::default();
        assert!(logic.cel_expression.is_empty());
        assert!(logic.preset.is_empty());
    }

    #[test]
    fn evaluation_logic_with_preset_serde() {
        let logic = EvaluationLogic {
            preset: "all_effective".to_string(),
            cel_expression: String::new(),
        };
        let json = serde_json::to_string(&logic).unwrap();
        // Empty cel_expression should be omitted
        assert!(!json.contains("cel_expression"));
        let decoded: EvaluationLogic = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.preset, "all_effective");
    }

    #[test]
    fn control_with_framework_mappings_serde() {
        let control = Control {
            id: "cc6.1".to_string(),
            name: "MFA Enforcement".to_string(),
            description: "All users must use MFA".to_string(),
            evaluation_logic: EvaluationLogic { preset: "all_effective".to_string(), cel_expression: String::new() },
            framework_mappings: vec![FrameworkMapping {
                framework: "SOC2".to_string(),
                requirement_id: "CC6.1".to_string(),
                description: "Logical access controls".to_string(),
            }],
            component_controls: vec![],
            evaluation_expression_hash: String::new(),
        };
        let json = serde_json::to_string(&control).unwrap();
        let decoded: Control = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.framework_mappings.len(), 1);
        assert_eq!(decoded.framework_mappings[0].framework, "SOC2");
    }

    #[test]
    fn uptime_result_serde() {
        let uptime = UptimeResult {
            control_id: "cc6.1".to_string(),
            from_time: Utc::now(),
            to_time: Utc::now(),
            total_buckets: 100,
            effective_buckets: 95,
            ineffective_buckets: 3,
            gap_buckets: 2,
            uptime_percent: 95.0,
        };
        let json = serde_json::to_string(&uptime).unwrap();
        let decoded: UptimeResult = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.total_buckets, 100);
        assert!((decoded.uptime_percent - 95.0).abs() < f64::EPSILON);
    }

    // --- Control::load_yaml ---

    const CONTROL_YAML: &str = r#"
id: iam.mfa_enforcement
name: MFA Enforcement Policy
description: Verifies MFA is enforced.
framework_mappings:
  - framework: soc2
    control: CC6.1
  - framework: iso27001
    control: A.9.4.2
    description: Authentication controls
evaluation:
  cel: "effective_count > 0 && ineffective_count == 0"
"#;

    #[test]
    fn control_load_yaml_parses_id_name() {
        let ctrl = Control::load_yaml(CONTROL_YAML).unwrap();
        assert_eq!(ctrl.id, "iam.mfa_enforcement");
        assert_eq!(ctrl.name, "MFA Enforcement Policy");
    }

    #[test]
    fn control_load_yaml_parses_framework_mappings() {
        let ctrl = Control::load_yaml(CONTROL_YAML).unwrap();
        assert_eq!(ctrl.framework_mappings.len(), 2);
        assert_eq!(ctrl.framework_mappings[0].framework, "soc2");
        assert_eq!(ctrl.framework_mappings[0].requirement_id, "CC6.1");
        assert_eq!(ctrl.framework_mappings[1].description, "Authentication controls");
    }

    #[test]
    fn control_load_yaml_parses_cel_expression() {
        let ctrl = Control::load_yaml(CONTROL_YAML).unwrap();
        assert!(ctrl.evaluation_logic.preset.is_empty());
        assert!(ctrl.evaluation_logic.cel_expression.contains("effective_count"));
    }

    #[test]
    fn control_load_yaml_with_preset() {
        let yaml = r#"
id: ctrl.a
name: Control A
description: A control.
evaluation:
  preset: all_effective
"#;
        let ctrl = Control::load_yaml(yaml).unwrap();
        assert_eq!(ctrl.evaluation_logic.preset, "all_effective");
        assert!(ctrl.evaluation_logic.cel_expression.is_empty());
    }

    #[test]
    fn control_load_yaml_invalid_returns_error() {
        let result = Control::load_yaml("- not a mapping");
        assert!(result.is_err());
    }

    #[test]
    fn control_load_yaml_empty_component_controls_by_default() {
        let ctrl = Control::load_yaml(CONTROL_YAML).unwrap();
        assert!(ctrl.component_controls.is_empty());
    }
}
