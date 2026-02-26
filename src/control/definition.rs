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
