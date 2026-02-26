// Evidence — the foundational entity in OCEAN.
//
// Every collector and tester produces Evidence records. Evidence is immutable
// once created and carries enough context to prove what was observed, when,
// and by which module.

pub mod transcript;
pub mod observable;
pub mod redaction;
pub mod validator;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

pub use transcript::{TestTranscript, TranscriptRecorder};
pub use observable::extract_observables;
pub use redaction::{RedactionConfig, redact_evidence};

// ---------------------------------------------------------------------------
// StatusId
// ---------------------------------------------------------------------------

/// The outcome of an evidence collection or active test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "i32", into = "i32")]
pub enum StatusId {
    /// Outcome could not be determined.
    Unknown,
    /// Control is operating effectively.
    Effective,
    /// Control is not operating effectively.
    Ineffective,
    /// Non-standard outcome requiring human review.
    Other,
}

impl From<i32> for StatusId {
    fn from(v: i32) -> Self {
        match v {
            1 => Self::Effective,
            2 => Self::Ineffective,
            99 => Self::Other,
            _ => Self::Unknown,
        }
    }
}

impl From<StatusId> for i32 {
    fn from(s: StatusId) -> Self {
        match s {
            StatusId::Unknown => 0,
            StatusId::Effective => 1,
            StatusId::Ineffective => 2,
            StatusId::Other => 99,
        }
    }
}

// ---------------------------------------------------------------------------
// ConfidenceLevel
// ---------------------------------------------------------------------------

/// Degree of confidence in an evidence record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceLevel {
    /// Evidence gathered by reading state (collector).
    PassiveObservation,
    /// Evidence gathered by performing an active test (tester).
    ActiveVerification,
}

impl ConfidenceLevel {
    pub fn is_valid(&self) -> bool {
        true // all enum variants are valid
    }
}

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

/// Identifies the OCEAN module that produced this evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub name: String,
    pub version: String,
    /// "collector", "tester", or "dual"
    #[serde(rename = "type")]
    pub module_type: String,
}

/// Identifies the external system from which evidence was gathered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceInfo {
    pub system: String,
    pub api_version: String,
    pub endpoint: String,
}

/// Provenance information about how evidence was collected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    pub module: ModuleInfo,
    pub source: SourceInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_time: Option<DateTime<Utc>>,
    pub processed_time: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safety_classification: Option<String>,
}

/// A single observable value extracted from evidence (username, IP, resource ID, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Observable {
    #[serde(rename = "type")]
    pub obs_type: String,
    pub value: String,
}

/// A discrete finding within an evidence record (misconfiguration, ineffective control).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub title: String,
    pub description: String,
    pub severity_id: i32,
}

/// Additional context added to evidence after initial collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Enrichment {
    #[serde(rename = "type")]
    pub enrichment_type: String,
    pub data: Value,
    pub enriched_time: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Evidence — the core entity
// ---------------------------------------------------------------------------

/// A structured, immutable record proving a control was (or was not) operating
/// effectively at a given point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: Uuid,
    pub control_id: String,
    pub class_uid: i32,
    pub category_uid: i32,
    pub activity_id: i32,
    pub time: DateTime<Utc>,
    pub confidence_level: ConfidenceLevel,
    pub metadata: Metadata,
    #[serde(default)]
    pub observables: Vec<Observable>,
    pub status_id: StatusId,
    pub status: String,
    pub raw_data: Value,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_transcript: Option<TestTranscript>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enrichments: Vec<Enrichment>,
}
