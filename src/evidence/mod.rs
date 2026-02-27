// Evidence — the foundational entity in OCEAN.
//
// Every collector and tester produces Evidence records. Evidence is immutable
// once created and carries enough context to prove what was observed, when,
// and by which module.

pub mod observable;
pub mod redaction;
pub mod transcript;
pub mod validator;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

pub use observable::extract_observables;
pub use redaction::{redact_evidence, RedactionConfig};
pub use transcript::{TestTranscript, TranscriptRecorder};

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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_metadata() -> Metadata {
        Metadata {
            module: ModuleInfo {
                name: "test.module".to_string(),
                version: "0.1.0".to_string(),
                module_type: "collector".to_string(),
            },
            source: SourceInfo {
                system: "mock".to_string(),
                api_version: "v1".to_string(),
                endpoint: "mock://ep".to_string(),
            },
            original_time: None,
            processed_time: chrono::Utc::now(),
            safety_classification: None,
        }
    }

    #[test]
    fn status_id_from_known_values() {
        assert_eq!(StatusId::from(1), StatusId::Effective);
        assert_eq!(StatusId::from(2), StatusId::Ineffective);
        assert_eq!(StatusId::from(99), StatusId::Other);
        assert_eq!(StatusId::from(0), StatusId::Unknown);
    }

    #[test]
    fn status_id_from_unknown_fallback() {
        assert_eq!(StatusId::from(42), StatusId::Unknown);
        assert_eq!(StatusId::from(-1), StatusId::Unknown);
    }

    #[test]
    fn status_id_into_i32_all_variants() {
        assert_eq!(i32::from(StatusId::Unknown), 0);
        assert_eq!(i32::from(StatusId::Effective), 1);
        assert_eq!(i32::from(StatusId::Ineffective), 2);
        assert_eq!(i32::from(StatusId::Other), 99);
    }

    #[test]
    fn status_id_serde_round_trip() {
        for s in [
            StatusId::Unknown,
            StatusId::Effective,
            StatusId::Ineffective,
            StatusId::Other,
        ] {
            let json = serde_json::to_string(&s).unwrap();
            let decoded: StatusId = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, s);
        }
    }

    #[test]
    fn confidence_level_serde_round_trip() {
        for level in [
            ConfidenceLevel::PassiveObservation,
            ConfidenceLevel::ActiveVerification,
        ] {
            let json = serde_json::to_string(&level).unwrap();
            let decoded: ConfidenceLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, level);
        }
    }

    #[test]
    fn confidence_level_is_valid_always_true() {
        assert!(ConfidenceLevel::PassiveObservation.is_valid());
        assert!(ConfidenceLevel::ActiveVerification.is_valid());
    }

    #[test]
    fn module_info_type_field_renamed_in_json() {
        let info = ModuleInfo {
            name: "aws.iam".to_string(),
            version: "1.2.3".to_string(),
            module_type: "collector".to_string(),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"type\""));
        let decoded: ModuleInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.module_type, "collector");
    }

    #[test]
    fn observable_type_field_renamed_in_json() {
        let obs = Observable {
            obs_type: "ip".to_string(),
            value: "1.2.3.4".to_string(),
        };
        let json = serde_json::to_string(&obs).unwrap();
        assert!(json.contains("\"type\""));
        let decoded: Observable = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, obs);
    }

    #[test]
    fn metadata_with_optional_fields_populated() {
        let mut m = make_metadata();
        m.original_time = Some(chrono::Utc::now());
        m.safety_classification = Some("safe".to_string());
        let json = serde_json::to_string(&m).unwrap();
        let decoded: Metadata = serde_json::from_str(&json).unwrap();
        assert!(decoded.original_time.is_some());
        assert_eq!(decoded.safety_classification, Some("safe".to_string()));
    }

    #[test]
    fn evidence_serde_round_trip() {
        let ev = crate::testutil::make_evidence();
        let json = serde_json::to_string(&ev).unwrap();
        let decoded: Evidence = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id, ev.id);
        assert_eq!(decoded.control_id, ev.control_id);
        assert_eq!(decoded.status_id, ev.status_id);
        assert_eq!(decoded.status, ev.status);
    }

    #[test]
    fn evidence_none_transcript_absent_in_json() {
        let ev = crate::testutil::make_evidence();
        assert!(ev.test_transcript.is_none());
        let json = serde_json::to_string(&ev).unwrap();
        assert!(!json.contains("test_transcript"));
    }

    #[test]
    fn finding_and_enrichment_serde() {
        let f = Finding {
            title: "T".to_string(),
            description: "D".to_string(),
            severity_id: 4,
        };
        let json = serde_json::to_string(&f).unwrap();
        let decoded: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.severity_id, 4);

        let e = Enrichment {
            enrichment_type: "geo".to_string(),
            data: serde_json::json!({"cc": "US"}),
            enriched_time: chrono::Utc::now(),
        };
        let json2 = serde_json::to_string(&e).unwrap();
        let decoded2: Enrichment = serde_json::from_str(&json2).unwrap();
        assert_eq!(decoded2.enrichment_type, "geo");
    }
}
