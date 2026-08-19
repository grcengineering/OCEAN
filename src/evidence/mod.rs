// Evidence — the foundational entity in OCEAN.
//
// Types are re-exported from grc-controls-models (the shared crate).
// OCEAN-specific logic (observable extraction, redaction, validation)
// remains in local submodules.

pub mod observable;
pub mod redaction;
pub mod transcript;
pub mod validator;

// Re-export all evidence types from shared crate
pub use grc_controls_models::{
    ConfidenceLevel, Enrichment, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo,
    StatusId,
};

pub use observable::extract_observables;
pub use redaction::{redact_evidence, RedactionConfig};
pub use transcript::{TestTranscript, TranscriptRecorder};

// Extension trait for ConfidenceLevel — preserves OCEAN's existing API.
pub trait ConfidenceLevelExt {
    fn is_valid(&self) -> bool;
}

impl ConfidenceLevelExt for ConfidenceLevel {
    fn is_valid(&self) -> bool {
        true // all enum variants are valid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            module_type: "observer".to_string(),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"type\""));
        let decoded: ModuleInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.module_type, "observer");
    }

    #[test]
    fn observable_type_field_renamed_in_json() {
        let obs = Observable {
            obs_type: "ip".to_string(),
            value: "1.2.3.4".to_string(),
            name: String::new(),
        };
        let json = serde_json::to_string(&obs).unwrap();
        assert!(json.contains("\"type\""));
        let decoded: Observable = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, obs);
    }

    #[test]
    fn observable_name_omitted_when_empty() {
        let obs = Observable {
            obs_type: "ip".to_string(),
            value: "1.2.3.4".to_string(),
            name: String::new(),
        };
        let json = serde_json::to_string(&obs).unwrap();
        assert!(!json.contains("\"name\""), "empty name should be omitted");
    }

    #[test]
    fn observable_named_export_roundtrip() {
        let obs = Observable {
            obs_type: "ip_range".to_string(),
            value: "173.245.48.0/20".to_string(),
            name: "egress_ip".to_string(),
        };
        let json = serde_json::to_string(&obs).unwrap();
        assert!(json.contains("\"name\""));
        let decoded: Observable = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.name, "egress_ip");
    }

    #[test]
    fn metadata_with_optional_fields_populated() {
        let mut m = Metadata {
            module: ModuleInfo {
                name: "test.module".to_string(),
                version: "0.1.0".to_string(),
                module_type: "observer".to_string(),
            },
            source: SourceInfo {
                system: "mock".to_string(),
                api_version: "v1".to_string(),
                endpoint: "mock://ep".to_string(),
            },
            original_time: None,
            processed_time: chrono::Utc::now(),
            safety_classification: None,
        };
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
