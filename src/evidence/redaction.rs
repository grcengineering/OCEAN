use sha2::{Digest, Sha256};
use std::collections::HashSet;

use super::Evidence;

const REDACTED_PLACEHOLDER: &str = "***REDACTED***";

/// Specifies which fields and values to redact from evidence.
#[derive(Debug, Clone, Default)]
pub struct RedactionConfig {
    /// Remove the entire raw_data field.
    pub remove_raw_data: bool,
    /// Replace observable values of these types with REDACTED_PLACEHOLDER.
    pub mask_observable_types: Vec<String>,
    /// Replace observable values of these types with SHA-256 hashes.
    /// Preserves referential integrity while hiding the original value.
    pub hash_observable_types: Vec<String>,
    /// Remove these top-level fields by name.
    /// Supported: "findings", "enrichments", "test_transcript".
    pub remove_fields: Vec<String>,
}

/// Returns a new Evidence record with sensitive fields redacted.
/// The original evidence is not modified — returns a clone with redactions applied.
pub fn redact_evidence(ev: &Evidence, config: &RedactionConfig) -> Evidence {
    let mut redacted = ev.clone();

    if config.remove_raw_data {
        redacted.raw_data = serde_json::Value::Null;
    }

    let mask_set: HashSet<&str> = config
        .mask_observable_types
        .iter()
        .map(|s| s.as_str())
        .collect();
    let hash_set: HashSet<&str> = config
        .hash_observable_types
        .iter()
        .map(|s| s.as_str())
        .collect();

    for obs in &mut redacted.observables {
        if mask_set.contains(obs.obs_type.as_str()) {
            obs.value = REDACTED_PLACEHOLDER.to_string();
        } else if hash_set.contains(obs.obs_type.as_str()) {
            obs.value = hash_value(&obs.value);
        }
    }

    let remove_set: HashSet<&str> = config.remove_fields.iter().map(|s| s.as_str()).collect();
    if remove_set.contains("findings") {
        redacted.findings.clear();
    }
    if remove_set.contains("enrichments") {
        redacted.enrichments.clear();
    }
    if remove_set.contains("test_transcript") {
        redacted.test_transcript = None;
    }

    redacted
}

fn hash_value(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::transcript::TranscriptRecorder;
    use crate::evidence::{Finding, Observable};

    #[test]
    fn noop_config_returns_clone() {
        let ev = crate::testutil::make_evidence();
        let config = RedactionConfig::default();
        let redacted = redact_evidence(&ev, &config);
        assert_eq!(redacted.id, ev.id);
        assert_eq!(redacted.raw_data, ev.raw_data);
        assert_eq!(redacted.observables.len(), ev.observables.len());
        assert_eq!(redacted.findings.len(), ev.findings.len());
    }

    #[test]
    fn remove_raw_data() {
        let ev = crate::testutil::make_evidence();
        let config = RedactionConfig {
            remove_raw_data: true,
            ..Default::default()
        };
        let redacted = redact_evidence(&ev, &config);
        assert!(redacted.raw_data.is_null());
    }

    #[test]
    fn mask_observable_type() {
        let mut ev = crate::testutil::make_evidence();
        ev.observables = vec![
            Observable {
                obs_type: "user".to_string(),
                value: "alice".to_string(),
            },
            Observable {
                obs_type: "ip".to_string(),
                value: "1.2.3.4".to_string(),
            },
        ];
        let config = RedactionConfig {
            mask_observable_types: vec!["user".to_string()],
            ..Default::default()
        };
        let redacted = redact_evidence(&ev, &config);
        assert_eq!(redacted.observables[0].value, "***REDACTED***");
        assert_eq!(redacted.observables[1].value, "1.2.3.4"); // untouched
    }

    #[test]
    fn hash_observable_type() {
        let mut ev = crate::testutil::make_evidence();
        ev.observables = vec![Observable {
            obs_type: "ip".to_string(),
            value: "10.0.0.1".to_string(),
        }];
        let config = RedactionConfig {
            hash_observable_types: vec!["ip".to_string()],
            ..Default::default()
        };
        let redacted = redact_evidence(&ev, &config);
        assert!(redacted.observables[0].value.starts_with("sha256:"));
        assert_ne!(redacted.observables[0].value, "10.0.0.1");
    }

    #[test]
    fn remove_findings() {
        let mut ev = crate::testutil::make_evidence();
        ev.findings = vec![Finding {
            title: "T".to_string(),
            description: "D".to_string(),
            severity_id: 1,
        }];
        let config = RedactionConfig {
            remove_fields: vec!["findings".to_string()],
            ..Default::default()
        };
        let redacted = redact_evidence(&ev, &config);
        assert!(redacted.findings.is_empty());
    }

    #[test]
    fn remove_enrichments() {
        let mut ev = crate::testutil::make_evidence();
        ev.enrichments = vec![crate::evidence::Enrichment {
            enrichment_type: "geo".to_string(),
            data: serde_json::json!({}),
            enriched_time: chrono::Utc::now(),
        }];
        let config = RedactionConfig {
            remove_fields: vec!["enrichments".to_string()],
            ..Default::default()
        };
        let redacted = redact_evidence(&ev, &config);
        assert!(redacted.enrichments.is_empty());
    }

    #[test]
    fn remove_test_transcript() {
        let mut ev = crate::testutil::make_evidence();
        let mut rec = TranscriptRecorder::new();
        rec.record_action("attack", None);
        ev.test_transcript = Some(rec.finalize());
        assert!(ev.test_transcript.is_some());

        let config = RedactionConfig {
            remove_fields: vec!["test_transcript".to_string()],
            ..Default::default()
        };
        let redacted = redact_evidence(&ev, &config);
        assert!(redacted.test_transcript.is_none());
    }

    #[test]
    fn original_not_mutated() {
        let ev = crate::testutil::make_evidence();
        let config = RedactionConfig {
            remove_raw_data: true,
            ..Default::default()
        };
        let _redacted = redact_evidence(&ev, &config);
        assert!(!ev.raw_data.is_null()); // original unchanged
    }
}
