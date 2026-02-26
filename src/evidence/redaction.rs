use sha2::{Sha256, Digest};
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

    let mask_set: HashSet<&str> = config.mask_observable_types.iter().map(|s| s.as_str()).collect();
    let hash_set: HashSet<&str> = config.hash_observable_types.iter().map(|s| s.as_str()).collect();

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
