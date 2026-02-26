use serde_json::Value;
use std::collections::HashSet;

use super::Observable;

/// Pattern table: field-name substrings → observable type.
static PATTERNS: &[(&[&str], &str)] = &[
    (&["user", "email", "account"], "user"),
    (&["ip", "address"], "ip"),
    (&["resource", "arn", "id"], "resource"),
    (&["domain", "url", "host"], "domain"),
];

/// Scans raw evidence data (JSON Value) to surface key indicators such as
/// usernames, IP addresses, resource identifiers, and domain names.
/// Returns a deduplicated set of observables.
pub fn extract_observables(raw_data: &Value) -> Vec<Observable> {
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut result = Vec::new();
    walk_json("", raw_data, &mut |key: &str, value: &str| {
        let lower = key.to_lowercase();
        for (substrings, obs_type) in PATTERNS {
            if substrings.iter().any(|s| lower.contains(s)) {
                let key = (obs_type.to_string(), value.to_string());
                if seen.insert(key) {
                    result.push(Observable {
                        obs_type: obs_type.to_string(),
                        value: value.to_string(),
                    });
                }
                return; // first match wins
            }
        }
    });
    result
}

fn walk_json(key: &str, value: &Value, cb: &mut impl FnMut(&str, &str)) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                walk_json(k, v, cb);
            }
        }
        Value::Array(arr) => {
            for item in arr {
                walk_json(key, item, cb);
            }
        }
        Value::String(s) if !s.is_empty() => {
            cb(key, s);
        }
        _ => {}
    }
}
