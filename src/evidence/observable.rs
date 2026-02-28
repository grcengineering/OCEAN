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
                        name: String::new(), // auto-extracted: no named export
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_user_observable() {
        let data = serde_json::json!({"username": "alice"});
        let obs = extract_observables(&data);
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].obs_type, "user");
        assert_eq!(obs[0].value, "alice");
    }

    #[test]
    fn extracts_email_as_user() {
        let data = serde_json::json!({"email": "alice@example.com"});
        let obs = extract_observables(&data);
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].obs_type, "user");
    }

    #[test]
    fn extracts_account_as_user() {
        let data = serde_json::json!({"account_id": "123456"});
        let obs = extract_observables(&data);
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].obs_type, "user");
    }

    #[test]
    fn extracts_ip_observable() {
        let data = serde_json::json!({"ip_address": "192.168.1.1"});
        let obs = extract_observables(&data);
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].obs_type, "ip");
    }

    #[test]
    fn extracts_resource_by_arn() {
        let data = serde_json::json!({"arn": "arn:aws:s3:::bucket"});
        let obs = extract_observables(&data);
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].obs_type, "resource");
    }

    #[test]
    fn extracts_resource_by_id() {
        let data = serde_json::json!({"resource_id": "r-1234"});
        let obs = extract_observables(&data);
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].obs_type, "resource");
    }

    #[test]
    fn extracts_domain_observable() {
        let data = serde_json::json!({"domain": "example.com"});
        let obs = extract_observables(&data);
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].obs_type, "domain");
    }

    #[test]
    fn extracts_url_as_domain() {
        let data = serde_json::json!({"url": "https://example.com/path"});
        let obs = extract_observables(&data);
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].obs_type, "domain");
    }

    #[test]
    fn extracts_host_as_domain() {
        let data = serde_json::json!({"hostname": "myhost.example.com"});
        let obs = extract_observables(&data);
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].obs_type, "domain");
    }

    #[test]
    fn deduplicates_same_value() {
        let data = serde_json::json!({"user1": "alice", "user2": "alice"});
        let obs = extract_observables(&data);
        // Both keys contain "user", same value → deduplicated to 1
        assert_eq!(obs.len(), 1);
    }

    #[test]
    fn no_match_returns_empty() {
        let data = serde_json::json!({"bucket_name": "my-bucket", "region": "us-east-1"});
        let obs = extract_observables(&data);
        assert!(obs.is_empty());
    }

    #[test]
    fn empty_string_value_skipped() {
        let data = serde_json::json!({"username": ""});
        let obs = extract_observables(&data);
        assert!(obs.is_empty());
    }

    #[test]
    fn nested_object_traversed() {
        let data = serde_json::json!({"outer": {"username": "bob"}});
        let obs = extract_observables(&data);
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].value, "bob");
    }

    #[test]
    fn array_traversed() {
        let data = serde_json::json!({"users": ["alice", "bob"]});
        // key is "users" which contains "user" → both items extracted
        let obs = extract_observables(&data);
        assert_eq!(obs.len(), 2);
    }

    #[test]
    fn non_string_values_skipped() {
        let data = serde_json::json!({"user_id": 42, "active": true, "score": 3.14});
        let obs = extract_observables(&data);
        assert!(obs.is_empty());
    }

    #[test]
    fn null_input() {
        let obs = extract_observables(&serde_json::Value::Null);
        assert!(obs.is_empty());
    }
}
