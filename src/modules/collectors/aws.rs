use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
};
use crate::module::{collector::Collector, CredentialReq, Module};

// ─── Constants ────────────────────────────────────────────────────────────────

const DEFAULT_IAM_ENDPOINT: &str = "https://iam.amazonaws.com/";
const IAM_SERVICE: &str = "iam";
const IAM_API_VERSION: &str = "2010-05-08";
const IAM_REGION: &str = "us-east-1";
const ACCESS_KEY_MAX_AGE_DAYS: i64 = 90;

// ─── Crypto helpers ───────────────────────────────────────────────────────────

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn derive_signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{}", secret).as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

/// Percent-encode a string for use in AWS canonical query strings.
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char);
            }
            other => out.push_str(&format!("%{:02X}", other)),
        }
    }
    out
}

// ─── AWS HTTP request (SigV4) ─────────────────────────────────────────────────

/// Signs and executes a GET request to an AWS service endpoint using SigV4.
/// The `base_url` defaults to the real AWS endpoint but can be overridden
/// in config (key: `AWS_BASE_URL`) for testing with a mock server.
fn do_aws_get(
    access_key: &str,
    secret_key: &str,
    session_token: Option<&str>,
    region: &str,
    base_url: &str,
    service: &str,
    params: &[(&str, &str)],
) -> Result<String> {
    let now = Utc::now();
    let datetime = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();

    // Sort params alphabetically for canonical query string.
    let mut sorted: Vec<(&str, &str)> = params.to_vec();
    sorted.sort_by_key(|(k, _)| *k);
    let query_string: String = sorted
        .iter()
        .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    // Extract host from base_url for canonical headers.
    let host = base_url
        .trim_end_matches('/')
        .trim_start_matches("https://")
        .trim_start_matches("http://");

    let payload_hash = sha256_hex(b"");

    // Build canonical headers and signed headers list.
    let mut canonical_headers = format!("host:{}\nx-amz-date:{}\n", host, datetime);
    let mut signed_headers = "host;x-amz-date".to_string();
    if let Some(token) = session_token {
        canonical_headers.push_str(&format!("x-amz-security-token:{}\n", token));
        signed_headers = "host;x-amz-date;x-amz-security-token".to_string();
    }

    // Canonical request.
    let canonical_request = format!(
        "GET\n/\n{}\n{}\n{}\n{}",
        query_string, canonical_headers, signed_headers, payload_hash
    );

    // String to sign.
    let credential_scope = format!("{}/{}/{}/aws4_request", date, region, service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        datetime,
        credential_scope,
        sha256_hex(canonical_request.as_bytes())
    );

    // Signing key and signature.
    let sk = derive_signing_key(secret_key, &date, region, service);
    let signature = hex::encode(hmac_sha256(&sk, string_to_sign.as_bytes()));

    // Authorization header.
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={}/{},SignedHeaders={},Signature={}",
        access_key, credential_scope, signed_headers, signature
    );

    let url = format!("{}?{}", base_url.trim_end_matches('/'), query_string);

    let mut req = ureq::get(&url)
        .set("x-amz-date", &datetime)
        .set("Authorization", &auth);

    if let Some(token) = session_token {
        req = req.set("x-amz-security-token", token);
    }

    let resp = req
        .call()
        .map_err(|e| anyhow!("AWS IAM request failed: {}", e))?;
    resp.into_string()
        .map_err(|e| anyhow!("reading AWS response: {}", e))
}

// ─── XML parsing helpers ──────────────────────────────────────────────────────

/// Extract the text content of the first `<tag>content</tag>` in a line.
fn tag_value(line: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    line.find(&open).and_then(|s| {
        let start = s + open.len();
        line[start..]
            .find(&close)
            .map(|e| line[start..start + e].to_string())
    })
}

#[derive(Default)]
struct IamUser {
    user_name: String,
    user_id: String,
    arn: String,
}

/// Parse a `ListUsers` XML response into a Vec of users.
fn parse_list_users(xml: &str) -> Vec<IamUser> {
    let mut users = Vec::new();
    let mut in_member = false;
    let mut cur = IamUser::default();

    for line in xml.lines() {
        let line = line.trim();
        if line == "<member>" {
            in_member = true;
            cur = IamUser::default();
        } else if line == "</member>" && in_member {
            users.push(cur);
            cur = IamUser::default();
            in_member = false;
        } else if in_member {
            if let Some(v) = tag_value(line, "UserName") {
                cur.user_name = v;
            } else if let Some(v) = tag_value(line, "UserId") {
                cur.user_id = v;
            } else if let Some(v) = tag_value(line, "Arn") {
                cur.arn = v;
            }
        }
    }
    users
}

/// Count MFA devices in a `ListMFADevices` XML response.
fn count_mfa_devices(xml: &str) -> i32 {
    xml.matches("<SerialNumber>").count() as i32
}

#[derive(Default)]
struct AccessKeyInfo {
    access_key_id: String,
    status: String,
    create_date: String,
    age_days: i64,
}

/// Parse a `ListAccessKeys` XML response.
fn parse_access_keys(xml: &str, now: DateTime<Utc>) -> Vec<AccessKeyInfo> {
    let mut keys = Vec::new();
    let mut in_member = false;
    let mut cur = AccessKeyInfo::default();

    for line in xml.lines() {
        let line = line.trim();
        if line == "<member>" {
            in_member = true;
            cur = AccessKeyInfo::default();
        } else if line == "</member>" && in_member {
            keys.push(cur);
            cur = AccessKeyInfo::default();
            in_member = false;
        } else if in_member {
            if let Some(v) = tag_value(line, "AccessKeyId") {
                cur.access_key_id = v;
            } else if let Some(v) = tag_value(line, "Status") {
                cur.status = v;
            } else if let Some(v) = tag_value(line, "CreateDate") {
                if let Ok(dt) = DateTime::parse_from_rfc3339(&v) {
                    cur.age_days = (now - dt.with_timezone(&Utc)).num_days();
                }
                cur.create_date = v;
            }
        }
    }
    keys
}

// ─── IAMCollector ─────────────────────────────────────────────────────────────

/// Queries AWS IAM to collect MFA enrollment and access key age evidence.
///
/// Required config keys: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`.
/// Optional: `AWS_SESSION_TOKEN`, `AWS_REGION`, `AWS_BASE_URL` (test override).
pub struct IamCollector;

impl Module for IamCollector {
    fn id(&self) -> &str {
        "aws.iam"
    }
    fn name(&self) -> &str {
        "AWS IAM Collector"
    }
    fn version(&self) -> &str {
        "0.1.0"
    }
    fn source_system(&self) -> &str {
        "aws"
    }
    fn evidence_types(&self) -> &[i32] {
        &[1002]
    }

    fn credential_requirements(&self) -> Vec<CredentialReq> {
        vec![
            CredentialReq {
                name: "AWS_ACCESS_KEY_ID".to_string(),
                cred_type: "api_key".to_string(),
                description: "AWS access key ID with IAM read permissions".to_string(),
                required: true,
            },
            CredentialReq {
                name: "AWS_SECRET_ACCESS_KEY".to_string(),
                cred_type: "secret".to_string(),
                description: "AWS secret access key".to_string(),
                required: true,
            },
            CredentialReq {
                name: "AWS_SESSION_TOKEN".to_string(),
                cred_type: "token".to_string(),
                description: "AWS session token for temporary credentials".to_string(),
                required: false,
            },
            CredentialReq {
                name: "AWS_REGION".to_string(),
                cred_type: "config".to_string(),
                description: "AWS region (default: us-east-1)".to_string(),
                required: false,
            },
        ]
    }
}

impl Collector for IamCollector {
    fn collect(&self, config: &HashMap<String, String>) -> Result<Vec<Evidence>> {
        let access_key = config
            .get("AWS_ACCESS_KEY_ID")
            .ok_or_else(|| anyhow!("AWS_ACCESS_KEY_ID is required"))?;
        let secret_key = config
            .get("AWS_SECRET_ACCESS_KEY")
            .ok_or_else(|| anyhow!("AWS_SECRET_ACCESS_KEY is required"))?;
        let session_token = config.get("AWS_SESSION_TOKEN").map(|s| s.as_str());
        let base_url = config
            .get("AWS_BASE_URL")
            .map(|s| s.as_str())
            .unwrap_or(DEFAULT_IAM_ENDPOINT);

        let now = Utc::now();

        // Step 1: List all IAM users.
        let users_xml = do_aws_get(
            access_key,
            secret_key,
            session_token,
            IAM_REGION,
            base_url,
            IAM_SERVICE,
            &[("Action", "ListUsers"), ("Version", IAM_API_VERSION)],
        )?;
        let users = parse_list_users(&users_xml);

        // Step 2: For each user, check MFA devices and access keys.
        struct UserStatus {
            user_name: String,
            user_id: String,
            arn: String,
            mfa_enabled: bool,
            mfa_devices: i32,
            access_keys: Vec<AccessKeyInfo>,
        }

        let mut statuses: Vec<UserStatus> = Vec::new();
        for user in &users {
            let mfa_xml = do_aws_get(
                access_key,
                secret_key,
                session_token,
                IAM_REGION,
                base_url,
                IAM_SERVICE,
                &[
                    ("Action", "ListMFADevices"),
                    ("UserName", &user.user_name),
                    ("Version", IAM_API_VERSION),
                ],
            )?;
            let mfa_count = count_mfa_devices(&mfa_xml);

            let keys_xml = do_aws_get(
                access_key,
                secret_key,
                session_token,
                IAM_REGION,
                base_url,
                IAM_SERVICE,
                &[
                    ("Action", "ListAccessKeys"),
                    ("UserName", &user.user_name),
                    ("Version", IAM_API_VERSION),
                ],
            )?;
            let access_keys = parse_access_keys(&keys_xml, now);

            statuses.push(UserStatus {
                user_name: user.user_name.clone(),
                user_id: user.user_id.clone(),
                arn: user.arn.clone(),
                mfa_enabled: mfa_count > 0,
                mfa_devices: mfa_count,
                access_keys,
            });
        }

        // Step 3: Build findings and observables.
        let mut findings: Vec<Finding> = Vec::new();
        let mut observables: Vec<Observable> = Vec::new();
        let mut users_without_mfa = 0usize;
        let mut old_access_keys = 0usize;

        for s in &statuses {
            observables.push(Observable {
                obs_type: "user".to_string(),
                value: s.user_name.clone(),
                name: String::new(),
            });
            observables.push(Observable {
                obs_type: "resource".to_string(),
                value: s.arn.clone(),
                name: String::new(),
            });

            if !s.mfa_enabled {
                users_without_mfa += 1;
                findings.push(Finding {
                    title: "User Without MFA".to_string(),
                    description: format!(
                        "IAM user {:?} does not have any MFA device configured",
                        s.user_name
                    ),
                    severity_id: 3,
                });
            }

            for key in &s.access_keys {
                if key.status == "Active" && key.age_days > ACCESS_KEY_MAX_AGE_DAYS {
                    old_access_keys += 1;
                    findings.push(Finding {
                        title: "Stale Access Key".to_string(),
                        description: format!(
                            "IAM user {:?} has active access key {} that is {} days old (max {})",
                            s.user_name, key.access_key_id, key.age_days, ACCESS_KEY_MAX_AGE_DAYS
                        ),
                        severity_id: 2,
                    });
                }
            }
        }

        if findings.is_empty() {
            findings.push(Finding {
                title: "IAM Users Compliant".to_string(),
                description: format!(
                    "All {} IAM users have MFA enabled and no stale access keys",
                    statuses.len()
                ),
                severity_id: 0,
            });
        }

        let (status_id, status_text) = if users_without_mfa > 0 || old_access_keys > 0 {
            (
                StatusId::Ineffective,
                format!(
                    "{} users without MFA, {} stale access keys out of {} total users",
                    users_without_mfa,
                    old_access_keys,
                    statuses.len()
                ),
            )
        } else {
            (
                StatusId::Effective,
                format!(
                    "All {} IAM users have MFA enabled with no stale access keys",
                    statuses.len()
                ),
            )
        };

        let user_details: Vec<_> = statuses
            .iter()
            .map(|s| {
                json!({
                    "user_name": s.user_name,
                    "user_id": s.user_id,
                    "arn": s.arn,
                    "mfa_enabled": s.mfa_enabled,
                    "mfa_devices": s.mfa_devices,
                    "access_keys": s.access_keys.iter().map(|k| json!({
                        "access_key_id": k.access_key_id,
                        "status": k.status,
                        "age_days": k.age_days,
                        "create_date": k.create_date,
                    })).collect::<Vec<_>>()
                })
            })
            .collect();

        let raw_data = json!({
            "total_users": statuses.len(),
            "users_without_mfa": users_without_mfa,
            "stale_access_keys": old_access_keys,
            "max_key_age_days": ACCESS_KEY_MAX_AGE_DAYS,
            "user_details": user_details,
        });

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "iam.mfa_enforcement".to_string(),
            class_uid: 1002,
            category_uid: 1,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "aws.iam".to_string(),
                    version: "0.1.0".to_string(),
                    module_type: "collector".to_string(),
                },
                source: SourceInfo {
                    system: "aws".to_string(),
                    api_version: IAM_API_VERSION.to_string(),
                    endpoint: base_url.to_string(),
                },
                original_time: None,
                processed_time: now,
                safety_classification: None,
            },
            observables,
            status_id,
            status: status_text,
            raw_data,
            findings,
            test_transcript: None,
            enrichments: vec![],
        }])
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Crypto helpers ───────────────────────────────────────────────────────

    #[test]
    fn sha256_hex_empty_string() {
        // Canonical SHA-256 of empty string.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_hex_known_value() {
        assert_eq!(
            sha256_hex(b"hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn hmac_sha256_returns_32_bytes() {
        assert_eq!(hmac_sha256(b"key", b"data").len(), 32);
    }

    #[test]
    fn derive_signing_key_returns_32_bytes() {
        let key = derive_signing_key("secret", "20260101", "us-east-1", "iam");
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn url_encode_passthrough_safe_chars() {
        assert_eq!(url_encode("Action"), "Action");
        assert_eq!(url_encode("us-east-1"), "us-east-1");
        assert_eq!(url_encode("ListUsers"), "ListUsers");
        assert_eq!(url_encode("2010-05-08"), "2010-05-08");
    }

    #[test]
    fn url_encode_special_chars() {
        assert_eq!(url_encode(" "), "%20");
        assert_eq!(url_encode("+"), "%2B");
        assert_eq!(url_encode("/"), "%2F");
        assert_eq!(url_encode("="), "%3D");
        assert_eq!(url_encode("&"), "%26");
    }

    // ── XML parsing ──────────────────────────────────────────────────────────

    const EMPTY_USERS: &str = r#"<ListUsersResponse>
  <ListUsersResult>
    <Users/>
    <IsTruncated>false</IsTruncated>
  </ListUsersResult>
</ListUsersResponse>"#;

    const ONE_USER: &str = r#"<ListUsersResponse>
  <ListUsersResult>
    <Users>
      <member>
        <UserName>alice</UserName>
        <UserId>AIDAIOSFODNN7EXAMPLE</UserId>
        <Arn>arn:aws:iam::123456789012:user/alice</Arn>
        <CreateDate>2020-01-01T00:00:00Z</CreateDate>
      </member>
    </Users>
    <IsTruncated>false</IsTruncated>
  </ListUsersResult>
</ListUsersResponse>"#;

    const TWO_USERS: &str = r#"<ListUsersResponse>
  <ListUsersResult>
    <Users>
      <member>
        <UserName>alice</UserName>
        <UserId>ID1</UserId>
        <Arn>arn:aws:iam::123:user/alice</Arn>
        <CreateDate>2020-01-01T00:00:00Z</CreateDate>
      </member>
      <member>
        <UserName>bob</UserName>
        <UserId>ID2</UserId>
        <Arn>arn:aws:iam::123:user/bob</Arn>
        <CreateDate>2021-01-01T00:00:00Z</CreateDate>
      </member>
    </Users>
    <IsTruncated>false</IsTruncated>
  </ListUsersResult>
</ListUsersResponse>"#;

    const MFA_ONE: &str = r#"<ListMFADevicesResponse>
  <ListMFADevicesResult>
    <MFADevices>
      <member>
        <SerialNumber>arn:aws:iam::123:mfa/alice</SerialNumber>
        <EnableDate>2022-01-01T00:00:00Z</EnableDate>
      </member>
    </MFADevices>
  </ListMFADevicesResult>
</ListMFADevicesResponse>"#;

    const MFA_NONE: &str = r#"<ListMFADevicesResponse>
  <ListMFADevicesResult>
    <MFADevices/>
  </ListMFADevicesResult>
</ListMFADevicesResponse>"#;

    const KEYS_FRESH: &str = r#"<ListAccessKeysResponse>
  <ListAccessKeysResult>
    <AccessKeyMetadata>
      <member>
        <AccessKeyId>FRESHKEY</AccessKeyId>
        <Status>Active</Status>
        <CreateDate>2026-01-01T00:00:00Z</CreateDate>
        <UserName>alice</UserName>
      </member>
    </AccessKeyMetadata>
  </ListAccessKeysResult>
</ListAccessKeysResponse>"#;

    const KEYS_STALE: &str = r#"<ListAccessKeysResponse>
  <ListAccessKeysResult>
    <AccessKeyMetadata>
      <member>
        <AccessKeyId>STALEKEY</AccessKeyId>
        <Status>Active</Status>
        <CreateDate>2024-01-01T00:00:00Z</CreateDate>
        <UserName>alice</UserName>
      </member>
    </AccessKeyMetadata>
  </ListAccessKeysResult>
</ListAccessKeysResponse>"#;

    const KEYS_INACTIVE_STALE: &str = r#"<ListAccessKeysResponse>
  <ListAccessKeysResult>
    <AccessKeyMetadata>
      <member>
        <AccessKeyId>OLDKEY</AccessKeyId>
        <Status>Inactive</Status>
        <CreateDate>2020-01-01T00:00:00Z</CreateDate>
        <UserName>alice</UserName>
      </member>
    </AccessKeyMetadata>
  </ListAccessKeysResult>
</ListAccessKeysResponse>"#;

    const KEYS_EMPTY: &str = r#"<ListAccessKeysResponse>
  <ListAccessKeysResult>
    <AccessKeyMetadata/>
  </ListAccessKeysResult>
</ListAccessKeysResponse>"#;

    #[test]
    fn parse_list_users_empty() {
        assert!(parse_list_users(EMPTY_USERS).is_empty());
    }

    #[test]
    fn parse_list_users_one() {
        let users = parse_list_users(ONE_USER);
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].user_name, "alice");
        assert_eq!(users[0].user_id, "AIDAIOSFODNN7EXAMPLE");
        assert!(users[0].arn.contains("alice"));
    }

    #[test]
    fn parse_list_users_two() {
        let users = parse_list_users(TWO_USERS);
        assert_eq!(users.len(), 2);
        assert_eq!(users[0].user_name, "alice");
        assert_eq!(users[1].user_name, "bob");
    }

    #[test]
    fn count_mfa_devices_zero() {
        assert_eq!(count_mfa_devices(MFA_NONE), 0);
    }

    #[test]
    fn count_mfa_devices_one() {
        assert_eq!(count_mfa_devices(MFA_ONE), 1);
    }

    #[test]
    fn parse_access_keys_empty() {
        assert!(parse_access_keys(KEYS_EMPTY, Utc::now()).is_empty());
    }

    #[test]
    fn parse_access_keys_fresh_under_90_days() {
        let now = DateTime::parse_from_rfc3339("2026-02-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let keys = parse_access_keys(KEYS_FRESH, now);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].access_key_id, "FRESHKEY");
        assert_eq!(keys[0].status, "Active");
        assert!(keys[0].age_days < 90);
    }

    #[test]
    fn parse_access_keys_stale_over_90_days() {
        let keys = parse_access_keys(KEYS_STALE, Utc::now());
        assert_eq!(keys.len(), 1);
        assert!(keys[0].age_days > 90);
    }

    #[test]
    fn parse_access_keys_inactive_not_flagged() {
        // age_days will be high but Status=Inactive
        let keys = parse_access_keys(KEYS_INACTIVE_STALE, Utc::now());
        assert_eq!(keys[0].status, "Inactive");
        // The IamCollector only flags Active + stale keys
    }

    // ── IamCollector metadata ────────────────────────────────────────────────

    #[test]
    fn iam_collector_id() {
        assert_eq!(IamCollector.id(), "aws.iam");
    }

    #[test]
    fn iam_collector_name() {
        assert_eq!(IamCollector.name(), "AWS IAM Collector");
    }

    #[test]
    fn iam_collector_version() {
        assert_eq!(IamCollector.version(), "0.1.0");
    }

    #[test]
    fn iam_collector_source_system() {
        assert_eq!(IamCollector.source_system(), "aws");
    }

    #[test]
    fn iam_collector_evidence_types() {
        assert_eq!(IamCollector.evidence_types(), &[1002]);
    }

    #[test]
    fn iam_collector_credential_requirements() {
        let reqs = IamCollector.credential_requirements();
        assert_eq!(reqs.len(), 4);
        assert!(reqs
            .iter()
            .any(|r| r.name == "AWS_ACCESS_KEY_ID" && r.required));
        assert!(reqs
            .iter()
            .any(|r| r.name == "AWS_SECRET_ACCESS_KEY" && r.required));
        assert!(reqs
            .iter()
            .any(|r| r.name == "AWS_SESSION_TOKEN" && !r.required));
        assert!(reqs.iter().any(|r| r.name == "AWS_REGION" && !r.required));
    }

    #[test]
    fn iam_collector_missing_access_key_errors() {
        let err = IamCollector
            .collect(&HashMap::from([(
                "AWS_SECRET_ACCESS_KEY".to_string(),
                "secret".to_string(),
            )]))
            .unwrap_err();
        assert!(err.to_string().contains("AWS_ACCESS_KEY_ID"));
    }

    #[test]
    fn iam_collector_missing_secret_key_errors() {
        let err = IamCollector
            .collect(&HashMap::from([(
                "AWS_ACCESS_KEY_ID".to_string(),
                "key".to_string(),
            )]))
            .unwrap_err();
        assert!(err.to_string().contains("AWS_SECRET_ACCESS_KEY"));
    }

    // ── IamCollector HTTP integration (mock server) ──────────────────────────

    /// Starts a mock HTTP server that serves `responses` in order, one per connection.
    fn mock_server(responses: Vec<String>) -> String {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        thread::spawn(move || {
            for body in responses {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0u8; 8192];
                    let _ = stream.read(&mut buf);
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                }
            }
        });

        format!("http://127.0.0.1:{}/", addr.port())
    }

    fn base_config(base_url: &str) -> HashMap<String, String> {
        HashMap::from([
            ("AWS_ACCESS_KEY_ID".to_string(), "AKID".to_string()),
            ("AWS_SECRET_ACCESS_KEY".to_string(), "secret".to_string()),
            ("AWS_BASE_URL".to_string(), base_url.to_string()),
        ])
    }

    #[test]
    fn iam_collector_no_users_is_compliant() {
        let srv = mock_server(vec![EMPTY_USERS.to_string()]);
        let results = IamCollector.collect(&base_config(&srv)).unwrap();
        assert_eq!(results.len(), 1);
        let ev = &results[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.control_id, "iam.mfa_enforcement");
        assert_eq!(ev.findings[0].title, "IAM Users Compliant");
        assert!(ev.test_transcript.is_none());
    }

    #[test]
    fn iam_collector_user_with_mfa_fresh_key_compliant() {
        let srv = mock_server(vec![
            ONE_USER.to_string(),
            MFA_ONE.to_string(),
            KEYS_FRESH.to_string(),
        ]);
        let ev = &IamCollector.collect(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.class_uid, 1002);
        assert!(!ev.observables.is_empty());
    }

    #[test]
    fn iam_collector_user_no_mfa_is_ineffective() {
        let srv = mock_server(vec![
            ONE_USER.to_string(),
            MFA_NONE.to_string(),
            KEYS_EMPTY.to_string(),
        ]);
        let ev = &IamCollector.collect(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev.findings.iter().any(|f| f.title == "User Without MFA"));
    }

    #[test]
    fn iam_collector_stale_key_is_ineffective() {
        let srv = mock_server(vec![
            ONE_USER.to_string(),
            MFA_ONE.to_string(),
            KEYS_STALE.to_string(),
        ]);
        let ev = &IamCollector.collect(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev.findings.iter().any(|f| f.title == "Stale Access Key"));
    }

    #[test]
    fn iam_collector_inactive_stale_key_is_compliant() {
        // Inactive keys don't count as stale.
        let srv = mock_server(vec![
            ONE_USER.to_string(),
            MFA_ONE.to_string(),
            KEYS_INACTIVE_STALE.to_string(),
        ]);
        let ev = &IamCollector.collect(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
    }

    #[test]
    fn iam_collector_two_users_one_bad() {
        // alice: MFA + fresh key → ok; bob: no MFA + stale key → bad
        let srv = mock_server(vec![
            TWO_USERS.to_string(),
            MFA_ONE.to_string(),    // alice mfa
            KEYS_FRESH.to_string(), // alice keys
            MFA_NONE.to_string(),   // bob mfa (none)
            KEYS_STALE.to_string(), // bob keys (stale)
        ]);
        let ev = &IamCollector.collect(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev.findings.iter().any(|f| f.title == "User Without MFA"));
        assert!(ev.findings.iter().any(|f| f.title == "Stale Access Key"));
        // 4 observables: 2 users × (user + resource)
        assert_eq!(ev.observables.len(), 4);
    }

    #[test]
    fn iam_collector_raw_data_has_expected_keys() {
        let srv = mock_server(vec![EMPTY_USERS.to_string()]);
        let ev = &IamCollector.collect(&base_config(&srv)).unwrap()[0];
        assert!(ev.raw_data.get("total_users").is_some());
        assert!(ev.raw_data.get("users_without_mfa").is_some());
        assert!(ev.raw_data.get("stale_access_keys").is_some());
        assert!(ev.raw_data.get("max_key_age_days").is_some());
    }
}
