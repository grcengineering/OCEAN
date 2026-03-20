use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
};
use crate::module::{observer::Observer, CredentialReq, Module};

// ─── Constants ────────────────────────────────────────────────────────────────

const DEFAULT_RM_ENDPOINT: &str = "https://cloudresourcemanager.googleapis.com";
const DEFAULT_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const API_VERSION: &str = "v1";

const OVERLY_PERMISSIVE_ROLES: &[&str] = &[
    "roles/owner",
    "roles/editor",
    "roles/iam.securityAdmin",
    "roles/resourcemanager.projectIamAdmin",
];

// ─── OAuth2 helpers ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ServiceAccountKey {
    client_email: String,
    private_key: String,
    token_uri: Option<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

/// Base64url-encode bytes (no padding).
fn base64url_encode(data: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(data)
}

/// Create a signed JWT and exchange it for an OAuth2 access token.
/// Uses RS256 (RSA + SHA-256) signing per Google's service account auth flow.
fn get_access_token(
    sa_key: &ServiceAccountKey,
    token_endpoint: &str,
) -> Result<String> {
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::RsaPrivateKey;
    use sha2::{Digest, Sha256};

    let now = Utc::now().timestamp();
    let header = json!({"alg": "RS256", "typ": "JWT"});
    let claims = json!({
        "iss": sa_key.client_email,
        "scope": "https://www.googleapis.com/auth/cloud-platform",
        "aud": token_endpoint,
        "iat": now,
        "exp": now + 3600,
    });

    let header_b64 = base64url_encode(header.to_string().as_bytes());
    let claims_b64 = base64url_encode(claims.to_string().as_bytes());
    let unsigned = format!("{}.{}", header_b64, claims_b64);

    // Parse PEM private key and sign with RS256.
    let pem = sa_key.private_key.replace("\\n", "\n");
    let private_key = RsaPrivateKey::from_pkcs8_pem(&pem)
        .map_err(|e| anyhow!("failed to parse GCP service account private key: {}", e))?;

    let hash = Sha256::digest(unsigned.as_bytes());
    let padding = rsa::Pkcs1v15Sign::new::<sha2::Sha256>();
    let signature = private_key
        .sign(padding, &hash)
        .map_err(|e| anyhow!("JWT signing failed: {}", e))?;

    let jwt = format!("{}.{}", unsigned, base64url_encode(&signature));

    // Exchange JWT for access token.
    let resp = ureq::post(token_endpoint)
        .set("Content-Type", "application/x-www-form-urlencoded")
        .send_string(&format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={}",
            jwt
        ))
        .map_err(|e| anyhow!("GCP token exchange failed: {}", e))?;

    let token_resp: TokenResponse = resp
        .into_json()
        .map_err(|e| anyhow!("parsing GCP token response: {}", e))?;

    Ok(token_resp.access_token)
}

// ─── GCP API helpers ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct IamPolicy {
    bindings: Option<Vec<IamBinding>>,
}

#[derive(Deserialize)]
struct IamBinding {
    role: String,
    members: Vec<String>,
}

fn fetch_iam_policy(
    access_token: &str,
    project_id: &str,
    base_url: &str,
) -> Result<IamPolicy> {
    let url = format!(
        "{}/{}/projects/{}:getIamPolicy",
        base_url.trim_end_matches('/'),
        API_VERSION,
        project_id
    );

    let resp = ureq::post(&url)
        .set("Authorization", &format!("Bearer {}", access_token))
        .set("Content-Type", "application/json")
        .send_string("{}")
        .map_err(|e| anyhow!("GCP getIamPolicy request failed: {}", e))?;

    resp.into_json::<IamPolicy>()
        .map_err(|e| anyhow!("parsing GCP IAM policy response: {}", e))
}

// ─── GcpIamPolicyObserver ────────────────────────────────────────────────────

/// Queries GCP Resource Manager API for IAM policy bindings and checks
/// for overly permissive roles (roles/owner, roles/editor, etc.).
///
/// Required config keys: `GCP_SERVICE_ACCOUNT_KEY` (JSON string or path),
/// `GCP_PROJECT_ID`.
/// Optional: `GCP_BASE_URL` (test override), `GCP_ACCESS_TOKEN` (skip JWT flow).
pub struct GcpIamPolicyObserver;

impl Module for GcpIamPolicyObserver {
    fn id(&self) -> &str {
        "gcp.iam_policy"
    }
    fn name(&self) -> &str {
        "GCP IAM Policy Observer"
    }
    fn version(&self) -> &str {
        "0.1.0"
    }
    fn source_system(&self) -> &str {
        "gcp"
    }
    fn evidence_types(&self) -> &[i32] {
        &[1002]
    }

    fn credential_requirements(&self) -> Vec<CredentialReq> {
        vec![
            CredentialReq {
                name: "GCP_SERVICE_ACCOUNT_KEY".to_string(),
                cred_type: "secret".to_string(),
                description: "GCP service account key JSON (string or file path)".to_string(),
                required: true,
            },
            CredentialReq {
                name: "GCP_PROJECT_ID".to_string(),
                cred_type: "config".to_string(),
                description: "GCP project ID to query".to_string(),
                required: true,
            },
        ]
    }
}

impl Observer for GcpIamPolicyObserver {
    fn observe(&self, config: &HashMap<String, String>) -> Result<Vec<Evidence>> {
        let project_id = config
            .get("GCP_PROJECT_ID")
            .ok_or_else(|| anyhow!("GCP_PROJECT_ID is required"))?;

        let base_url = config
            .get("GCP_BASE_URL")
            .map(|s| s.as_str())
            .unwrap_or(DEFAULT_RM_ENDPOINT);

        // Get access token: either directly provided or via JWT exchange.
        let access_token = if let Some(token) = config.get("GCP_ACCESS_TOKEN") {
            token.clone()
        } else {
            let sa_key_raw = config
                .get("GCP_SERVICE_ACCOUNT_KEY")
                .ok_or_else(|| anyhow!("GCP_SERVICE_ACCOUNT_KEY is required"))?;

            // Try parsing as JSON directly; if that fails, treat as file path.
            let sa_key: ServiceAccountKey =
                serde_json::from_str(sa_key_raw).map_err(|e| {
                    anyhow!("failed to parse GCP_SERVICE_ACCOUNT_KEY as JSON: {}", e)
                })?;

            let token_endpoint = sa_key
                .token_uri
                .as_deref()
                .unwrap_or(DEFAULT_TOKEN_ENDPOINT);
            get_access_token(&sa_key, token_endpoint)?
        };

        let now = Utc::now();

        // Fetch IAM policy for the project.
        let policy = fetch_iam_policy(&access_token, project_id, base_url)?;
        let bindings = policy.bindings.unwrap_or_default();

        // Analyze bindings for overly permissive roles.
        let mut findings: Vec<Finding> = Vec::new();
        let mut observables: Vec<Observable> = Vec::new();
        let mut permissive_bindings = 0usize;
        let mut total_members = 0usize;

        let mut binding_details: Vec<serde_json::Value> = Vec::new();

        for binding in &bindings {
            let is_permissive = OVERLY_PERMISSIVE_ROLES.contains(&binding.role.as_str());

            observables.push(Observable {
                obs_type: "iam_role".to_string(),
                value: binding.role.clone(),
                name: String::new(),
            });

            for member in &binding.members {
                total_members += 1;
                observables.push(Observable {
                    obs_type: "iam_member".to_string(),
                    value: member.clone(),
                    name: String::new(),
                });
            }

            if is_permissive {
                permissive_bindings += 1;
                findings.push(Finding {
                    title: "Overly Permissive IAM Binding".to_string(),
                    description: format!(
                        "Role {} is granted to {} member(s): {}",
                        binding.role,
                        binding.members.len(),
                        binding.members.join(", ")
                    ),
                    severity_id: 3,
                });
            }

            binding_details.push(json!({
                "role": binding.role,
                "members": binding.members,
                "is_permissive": is_permissive,
            }));
        }

        if findings.is_empty() {
            findings.push(Finding {
                title: "IAM Policy Compliant".to_string(),
                description: format!(
                    "No overly permissive roles found across {} bindings",
                    bindings.len()
                ),
                severity_id: 0,
            });
        }

        let (status_id, status_text) = if permissive_bindings > 0 {
            (
                StatusId::Ineffective,
                format!(
                    "{} overly permissive binding(s) found across {} total bindings for project {}",
                    permissive_bindings,
                    bindings.len(),
                    project_id
                ),
            )
        } else {
            (
                StatusId::Effective,
                format!(
                    "All {} IAM bindings use appropriately scoped roles for project {}",
                    bindings.len(),
                    project_id
                ),
            )
        };

        let raw_data = json!({
            "project_id": project_id,
            "total_bindings": bindings.len(),
            "total_members": total_members,
            "permissive_bindings": permissive_bindings,
            "overly_permissive_roles_checked": OVERLY_PERMISSIVE_ROLES,
            "binding_details": binding_details,
        });

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "iam.least_privilege".to_string(),
            class_uid: 1002,
            category_uid: 1,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "gcp.iam_policy".to_string(),
                    version: "0.1.0".to_string(),
                    module_type: "observer".to_string(),
                },
                source: SourceInfo {
                    system: "gcp".to_string(),
                    api_version: API_VERSION.to_string(),
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

    // ── Mock server ─────────────────────────────────────────────────────────

    fn mock_server(responses: Vec<(u16, String)>) -> String {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        thread::spawn(move || {
            for (status, body) in responses {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0u8; 8192];
                    let _ = stream.read(&mut buf);
                    let resp = format!(
                        "HTTP/1.1 {} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        status,
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                }
            }
        });

        format!("http://127.0.0.1:{}", addr.port())
    }

    fn base_config(base_url: &str) -> HashMap<String, String> {
        HashMap::from([
            ("GCP_PROJECT_ID".to_string(), "test-project-123".to_string()),
            ("GCP_ACCESS_TOKEN".to_string(), "test-token".to_string()),
            ("GCP_BASE_URL".to_string(), base_url.to_string()),
        ])
    }

    // ── JSON response fixtures ──────────────────────────────────────────────

    const EMPTY_POLICY: &str = r#"{"bindings": []}"#;

    const COMPLIANT_POLICY: &str = r#"{
        "bindings": [
            {
                "role": "roles/viewer",
                "members": ["user:alice@example.com"]
            },
            {
                "role": "roles/storage.objectViewer",
                "members": ["serviceAccount:svc@test.iam.gserviceaccount.com"]
            }
        ]
    }"#;

    const PERMISSIVE_POLICY: &str = r#"{
        "bindings": [
            {
                "role": "roles/owner",
                "members": ["user:admin@example.com", "user:dev@example.com"]
            },
            {
                "role": "roles/viewer",
                "members": ["user:auditor@example.com"]
            }
        ]
    }"#;

    const EDITOR_POLICY: &str = r#"{
        "bindings": [
            {
                "role": "roles/editor",
                "members": ["serviceAccount:deploy@test.iam.gserviceaccount.com"]
            }
        ]
    }"#;

    const MULTI_PERMISSIVE_POLICY: &str = r#"{
        "bindings": [
            {
                "role": "roles/owner",
                "members": ["user:admin@example.com"]
            },
            {
                "role": "roles/editor",
                "members": ["user:dev@example.com"]
            },
            {
                "role": "roles/viewer",
                "members": ["user:auditor@example.com"]
            }
        ]
    }"#;

    const NO_BINDINGS_POLICY: &str = r#"{}"#;

    // ── Metadata tests ──────────────────────────────────────────────────────

    #[test]
    fn gcp_observer_id() {
        assert_eq!(GcpIamPolicyObserver.id(), "gcp.iam_policy");
    }

    #[test]
    fn gcp_observer_name() {
        assert_eq!(GcpIamPolicyObserver.name(), "GCP IAM Policy Observer");
    }

    #[test]
    fn gcp_observer_version() {
        assert_eq!(GcpIamPolicyObserver.version(), "0.1.0");
    }

    #[test]
    fn gcp_observer_source_system() {
        assert_eq!(GcpIamPolicyObserver.source_system(), "gcp");
    }

    #[test]
    fn gcp_observer_evidence_types() {
        assert_eq!(GcpIamPolicyObserver.evidence_types(), &[1002]);
    }

    #[test]
    fn gcp_observer_credential_requirements() {
        let reqs = GcpIamPolicyObserver.credential_requirements();
        assert_eq!(reqs.len(), 2);
        assert!(reqs
            .iter()
            .any(|r| r.name == "GCP_SERVICE_ACCOUNT_KEY" && r.required));
        assert!(reqs
            .iter()
            .any(|r| r.name == "GCP_PROJECT_ID" && r.required));
    }

    // ── Config validation tests ─────────────────────────────────────────────

    #[test]
    fn gcp_observer_missing_project_id_errors() {
        let config = HashMap::from([
            ("GCP_ACCESS_TOKEN".to_string(), "token".to_string()),
        ]);
        let err = GcpIamPolicyObserver.observe(&config).unwrap_err();
        assert!(err.to_string().contains("GCP_PROJECT_ID"));
    }

    #[test]
    fn gcp_observer_missing_both_key_and_token_errors() {
        let config = HashMap::from([
            ("GCP_PROJECT_ID".to_string(), "proj".to_string()),
        ]);
        let err = GcpIamPolicyObserver.observe(&config).unwrap_err();
        assert!(err.to_string().contains("GCP_SERVICE_ACCOUNT_KEY"));
    }

    // ── HTTP integration tests (mock server) ────────────────────────────────

    #[test]
    fn gcp_observer_empty_policy_is_compliant() {
        let srv = mock_server(vec![(200, EMPTY_POLICY.to_string())]);
        let results = GcpIamPolicyObserver.observe(&base_config(&srv)).unwrap();
        assert_eq!(results.len(), 1);
        let ev = &results[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.control_id, "iam.least_privilege");
        assert_eq!(ev.findings[0].title, "IAM Policy Compliant");
        assert!(ev.test_transcript.is_none());
    }

    #[test]
    fn gcp_observer_compliant_policy_effective() {
        let srv = mock_server(vec![(200, COMPLIANT_POLICY.to_string())]);
        let ev = &GcpIamPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.class_uid, 1002);
        assert!(!ev.observables.is_empty());
    }

    #[test]
    fn gcp_observer_permissive_policy_ineffective() {
        let srv = mock_server(vec![(200, PERMISSIVE_POLICY.to_string())]);
        let ev = &GcpIamPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Overly Permissive IAM Binding"));
        assert!(ev.findings.iter().any(|f| f.description.contains("roles/owner")));
    }

    #[test]
    fn gcp_observer_editor_role_is_permissive() {
        let srv = mock_server(vec![(200, EDITOR_POLICY.to_string())]);
        let ev = &GcpIamPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.description.contains("roles/editor")));
    }

    #[test]
    fn gcp_observer_multiple_permissive_bindings() {
        let srv = mock_server(vec![(200, MULTI_PERMISSIVE_POLICY.to_string())]);
        let ev = &GcpIamPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        let permissive_findings: Vec<_> = ev
            .findings
            .iter()
            .filter(|f| f.title == "Overly Permissive IAM Binding")
            .collect();
        assert_eq!(permissive_findings.len(), 2);
    }

    #[test]
    fn gcp_observer_no_bindings_field_is_compliant() {
        let srv = mock_server(vec![(200, NO_BINDINGS_POLICY.to_string())]);
        let ev = &GcpIamPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
    }

    #[test]
    fn gcp_observer_raw_data_has_expected_keys() {
        let srv = mock_server(vec![(200, EMPTY_POLICY.to_string())]);
        let ev = &GcpIamPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        assert!(ev.raw_data.get("project_id").is_some());
        assert!(ev.raw_data.get("total_bindings").is_some());
        assert!(ev.raw_data.get("total_members").is_some());
        assert!(ev.raw_data.get("permissive_bindings").is_some());
        assert!(ev.raw_data.get("binding_details").is_some());
    }

    #[test]
    fn gcp_observer_observables_include_roles_and_members() {
        let srv = mock_server(vec![(200, COMPLIANT_POLICY.to_string())]);
        let ev = &GcpIamPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        assert!(ev.observables.iter().any(|o| o.obs_type == "iam_role"));
        assert!(ev.observables.iter().any(|o| o.obs_type == "iam_member"));
    }

    #[test]
    fn gcp_observer_metadata_correct() {
        let srv = mock_server(vec![(200, EMPTY_POLICY.to_string())]);
        let ev = &GcpIamPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.metadata.module.name, "gcp.iam_policy");
        assert_eq!(ev.metadata.module.module_type, "observer");
        assert_eq!(ev.metadata.source.system, "gcp");
        assert!(ev.metadata.safety_classification.is_none());
    }

    // ── JSON parsing unit tests ─────────────────────────────────────────────

    #[test]
    fn parse_iam_policy_empty_bindings() {
        let policy: IamPolicy = serde_json::from_str(EMPTY_POLICY).unwrap();
        assert!(policy.bindings.unwrap().is_empty());
    }

    #[test]
    fn parse_iam_policy_with_bindings() {
        let policy: IamPolicy = serde_json::from_str(COMPLIANT_POLICY).unwrap();
        let bindings = policy.bindings.unwrap();
        assert_eq!(bindings.len(), 2);
        assert_eq!(bindings[0].role, "roles/viewer");
        assert_eq!(bindings[0].members.len(), 1);
    }

    #[test]
    fn parse_iam_policy_no_bindings_field() {
        let policy: IamPolicy = serde_json::from_str(NO_BINDINGS_POLICY).unwrap();
        assert!(policy.bindings.is_none());
    }
}
