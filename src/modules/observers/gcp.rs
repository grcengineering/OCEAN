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

/// Sign `message` with RS256 (RSA PKCS#1 v1.5 padding + SHA-256) using a
/// PEM-encoded PKCS#8 RSA private key, as shipped in GCP service account
/// key files.
///
/// Uses `ring`'s RSA implementation rather than the pure-Rust `rsa` crate:
/// the `rsa` crate's PKCS#1v1.5 signing has no constant-time guarantee
/// (RUSTSEC-2023-0071, the "Marvin Attack" — the advisory's `patched`
/// list is empty, i.e. no fixed version exists). `ring` wraps audited,
/// side-channel-hardened primitives and is already part of this crate's
/// dependency tree via `rustls`.
fn sign_rs256(pem_private_key: &str, message: &[u8]) -> Result<Vec<u8>> {
    use ring::rand::SystemRandom;
    use ring::rsa::KeyPair;
    use ring::signature::RSA_PKCS1_SHA256;

    let pem = pem_private_key.replace("\\n", "\n");
    let pkcs8_der = pem_to_der(&pem)?;

    let key_pair = KeyPair::from_pkcs8(&pkcs8_der)
        .map_err(|e| anyhow!("failed to parse GCP service account private key: {}", e))?;

    let rng = SystemRandom::new();
    let mut signature = vec![0u8; key_pair.public().modulus_len()];
    key_pair
        .sign(&RSA_PKCS1_SHA256, &rng, message, &mut signature)
        .map_err(|e| anyhow!("RS256 signing failed: {}", e))?;

    Ok(signature)
}

/// Strip PEM armor (`-----BEGIN ...-----` / `-----END ...-----`) and decode
/// the base64 body to raw DER bytes.
fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();

    STANDARD
        .decode(body)
        .map_err(|e| anyhow!("failed to base64-decode PEM body: {}", e))
}

/// Create a signed JWT and exchange it for an OAuth2 access token.
/// Uses RS256 (RSA + SHA-256) signing per Google's service account auth flow.
fn get_access_token(sa_key: &ServiceAccountKey, token_endpoint: &str) -> Result<String> {
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

    let signature = sign_rs256(&sa_key.private_key, unsigned.as_bytes())?;

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

fn fetch_iam_policy(access_token: &str, project_id: &str, base_url: &str) -> Result<IamPolicy> {
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
            let sa_key: ServiceAccountKey = serde_json::from_str(sa_key_raw)
                .map_err(|e| anyhow!("failed to parse GCP_SERVICE_ACCOUNT_KEY as JSON: {}", e))?;

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
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        thread::spawn(move || {
            for (status, body) in responses {
                if let Ok((mut stream, _)) = listener.accept() {
                    // Fully drain whatever the client sent before responding.
                    // A single `read()` can capture only part of the request
                    // when the client's write is split across TCP segments
                    // (this request carries Authorization + Content-Type
                    // headers and a JSON body, so it's more likely to span
                    // more than one segment than a bare GET). Closing the
                    // stream while bytes remain unread in the kernel's
                    // receive buffer makes some platforms answer with an RST
                    // instead of a graceful close, which corrupts the
                    // client's read of the response written below -- this
                    // was observed as an intermittent "Failed to read JSON"
                    // error on the client side. A short read timeout bounds
                    // the drain without needing to parse HTTP framing: keep
                    // reading until nothing more arrives within the window.
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
                    let mut buf = [0u8; 8192];
                    loop {
                        match stream.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(_) => continue,
                        }
                    }
                    let _ = stream.set_read_timeout(None);

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
        let config = HashMap::from([("GCP_ACCESS_TOKEN".to_string(), "token".to_string())]);
        let err = GcpIamPolicyObserver.observe(&config).unwrap_err();
        assert!(err.to_string().contains("GCP_PROJECT_ID"));
    }

    #[test]
    fn gcp_observer_missing_both_key_and_token_errors() {
        let config = HashMap::from([("GCP_PROJECT_ID".to_string(), "proj".to_string())]);
        let err = GcpIamPolicyObserver.observe(&config).unwrap_err();
        assert!(err.to_string().contains("GCP_SERVICE_ACCOUNT_KEY"));
    }

    // ── RS256 signing tests ──────────────────────────────────────────────────
    //
    // `sign_rs256` is the function that replaced the `rsa`-crate-based
    // signer (see its doc comment for why: RUSTSEC-2023-0071, unpatched).
    // These tests prove the `ring`-based replacement actually produces a
    // valid RS256 signature, not just that it compiles and runs.

    /// A throwaway 2048-bit RSA key pair, generated once per test run with the
    /// `openssl` CLI rather than checked in, so the repository stores no private
    /// key that secret scanners would have to be told to ignore. `ring` cannot
    /// generate RSA keys, and the `rsa` crate is what `sign_rs256` exists to
    /// avoid. Returns the PKCS#8 PEM private key and the matching public key as
    /// ASN.1 `RSAPublicKey` DER, the form `ring::signature::UnparsedPublicKey`
    /// expects for `RSA_PKCS1_*` verification. The public half is derived by
    /// `openssl`, independently of the code under test. Panics if `openssl` is
    /// missing, so these tests fail loudly instead of silently skipping.
    fn test_rsa_keypair() -> &'static (String, Vec<u8>) {
        use std::io::Write;
        use std::process::{Command, Stdio};
        use std::sync::OnceLock;

        static KEYPAIR: OnceLock<(String, Vec<u8>)> = OnceLock::new();
        KEYPAIR.get_or_init(|| {
            let generated = Command::new("openssl")
                .args([
                    "genpkey",
                    "-algorithm",
                    "RSA",
                    "-pkeyopt",
                    "rsa_keygen_bits:2048",
                    "-pkeyopt",
                    "rsa_keygen_pubexp:65537",
                ])
                .output()
                .expect("the RS256 tests need the `openssl` CLI to generate a throwaway key");
            assert!(
                generated.status.success(),
                "openssl genpkey failed: {}",
                String::from_utf8_lossy(&generated.stderr)
            );
            let private_pem =
                String::from_utf8(generated.stdout).expect("openssl genpkey emits ASCII PEM");

            let mut child = Command::new("openssl")
                .args(["rsa", "-RSAPublicKey_out", "-outform", "DER"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("the RS256 tests need the `openssl` CLI to derive the public key");
            child
                .stdin
                .take()
                .expect("stdin is piped")
                .write_all(private_pem.as_bytes())
                .expect("writing the key to openssl must succeed");
            let derived = child
                .wait_with_output()
                .expect("openssl rsa must run to completion");
            assert!(
                derived.status.success(),
                "openssl rsa failed: {}",
                String::from_utf8_lossy(&derived.stderr)
            );
            (private_pem, derived.stdout)
        })
    }

    #[test]
    fn sign_rs256_produces_a_signature_verifiable_against_the_matching_public_key() {
        use ring::signature::{UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256};

        let (private_pem, public_der) = test_rsa_keypair();
        let message = b"header.claims";
        let signature =
            sign_rs256(private_pem, message).expect("signing with a valid PKCS#8 key must succeed");

        // A 2048-bit RSA PKCS#1v1.5 signature is exactly 256 bytes.
        assert_eq!(signature.len(), 256);

        let public_key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public_der);

        public_key.verify(message, &signature).expect(
            "signature produced by sign_rs256 must cryptographically verify \
             against the matching public key",
        );
    }

    #[test]
    fn sign_rs256_signature_does_not_verify_against_a_tampered_message() {
        use ring::signature::{UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256};

        let (private_pem, public_der) = test_rsa_keypair();
        let signature = sign_rs256(private_pem, b"original message").unwrap();

        let public_key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public_der);

        assert!(public_key.verify(b"tampered message", &signature).is_err());
    }

    #[test]
    fn sign_rs256_rejects_non_base64_pem_body() {
        let err = sign_rs256("not a valid pem body", b"message").unwrap_err();
        assert!(err.to_string().contains("failed to base64-decode PEM body"));
    }

    #[test]
    fn sign_rs256_rejects_base64_that_is_not_a_pkcs8_key() {
        // Valid base64 ("ABCD"), but not a PKCS#8-encoded RSA private key.
        let bogus_pem = "-----BEGIN PRIVATE KEY-----\nQUJDRA==\n-----END PRIVATE KEY-----\n";
        let err = sign_rs256(bogus_pem, b"message").unwrap_err();
        assert!(err
            .to_string()
            .contains("failed to parse GCP service account private key"));
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
        assert!(ev
            .findings
            .iter()
            .any(|f| f.description.contains("roles/owner")));
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
