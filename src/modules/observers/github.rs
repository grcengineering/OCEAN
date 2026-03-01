use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
};
use crate::module::{observer::Observer, CredentialReq, Module};

// ─── Constants ────────────────────────────────────────────────────────────────

const DEFAULT_GITHUB_API: &str = "https://api.github.com";
const GITHUB_API_VERSION: &str = "2022-11-28";

// ─── GitHub HTTP client ───────────────────────────────────────────────────────

/// Performs an authenticated GET to the GitHub REST API v3.
/// `base_url` is `https://api.github.com` by default; tests override it.
fn github_get(token: &str, base_url: &str, path: &str) -> Result<(Value, u16)> {
    let url = format!("{}{}", base_url.trim_end_matches('/'), path);
    let resp = ureq::get(&url)
        .set("Accept", "application/vnd.github+json")
        .set("Authorization", &format!("Bearer {}", token))
        .set("X-GitHub-Api-Version", GITHUB_API_VERSION)
        .call();

    match resp {
        Ok(r) => {
            let status = r.status();
            let body: Value = r
                .into_json()
                .map_err(|e| anyhow!("parsing GitHub JSON: {}", e))?;
            Ok((body, status))
        }
        Err(ureq::Error::Status(code, r)) => {
            let body: Value = r
                .into_json()
                .unwrap_or_else(|_| json!({"message": "unknown error"}));
            Ok((body, code))
        }
        Err(e) => Err(anyhow!("GitHub API request failed: {}", e)),
    }
}

// ─── BranchProtectionObserver ────────────────────────────────────────────────

/// Queries the GitHub branch protection API to gather evidence about
/// repository branch protection rules. Checks PR reviews, status checks,
/// force-push restrictions, admin enforcement, and branch deletion settings.
///
/// Required config: `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO`.
/// Optional: `GITHUB_BRANCH` (defaults to "main"), `GITHUB_API_URL` (test override).
pub struct BranchProtectionObserver;

impl Module for BranchProtectionObserver {
    fn id(&self) -> &str {
        "github.branch_protection"
    }
    fn name(&self) -> &str {
        "GitHub Branch Protection Observer"
    }
    fn version(&self) -> &str {
        "0.1.0"
    }
    fn source_system(&self) -> &str {
        "github"
    }
    fn evidence_types(&self) -> &[i32] {
        &[1003]
    }

    fn credential_requirements(&self) -> Vec<CredentialReq> {
        vec![
            CredentialReq {
                name: "GITHUB_TOKEN".to_string(),
                cred_type: "api_token".to_string(),
                description: "GitHub PAT with repo scope for reading branch protection".to_string(),
                required: true,
            },
            CredentialReq {
                name: "GITHUB_OWNER".to_string(),
                cred_type: "config".to_string(),
                description: "GitHub repository owner (user or organization)".to_string(),
                required: true,
            },
            CredentialReq {
                name: "GITHUB_REPO".to_string(),
                cred_type: "config".to_string(),
                description: "GitHub repository name".to_string(),
                required: true,
            },
            CredentialReq {
                name: "GITHUB_BRANCH".to_string(),
                cred_type: "config".to_string(),
                description: "Branch to check (default: main)".to_string(),
                required: false,
            },
        ]
    }
}

impl Observer for BranchProtectionObserver {
    fn observe(&self, config: &HashMap<String, String>) -> Result<Vec<Evidence>> {
        let token = config
            .get("GITHUB_TOKEN")
            .ok_or_else(|| anyhow!("GITHUB_TOKEN is required"))?;
        let owner = config
            .get("GITHUB_OWNER")
            .ok_or_else(|| anyhow!("GITHUB_OWNER is required"))?;
        let repo = config
            .get("GITHUB_REPO")
            .ok_or_else(|| anyhow!("GITHUB_REPO is required"))?;
        let branch = config
            .get("GITHUB_BRANCH")
            .map(|s| s.as_str())
            .unwrap_or("main");
        let base_url = config
            .get("GITHUB_API_URL")
            .map(|s| s.as_str())
            .unwrap_or(DEFAULT_GITHUB_API);

        let now = Utc::now();
        let path = format!("/repos/{}/{}/branches/{}/protection", owner, repo, branch);
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), path);

        let (body, status) = github_get(token, base_url, &path)?;

        // 404 means branch protection is completely disabled.
        if status == 404 {
            return Ok(vec![Evidence {
                id: Uuid::new_v4(),
                control_id: "scm.branch_protection".to_string(),
                class_uid: 1003,
                category_uid: 2,
                activity_id: 1,
                time: now,
                confidence_level: ConfidenceLevel::PassiveObservation,
                metadata: Metadata {
                    module: ModuleInfo {
                        name: "github.branch_protection".to_string(),
                        version: "0.1.0".to_string(),
                        module_type: "observer".to_string(),
                    },
                    source: SourceInfo {
                        system: "github".to_string(),
                        api_version: "v3".to_string(),
                        endpoint: endpoint.clone(),
                    },
                    original_time: None,
                    processed_time: now,
                    safety_classification: None,
                },
                observables: vec![
                    Observable {
                        obs_type: "resource".to_string(),
                        value: format!("{}/{}:{}:branch_protection", owner, repo, branch),
                        name: String::new(),
                    },
                    Observable {
                        obs_type: "domain".to_string(),
                        value: "github.com".to_string(),
                        name: String::new(),
                    },
                ],
                status_id: StatusId::Ineffective,
                status: format!(
                    "Branch protection is not enabled on {}/{} branch {}",
                    owner, repo, branch
                ),
                raw_data: body,
                findings: vec![Finding {
                    title: "Branch Protection Disabled".to_string(),
                    description: format!(
                        "No branch protection rules are configured for {}/{} branch {}. \
                         This allows unrestricted pushes, force pushes, and deletions.",
                        owner, repo, branch
                    ),
                    severity_id: 4,
                }],
                test_transcript: None,
                enrichments: vec![],
            }]);
        }

        if status != 200 {
            return Err(anyhow!(
                "GitHub API returned status {} for {}",
                status,
                path
            ));
        }

        // Parse protection fields and build findings.
        let mut findings: Vec<Finding> = Vec::new();
        let mut status_id = StatusId::Effective;

        // Required pull request reviews.
        if body.get("required_pull_request_reviews").is_none() {
            findings.push(Finding {
                title: "Pull Request Reviews Not Required".to_string(),
                description: "Branch protection does not require pull request reviews. Code can be merged without peer review.".to_string(),
                severity_id: 3,
            });
            status_id = StatusId::Ineffective;
        } else {
            let reviews = &body["required_pull_request_reviews"];
            if reviews
                .get("required_approving_review_count")
                .and_then(|v| v.as_i64())
                .unwrap_or(0)
                < 1
            {
                findings.push(Finding {
                    title: "No Minimum Review Count".to_string(),
                    description:
                        "Pull request reviews configured but no minimum approving review count set."
                            .to_string(),
                    severity_id: 2,
                });
            }
            if !reviews
                .get("dismiss_stale_reviews")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                findings.push(Finding {
                    title: "Stale Reviews Not Dismissed".to_string(),
                    description:
                        "Stale pull request reviews are not dismissed when new commits are pushed."
                            .to_string(),
                    severity_id: 2,
                });
            }
        }

        // Required status checks.
        if body.get("required_status_checks").is_none() {
            findings.push(Finding {
                title: "Status Checks Not Required".to_string(),
                description: "Branch protection does not require status checks. Code can merge without passing CI.".to_string(),
                severity_id: 3,
            });
            status_id = StatusId::Ineffective;
        } else {
            let checks = &body["required_status_checks"];
            if checks
                .get("contexts")
                .and_then(|v| v.as_array())
                .map(|a| a.is_empty())
                .unwrap_or(true)
            {
                findings.push(Finding {
                    title: "No Status Check Contexts Defined".to_string(),
                    description: "Status checks required but no specific contexts configured."
                        .to_string(),
                    severity_id: 2,
                });
            }
        }

        // Admin enforcement.
        if !body
            .get("enforce_admins")
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            findings.push(Finding {
                title: "Admin Enforcement Disabled".to_string(),
                description:
                    "Branch protection rules are not enforced for repository administrators."
                        .to_string(),
                severity_id: 2,
            });
        }

        // Force pushes.
        if body
            .get("allow_force_pushes")
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            findings.push(Finding {
                title: "Force Pushes Allowed".to_string(),
                description: "Force pushes are allowed, enabling rewrite of commit history."
                    .to_string(),
                severity_id: 3,
            });
            status_id = StatusId::Ineffective;
        }

        // Branch deletion.
        if body
            .get("allow_deletions")
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            findings.push(Finding {
                title: "Branch Deletion Allowed".to_string(),
                description: "The protected branch can be deleted.".to_string(),
                severity_id: 3,
            });
            status_id = StatusId::Ineffective;
        }

        if findings.is_empty() {
            findings.push(Finding {
                title: "Branch Protection Properly Configured".to_string(),
                description: format!(
                    "Branch protection on {}/{} branch {} includes required reviews, status checks, and force-push restrictions.",
                    owner, repo, branch
                ),
                severity_id: 0,
            });
        }

        let status_msg = if status_id == StatusId::Effective {
            format!(
                "Branch protection is properly configured on {}/{} branch {}",
                owner, repo, branch
            )
        } else {
            format!(
                "Branch protection on {}/{} branch {} has gaps",
                owner, repo, branch
            )
        };

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "scm.branch_protection".to_string(),
            class_uid: 1003,
            category_uid: 2,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "github.branch_protection".to_string(),
                    version: "0.1.0".to_string(),
                    module_type: "observer".to_string(),
                },
                source: SourceInfo {
                    system: "github".to_string(),
                    api_version: "v3".to_string(),
                    endpoint,
                },
                original_time: None,
                processed_time: now,
                safety_classification: None,
            },
            observables: vec![
                Observable {
                    obs_type: "resource".to_string(),
                    value: format!("{}/{}:{}:branch_protection", owner, repo, branch),
                    name: String::new(),
                },
                Observable {
                    obs_type: "domain".to_string(),
                    value: "github.com".to_string(),
                    name: String::new(),
                },
            ],
            status_id,
            status: status_msg,
            raw_data: body,
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

    // Minimal mock server that serves one response.
    fn mock_server(status: u16, body: &str) -> String {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = body.to_string();

        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
                    len = body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });

        format!("http://127.0.0.1:{}", addr.port())
    }

    fn base_config(base_url: &str) -> HashMap<String, String> {
        HashMap::from([
            ("GITHUB_TOKEN".to_string(), "ghp_test".to_string()),
            ("GITHUB_OWNER".to_string(), "acme".to_string()),
            ("GITHUB_REPO".to_string(), "app".to_string()),
            ("GITHUB_API_URL".to_string(), base_url.to_string()),
        ])
    }

    // ── Module metadata ──────────────────────────────────────────────────────

    #[test]
    fn bp_observer_id() {
        assert_eq!(BranchProtectionObserver.id(), "github.branch_protection");
    }

    #[test]
    fn bp_observer_name() {
        assert_eq!(
            BranchProtectionObserver.name(),
            "GitHub Branch Protection Observer"
        );
    }

    #[test]
    fn bp_observer_version() {
        assert_eq!(BranchProtectionObserver.version(), "0.1.0");
    }

    #[test]
    fn bp_observer_source_system() {
        assert_eq!(BranchProtectionObserver.source_system(), "github");
    }

    #[test]
    fn bp_observer_evidence_types() {
        assert_eq!(BranchProtectionObserver.evidence_types(), &[1003]);
    }

    #[test]
    fn bp_observer_credential_requirements() {
        let reqs = BranchProtectionObserver.credential_requirements();
        assert_eq!(reqs.len(), 4);
        assert!(reqs.iter().any(|r| r.name == "GITHUB_TOKEN" && r.required));
        assert!(reqs.iter().any(|r| r.name == "GITHUB_OWNER" && r.required));
        assert!(reqs.iter().any(|r| r.name == "GITHUB_REPO" && r.required));
        assert!(reqs
            .iter()
            .any(|r| r.name == "GITHUB_BRANCH" && !r.required));
    }

    // ── Config validation ────────────────────────────────────────────────────

    #[test]
    fn bp_observer_missing_token_errors() {
        let err = BranchProtectionObserver
            .observe(&HashMap::from([
                ("GITHUB_OWNER".to_string(), "o".to_string()),
                ("GITHUB_REPO".to_string(), "r".to_string()),
            ]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_TOKEN"));
    }

    #[test]
    fn bp_observer_missing_owner_errors() {
        let err = BranchProtectionObserver
            .observe(&HashMap::from([
                ("GITHUB_TOKEN".to_string(), "tok".to_string()),
                ("GITHUB_REPO".to_string(), "r".to_string()),
            ]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_OWNER"));
    }

    #[test]
    fn bp_observer_missing_repo_errors() {
        let err = BranchProtectionObserver
            .observe(&HashMap::from([
                ("GITHUB_TOKEN".to_string(), "tok".to_string()),
                ("GITHUB_OWNER".to_string(), "o".to_string()),
            ]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_REPO"));
    }

    // ── HTTP integration ─────────────────────────────────────────────────────

    const FULL_PROTECTION: &str = r#"{
        "required_pull_request_reviews": {
            "dismiss_stale_reviews": true,
            "require_code_owner_reviews": true,
            "required_approving_review_count": 2
        },
        "required_status_checks": {
            "strict": true,
            "contexts": ["ci/build", "ci/test"]
        },
        "enforce_admins": { "enabled": true },
        "allow_force_pushes": { "enabled": false },
        "allow_deletions": { "enabled": false }
    }"#;

    const NO_PR_REVIEWS: &str = r#"{
        "required_status_checks": { "strict": true, "contexts": ["ci"] },
        "enforce_admins": { "enabled": true },
        "allow_force_pushes": { "enabled": false }
    }"#;

    const FORCE_PUSHES_ON: &str = r#"{
        "required_pull_request_reviews": {
            "dismiss_stale_reviews": true,
            "required_approving_review_count": 1
        },
        "required_status_checks": { "strict": true, "contexts": ["ci"] },
        "enforce_admins": { "enabled": true },
        "allow_force_pushes": { "enabled": true }
    }"#;

    #[test]
    fn bp_observer_404_means_protection_disabled() {
        let srv = mock_server(404, r#"{"message":"Branch not protected"}"#);
        let ev = &BranchProtectionObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert_eq!(ev.findings[0].title, "Branch Protection Disabled");
        assert_eq!(ev.control_id, "scm.branch_protection");
    }

    #[test]
    fn bp_observer_full_protection_is_effective() {
        let srv = mock_server(200, FULL_PROTECTION);
        let ev = &BranchProtectionObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(
            ev.findings[0].title,
            "Branch Protection Properly Configured"
        );
        assert_eq!(ev.class_uid, 1003);
        assert_eq!(ev.observables.len(), 2);
    }

    #[test]
    fn bp_observer_no_pr_reviews_is_ineffective() {
        let srv = mock_server(200, NO_PR_REVIEWS);
        let ev = &BranchProtectionObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Pull Request Reviews Not Required"));
    }

    #[test]
    fn bp_observer_force_pushes_enabled_is_ineffective() {
        let srv = mock_server(200, FORCE_PUSHES_ON);
        let ev = &BranchProtectionObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Force Pushes Allowed"));
    }

    #[test]
    fn bp_observer_500_returns_error() {
        let srv = mock_server(500, r#"{"message":"Internal Server Error"}"#);
        // 500 is not 200 or 404 → should return Err
        let result = BranchProtectionObserver.observe(&base_config(&srv));
        assert!(result.is_err());
    }

    #[test]
    fn bp_observer_uses_default_main_branch() {
        // No GITHUB_BRANCH key → should still make a request (uses "main")
        let srv = mock_server(200, FULL_PROTECTION);
        let mut cfg = base_config(&srv);
        cfg.remove("GITHUB_BRANCH");
        let ev = &BranchProtectionObserver.observe(&cfg).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
    }

    #[test]
    fn bp_observer_custom_branch_in_metadata() {
        let srv = mock_server(200, FULL_PROTECTION);
        let mut cfg = base_config(&srv);
        cfg.insert("GITHUB_BRANCH".to_string(), "develop".to_string());
        let ev = &BranchProtectionObserver.observe(&cfg).unwrap()[0];
        // observables should reference the branch
        assert!(ev.observables[0].value.contains("develop"));
    }

    #[test]
    fn bp_observer_stale_reviews_not_dismissed_finding() {
        let body = r#"{
            "required_pull_request_reviews": {
                "dismiss_stale_reviews": false,
                "required_approving_review_count": 2
            },
            "required_status_checks": { "strict": true, "contexts": ["ci"] },
            "enforce_admins": { "enabled": true }
        }"#;
        let srv = mock_server(200, body);
        let ev = &BranchProtectionObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Stale Reviews Not Dismissed"));
    }

    #[test]
    fn bp_observer_no_status_check_contexts_finding() {
        let body = r#"{
            "required_pull_request_reviews": {
                "dismiss_stale_reviews": true,
                "required_approving_review_count": 1
            },
            "required_status_checks": { "strict": false, "contexts": [] },
            "enforce_admins": { "enabled": true }
        }"#;
        let srv = mock_server(200, body);
        let ev = &BranchProtectionObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "No Status Check Contexts Defined"));
    }
}
