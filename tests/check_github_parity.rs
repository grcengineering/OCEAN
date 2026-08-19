// Integration test: load + execute GitHub HTH-parity checks end-to-end (mocked HTTP).
//
// Mirrors tests/check_slack_parity.rs's MockHTTPServer pattern. Covers pass and
// fail cases for the five newly authored checks that close HTH parity gaps
// (GH-5.06, GH-6.05, GH-7.02, GH-7.03, GH-8.02) plus three existing checks
// whose `references.hth` mapping was corrected to match the HTH guide's real
// section numbering (GH-2.01, GH-2.05, GH-3.05), and a load-all sanity test
// for checks/github/.
//
// Fixtures reflect the field shapes the HTH how-to-harden GitHub pack code
// parses, cross-checked against docs.github.com/en/rest:
//   - GET /orgs/{org}/properties/schema -> bare array of custom property
//     definitions (packs/github/api/hth-github-5.12-configure-repository-custom-properties.sh)
//   - GET /orgs/{org}/rulesets -> bare array of Repository ruleset objects,
//     each carrying an inline `rules` array (packs/github/api/hth-github-6.06-enforce-dependency-review.sh,
//     hth-github-7.04-configure-required-workflows.sh)
//   - GET /orgs/{org}/custom-repository-roles -> {total_count, custom_roles: [...]}
//     (packs/github/api/hth-github-7.03-create-custom-repository-roles.sh)
//   - GET /orgs/{org}/dependabot|secret-scanning|code-scanning alert endpoints
//     -> bare arrays (packs/github/api/hth-github-8.01-security-overview-dashboard.sh)
//   - GET /repos/{owner}/{repo} security_and_analysis envelope
//     (packs/github/api/ used by GH-2.01)
//   - GET /repos/{owner}/{repo}/branches/{branch}/protection (GH-2.05)
//   - GET /repos/{owner}/{repo}/environments (GH-3.05)

use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use ocean::check::register_check;
use ocean::evidence::StatusId;
use ocean::module::{Executor, Registry};

/// Minimal mock HTTP server for integration tests.
///
/// Serves a queue of `(status_code, body)` responses in order on an ephemeral port.
struct MockHTTPServer {
    base_url: String,
}

impl MockHTTPServer {
    fn new(responses: Vec<(u16, String)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock HTTP server");
        let addr = listener.local_addr().expect("local addr");
        let queue = Arc::new(Mutex::new(responses));

        std::thread::spawn(move || loop {
            let resp = {
                let mut q = queue.lock().unwrap();
                if q.is_empty() {
                    break;
                }
                q.remove(0)
            };
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf);
                let (status, body) = resp;
                let raw = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Length: {len}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}",
                    len = body.len()
                );
                let _ = stream.write_all(raw.as_bytes());
            }
        });

        Self {
            base_url: format!("http://127.0.0.1:{}", addr.port()),
        }
    }

    fn url(&self) -> &str {
        &self.base_url
    }
}

fn github_check_path(filename: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("checks/github")
        .join(filename)
}

/// Load a bundled GitHub check, rewriting the real API host to the mock server.
fn load_check_with_mock_urls(filename: &str, mock_base: &str) -> ocean::check::CheckDefinition {
    let content = std::fs::read_to_string(github_check_path(filename))
        .unwrap_or_else(|e| panic!("read {filename}: {e}"));
    let rewritten = content.replace("https://api.github.com", mock_base);
    serde_yaml::from_str(&rewritten).unwrap_or_else(|e| panic!("parse rewritten {filename}: {e}"))
}

fn run_observer(
    def: ocean::check::CheckDefinition,
    config: &HashMap<String, String>,
) -> Vec<ocean::evidence::Evidence> {
    let registry = Arc::new(Registry::new());
    let id = def.id.clone();
    register_check(&registry, def);
    let executor = Executor::new(Arc::clone(&registry));
    executor
        .execute_observer(&id, config)
        .unwrap_or_else(|e| panic!("execute {id}: {e}"))
}

fn org_config() -> HashMap<String, String> {
    let mut cfg = HashMap::new();
    cfg.insert("GITHUB_TOKEN".to_string(), "ghp_test_token".to_string());
    cfg.insert("GITHUB_ORG".to_string(), "test-org".to_string());
    cfg
}

fn repo_config() -> HashMap<String, String> {
    let mut cfg = HashMap::new();
    cfg.insert("GITHUB_TOKEN".to_string(), "ghp_test_token".to_string());
    cfg.insert("GITHUB_ORG".to_string(), "test-org".to_string());
    cfg.insert("GITHUB_OWNER".to_string(), "test-org".to_string());
    cfg.insert("GITHUB_REPO".to_string(), "test-repo".to_string());
    cfg
}

// ---------------------------------------------------------------------------
// GH-5.06 — repository custom properties for security classification
// ---------------------------------------------------------------------------

#[test]
fn gh506_pass_required_property_defined() {
    let body = serde_json::json!([
        {
            "property_name": "security-tier",
            "value_type": "single_select",
            "required": true,
            "default_value": "standard",
            "allowed_values": ["critical", "high", "standard", "low"]
        }
    ]);
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls("GH-5.06-repo-custom-properties.check.yaml", server.url());

    let evidence = run_observer(def, &org_config());
    assert_eq!(
        evidence.len(),
        2,
        "expected 2 evidence items (one per assertion)"
    );
    for ev in &evidence {
        assert_eq!(ev.control_id, "GH-5.06");
        assert_eq!(
            ev.status_id,
            StatusId::Effective,
            "expected Effective, got: {}",
            ev.status
        );
        assert!(ev.findings.is_empty());
    }
}

#[test]
fn gh506_fail_no_custom_properties() {
    let body = serde_json::json!([]);
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls("GH-5.06-repo-custom-properties.check.yaml", server.url());

    let evidence = run_observer(def, &org_config());
    assert_eq!(evidence.len(), 2);
    for ev in &evidence {
        assert_eq!(
            ev.status_id,
            StatusId::Ineffective,
            "expected Ineffective, got: {}",
            ev.status
        );
        assert!(!ev.findings.is_empty());
    }
    assert_eq!(
        evidence[0].findings[0].title,
        "Organization Custom Properties Defined"
    );
}

// ---------------------------------------------------------------------------
// GH-6.05 — dependency review enforced via organization ruleset
// ---------------------------------------------------------------------------

#[test]
fn gh605_pass_dependency_review_ruleset_active() {
    let body = serde_json::json!([
        {
            "id": 1,
            "name": "Require Dependency Review",
            "target": "branch",
            "enforcement": "active",
            "rules": [
                {
                    "type": "workflows",
                    "parameters": {
                        "workflows": [
                            {"path": ".github/workflows/dependency-review.yml", "repository_id": 0, "ref": "refs/heads/main"}
                        ]
                    }
                }
            ]
        }
    ]);
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def =
        load_check_with_mock_urls("GH-6.05-dependency-review-ruleset.check.yaml", server.url());

    let evidence = run_observer(def, &org_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].control_id, "GH-6.05");
    assert_eq!(evidence[0].status_id, StatusId::Effective);
    assert!(evidence[0].findings.is_empty());
}

#[test]
fn gh605_fail_ruleset_exists_but_no_dependency_review_workflow() {
    let body = serde_json::json!([
        {
            "id": 2,
            "name": "Basic Protection",
            "target": "branch",
            "enforcement": "active",
            "rules": [
                {"type": "deletion"}
            ]
        }
    ]);
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def =
        load_check_with_mock_urls("GH-6.05-dependency-review-ruleset.check.yaml", server.url());

    let evidence = run_observer(def, &org_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 4); // high
}

// ---------------------------------------------------------------------------
// GH-7.02 — custom repository roles defined
// ---------------------------------------------------------------------------

#[test]
fn gh702_pass_custom_role_defined() {
    let body = serde_json::json!({
        "total_count": 1,
        "custom_roles": [
            {"id": 1, "name": "Security Reviewer", "base_role": "read", "permissions": ["security_events"]}
        ]
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls("GH-7.02-custom-repository-roles.check.yaml", server.url());

    let evidence = run_observer(def, &org_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].control_id, "GH-7.02");
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn gh702_fail_no_custom_roles() {
    let body = serde_json::json!({
        "total_count": 0,
        "custom_roles": []
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls("GH-7.02-custom-repository-roles.check.yaml", server.url());

    let evidence = run_observer(def, &org_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 2); // low
}

// ---------------------------------------------------------------------------
// GH-7.03 — required workflows enforced via organization ruleset (general)
// ---------------------------------------------------------------------------

#[test]
fn gh703_pass_required_workflow_ruleset_active() {
    let body = serde_json::json!([
        {
            "id": 1,
            "name": "Required Security Workflows",
            "target": "branch",
            "enforcement": "active",
            "rules": [
                {
                    "type": "workflows",
                    "parameters": {
                        "workflows": [
                            {"path": ".github/workflows/security-scan.yml", "repository_id": 0, "ref": "refs/heads/main"}
                        ]
                    }
                }
            ]
        }
    ]);
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "GH-7.03-required-workflow-rulesets.check.yaml",
        server.url(),
    );

    let evidence = run_observer(def, &org_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn gh703_fail_no_active_workflow_ruleset() {
    let body = serde_json::json!([
        {
            "id": 2,
            "name": "Deletion Protection Only",
            "target": "branch",
            "enforcement": "active",
            "rules": [
                {"type": "deletion"}
            ]
        }
    ]);
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "GH-7.03-required-workflow-rulesets.check.yaml",
        server.url(),
    );

    let evidence = run_observer(def, &org_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 4); // high
}

// ---------------------------------------------------------------------------
// GH-8.02 — org-wide security overview alert summary (3 sequential steps)
// ---------------------------------------------------------------------------

#[test]
fn gh802_pass_no_open_alerts_org_wide() {
    let empty = serde_json::json!([]);
    let server = MockHTTPServer::new(vec![
        (200, empty.to_string()), // dependabot
        (200, empty.to_string()), // secret scanning
        (200, empty.to_string()), // code scanning
    ]);
    let def = load_check_with_mock_urls(
        "GH-8.02-security-overview-dashboard.check.yaml",
        server.url(),
    );

    let evidence = run_observer(def, &org_config());
    assert_eq!(
        evidence.len(),
        3,
        "expected 3 evidence items (one per assertion)"
    );
    for ev in &evidence {
        assert_eq!(ev.control_id, "GH-8.02");
        assert_eq!(
            ev.status_id,
            StatusId::Effective,
            "expected Effective, got: {}",
            ev.status
        );
    }
}

#[test]
fn gh802_fail_critical_dependabot_alerts_open() {
    let dependabot_alerts = serde_json::json!([
        {"number": 1, "state": "open", "security_advisory": {"severity": "critical"}}
    ]);
    let empty = serde_json::json!([]);
    let server = MockHTTPServer::new(vec![
        (200, dependabot_alerts.to_string()), // dependabot: 1 open critical
        (200, empty.to_string()),             // secret scanning: none
        (200, empty.to_string()),             // code scanning: none
    ]);
    let def = load_check_with_mock_urls(
        "GH-8.02-security-overview-dashboard.check.yaml",
        server.url(),
    );

    let evidence = run_observer(def, &org_config());
    assert_eq!(evidence.len(), 3);

    // Dependabot assertion fails; the other two pass.
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 4); // high
    assert_eq!(evidence[1].status_id, StatusId::Effective);
    assert_eq!(evidence[2].status_id, StatusId::Effective);
}

// ---------------------------------------------------------------------------
// GH-2.01 — secret scanning and push protection (existing check, hth remapped
// from a coincidental "2.1" ID match to its real HTH section "2.2")
// ---------------------------------------------------------------------------

#[test]
fn gh201_pass_secret_scanning_and_push_protection_enabled() {
    let body = serde_json::json!({
        "security_and_analysis": {
            "secret_scanning": {"status": "enabled"},
            "secret_scanning_push_protection": {"status": "enabled"}
        }
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls("GH-2.01-secret-scanning.check.yaml", server.url());

    let evidence = run_observer(def, &repo_config());
    assert_eq!(evidence.len(), 2);
    for ev in &evidence {
        assert_eq!(ev.control_id, "GH-2.01");
        assert_eq!(
            ev.status_id,
            StatusId::Effective,
            "expected Effective, got: {}",
            ev.status
        );
    }
}

#[test]
fn gh201_fail_push_protection_disabled() {
    let body = serde_json::json!({
        "security_and_analysis": {
            "secret_scanning": {"status": "enabled"},
            "secret_scanning_push_protection": {"status": "disabled"}
        }
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls("GH-2.01-secret-scanning.check.yaml", server.url());

    let evidence = run_observer(def, &repo_config());
    assert_eq!(evidence.len(), 2);
    // Secret scanning enabled -> pass.
    assert_eq!(evidence[0].status_id, StatusId::Effective);
    // Push protection disabled -> fail.
    assert_eq!(evidence[1].status_id, StatusId::Ineffective);
    assert_eq!(evidence[1].findings[0].title, "Push Protection Enabled");
}

// ---------------------------------------------------------------------------
// GH-2.05 — branch protection on the default branch (existing check, hth
// remapped from a coincidental "2.5" ID match to its real HTH section "2.1")
// ---------------------------------------------------------------------------

#[test]
fn gh205_pass_branch_protection_fully_configured() {
    let repo = serde_json::json!({"default_branch": "main"});
    let protection = serde_json::json!({
        "url": "https://api.github.com/repos/test-org/test-repo/branches/main/protection",
        "required_pull_request_reviews": {"required_approving_review_count": 1},
        "enforce_admins": {"enabled": true},
        "required_status_checks": null
    });
    let server = MockHTTPServer::new(vec![(200, repo.to_string()), (200, protection.to_string())]);
    let def = load_check_with_mock_urls("GH-2.05-branch-protection.check.yaml", server.url());

    let evidence = run_observer(def, &repo_config());
    assert_eq!(evidence.len(), 3);
    for ev in &evidence {
        assert_eq!(ev.control_id, "GH-2.05");
        assert_eq!(
            ev.status_id,
            StatusId::Effective,
            "expected Effective, got: {}",
            ev.status
        );
    }
}

#[test]
fn gh205_fail_admin_enforcement_disabled() {
    let repo = serde_json::json!({"default_branch": "main"});
    let protection = serde_json::json!({
        "url": "https://api.github.com/repos/test-org/test-repo/branches/main/protection",
        "required_pull_request_reviews": {"required_approving_review_count": 1},
        "enforce_admins": {"enabled": false},
        "required_status_checks": null
    });
    let server = MockHTTPServer::new(vec![(200, repo.to_string()), (200, protection.to_string())]);
    let def = load_check_with_mock_urls("GH-2.05-branch-protection.check.yaml", server.url());

    let evidence = run_observer(def, &repo_config());
    assert_eq!(evidence.len(), 3);
    // Protection exists and PR reviews required -> pass.
    assert_eq!(evidence[0].status_id, StatusId::Effective);
    assert_eq!(evidence[1].status_id, StatusId::Effective);
    // Admin enforcement disabled -> fail.
    assert_eq!(evidence[2].status_id, StatusId::Ineffective);
    assert_eq!(evidence[2].findings[0].title, "Admin Enforcement Enabled");
}

// ---------------------------------------------------------------------------
// GH-3.05 — deployment environment protection rules (existing check, hth
// remapped from a coincidental "3.5" ID match to its real HTH section "5.1")
// ---------------------------------------------------------------------------

#[test]
fn gh305_pass_all_environments_require_reviewers() {
    let body = serde_json::json!({
        "total_count": 1,
        "environments": [
            {
                "name": "production",
                "protection_rules": [
                    {"id": 1, "type": "required_reviewers"}
                ]
            }
        ]
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls("GH-3.05-environment-protection.check.yaml", server.url());

    let evidence = run_observer(def, &repo_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].control_id, "GH-3.05");
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn gh305_fail_environment_missing_required_reviewers() {
    let body = serde_json::json!({
        "total_count": 1,
        "environments": [
            {
                "name": "production",
                "protection_rules": []
            }
        ]
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls("GH-3.05-environment-protection.check.yaml", server.url());

    let evidence = run_observer(def, &repo_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 4); // high
}

// ---------------------------------------------------------------------------
// Loader integration: every checks/github/*.check.yaml file loads cleanly
// and carries a valid references.hth mapping.
// ---------------------------------------------------------------------------

#[test]
fn all_github_checks_load_and_have_hth_references() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("checks/github");
    let defs = ocean::check::loader::load_definitions_from_dir(&dir);

    assert!(
        !defs.is_empty(),
        "expected at least one GitHub check to load"
    );

    let ids: Vec<&str> = defs.iter().map(|d| d.id.as_str()).collect();
    for expect_id in ["GH-5.06", "GH-6.05", "GH-7.02", "GH-7.03", "GH-8.02"] {
        assert!(
            ids.contains(&expect_id),
            "missing {expect_id}, got: {ids:?}"
        );
    }

    for def in &defs {
        assert_eq!(
            def.source, "github",
            "{}: source should be 'github'",
            def.id
        );
        assert!(
            !def.references.hth.is_empty(),
            "{}: references.hth is mandatory for GitHub checks",
            def.id
        );
        assert!(
            def.references.hth.starts_with("github:"),
            "{}: references.hth should be 'github:N.N', got '{}'",
            def.id,
            def.references.hth
        );
        assert!(
            !def.assertions.is_empty(),
            "{}: check has no assertions",
            def.id
        );
    }
}
