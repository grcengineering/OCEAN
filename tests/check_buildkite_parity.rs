// Integration tests: Buildkite (HTH parity) checks under checks/buildkite/ and
// the five CI/CD controls under controls/cicd/ that wire them.
//
// Mirrors the MockHTTPServer TDD pattern from tests/check_okta_parity.rs and
// tests/check_github_parity.rs. Six representative checks each get a pass case
// and a fail case built from Buildkite's documented response shapes, plus two
// degraded-read cases (GraphQL `data.organization: null` and a REST 404) that
// exercise the UNKNOWN-vs-finding discriminator the check descriptions promise.
// Structural tests then guard the whole vendor surface: every definition loads,
// ids are unique and match the BK-* convention, every CEL expression compiles,
// every declared credential is on the fleet allowlist, no check smuggles in the
// vestigial `implementation: native` field, and every control observer resolves
// to a real check id.
//
// Fixture provenance. Field names come from Buildkite's own API surface as
// captured during live introspection of the `grcengineering` tenant on
// 2026-08-18 and from the shipped checks' own `extract:` JSONPaths:
//   - POST https://graphql.buildkite.com/v1 -> {"data": {"organization": {...}}}
//     with scalars `id`, `slug`, `public`, `membersRequireTwoFactorAuthentication`,
//     `allowedApiIpAddresses`, `revokeInactiveTokensAfter`
//     (BK-1.02, BK-2.05a, BK-2.05b, BK-4.01)
//   - GET /v2/organizations/{org}/pipelines -> bare array, each with `visibility`
//     and `provider.settings.build_pull_request_forks` (BK-2.02, BK-2.02b)
//   - GET /v2/organizations/{org}/members -> bare array, each with `role`
//     (BK-2.03)
//   - GET /v2/organizations/{org}/clusters/{cluster}/tokens -> bare array, each
//     with `expires_at` and `allowed_ip_addresses` (BK-3.01a, BK-3.01b)
//   - GET /v2/organizations/{org}/clusters -> bare array with `id`/`name`, and
//     .../clusters/{cluster}/secrets -> bare array with `key`/`policy` (BK-3.05)
//
// Deliberately self-contained. The sibling parity tests assert nothing against
// the how-to-harden checkout, and this one does not either: cross-repo section
// validation (does `hth: "buildkite:N.N"` name a control that exists in the
// guide?) is owned by `scripts/hth_parity.py --validate`, which runs as the
// "HTH Parity Validate" CI job. This file asserts the shape of the reference,
// not its cross-repo target.

use std::collections::{HashMap, HashSet};
use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use cel::Program;

use ocean::check::{load_check_file, register_check, CheckDefinition, CheckType};
use ocean::control::Control;
use ocean::evidence::{Evidence, StatusId};
use ocean::fleet::FleetManifest;
use ocean::module::{Executor, Registry};

// ---------------------------------------------------------------------------
// Mock HTTP server (copied from tests/check_okta_parity.rs — kept local so this
// file has no cross-test-file dependency).
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Loader / execution helpers
// ---------------------------------------------------------------------------

fn buildkite_checks_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("checks/buildkite")
}

fn buildkite_check_path(filename: &str) -> PathBuf {
    buildkite_checks_dir().join(filename)
}

/// Load a bundled Buildkite check, rewriting BOTH real hosts to the mock server.
///
/// Buildkite splits its surface across two hosts — GraphQL on
/// `graphql.buildkite.com/v1` and REST on `api.buildkite.com/v2` — so a single
/// host rewrite (as the GitHub and Okta tests use) is not enough here.
fn load_check_with_mock_urls(filename: &str, mock_base: &str) -> CheckDefinition {
    let path = buildkite_check_path(filename);
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    let rewritten = content
        .replace("https://graphql.buildkite.com/v1", mock_base)
        .replace("https://api.buildkite.com", mock_base);
    serde_yaml::from_str(&rewritten).unwrap_or_else(|e| panic!("parse rewritten {filename}: {e}"))
}

/// Config for the organization-scoped checks (`org` input via BUILDKITE_ORG_SLUG).
fn org_config() -> HashMap<String, String> {
    let mut cfg = HashMap::new();
    cfg.insert(
        "BUILDKITE_API_TOKEN".to_string(),
        "bkua_test_token".to_string(),
    );
    cfg.insert("BUILDKITE_ORG_SLUG".to_string(), "test-org".to_string());
    cfg
}

/// Config for the cluster-scoped checks. Both spellings of the cluster input's
/// env var are supplied: BK-3.01a/BK-3.01b/BK-3.05 read BUILDKITE_CLUSTER_ID and
/// BK-3.07 reads BUILDKITE_CLUSTER_UUID for the same `cluster` input.
fn cluster_config() -> HashMap<String, String> {
    let mut cfg = org_config();
    cfg.insert(
        "BUILDKITE_CLUSTER_ID".to_string(),
        "6a2b7f6a-2c31-49ef-a1b0-a3a675aaa10f".to_string(),
    );
    cfg.insert(
        "BUILDKITE_CLUSTER_UUID".to_string(),
        "6a2b7f6a-2c31-49ef-a1b0-a3a675aaa10f".to_string(),
    );
    cfg
}

/// Register a loaded check and run it as an observer.
///
/// Returns the assertion ids in declaration order alongside the emitted
/// evidence — the interpreter produces exactly one Evidence per assertion, in
/// the same order, which the returned length equality re-asserts.
fn run_observer(
    def: CheckDefinition,
    config: &HashMap<String, String>,
) -> (Vec<String>, Vec<Evidence>) {
    let id = def.id.clone();
    let assertion_ids: Vec<String> = def.assertions.iter().map(|a| a.id.clone()).collect();

    let registry = Arc::new(Registry::new());
    register_check(&registry, def);
    let executor = Executor::new(Arc::clone(&registry));
    let evidence = executor
        .execute_observer(&id, config)
        .unwrap_or_else(|e| panic!("execute observer {id}: {e}"));

    assert_eq!(
        evidence.len(),
        assertion_ids.len(),
        "{id}: expected one Evidence per assertion, got {} for {assertion_ids:?}",
        evidence.len()
    );
    (assertion_ids, evidence)
}

/// Look up the evidence item produced by a named assertion.
///
/// Addressing by assertion id rather than by position keeps these cases legible
/// and stable if a future assertion is inserted ahead of the one under test.
fn evidence_for<'a>(ids: &[String], evidence: &'a [Evidence], assertion_id: &str) -> &'a Evidence {
    let idx = ids
        .iter()
        .position(|i| i == assertion_id)
        .unwrap_or_else(|| panic!("no assertion '{assertion_id}' among {ids:?}"));
    &evidence[idx]
}

fn assert_effective(ids: &[String], evidence: &[Evidence], assertion_id: &str) {
    let ev = evidence_for(ids, evidence, assertion_id);
    assert_eq!(
        ev.status_id,
        StatusId::Effective,
        "{assertion_id}: expected Effective, got '{}'",
        ev.status
    );
    assert!(
        ev.findings.is_empty(),
        "{assertion_id}: a passing assertion must not raise a finding"
    );
}

fn assert_ineffective(ids: &[String], evidence: &[Evidence], assertion_id: &str, severity_id: i32) {
    let ev = evidence_for(ids, evidence, assertion_id);
    assert_eq!(
        ev.status_id,
        StatusId::Ineffective,
        "{assertion_id}: expected Ineffective, got '{}'",
        ev.status
    );
    assert!(
        !ev.findings.is_empty(),
        "{assertion_id}: a failing assertion must raise a finding"
    );
    assert_eq!(
        ev.findings[0].severity_id, severity_id,
        "{assertion_id}: unexpected finding severity"
    );
}

// ===========================================================================
// BK-1.02 — Organization-wide two-factor enforcement (GraphQL scalar)
// ===========================================================================

fn org_two_factor_body(mfa: bool) -> serde_json::Value {
    serde_json::json!({
        "data": {
            "organization": {
                "id": "T3JnYW5pemF0aW9uLS0tYmt0ZXN0",
                "slug": "test-org",
                "membersRequireTwoFactorAuthentication": mfa
            }
        }
    })
}

#[test]
fn bk102_pass_two_factor_enforced() {
    let server = MockHTTPServer::new(vec![(200, org_two_factor_body(true).to_string())]);
    let def = load_check_with_mock_urls("BK-1.02-enforce-2fa.check.yaml", server.url());
    let (ids, evidence) = run_observer(def, &org_config());

    assert_effective(&ids, &evidence, "organization_readable");
    assert_effective(&ids, &evidence, "two_factor_enforced");
}

#[test]
fn bk102_fail_two_factor_not_enforced() {
    let server = MockHTTPServer::new(vec![(200, org_two_factor_body(false).to_string())]);
    let def = load_check_with_mock_urls("BK-1.02-enforce-2fa.check.yaml", server.url());
    let (ids, evidence) = run_observer(def, &org_config());

    // The read succeeded, so the two-factor verdict below is authoritative.
    assert_effective(&ids, &evidence, "organization_readable");
    assert_ineffective(&ids, &evidence, "two_factor_enforced", 5); // critical
}

#[test]
fn bk102_unreadable_organization_reports_collection_failure_not_a_mfa_finding() {
    // Buildkite resolves `data.organization` to null for a token without GraphQL
    // API access, a wrong slug, an IP-allowlist block, or an expired credential.
    // Nothing was observed, so the only honest output is the readability signal:
    // `organization_readable` reports Ineffective while the root-anchored guard
    // makes the two-factor assertion abstain instead of reporting an
    // organization that was never read as non-compliant.
    //
    // This is ONE of the three unreadable shapes. The other two (`data: null`
    // and no `data` key) are covered by
    // `bk102_every_unreadable_shape_abstains_without_attesting_to_2fa`, which
    // also pins the abstention MESSAGE. Keeping this case standalone preserves
    // the original regression it was written for.
    let body = serde_json::json!({
        "data": {"organization": null},
        "errors": [{"message": "No organization found"}]
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls("BK-1.02-enforce-2fa.check.yaml", server.url());
    let (ids, evidence) = run_observer(def, &org_config());

    assert_ineffective(&ids, &evidence, "organization_readable", 1); // info
    assert_effective(&ids, &evidence, "two_factor_enforced");
}

// ===========================================================================
// BK-4.01 — Organization not publicly visible (GraphQL scalar)
// ===========================================================================

fn org_visibility_body(public: bool) -> serde_json::Value {
    serde_json::json!({
        "data": {
            "organization": {
                "id": "T3JnYW5pemF0aW9uLS0tYmt0ZXN0",
                "slug": "test-org",
                "public": public
            }
        }
    })
}

#[test]
fn bk401_pass_organization_private() {
    let server = MockHTTPServer::new(vec![(200, org_visibility_body(false).to_string())]);
    let def = load_check_with_mock_urls("BK-4.01-org-not-public.check.yaml", server.url());
    let (ids, evidence) = run_observer(def, &org_config());

    assert_effective(&ids, &evidence, "organization_readable");
    assert_effective(&ids, &evidence, "organization_not_public");
}

#[test]
fn bk401_fail_organization_public() {
    let server = MockHTTPServer::new(vec![(200, org_visibility_body(true).to_string())]);
    let def = load_check_with_mock_urls("BK-4.01-org-not-public.check.yaml", server.url());
    let (ids, evidence) = run_observer(def, &org_config());

    assert_effective(&ids, &evidence, "organization_readable");
    assert_ineffective(&ids, &evidence, "organization_not_public", 4); // high
}

// ===========================================================================
// BK-2.02 — No publicly visible pipelines (REST array + CEL filter macro)
// ===========================================================================

fn pipelines_body(second_visibility: &str) -> serde_json::Value {
    serde_json::json!([
        {"slug": "api-service", "name": "api-service", "visibility": "private"},
        {"slug": "web-app", "name": "web-app", "visibility": second_visibility}
    ])
}

#[test]
fn bk202_pass_all_pipelines_private() {
    let server = MockHTTPServer::new(vec![(200, pipelines_body("private").to_string())]);
    let def = load_check_with_mock_urls("BK-2.02-no-public-pipelines.check.yaml", server.url());
    let (ids, evidence) = run_observer(def, &org_config());

    assert_effective(&ids, &evidence, "pipelines_api_reachable");
    assert_effective(&ids, &evidence, "no_public_pipelines");
}

#[test]
fn bk202_fail_one_public_pipeline() {
    let server = MockHTTPServer::new(vec![(200, pipelines_body("public").to_string())]);
    let def = load_check_with_mock_urls("BK-2.02-no-public-pipelines.check.yaml", server.url());
    let (ids, evidence) = run_observer(def, &org_config());

    assert_effective(&ids, &evidence, "pipelines_api_reachable");
    assert_ineffective(&ids, &evidence, "no_public_pipelines", 4); // high
}

// ===========================================================================
// BK-2.03 — Organization admin count bounded (REST array + reachability guard)
// ===========================================================================

fn members_body(roles: &[&str]) -> serde_json::Value {
    let members: Vec<serde_json::Value> = roles
        .iter()
        .enumerate()
        .map(|(i, role)| {
            serde_json::json!({
                "id": format!("member-{i}"),
                "role": role,
                "user": {"id": format!("user-{i}"), "email": format!("user{i}@example.com")}
            })
        })
        .collect();
    serde_json::Value::Array(members)
}

#[test]
fn bk203_pass_admin_count_within_bound() {
    let body = members_body(&["admin", "admin", "member", "member"]);
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls("BK-2.03-admin-count-bounded.check.yaml", server.url());
    let (ids, evidence) = run_observer(def, &org_config());

    assert_effective(&ids, &evidence, "members_api_reachable");
    assert_effective(&ids, &evidence, "admin_count_within_bound");
}

#[test]
fn bk203_fail_too_many_admins() {
    let body = members_body(&["admin", "admin", "admin", "admin"]);
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls("BK-2.03-admin-count-bounded.check.yaml", server.url());
    let (ids, evidence) = run_observer(def, &org_config());

    assert_effective(&ids, &evidence, "members_api_reachable");
    assert_ineffective(&ids, &evidence, "admin_count_within_bound", 3); // medium
}

#[test]
fn bk203_unreachable_endpoint_reports_collection_failure_not_a_bound_breach() {
    // The `list_members_status_code != 200 ||` prefix is a deliberate reachability
    // guard: on a 404 the reachability assertion carries the finding and the
    // bounded assertion abstains rather than accusing on an empty list. Pinning
    // this keeps the guard from being refactored away.
    let body = serde_json::json!({"message": "Not Found"});
    let server = MockHTTPServer::new(vec![(404, body.to_string())]);
    let def = load_check_with_mock_urls("BK-2.03-admin-count-bounded.check.yaml", server.url());
    let (ids, evidence) = run_observer(def, &org_config());

    assert_ineffective(&ids, &evidence, "members_api_reachable", 3); // medium
    assert_effective(&ids, &evidence, "admin_count_within_bound");
}

// ===========================================================================
// Degraded GraphQL reads — the reachability guard, exercised on EVERY shape
// Buildkite can answer a failed request with.
//
// This block exists because the original single fixture
// (`{"data":{"organization":null}}`) tested only the ONE unreadable shape in
// which the guard's old `org_object == null` clause happened to bind, and so
// certified a guard that was in fact defeated by the two commoner ones.
//
// GraphQL reports REQUEST-level errors with HTTP 200. There are three distinct
// shapes and the extraction behaves differently in each:
//
//   1. {"data":{"organization":null}} — field resolved to nothing.
//      `$.data.organization` navigates to the null, so `org_object` BINDS.
//   2. {"data":null}                  — query validation failed. This is what
//      an Enterprise-gated field on a lower plan actually produces, which is
//      the scenario BK-1.02's own description names.
//      `$.data.organization` cannot navigate past the null, so `org_object`
//      and every scalar are UNBOUND.
//   3. no "data" key at all           — the request never reached execution.
//      Same unbound outcome as (2).
//
// In shapes (2) and (3) a guard written against an extracted name raises
// "Undeclared reference", and the interpreter's fail-closed `.unwrap_or(false)`
// converts that collection failure into a FINDING — a critical "2FA is NOT
// enforced" against an organization that was never read. The guards are now
// anchored on `body_root` (`$`), which `jsonpath_extract` binds unconditionally
// for every response shape, so all three abstain.
//
// Each case also asserts the ABSTENTION MESSAGE. OCEAN emits `pass_message` on
// Effective, and an abstaining assertion is Effective, so a guard that merely
// abstains still publishes whatever `pass_message` says. If that sentence
// asserts the positive fact, the check has traded a false accusation for a
// false attestation — the worse of the two for a compliance tool. These cases
// pin that the message never states the unobserved fact and never leaks an
// unrendered `{{placeholder}}` from a binding that does not exist on this path.
// ===========================================================================

/// The three response shapes that mean "no organization was read", labelled.
fn unreadable_graphql_bodies() -> Vec<(&'static str, serde_json::Value)> {
    vec![
        (
            "data.organization null",
            serde_json::json!({
                "data": {"organization": null},
                "errors": [{"message": "No organization found"}]
            }),
        ),
        (
            "data null (query validation failed)",
            serde_json::json!({
                "data": null,
                "errors": [{
                    "message": "Field 'revokeInactiveTokensAfter' doesn't exist on type 'Organization'",
                    "extensions": {"code": "undefinedField"}
                }]
            }),
        ),
        (
            "no data key (request never executed)",
            serde_json::json!({
                "errors": [{"message": "Parse error on \"organization\""}]
            }),
        ),
    ]
}

/// Assert a guarded verdict abstained AND said nothing it did not observe.
fn assert_abstained_without_attesting(
    ids: &[String],
    evidence: &[Evidence],
    assertion_id: &str,
    shape: &str,
    forbidden_claims: &[&str],
) {
    let ev = evidence_for(ids, evidence, assertion_id);
    assert_eq!(
        ev.status_id,
        StatusId::Effective,
        "{assertion_id} [{shape}]: an unreadable organization must ABSTAIN, not accuse; \
         got Ineffective with message '{}'",
        ev.status
    );
    assert!(
        ev.findings.is_empty(),
        "{assertion_id} [{shape}]: abstention must raise no finding, got {:?}",
        ev.findings
    );
    assert!(
        !ev.status.contains("{{"),
        "{assertion_id} [{shape}]: message leaks an unrendered placeholder from a \
         binding that does not exist on the abstention path: '{}'",
        ev.status
    );
    for claim in forbidden_claims {
        assert!(
            !ev.status.contains(claim),
            "{assertion_id} [{shape}]: FALSE ATTESTATION — the abstention message \
             asserts '{claim}', a fact this run never observed. Full message: '{}'",
            ev.status
        );
    }
}

#[test]
fn bk102_every_unreadable_shape_abstains_without_attesting_to_2fa() {
    for (shape, body) in unreadable_graphql_bodies() {
        let server = MockHTTPServer::new(vec![(200, body.to_string())]);
        let def = load_check_with_mock_urls("BK-1.02-enforce-2fa.check.yaml", server.url());
        let (ids, evidence) = run_observer(def, &org_config());

        assert_ineffective(&ids, &evidence, "organization_readable", 1); // info
        assert_abstained_without_attesting(
            &ids,
            &evidence,
            "two_factor_enforced",
            shape,
            &["is enforced for all members"],
        );
    }
}

#[test]
fn bk401_every_unreadable_shape_abstains_without_attesting_to_privacy() {
    for (shape, body) in unreadable_graphql_bodies() {
        let server = MockHTTPServer::new(vec![(200, body.to_string())]);
        let def = load_check_with_mock_urls("BK-4.01-org-not-public.check.yaml", server.url());
        let (ids, evidence) = run_observer(def, &org_config());

        assert_ineffective(&ids, &evidence, "organization_readable", 1); // info
        assert_abstained_without_attesting(
            &ids,
            &evidence,
            "organization_not_public",
            shape,
            &["is not publicly visible"],
        );
    }
}

#[test]
fn bk205a_every_unreadable_shape_abstains_without_attesting_to_an_allowlist() {
    for (shape, body) in unreadable_graphql_bodies() {
        let server = MockHTTPServer::new(vec![(200, body.to_string())]);
        let def = load_check_with_mock_urls("BK-2.05a-api-ip-allowlist.check.yaml", server.url());
        let (ids, evidence) = run_observer(def, &org_config());

        assert_ineffective(&ids, &evidence, "organization_readable", 1); // info
        assert_abstained_without_attesting(
            &ids,
            &evidence,
            "api_ip_allowlist_configured",
            shape,
            &["is restricted to"],
        );
    }
}

#[test]
fn bk205b_every_unreadable_shape_abstains_without_attesting_to_revocation() {
    for (shape, body) in unreadable_graphql_bodies() {
        let server = MockHTTPServer::new(vec![(200, body.to_string())]);
        let def = load_check_with_mock_urls(
            "BK-2.05b-inactive-token-revocation.check.yaml",
            server.url(),
        );
        let (ids, evidence) = run_observer(def, &org_config());

        assert_ineffective(&ids, &evidence, "organization_readable", 1);
        // Both revocation verdicts are guarded; both must abstain silently.
        assert_abstained_without_attesting(
            &ids,
            &evidence,
            "inactive_token_revocation_configured",
            shape,
            &["revokes inactive API access tokens after"],
        );
        assert_abstained_without_attesting(
            &ids,
            &evidence,
            "inactive_token_revocation_effective",
            shape,
            &["has an effective inactive-token revocation window"],
        );
    }
}

#[test]
fn bk205a_and_bk205b_pass_and_fail_on_a_readable_organization() {
    // The guards must not have made the checks vacuous: a readable organization
    // still produces a real verdict in both directions.
    let configured = serde_json::json!({"data": {"organization": {
        "id": "T3JnYW5pemF0aW9uLS0tYmt0ZXN0", "slug": "test-org",
        "allowedApiIpAddresses": "203.0.113.0/24"
    }}});
    let unset = serde_json::json!({"data": {"organization": {
        "id": "T3JnYW5pemF0aW9uLS0tYmt0ZXN0", "slug": "test-org",
        "allowedApiIpAddresses": null
    }}});

    let server = MockHTTPServer::new(vec![(200, configured.to_string())]);
    let def = load_check_with_mock_urls("BK-2.05a-api-ip-allowlist.check.yaml", server.url());
    let (ids, evidence) = run_observer(def, &org_config());
    assert_effective(&ids, &evidence, "organization_readable");
    assert_effective(&ids, &evidence, "api_ip_allowlist_configured");

    let server = MockHTTPServer::new(vec![(200, unset.to_string())]);
    let def = load_check_with_mock_urls("BK-2.05a-api-ip-allowlist.check.yaml", server.url());
    let (ids, evidence) = run_observer(def, &org_config());
    assert_effective(&ids, &evidence, "organization_readable");
    assert_ineffective(&ids, &evidence, "api_ip_allowlist_configured", 3); // medium

    // BK-2.05b is tri-state: unset and NEVER carry identical risk but are
    // asserted separately so operator intent stays visible.
    for (period, configured_ok) in [
        (serde_json::json!("DAYS_90"), true),
        (serde_json::json!("NEVER"), true),
        (serde_json::Value::Null, false),
    ] {
        let is_never = period == serde_json::json!("NEVER");
        let body = serde_json::json!({"data": {"organization": {
            "id": "T3JnYW5pemF0aW9uLS0tYmt0ZXN0", "slug": "test-org",
            "revokeInactiveTokensAfter": period
        }}});
        let server = MockHTTPServer::new(vec![(200, body.to_string())]);
        let def = load_check_with_mock_urls(
            "BK-2.05b-inactive-token-revocation.check.yaml",
            server.url(),
        );
        let (ids, evidence) = run_observer(def, &org_config());
        assert_effective(&ids, &evidence, "organization_readable");
        if configured_ok {
            assert_effective(&ids, &evidence, "inactive_token_revocation_configured");
        } else {
            assert_ineffective(&ids, &evidence, "inactive_token_revocation_configured", 3);
        }
        if configured_ok && !is_never {
            assert_effective(&ids, &evidence, "inactive_token_revocation_effective");
        } else {
            assert_ineffective(&ids, &evidence, "inactive_token_revocation_effective", 3);
        }
    }
}

#[test]
fn bk301a_unreachable_endpoint_abstains_without_counting_phantom_tokens() {
    // `$length` falls back to 1 for a non-array body, so a 404 error object
    // binds `token_count = 1`. The abstention message must therefore not
    // interpolate the count into a claim: "All 1 agent token(s) ... carry an
    // expiry" is a sentence about a cluster that returned 404.
    let body = serde_json::json!({"message": "Not Found"});
    let server = MockHTTPServer::new(vec![(404, body.to_string())]);
    let def = load_check_with_mock_urls("BK-3.01a-agent-token-expiry.check.yaml", server.url());
    let (ids, evidence) = run_observer(def, &cluster_config());

    assert_ineffective(&ids, &evidence, "agent_tokens_api_reachable", 3); // medium
    assert_abstained_without_attesting(
        &ids,
        &evidence,
        "all_tokens_expire",
        "REST 404",
        &["All 1 agent token", "All 1 "],
    );
}

#[test]
fn bk301b_unreachable_endpoint_abstains_without_counting_phantom_tokens() {
    let body = serde_json::json!({"message": "Not Found"});
    let server = MockHTTPServer::new(vec![(404, body.to_string())]);
    let def = load_check_with_mock_urls(
        "BK-3.01b-agent-token-ip-restricted.check.yaml",
        server.url(),
    );
    let (ids, evidence) = run_observer(def, &cluster_config());

    assert_ineffective(&ids, &evidence, "agent_tokens_api_reachable", 3); // medium
    assert_abstained_without_attesting(
        &ids,
        &evidence,
        "all_tokens_ip_restricted",
        "REST 404",
        &["All 1 agent token", "All 1 "],
    );
}

// ===========================================================================
// BK-3.01a — Every cluster agent token expires (CEL `all` macro over a list)
// ===========================================================================

fn agent_tokens_body(second_expiry: serde_json::Value) -> serde_json::Value {
    serde_json::json!([
        {
            "id": "token-1",
            "description": "ci-runners",
            "expires_at": "2026-12-31T00:00:00Z",
            "allowed_ip_addresses": "203.0.113.0/24"
        },
        {
            "id": "token-2",
            "description": "legacy",
            "expires_at": second_expiry,
            "allowed_ip_addresses": "203.0.113.0/24"
        }
    ])
}

#[test]
fn bk301a_pass_all_tokens_expire() {
    let body = agent_tokens_body(serde_json::json!("2027-01-01T00:00:00Z"));
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls("BK-3.01a-agent-token-expiry.check.yaml", server.url());
    let (ids, evidence) = run_observer(def, &cluster_config());

    assert_effective(&ids, &evidence, "agent_tokens_api_reachable");
    assert_effective(&ids, &evidence, "all_tokens_expire");
}

#[test]
fn bk301a_fail_non_expiring_token() {
    let body = agent_tokens_body(serde_json::Value::Null);
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls("BK-3.01a-agent-token-expiry.check.yaml", server.url());
    let (ids, evidence) = run_observer(def, &cluster_config());

    assert_effective(&ids, &evidence, "agent_tokens_api_reachable");
    assert_ineffective(&ids, &evidence, "all_tokens_expire", 4); // high
}

// ===========================================================================
// BK-3.05 — Every cluster secret carries a policy
// (two-step check; CEL `has()` presence macro over extracted objects)
// ===========================================================================

fn clusters_body() -> serde_json::Value {
    serde_json::json!([
        {
            "id": "Q2x1c3Rlci0tLTZhMmI3ZjZhLTJjMzEtNDllZi1hMWIwLWEzYTY3NWFhYTEwZg==",
            "uuid": "6a2b7f6a-2c31-49ef-a1b0-a3a675aaa10f",
            "name": "Default cluster"
        }
    ])
}

fn secrets_body(second: serde_json::Value) -> serde_json::Value {
    serde_json::json!([
        {"uuid": "secret-1", "key": "NPM_TOKEN", "policy": "pipelines: [api-service]"},
        second
    ])
}

#[test]
fn bk305_pass_every_secret_has_policy() {
    let second = serde_json::json!({
        "uuid": "secret-2", "key": "DEPLOY_KEY", "policy": "pipelines: [web-app]"
    });
    let server = MockHTTPServer::new(vec![
        (200, clusters_body().to_string()),
        (200, secrets_body(second).to_string()),
    ]);
    let def = load_check_with_mock_urls("BK-3.05-secret-policies.check.yaml", server.url());
    let (ids, evidence) = run_observer(def, &cluster_config());

    assert_effective(&ids, &evidence, "secrets_api_reachable");
    assert_effective(&ids, &evidence, "every_secret_has_policy");
}

#[test]
fn bk305_fail_secret_without_policy() {
    // The `policy` key is absent entirely, which is how Buildkite renders an
    // unrestricted secret — `has(s.policy)` is the discriminator, not a null read.
    let second = serde_json::json!({"uuid": "secret-2", "key": "DEPLOY_KEY"});
    let server = MockHTTPServer::new(vec![
        (200, clusters_body().to_string()),
        (200, secrets_body(second).to_string()),
    ]);
    let def = load_check_with_mock_urls("BK-3.05-secret-policies.check.yaml", server.url());
    let (ids, evidence) = run_observer(def, &cluster_config());

    assert_effective(&ids, &evidence, "secrets_api_reachable");
    assert_ineffective(&ids, &evidence, "every_secret_has_policy", 4); // high
}

// ===========================================================================
// Structural parity: the whole checks/buildkite/ surface
// ===========================================================================

/// The full shipped Buildkite check set. Kept explicit — as in
/// tests/check_w3a_parity.rs's `assert_vendor_dir_loads` — so that adding or
/// removing a check is a deliberate edit to this list, not a silent drift.
const EXPECTED_BUILDKITE_CHECK_IDS: &[&str] = &[
    "BK-1.02", "BK-2.02", "BK-2.02b", "BK-2.03", "BK-2.05a", "BK-2.05b", "BK-2.07", "BK-3.01a",
    "BK-3.01b", "BK-3.05", "BK-3.07", "BK-4.01",
];

/// Every `*.check.yaml` file under checks/buildkite/, sorted by path.
fn buildkite_check_files() -> Vec<PathBuf> {
    let dir = buildkite_checks_dir();
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|entry| entry.expect("dir entry").path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".check.yaml"))
        })
        .collect();
    paths.sort();
    paths
}

/// Load every Buildkite definition through `load_check_file`, which surfaces a
/// parse error instead of skipping the file the way `load_definitions_from_dir`
/// does. A definition that stops deserializing must fail the suite, not vanish.
fn load_all_buildkite_defs() -> Vec<CheckDefinition> {
    buildkite_check_files()
        .iter()
        .map(|path| {
            load_check_file(path).unwrap_or_else(|e| panic!("load {}: {e}", path.display()))
        })
        .collect()
}

#[test]
fn all_buildkite_checks_deserialize_with_unique_bk_ids() {
    let files = buildkite_check_files();
    let defs = load_all_buildkite_defs();
    assert_eq!(
        defs.len(),
        files.len(),
        "every checks/buildkite/*.check.yaml file must deserialize"
    );

    // The lossy loader must agree with the strict one — a file that only the
    // strict path can read is a file the runtime would silently skip.
    let lossy = ocean::check::loader::load_definitions_from_dir(&buildkite_checks_dir());
    assert_eq!(
        lossy.len(),
        defs.len(),
        "load_definitions_from_dir silently skipped a Buildkite check"
    );

    let mut ids = HashSet::new();
    for (def, path) in defs.iter().zip(files.iter()) {
        assert!(!def.id.is_empty(), "{} has an empty id", path.display());
        assert!(
            ids.insert(def.id.clone()),
            "duplicate check id '{}' in {}",
            def.id,
            path.display()
        );
        assert!(
            is_buildkite_check_id(&def.id),
            "{}: id '{}' does not match the BK-<major>.<minor>[suffix] convention",
            path.display(),
            def.id
        );
        assert!(!def.name.is_empty(), "{}: name is mandatory", def.id);
    }

    let expected: HashSet<String> = EXPECTED_BUILDKITE_CHECK_IDS
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(
        ids, expected,
        "checks/buildkite/ drifted from the declared check set"
    );
}

/// `BK-<major>.<two-digit minor>` with an optional lowercase disambiguator, as
/// used by BK-2.02b, BK-2.05a/b and BK-3.01a/b when two checks split one guide
/// control.
fn is_buildkite_check_id(id: &str) -> bool {
    let Some(rest) = id.strip_prefix("BK-") else {
        return false;
    };
    let Some((major, minor)) = rest.split_once('.') else {
        return false;
    };
    let minor_digits = minor.trim_end_matches(|c: char| c.is_ascii_lowercase());
    let suffix_len = minor.len() - minor_digits.len();

    !major.is_empty()
        && major.chars().all(|c| c.is_ascii_digit())
        && minor_digits.len() == 2
        && minor_digits.chars().all(|c| c.is_ascii_digit())
        && suffix_len <= 1
}

#[test]
fn all_buildkite_checks_declare_source_hth_steps_and_assertions() {
    for def in load_all_buildkite_defs() {
        assert_eq!(
            def.source, "buildkite",
            "{}: source should be 'buildkite'",
            def.id
        );
        assert!(
            !def.references.hth.is_empty(),
            "{}: references.hth is mandatory for Buildkite checks",
            def.id
        );
        assert!(
            def.references.hth.starts_with("buildkite:"),
            "{}: references.hth should be 'buildkite:N.N', got '{}'",
            def.id,
            def.references.hth
        );
        assert!(!def.steps.is_empty(), "{}: check has no steps", def.id);
        assert!(
            !def.assertions.is_empty(),
            "{}: check has no assertions",
            def.id
        );
        assert!(
            !def.credentials.is_empty(),
            "{}: check declares no credentials",
            def.id
        );
        // Every shipped Buildkite check is read-only. The tenant these run
        // against is a real organization; promoting one to `type: active` is a
        // safety decision that must be made deliberately, not by omission.
        assert_eq!(
            def.check_type,
            CheckType::Passive,
            "{}: no active Buildkite check has been authorised",
            def.id
        );
    }
}

#[test]
fn no_buildkite_check_declares_a_native_implementation() {
    // `implementation: native` routes a check to a compiled Rust observer via
    // `modules::native_observer()`. No native Buildkite observer exists, so the
    // field can only be vestigial here — and setting it would make the check
    // fail to dispatch rather than degrade.
    for def in load_all_buildkite_defs() {
        assert!(
            def.implementation.is_empty(),
            "{}: implementation must be empty for declarative checks, got '{}'",
            def.id,
            def.implementation
        );
        assert!(
            def.native_module.is_empty(),
            "{}: native_module must be empty for declarative checks, got '{}'",
            def.id,
            def.native_module
        );
    }
}

#[test]
fn every_buildkite_assertion_expression_compiles_as_cel() {
    // The interpreter compiles assertion expressions lazily, at evaluation time,
    // and `evaluate_all_assertions` swallows the error into `unwrap_or(false)` —
    // so an un-compilable expression ships as a permanent false accusation
    // rather than as a loud failure. Compile them all up front.
    let mut failures = Vec::new();
    let mut compiled = 0;
    for def in load_all_buildkite_defs() {
        for assertion in &def.assertions {
            compiled += 1;
            if let Err(e) = Program::compile(&assertion.expr) {
                failures.push(format!(
                    "{}/{}: {e}\n    expr: {}",
                    def.id, assertion.id, assertion.expr
                ));
            }
        }
        // `when:` guards are compiled through the same path.
        for step in &def.steps {
            if step.when.is_empty() {
                continue;
            }
            compiled += 1;
            if let Err(e) = Program::compile(&step.when) {
                failures.push(format!("{}/{} (when): {e}", def.id, step.id));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "Buildkite CEL expressions failed to compile:\n{}",
        failures.join("\n")
    );
    assert!(
        compiled >= EXPECTED_BUILDKITE_CHECK_IDS.len(),
        "expected at least one expression per check, compiled only {compiled}"
    );
}

// ---------------------------------------------------------------------------
// Fleet credential allowlist
// ---------------------------------------------------------------------------

fn fleet_manifest_yaml(credentials: &[String]) -> String {
    let mut yaml = String::from(
        "fleet:\n  name: \"buildkite parity\"\ntargets:\n  - id: \"bk-parity\"\n    source: buildkite\n    credentials:\n",
    );
    for name in credentials {
        // Literal values (not `${VAR}` refs) are returned as-is by
        // `resolve_env_ref`, so this exercises the allowlist without touching
        // the process environment.
        yaml.push_str(&format!("      {name}: \"test-value\"\n"));
    }
    yaml
}

#[test]
fn every_credential_named_by_a_buildkite_check_is_fleet_allowlisted() {
    let mut declared: Vec<String> = load_all_buildkite_defs()
        .iter()
        .flat_map(|def| def.credentials.keys().cloned().collect::<Vec<_>>())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    declared.sort();
    assert!(
        !declared.is_empty(),
        "no Buildkite check declares a credential — the allowlist assertion would be vacuous"
    );

    // One target carrying every credential any check asks for: if the fleet
    // allowlist and the checks ever disagree, `validate_target` bails here.
    let yaml = fleet_manifest_yaml(&declared);
    let manifest = FleetManifest::from_yaml(yaml.as_bytes()).unwrap_or_else(|e| {
        panic!("credentials declared by checks/buildkite are not fleet-allowlisted: {e}\n{yaml}")
    });
    assert_eq!(manifest.targets.len(), 1);
    assert_eq!(manifest.targets[0].source, "buildkite");
    for name in &declared {
        assert!(
            manifest.targets[0].credentials.contains_key(name),
            "credential '{name}' did not survive fleet validation"
        );
    }
}

#[test]
fn fleet_rejects_a_credential_the_buildkite_allowlist_does_not_carry() {
    // Negative control: proves the assertion above has teeth rather than the
    // allowlist simply accepting anything for this source.
    let yaml = fleet_manifest_yaml(&["BUILDKITE_NOT_A_REAL_CREDENTIAL".to_string()]);
    let err = FleetManifest::from_yaml(yaml.as_bytes())
        .expect_err("an unlisted credential must be rejected for source 'buildkite'");
    assert!(
        err.to_string().contains("not allowed"),
        "unexpected error: {err}"
    );
}

// ===========================================================================
// Control wiring: controls/cicd/ observers must resolve to real check ids
// ===========================================================================

const EXPECTED_BUILDKITE_CONTROL_IDS: &[&str] = &[
    "cicd.buildkite_agent_credentials",
    "cicd.buildkite_api_token_posture",
    "cicd.buildkite_authorization_boundaries",
    "cicd.buildkite_identity",
    "cicd.buildkite_pipeline_exposure",
];

fn load_cicd_controls() -> Vec<(PathBuf, Control)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("controls/cicd");
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|entry| entry.expect("dir entry").path())
        .filter(|p| {
            matches!(
                p.extension().and_then(|e| e.to_str()),
                Some("yaml") | Some("yml")
            )
        })
        .collect();
    paths.sort();

    paths
        .into_iter()
        .map(|path| {
            let yaml = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            let control = Control::load_yaml(&yaml)
                .unwrap_or_else(|e| panic!("parse control {}: {e}", path.display()));
            (path, control)
        })
        .collect()
}

#[test]
fn cicd_controls_deserialize() {
    let controls = load_cicd_controls();
    assert!(!controls.is_empty(), "controls/cicd/ is empty");

    for (path, control) in &controls {
        assert!(
            !control.id.is_empty(),
            "{}: control id is empty",
            path.display()
        );
        assert!(
            !control.name.is_empty(),
            "{}: control name is empty",
            control.id
        );
        assert!(
            !control.description.is_empty(),
            "{}: control description is empty",
            control.id
        );
        assert!(
            !control.evaluation_logic.cel_expression.is_empty()
                || !control.evaluation_logic.preset.is_empty(),
            "{}: control declares neither evaluation.cel nor evaluation.preset",
            control.id
        );
    }
}

#[test]
fn every_buildkite_control_observer_resolves_to_a_shipped_check() {
    // Locks in the module-id rewire from commit be83ec2. Before it, the controls
    // named `buildkite.*` observers that no registry entry could ever resolve, so
    // each control looked wired while being incapable of returning a finding.
    let check_ids: HashSet<String> = load_all_buildkite_defs()
        .iter()
        .map(|def| def.id.clone())
        .collect();

    let controls = load_cicd_controls();
    let buildkite_controls: Vec<&Control> = controls
        .iter()
        .map(|(_, c)| c)
        .filter(|c| c.id.starts_with("cicd.buildkite"))
        .collect();

    let control_ids: HashSet<&str> = buildkite_controls.iter().map(|c| c.id.as_str()).collect();
    let expected_control_ids: HashSet<&str> =
        EXPECTED_BUILDKITE_CONTROL_IDS.iter().copied().collect();
    assert_eq!(
        control_ids, expected_control_ids,
        "controls/cicd/ drifted from the declared Buildkite control set"
    );

    let known: Vec<String> = {
        let mut sorted: Vec<String> = check_ids.iter().cloned().collect();
        sorted.sort();
        sorted
    };

    let mut referenced: Vec<String> = Vec::new();
    for control in &buildkite_controls {
        assert!(
            !control.observers.is_empty(),
            "{}: control declares no observers",
            control.id
        );
        assert!(
            control.testers.is_empty(),
            "{}: no active Buildkite tester has been authorised",
            control.id
        );
        for observer in &control.observers {
            assert!(
                !observer.module_id.starts_with("buildkite."),
                "{}: observer '{}' uses the dotted vendor prefix that resolves to no registered \
                 module — YAML checks register under their own BK-* id",
                control.id,
                observer.module_id
            );
            assert!(
                check_ids.contains(&observer.module_id),
                "{}: observer '{}' does not resolve to any checks/buildkite/ check id ({known:?})",
                control.id,
                observer.module_id
            );
            referenced.push(observer.module_id.clone());
        }
    }

    // Bijection: every check is wired to exactly one control, and every control
    // observer points at a check. Neither an orphaned check nor a double-wired
    // one can slip back in.
    let unique: HashSet<String> = referenced.iter().cloned().collect();
    assert_eq!(
        unique.len(),
        referenced.len(),
        "a Buildkite check is referenced by more than one control: {referenced:?}"
    );
    assert_eq!(
        unique, check_ids,
        "checks/buildkite/ and controls/cicd/ observers are not in bijection"
    );
}

#[test]
fn buildkite_controls_keep_their_scope_ceiling_and_invocation_disclosures() {
    // Two paragraphs in every Buildkite control description are load-bearing:
    //   SCOPE CEILING — the ~40% of the hardening surface that lives on the
    //   agent host and is invisible to any control-plane read, so a pass is not
    //   evidence that the agent fleet is hardened.
    //   INVOCATION — these controls resolve under `--target '*'`, not
    //   `--target buildkite`, because target_matches_module compares the first
    //   dot-segment of a module_id and "BK-1" is never "buildkite".
    // Dropping either turns a documented limitation back into a silent one.
    for (path, control) in load_cicd_controls() {
        if !control.id.starts_with("cicd.buildkite") {
            continue;
        }
        assert!(
            control.description.contains("SCOPE CEILING"),
            "{}: lost the parity-ceiling paragraph",
            path.display()
        );
        assert!(
            control.description.contains("INVOCATION"),
            "{}: lost the invocation paragraph",
            path.display()
        );
    }
}
