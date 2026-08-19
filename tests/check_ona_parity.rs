// Integration tests: Ona (formerly Gitpod) HTH-parity checks under checks/ona/
// and the six AI-platform controls under controls/ai-platform/ that wire them.
//
// Mirrors the MockHTTPServer TDD pattern from tests/check_buildkite_parity.rs.
// Every one of the 18 checks gets a PASS fixture and a FAIL fixture built from
// Ona's real Protobuf-JSON response shapes, plus three degraded-read families
// that exercise the abstention guard the check descriptions promise:
//   - a non-200 Connect error (401 / 400 failed_precondition),
//   - a 200 whose body is not an object (a JSON array, a JSON scalar),
//   - for ONA-4.02 only, a 404 that is a FINDING rather than a collection failure.
// Structural tests then guard the whole vendor surface: every definition loads,
// ids are unique and match ^ONA-\d+\.\d+[a-z]?$, every CEL expression compiles,
// every declared credential is on the fleet allowlist, no check smuggles in the
// vestigial `implementation: native` field, and every control observer resolves
// to a real check id in strict bijection.
//
// Fixture provenance. Field names come from Ona's generated API reference
// (259 pages fetched 2026-08-18, all HTTP 200) and from a live token exercised
// against a real organization on 2026-08-19. The single most load-bearing
// fixture is `default_policies_body()`: it reproduces, key for key, what
// GetOrganizationPolicies actually returned for an organization that had set
// none of these controls. Protobuf-JSON OMITS default values, so every hardening
// boolean is ABSENT rather than false. That body must FAIL nine of the ten
// policy-backed checks and PASS ONA-5.01, whose hardened value is false — the
// asymmetry is asserted explicitly in
// `proto3_default_organization_fails_the_nine_and_passes_the_inverted_one`,
// because getting it backwards is the exact defect that would either accuse
// every hardened organization or absolve every default one.
//
// Deliberately self-contained. Cross-repo section validation (does
// `hth: "ona:N.N"` name a control that exists in the guide?) is owned by
// `scripts/hth_parity.py --validate`. This file asserts the shape of the
// reference, not its cross-repo target.

use std::collections::{HashMap, HashSet};
use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use cel_interpreter::Program;

use ocean::check::{load_check_file, register_check, CheckDefinition, CheckType};
use ocean::control::Control;
use ocean::evidence::{Evidence, StatusId};
use ocean::fleet::FleetManifest;
use ocean::module::{Executor, Registry};

/// A syntactically valid organization UUID. Ona constrains `organizationId` with
/// `string.uuid=true`, so a fixture that used a slug would not exercise the real
/// request shape.
const TEST_ORG: &str = "b0e12f6c-4c67-429d-a4a6-d9838b5da047";

// Severity ids as emitted into Evidence findings.
const SEV_INFO: i32 = 1;
const SEV_MEDIUM: i32 = 3;
const SEV_HIGH: i32 = 4;

// ---------------------------------------------------------------------------
// Mock HTTP server (copied from tests/check_buildkite_parity.rs — kept local so
// this file has no cross-test-file dependency).
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
                drain_request(&mut stream);
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

/// Read the ENTIRE request — headers and, when `Content-Length` says so, the
/// body — before the handler replies.
///
/// This is not tidiness. Every Ona step is a Connect RPC `POST` carrying a JSON
/// body, so a single `read()` frequently returns only the header segment and
/// leaves the body sitting in the socket's receive buffer. Closing a TCP socket
/// with unread inbound data makes the kernel send RST rather than FIN, and an
/// RST tells the peer to DISCARD data it has already buffered — including the
/// response we just wrote. The client then sees a truncated body,
/// `into_json::<JsonValue>()` fails, `execute_step` falls back to
/// `JsonValue::Null`, and the check reports `body_root == null` on an HTTP 200.
///
/// That surfaced here as an intermittent, migrating failure: a readability
/// assertion reporting "returned no policies object … (HTTP 200)" for a check
/// whose fixture plainly contained one, on a different check each run. Draining
/// first makes the close a clean FIN and the harness deterministic.
fn drain_request(stream: &mut std::net::TcpStream) {
    let mut raw: Vec<u8> = Vec::with_capacity(8192);
    let mut buf = [0u8; 4096];

    // Phase 1: read until the header terminator is present.
    let header_end = loop {
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return, // peer closed or errored; nothing more to drain
            Ok(n) => raw.extend_from_slice(&buf[..n]),
        }
    };

    // Phase 2: read exactly `Content-Length` more bytes, when declared.
    let headers = String::from_utf8_lossy(&raw[..header_end]).to_lowercase();
    let content_length = headers
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);

    while raw.len() < header_end + content_length {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
        }
    }
}

// ---------------------------------------------------------------------------
// Loader / execution helpers
// ---------------------------------------------------------------------------

fn ona_checks_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("checks/ona")
}

/// Load a bundled Ona check, rewriting the real host to the mock server.
///
/// Ona serves its entire Connect RPC surface from ONE host. The shipped checks
/// address `app.gitpod.io` rather than the documented `app.ona.com` because the
/// latter 308-redirects and HTTP clients drop the bearer token on the hop, so a
/// single rewrite covers every step in the vendor.
fn load_check_with_mock_urls(filename: &str, mock_base: &str) -> CheckDefinition {
    let path = ona_checks_dir().join(filename);
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    let rewritten = content.replace("https://app.gitpod.io", mock_base);
    serde_yaml::from_str(&rewritten).unwrap_or_else(|e| panic!("parse rewritten {filename}: {e}"))
}

/// Config supplying the two credentials the whole ONA-* set declares.
fn ona_config() -> HashMap<String, String> {
    let mut cfg = HashMap::new();
    cfg.insert("ONA_TOKEN".to_string(), "ona_pat_test_token".to_string());
    cfg.insert("ONA_ORGANIZATION_ID".to_string(), TEST_ORG.to_string());
    cfg
}

/// Register a loaded check and run it as an observer.
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

/// Run one shipped check against one mocked (status, body) pair.
fn run_against(
    filename: &str,
    status: u16,
    body: &serde_json::Value,
) -> (Vec<String>, Vec<Evidence>) {
    let server = MockHTTPServer::new(vec![(status, body.to_string())]);
    let def = load_check_with_mock_urls(filename, server.url());
    run_observer(def, &ona_config())
}

/// Run one shipped check against a raw body string (for non-JSON-object shapes).
fn run_against_raw(filename: &str, status: u16, body: &str) -> (Vec<String>, Vec<Evidence>) {
    let server = MockHTTPServer::new(vec![(status, body.to_string())]);
    let def = load_check_with_mock_urls(filename, server.url());
    run_observer(def, &ona_config())
}

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

/// Assert a guarded verdict ABSTAINED and said nothing it did not observe.
///
/// OCEAN emits `pass_message` on every Effective status, and an abstaining
/// assertion IS Effective — so a guard that merely abstains still publishes
/// whatever `pass_message` says. If that sentence asserts the positive fact, the
/// check has traded a false accusation for a false attestation, which is the
/// worse of the two for a compliance tool: an accusation gets investigated and
/// disproven, while an attestation is trusted and closes the loop on nothing.
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
    assert!(
        ev.status.contains("ONLY if"),
        "{assertion_id} [{shape}]: an abstaining verdict published a pass_message with no \
         hedge. OCEAN prints pass_message on every Effective status, and abstaining IS \
         Effective, so the sentence must stay true when nothing was read — every ONA \
         verdict states its dependency on the sibling readability assertion with an \
         'ONLY if' clause. Full message: '{}'",
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

// ---------------------------------------------------------------------------
// Fixture bodies
// ---------------------------------------------------------------------------

/// GetOrganizationPolicies as a REAL organization answered it on 2026-08-19 with
/// none of these controls configured.
///
/// This is the fixture the whole vendor turns on. Protobuf-JSON omits default
/// values, so `restrictAccountCreationToScim`, `securityPolicyId`,
/// `agentPolicy.commandDenyList`, `agentPolicy.mcpDisabled`,
/// `agentPolicy.scmToolsDisabled`, `maxPortAdmissionLevel`,
/// `portSharingDisabled`, `webBrowserDisabled`, `maximumEnvironmentLifetime`,
/// `maximumEnvironmentTimeout`, `disableFromScratch` and `allowLocalRunners` are
/// all ABSENT — not present-and-false. Referencing an absent name in CEL raises
/// "Undeclared reference", which the interpreter evaluates fail-closed, so every
/// shipped assertion `has()`-tests before it dereferences.
///
/// The eleven keys below are exactly the eleven the live call returned.
/// `conversationSharingPolicy`'s VALUE is a placeholder (no shipped check reads
/// it; only the key's presence matters for shape fidelity).
fn default_policies_body() -> serde_json::Value {
    serde_json::json!({
        "policies": {
            "agentPolicy": {
                "conversationSharingPolicy": "CONVERSATION_SHARING_POLICY_UNSPECIFIED",
                "automationPolicy": {}
            },
            "archiveEnvironmentsAfter": "172800s",
            "defaultEditorId": "code",
            "deleteArchivedEnvironmentsAfter": "1209600s",
            "maximumEnvironmentsPerUser": 10,
            "maximumRunningEnvironmentsPerUser": 5,
            "membersCreateProjects": true,
            "organizationId": TEST_ORG,
            "securityAgentPolicy": {},
            "vetoExecPolicy": {
                "safelist": [
                    "/usr/bin/ona",
                    "/usr/bin/gitpod",
                    "/bin/sh",
                    "/bin/bash",
                    "/usr/bin/env",
                    "/usr/bin/dash"
                ]
            },
            "vetoFilePolicy": {}
        }
    })
}

/// A fully hardened policies object — every field this vendor asserts on, set to
/// its hardened value.
fn hardened_policies_body() -> serde_json::Value {
    serde_json::json!({
        "policies": {
            "organizationId": TEST_ORG,
            "restrictAccountCreationToScim": true,
            "securityPolicyId": "6a2b7f6a-2c31-49ef-a1b0-a3a675aaa10f",
            "agentPolicy": {
                "commandDenyList": ["curl", "wget", "nc"],
                "mcpDisabled": true,
                "scmToolsDisabled": true
            },
            "maxPortAdmissionLevel": "ADMISSION_LEVEL_CREATOR_ONLY",
            "webBrowserDisabled": true,
            "maximumEnvironmentLifetime": "604800s",
            "maximumEnvironmentLifetimeStrict": true,
            "maximumEnvironmentTimeout": "1800s",
            "disableFromScratch": true,
            "allowLocalRunners": false,
            "archiveEnvironmentsAfter": "172800s",
            "deleteArchivedEnvironmentsAfter": "1209600s"
        }
    })
}

/// Build a policies body from the default shape with one or more overrides
/// merged into `policies`.
fn policies_with(overrides: serde_json::Value) -> serde_json::Value {
    let mut body = default_policies_body();
    let policies = body
        .get_mut("policies")
        .and_then(|p| p.as_object_mut())
        .expect("fixture has a policies object");
    for (k, v) in overrides.as_object().expect("overrides is an object") {
        policies.insert(k.clone(), v.clone());
    }
    body
}

/// A Connect RPC error as Ona actually returns one. Confirmed live on
/// `EventService/ListAuditLogs` and `WebhookService/ListWebhooks` for a
/// non-Enterprise organization.
fn connect_error_body(code: &str, message: &str) -> serde_json::Value {
    serde_json::json!({"code": code, "message": message})
}

// ---------------------------------------------------------------------------
// The table of policy-backed checks. All ten read the same endpoint, share the
// `policies_readable` discriminator, and differ only in their verdict.
// ---------------------------------------------------------------------------

/// (file, verdict assertion id, verdict severity, a phrase the abstention
/// message must NOT contain).
const POLICY_BACKED: &[(&str, &str, i32, &str)] = &[
    (
        "ONA-1.02-scim-required.check.yaml",
        "account_creation_restricted_to_scim",
        SEV_HIGH,
        "is restricted to SCIM",
    ),
    (
        "ONA-2.01-security-policy-assigned.check.yaml",
        "security_policy_assigned",
        SEV_HIGH,
        "SecurityPolicy is assigned for",
    ),
    (
        "ONA-2.02-command-deny-list.check.yaml",
        "command_deny_list_populated",
        SEV_MEDIUM,
        "is defined for",
    ),
    (
        "ONA-2.03-mcp-disabled.check.yaml",
        "mcp_disabled",
        SEV_MEDIUM,
        "MCP is disabled for",
    ),
    (
        "ONA-2.04-scm-tools-scoped.check.yaml",
        "scm_tools_disabled_or_scoped",
        SEV_MEDIUM,
        "are disabled or group-scoped for",
    ),
    (
        "ONA-3.01-port-admission-capped.check.yaml",
        "port_admission_capped",
        SEV_HIGH,
        "is capped for",
    ),
    (
        "ONA-3.02-web-browser-disabled.check.yaml",
        "web_browser_disabled",
        SEV_MEDIUM,
        "browser is disabled for",
    ),
    (
        "ONA-3.03-lifetime-enforced.check.yaml",
        "lifetime_and_timeout_bounded",
        SEV_MEDIUM,
        "are bounded and strictly enforced for",
    ),
    (
        "ONA-3.04-from-scratch-restricted.check.yaml",
        "from_scratch_disabled",
        SEV_MEDIUM,
        "is admin-only for",
    ),
    (
        "ONA-5.01-local-runners-blocked.check.yaml",
        "local_runners_not_permitted",
        SEV_MEDIUM,
        "are blocked for",
    ),
];

/// The one policy-backed check whose hardened value is FALSE, so an absent field
/// is the DESIRED state rather than the insecure default.
const INVERTED_DEFAULT_CHECK: &str = "ONA-5.01-local-runners-blocked.check.yaml";

// ===========================================================================
// The proto3-omission asymmetry — the single most important behaviour here.
// ===========================================================================

#[test]
fn proto3_default_organization_fails_the_nine_and_passes_the_inverted_one() {
    // A real organization with nothing configured returns a policies object whose
    // hardening booleans are ABSENT, because Protobuf-JSON omits default values.
    // Nine checks must FAIL that body — absence IS the insecure default, and it
    // must arrive as a clean verdict rather than as a CEL "Undeclared reference"
    // evaluated fail-closed into the same answer for the wrong reason.
    //
    // ONA-5.01 must PASS it. `allowLocalRunners`'s hardened value is FALSE, so an
    // organization that never touched the setting is already in the desired
    // state. Writing that assertion the same way as the other nine would fail
    // every correctly-configured organization — the exact inverse defect.
    for (file, verdict, severity, _) in POLICY_BACKED {
        let (ids, evidence) = run_against(file, 200, &default_policies_body());

        // The read itself succeeded in every case: this is a real 200 with a real
        // policies object. Nothing here is a collection failure.
        assert_effective(&ids, &evidence, "policies_readable");

        if *file == INVERTED_DEFAULT_CHECK {
            assert_effective(&ids, &evidence, verdict);
        } else {
            assert_ineffective(&ids, &evidence, verdict, *severity);
        }
    }
}

#[test]
fn hardened_organization_passes_every_policy_backed_check() {
    for (file, verdict, _, _) in POLICY_BACKED {
        let (ids, evidence) = run_against(file, 200, &hardened_policies_body());
        assert_effective(&ids, &evidence, "policies_readable");
        assert_effective(&ids, &evidence, verdict);
    }
}

// ===========================================================================
// Abstention: an organization that could not be read is never accused.
// ===========================================================================

/// The shapes that mean "no policies object was read", labelled.
///
/// Ona is Connect RPC: unlike GraphQL it reports request-level errors with real
/// HTTP status codes, so the unreadable set is status-driven rather than
/// body-driven. The two 200-with-wrong-shape entries exist because a 200 whose
/// body is not a JSON object would otherwise reach `has(body_root.policies)`
/// with an unnavigable receiver.
fn unreadable_shapes() -> Vec<(&'static str, u16, String)> {
    vec![
        (
            "401 invalid token",
            401,
            connect_error_body("unauthenticated", "invalid token").to_string(),
        ),
        (
            "403 permission denied",
            403,
            connect_error_body("permission_denied", "permission denied").to_string(),
        ),
        (
            "400 enterprise gating",
            400,
            connect_error_body(
                "failed_precondition",
                "feature is only available for enterprise customers",
            )
            .to_string(),
        ),
        ("500 server error", 500, "{}".to_string()),
        ("200 with an array body", 200, "[]".to_string()),
        (
            "200 with a JSON scalar body",
            200,
            "\"unexpected\"".to_string(),
        ),
        ("200 with a null body", 200, "null".to_string()),
        ("200 with an empty object body", 200, "{}".to_string()),
    ]
}

#[test]
fn every_policy_backed_check_abstains_on_every_unreadable_shape() {
    // Fail-closed evaluation is what makes this necessary: an assertion that
    // raises is recorded as Ineffective, so an unguarded dereference against an
    // unreadable body would publish the compliance finding — accusing an
    // organization nothing was read from. Each verdict must instead ABSTAIN, and
    // must not attest to the fact it never observed.
    for (file, verdict, _, forbidden) in POLICY_BACKED {
        for (shape, status, body) in unreadable_shapes() {
            let (ids, evidence) = run_against_raw(file, status, &body);
            assert_ineffective(&ids, &evidence, "policies_readable", SEV_INFO);
            assert_abstained_without_attesting(&ids, &evidence, verdict, shape, &[forbidden]);
        }
    }
}

#[test]
fn every_list_backed_check_abstains_on_every_unreadable_shape() {
    // Same contract for the list-backed reads. Note the distinction these tests
    // pin: an EMPTY list is READ (a real verdict), while an unreadable response
    // is NOT read (an abstention). Conflating them is how a compliance tool
    // reports "no violations" for an endpoint it never reached.
    let cases: &[(&str, &str, &str, &str)] = &[
        (
            "ONA-1.01-sso-configured.check.yaml",
            "sso_configurations_readable",
            "non_builtin_sso_active",
            "SSO configuration exists for",
        ),
        (
            "ONA-1.01b-domain-verified.check.yaml",
            "domain_verifications_readable",
            "verified_domain_exists",
            "email domain is VERIFIED for",
        ),
        (
            "ONA-1.02b-scim-enabled.check.yaml",
            "scim_configurations_readable",
            "scim_configuration_enabled",
            "SCIM configuration is enabled in",
        ),
        (
            "ONA-1.04-service-account-expiry.check.yaml",
            "service_accounts_readable",
            "every_service_account_expires",
            "carries an expiry for",
        ),
        (
            "ONA-1.04b-pat-read-only.check.yaml",
            "personal_access_tokens_readable",
            "no_read_write_personal_access_tokens",
            "tokens are read-only for",
        ),
        (
            "ONA-2.01b-veto-rules-defined.check.yaml",
            "security_policies_readable",
            "executable_rules_defined",
            "carries executable rules for",
        ),
    ];

    for (file, readable, verdict, forbidden) in cases {
        for (shape, status, body) in unreadable_shapes() {
            // A 200 with an empty object is READABLE for a list endpoint: it means
            // the list is empty (Protobuf-JSON omits empty repeated fields), which
            // is a real verdict rather than a collection failure. Only the shapes
            // that are genuinely unreadable belong in this loop.
            if shape == "200 with an empty object body" {
                continue;
            }
            let (ids, evidence) = run_against_raw(file, status, &body);
            assert_ineffective(&ids, &evidence, readable, SEV_INFO);
            assert_abstained_without_attesting(&ids, &evidence, verdict, shape, &[forbidden]);
        }
    }
}

#[test]
fn ona105_abstains_on_every_unreadable_shape() {
    for (shape, status, body) in unreadable_shapes() {
        // An empty object has no `organization` key, and `organization` is a
        // REQUIRED field on GetOrganizationResponse — so an empty object IS
        // unreadable here, unlike for the list endpoints.
        let (ids, evidence) =
            run_against_raw("ONA-1.05-no-invite-domains.check.yaml", status, &body);
        assert_ineffective(&ids, &evidence, "organization_readable", SEV_INFO);
        assert_abstained_without_attesting(
            &ids,
            &evidence,
            "no_invite_domains",
            shape,
            &["auto-admit is off for"],
        );
    }
}

// ===========================================================================
// Per-check verdicts on present-but-wrong values.
//
// The proto3-default body above covers "field absent". These cases cover the
// other failure mode — the field IS present and carries an unhardened value —
// which absence-based fixtures alone would never exercise.
// ===========================================================================

#[test]
fn ona202_fails_on_an_explicitly_empty_deny_list() {
    let body = policies_with(serde_json::json!({
        "agentPolicy": {"commandDenyList": []}
    }));
    let (ids, evidence) = run_against("ONA-2.02-command-deny-list.check.yaml", 200, &body);
    assert_effective(&ids, &evidence, "policies_readable");
    assert_ineffective(&ids, &evidence, "command_deny_list_populated", SEV_MEDIUM);
}

#[test]
fn ona203_fails_when_mcp_is_explicitly_enabled() {
    let body = policies_with(serde_json::json!({
        "agentPolicy": {"mcpDisabled": false}
    }));
    let (ids, evidence) = run_against("ONA-2.03-mcp-disabled.check.yaml", 200, &body);
    assert_ineffective(&ids, &evidence, "mcp_disabled", SEV_MEDIUM);
}

#[test]
fn ona204_passes_on_the_group_scoped_branch() {
    // Both hardened states are accepted and neither is ranked: an organization
    // running agent-driven PR workflows for one team has taken the scoped path
    // legitimately. Demanding the off switch would fail a correct configuration.
    let body = policies_with(serde_json::json!({
        "agentPolicy": {
            "scmToolsDisabled": false,
            "scmToolsAllowedGroupId": "3f1c9a20-77ab-4a11-9b1e-91b7a3e5d2c8"
        }
    }));
    let (ids, evidence) = run_against("ONA-2.04-scm-tools-scoped.check.yaml", 200, &body);
    assert_effective(&ids, &evidence, "scm_tools_disabled_or_scoped");
}

#[test]
fn ona204_fails_when_scm_tools_are_enabled_with_an_empty_group() {
    // The vendor's own wording for this state: "Empty means no restriction (all
    // users can use SCM tools if not disabled)."
    let body = policies_with(serde_json::json!({
        "agentPolicy": {"scmToolsDisabled": false, "scmToolsAllowedGroupId": ""}
    }));
    let (ids, evidence) = run_against("ONA-2.04-scm-tools-scoped.check.yaml", 200, &body);
    assert_ineffective(&ids, &evidence, "scm_tools_disabled_or_scoped", SEV_MEDIUM);
}

#[test]
fn ona301_fails_on_admission_level_everyone() {
    let body = policies_with(serde_json::json!({
        "maxPortAdmissionLevel": "ADMISSION_LEVEL_EVERYONE"
    }));
    let (ids, evidence) = run_against("ONA-3.01-port-admission-capped.check.yaml", 200, &body);
    assert_ineffective(&ids, &evidence, "port_admission_capped", SEV_HIGH);
}

#[test]
fn ona301_passes_on_the_deprecated_owner_only_value() {
    // `ADMISSION_LEVEL_OWNER_ONLY` is marked deprecated in the vendor's enum table
    // AND used in the vendor's own CreateSecurityPolicy cURL example on the same
    // page, so it is genuinely in the wild. It enforces the same boundary as
    // creator-only, so it passes; the finding text names it for migration rather
    // than the check silently normalising it away.
    let body = policies_with(serde_json::json!({
        "maxPortAdmissionLevel": "ADMISSION_LEVEL_OWNER_ONLY"
    }));
    let (ids, evidence) = run_against("ONA-3.01-port-admission-capped.check.yaml", 200, &body);
    assert_effective(&ids, &evidence, "port_admission_capped");
}

#[test]
fn ona301_passes_when_port_sharing_is_disabled_outright() {
    // The vendor: the legacy `portSharingDisabled` field, "when true, takes
    // precedence and blocks all user-initiated port sharing". It must satisfy the
    // control even with no admission level set at all.
    let body = policies_with(serde_json::json!({"portSharingDisabled": true}));
    let (ids, evidence) = run_against("ONA-3.01-port-admission-capped.check.yaml", 200, &body);
    assert_effective(&ids, &evidence, "port_admission_capped");
}

#[test]
fn ona303_fails_on_zero_durations_which_mean_no_limit() {
    // The inversion this check exists to catch. `maximumEnvironmentTimeout` must
    // be "0s (no limit) or at least 1800s", and `maximumEnvironmentLifetime`
    // "0 means no maximum lifetime". A hardening script that ZEROES these fields
    // weakens the organization, and a check that only tested `has()` would call
    // that hardened.
    let body = policies_with(serde_json::json!({
        "maximumEnvironmentLifetime": "0s",
        "maximumEnvironmentLifetimeStrict": true,
        "maximumEnvironmentTimeout": "0s"
    }));
    let (ids, evidence) = run_against("ONA-3.03-lifetime-enforced.check.yaml", 200, &body);
    assert_effective(&ids, &evidence, "policies_readable");
    assert_ineffective(&ids, &evidence, "lifetime_and_timeout_bounded", SEV_MEDIUM);
}

#[test]
fn ona303_fails_when_the_lifetime_bound_is_not_strictly_enforced() {
    // Without `maximumEnvironmentLifetimeStrict`, a lifetime bound is advisory:
    // the lockdown timestamp passes and the environment still starts.
    let body = policies_with(serde_json::json!({
        "maximumEnvironmentLifetime": "604800s",
        "maximumEnvironmentLifetimeStrict": false,
        "maximumEnvironmentTimeout": "1800s"
    }));
    let (ids, evidence) = run_against("ONA-3.03-lifetime-enforced.check.yaml", 200, &body);
    assert_ineffective(&ids, &evidence, "lifetime_and_timeout_bounded", SEV_MEDIUM);
}

#[test]
fn ona501_fails_only_when_local_runners_are_explicitly_allowed() {
    let body = policies_with(serde_json::json!({"allowLocalRunners": true}));
    let (ids, evidence) = run_against(INVERTED_DEFAULT_CHECK, 200, &body);
    assert_effective(&ids, &evidence, "policies_readable");
    assert_ineffective(&ids, &evidence, "local_runners_not_permitted", SEV_MEDIUM);
}

#[test]
fn ona201_fails_on_an_empty_security_policy_id() {
    // The vendor documents the empty string as the clearing value, so an
    // explicitly-empty id is the same unassigned state as an absent key.
    let body = policies_with(serde_json::json!({"securityPolicyId": ""}));
    let (ids, evidence) = run_against("ONA-2.01-security-policy-assigned.check.yaml", 200, &body);
    assert_ineffective(&ids, &evidence, "security_policy_assigned", SEV_HIGH);
}

// ===========================================================================
// ONA-1.01 / ONA-1.01b / ONA-1.02b — list-backed identity reads
// ===========================================================================

#[test]
fn ona101_fails_when_only_builtin_providers_are_active() {
    // This is the live shape from a real tenant with NO federation configured:
    // two entries, both PROVIDER_TYPE_BUILTIN and both ACTIVE — Ona's own Google
    // and GitHub login buttons. A check written as "an ACTIVE SSO configuration
    // exists" would pass this and attest to federation that is not there.
    let body = serde_json::json!({
        "ssoConfigurations": [
            {
                "id": "1f0b0d5e-1e1a-4a4e-9d55-9d3f2a1c0b01",
                "providerType": "PROVIDER_TYPE_BUILTIN",
                "state": "SSO_CONFIGURATION_STATE_ACTIVE",
                "issuerUrl": "https://accounts.google.com"
            },
            {
                "id": "1f0b0d5e-1e1a-4a4e-9d55-9d3f2a1c0b02",
                "providerType": "PROVIDER_TYPE_BUILTIN",
                "state": "SSO_CONFIGURATION_STATE_ACTIVE",
                "issuerUrl": "https://github.com"
            }
        ]
    });
    let (ids, evidence) = run_against("ONA-1.01-sso-configured.check.yaml", 200, &body);
    assert_effective(&ids, &evidence, "sso_configurations_readable");
    assert_ineffective(&ids, &evidence, "non_builtin_sso_active", SEV_HIGH);
}

#[test]
fn ona101_passes_on_an_active_custom_provider() {
    let body = serde_json::json!({
        "ssoConfigurations": [
            {
                "id": "1f0b0d5e-1e1a-4a4e-9d55-9d3f2a1c0b01",
                "providerType": "PROVIDER_TYPE_BUILTIN",
                "state": "SSO_CONFIGURATION_STATE_ACTIVE"
            },
            {
                "id": "1f0b0d5e-1e1a-4a4e-9d55-9d3f2a1c0b03",
                "providerType": "PROVIDER_TYPE_CUSTOM",
                "state": "SSO_CONFIGURATION_STATE_ACTIVE",
                "issuerUrl": "https://example.okta.com",
                "emailDomains": ["example.com"]
            }
        ]
    });
    let (ids, evidence) = run_against("ONA-1.01-sso-configured.check.yaml", 200, &body);
    assert_effective(&ids, &evidence, "non_builtin_sso_active");
}

#[test]
fn ona101_fails_when_the_custom_provider_is_inactive() {
    let body = serde_json::json!({
        "ssoConfigurations": [{
            "id": "1f0b0d5e-1e1a-4a4e-9d55-9d3f2a1c0b03",
            "providerType": "PROVIDER_TYPE_CUSTOM",
            "state": "SSO_CONFIGURATION_STATE_INACTIVE"
        }]
    });
    let (ids, evidence) = run_against("ONA-1.01-sso-configured.check.yaml", 200, &body);
    assert_ineffective(&ids, &evidence, "non_builtin_sso_active", SEV_HIGH);
}

#[test]
fn ona101_fails_on_an_omitted_empty_list_but_still_reads_it_as_read() {
    // Protobuf-JSON omits empty repeated fields, so an organization with zero SSO
    // configurations returns `{}` — no `ssoConfigurations` key at all. That is a
    // genuine FAIL (there is no federation), and crucially NOT an abstention: the
    // readability assertion must still pass, or an empty result would be
    // indistinguishable from an unreachable endpoint.
    let (ids, evidence) = run_against_raw("ONA-1.01-sso-configured.check.yaml", 200, "{}");
    assert_effective(&ids, &evidence, "sso_configurations_readable");
    assert_ineffective(&ids, &evidence, "non_builtin_sso_active", SEV_HIGH);
}

#[test]
fn ona101b_passes_on_a_verified_domain_and_fails_on_a_pending_one() {
    let verified = serde_json::json!({
        "domainVerifications": [{
            "id": "2a1b0c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
            "domain": "example.com",
            "state": "DOMAIN_VERIFICATION_STATE_VERIFIED",
            "verifiedAt": "2026-08-01T10:00:00Z"
        }]
    });
    let (ids, evidence) = run_against("ONA-1.01b-domain-verified.check.yaml", 200, &verified);
    assert_effective(&ids, &evidence, "verified_domain_exists");

    // A started-but-unfinished verification grants nothing, so PENDING must not
    // count. "Sign in with SSO" is not rendered until a domain reaches VERIFIED.
    let pending = serde_json::json!({
        "domainVerifications": [{
            "id": "2a1b0c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
            "domain": "example.com",
            "state": "DOMAIN_VERIFICATION_STATE_PENDING"
        }]
    });
    let (ids, evidence) = run_against("ONA-1.01b-domain-verified.check.yaml", 200, &pending);
    assert_effective(&ids, &evidence, "domain_verifications_readable");
    assert_ineffective(&ids, &evidence, "verified_domain_exists", SEV_MEDIUM);
}

#[test]
fn ona102b_fails_on_the_created_but_not_enabled_trap() {
    // `CreateSCIMConfigurationRequest` has NO `enabled` field — only
    // `UpdateSCIMConfiguration` does — so a one-call provisioning script leaves a
    // configuration that exists, shows in the console, and provisions nothing.
    // Protobuf-JSON omits false booleans, so that state arrives with no `enabled`
    // key at all.
    let body = serde_json::json!({
        "scimConfigurations": [{
            "id": "5c4b3a29-1e0d-4f8a-b7c6-d5e4f3a2b1c0",
            "ssoConfigurationId": "1f0b0d5e-1e1a-4a4e-9d55-9d3f2a1c0b03",
            "tokenExpiresAt": "2026-12-01T00:00:00Z"
        }]
    });
    let (ids, evidence) = run_against("ONA-1.02b-scim-enabled.check.yaml", 200, &body);
    assert_effective(&ids, &evidence, "scim_configurations_readable");
    assert_ineffective(&ids, &evidence, "scim_configuration_enabled", SEV_HIGH);
}

#[test]
fn ona102b_passes_on_an_enabled_configuration() {
    let body = serde_json::json!({
        "scimConfigurations": [{
            "id": "5c4b3a29-1e0d-4f8a-b7c6-d5e4f3a2b1c0",
            "enabled": true,
            "ssoConfigurationId": "1f0b0d5e-1e1a-4a4e-9d55-9d3f2a1c0b03",
            "tokenExpiresAt": "2026-12-01T00:00:00Z"
        }]
    });
    let (ids, evidence) = run_against("ONA-1.02b-scim-enabled.check.yaml", 200, &body);
    assert_effective(&ids, &evidence, "scim_configuration_enabled");
}

// ===========================================================================
// ONA-1.04 / ONA-1.04b — credential hygiene
// ===========================================================================

#[test]
fn ona104_passes_when_every_live_service_account_carries_an_expiry() {
    let body = serde_json::json!({
        "serviceAccounts": [
            {"id": "aa000000-0000-4000-8000-000000000001", "name": "ci", "validUntil": "2027-01-01T00:00:00Z"},
            {"id": "aa000000-0000-4000-8000-000000000002", "name": "deploy", "validUntil": "2026-12-01T00:00:00Z"}
        ]
    });
    let (ids, evidence) = run_against("ONA-1.04-service-account-expiry.check.yaml", 200, &body);
    assert_effective(&ids, &evidence, "service_accounts_readable");
    assert_effective(&ids, &evidence, "every_service_account_expires");
}

#[test]
fn ona104_fails_on_an_unbounded_service_account() {
    let body = serde_json::json!({
        "serviceAccounts": [
            {"id": "aa000000-0000-4000-8000-000000000001", "name": "ci", "validUntil": "2027-01-01T00:00:00Z"},
            {"id": "aa000000-0000-4000-8000-000000000003", "name": "legacy-bot"}
        ]
    });
    let (ids, evidence) = run_against("ONA-1.04-service-account-expiry.check.yaml", 200, &body);
    assert_ineffective(&ids, &evidence, "every_service_account_expires", SEV_MEDIUM);
}

#[test]
fn ona104_ignores_a_suspended_account_with_no_expiry() {
    // `suspended` marks a soft-deleted account that "cannot be used for
    // authentication", so an expiry on it would be meaningless and flagging it
    // would be noise.
    let body = serde_json::json!({
        "serviceAccounts": [
            {"id": "aa000000-0000-4000-8000-000000000001", "name": "ci", "validUntil": "2027-01-01T00:00:00Z"},
            {"id": "aa000000-0000-4000-8000-000000000004", "name": "retired-bot", "suspended": true}
        ]
    });
    let (ids, evidence) = run_against("ONA-1.04-service-account-expiry.check.yaml", 200, &body);
    assert_effective(&ids, &evidence, "every_service_account_expires");
}

#[test]
fn ona104_passes_vacuously_when_no_service_account_exists() {
    // Protobuf-JSON omits the empty list. No service account exists, so none is
    // unbounded — this must PASS, and it must do so while still reporting the read
    // as successful.
    let (ids, evidence) = run_against_raw("ONA-1.04-service-account-expiry.check.yaml", 200, "{}");
    assert_effective(&ids, &evidence, "service_accounts_readable");
    assert_effective(&ids, &evidence, "every_service_account_expires");
}

#[test]
fn ona104b_flags_a_token_with_no_read_only_key_as_write_capable() {
    // The live shape: entries carried `expiresAt` and NO `readOnly` key, because
    // Protobuf-JSON omits false booleans. Reading absence as "unknown" or as
    // read-only would silently under-report every default token — and the console
    // dialog defaults to the Read & Write tab, so defaults are the common case.
    let body = serde_json::json!({
        "personalAccessTokens": [{
            "id": "bb000000-0000-4000-8000-000000000001",
            "userId": "cc000000-0000-4000-8000-000000000001",
            "expiresAt": "2026-11-01T00:00:00Z"
        }]
    });
    let (ids, evidence) = run_against("ONA-1.04b-pat-read-only.check.yaml", 200, &body);
    assert_effective(&ids, &evidence, "personal_access_tokens_readable");
    // INFO severity: a write-capable PAT is a review item, not a defect.
    assert_ineffective(
        &ids,
        &evidence,
        "no_read_write_personal_access_tokens",
        SEV_INFO,
    );
}

#[test]
fn ona104b_passes_when_every_visible_token_is_read_only() {
    let body = serde_json::json!({
        "personalAccessTokens": [{
            "id": "bb000000-0000-4000-8000-000000000002",
            "userId": "cc000000-0000-4000-8000-000000000001",
            "readOnly": true,
            "expiresAt": "2026-11-01T00:00:00Z"
        }]
    });
    let (ids, evidence) = run_against("ONA-1.04b-pat-read-only.check.yaml", 200, &body);
    assert_effective(&ids, &evidence, "no_read_write_personal_access_tokens");
}

// ===========================================================================
// ONA-1.05 — invite domains (absence PASSES)
// ===========================================================================

#[test]
fn ona105_passes_when_invite_domains_are_absent_or_empty() {
    // Three hardened shapes, all of which Protobuf-JSON can produce for "no
    // auto-admit": no `inviteDomains` key, an `inviteDomains` object with no
    // `domains` key, and an explicitly empty array. Each must PASS — an
    // absence-fails reading here would accuse every correctly configured
    // organization.
    let shapes = vec![
        serde_json::json!({"organization": {"id": TEST_ORG, "name": "Acme"}}),
        serde_json::json!({"organization": {"id": TEST_ORG, "inviteDomains": {}}}),
        serde_json::json!({"organization": {"id": TEST_ORG, "inviteDomains": {"domains": []}}}),
    ];
    for body in shapes {
        let (ids, evidence) = run_against("ONA-1.05-no-invite-domains.check.yaml", 200, &body);
        assert_effective(&ids, &evidence, "organization_readable");
        assert_effective(&ids, &evidence, "no_invite_domains");
    }
}

#[test]
fn ona105_fails_when_a_domain_auto_admits() {
    let body = serde_json::json!({
        "organization": {
            "id": TEST_ORG,
            "name": "Acme",
            "tier": "ORGANIZATION_TIER_ENTERPRISE",
            "inviteDomains": {"domains": ["example.com"]}
        }
    });
    let (ids, evidence) = run_against("ONA-1.05-no-invite-domains.check.yaml", 200, &body);
    assert_effective(&ids, &evidence, "organization_readable");
    assert_ineffective(&ids, &evidence, "no_invite_domains", SEV_MEDIUM);
}

// ===========================================================================
// ONA-2.01b — security policy executable rules
// ===========================================================================

#[test]
fn ona201b_passes_when_a_policy_carries_executable_rules() {
    let body = serde_json::json!({
        "securityPolicies": [{
            "id": "6a2b7f6a-2c31-49ef-a1b0-a3a675aaa10f",
            "metadata": {"name": "veto-exec-baseline"},
            "spec": {
                "executables": {
                    "defaultEffect": "EFFECT_ALLOW",
                    "rules": [
                        {"path": "/usr/bin/npx", "effect": "EFFECT_AUDIT"},
                        {"path": "nc", "effect": "EFFECT_BLOCK"}
                    ]
                }
            }
        }]
    });
    let (ids, evidence) = run_against("ONA-2.01b-veto-rules-defined.check.yaml", 200, &body);
    assert_effective(&ids, &evidence, "security_policies_readable");
    assert_effective(&ids, &evidence, "executable_rules_defined");
}

#[test]
fn ona201b_fails_on_a_policy_whose_rule_list_is_empty_or_omitted() {
    // A SecurityPolicy that exists but restricts nothing — the "empty shell" the
    // split between ONA-2.01 and ONA-2.01b exists to distinguish from a policy
    // that has rules but was never assigned.
    let body = serde_json::json!({
        "securityPolicies": [{
            "id": "6a2b7f6a-2c31-49ef-a1b0-a3a675aaa10f",
            "metadata": {"name": "empty-shell"},
            "spec": {"executables": {"defaultEffect": "EFFECT_ALLOW"}}
        }]
    });
    let (ids, evidence) = run_against("ONA-2.01b-veto-rules-defined.check.yaml", 200, &body);
    assert_effective(&ids, &evidence, "security_policies_readable");
    assert_ineffective(&ids, &evidence, "executable_rules_defined", SEV_MEDIUM);
}

#[test]
fn ona201b_fails_when_no_policy_exists_at_all() {
    let (ids, evidence) = run_against_raw("ONA-2.01b-veto-rules-defined.check.yaml", 200, "{}");
    assert_effective(&ids, &evidence, "security_policies_readable");
    assert_ineffective(&ids, &evidence, "executable_rules_defined", SEV_MEDIUM);
}

// ===========================================================================
// ONA-4.02 — OIDC, where a 404 is a FINDING rather than a collection failure
// ===========================================================================

#[test]
fn ona402_treats_a_404_as_not_configured_not_as_unreadable() {
    // `GetOIDCConfig` answers 404 `{"code":"not_found","message":"OIDC config not
    // found"}` when nothing is configured. That is a DEFINITIVE answer about the
    // organization's state, so abstaining on it would suppress the very finding
    // this check exists to raise. The reachability assertion must PASS on a 404,
    // and the verdict must FAIL.
    let body = connect_error_body("not_found", "OIDC config not found");
    let (ids, evidence) = run_against("ONA-4.02-oidc-v3-scoped.check.yaml", 404, &body);
    assert_effective(&ids, &evidence, "oidc_endpoint_answered");
    assert_ineffective(
        &ids,
        &evidence,
        "oidc_v3_with_scoped_sub_claims",
        SEV_MEDIUM,
    );
}

#[test]
fn ona402_fails_on_v2_and_on_bare_v3() {
    // V2 cannot be scoped at all. Bare V3 is the subtle one: the version is right
    // but the `sub` claim carries only its default shape, so the tightest cloud
    // trust-policy condition an operator can write pins the whole ORGANIZATION.
    let v2 = serde_json::json!({"oidcConfig": {"v2": {}}});
    let (ids, evidence) = run_against("ONA-4.02-oidc-v3-scoped.check.yaml", 200, &v2);
    assert_effective(&ids, &evidence, "oidc_endpoint_answered");
    assert_ineffective(
        &ids,
        &evidence,
        "oidc_v3_with_scoped_sub_claims",
        SEV_MEDIUM,
    );

    let bare_v3 = serde_json::json!({"oidcConfig": {"v3": {}}});
    let (ids, evidence) = run_against("ONA-4.02-oidc-v3-scoped.check.yaml", 200, &bare_v3);
    assert_effective(&ids, &evidence, "oidc_endpoint_answered");
    assert_ineffective(
        &ids,
        &evidence,
        "oidc_v3_with_scoped_sub_claims",
        SEV_MEDIUM,
    );
}

#[test]
fn ona402_passes_on_v3_with_extra_sub_fields() {
    let body = serde_json::json!({
        "oidcConfig": {"v3": {"extraSubFields": ["project_id", "runner_id"]}}
    });
    let (ids, evidence) = run_against("ONA-4.02-oidc-v3-scoped.check.yaml", 200, &body);
    assert_effective(&ids, &evidence, "oidc_endpoint_answered");
    assert_effective(&ids, &evidence, "oidc_v3_with_scoped_sub_claims");
}

#[test]
fn ona402_abstains_only_on_genuinely_ambiguous_statuses() {
    // 401 / 403 / 400-enterprise / 5xx say nothing about the organization's OIDC
    // state, so they must abstain — and must not attest to a configuration that
    // was never read. A 404 is deliberately absent from this list; it is covered
    // by `ona402_treats_a_404_as_not_configured_not_as_unreadable`.
    let ambiguous: &[(&str, u16, serde_json::Value)] = &[
        (
            "401 invalid token",
            401,
            connect_error_body("unauthenticated", "invalid token"),
        ),
        (
            "403 permission denied",
            403,
            connect_error_body("permission_denied", "permission denied"),
        ),
        (
            "400 enterprise gating",
            400,
            connect_error_body(
                "failed_precondition",
                "feature is only available for enterprise customers",
            ),
        ),
        ("500 server error", 500, serde_json::json!({})),
    ];

    for (shape, status, body) in ambiguous {
        let (ids, evidence) = run_against("ONA-4.02-oidc-v3-scoped.check.yaml", *status, body);
        assert_ineffective(&ids, &evidence, "oidc_endpoint_answered", SEV_INFO);
        assert_abstained_without_attesting(
            &ids,
            &evidence,
            "oidc_v3_with_scoped_sub_claims",
            shape,
            &["configuration carrying extraSubFields for"],
        );
    }
}

// ---------------------------------------------------------------------------
// Structural invariants across the whole vendor surface
// ---------------------------------------------------------------------------

const EXPECTED_ONA_CHECK_IDS: &[&str] = &[
    "ONA-1.01",
    "ONA-1.01b",
    "ONA-1.02",
    "ONA-1.02b",
    "ONA-1.04",
    "ONA-1.04b",
    "ONA-1.05",
    "ONA-2.01",
    "ONA-2.01b",
    "ONA-2.02",
    "ONA-2.03",
    "ONA-2.04",
    "ONA-3.01",
    "ONA-3.02",
    "ONA-3.03",
    "ONA-3.04",
    "ONA-4.02",
    "ONA-5.01",
];

/// Load every shipped Ona check through the SAME loader the binary uses.
///
/// `load_check_file` rather than a bare `serde_yaml::from_str`: a check that
/// parses as YAML but fails the loader's own validation would ship broken while a
/// direct-deserialisation test called it fine.
fn load_all_ona_defs() -> Vec<CheckDefinition> {
    let dir = ona_checks_dir();
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|entry| entry.expect("dir entry").path())
        .filter(|p| p.to_string_lossy().ends_with(".check.yaml"))
        .collect();
    paths.sort();

    paths
        .into_iter()
        .map(|path| {
            load_check_file(&path).unwrap_or_else(|e| panic!("load {}: {e}", path.display()))
        })
        .collect()
}

#[test]
fn every_ona_check_loads_and_the_set_matches_the_declared_inventory() {
    let defs = load_all_ona_defs();
    let ids: Vec<String> = defs.iter().map(|d| d.id.clone()).collect();

    let unique: HashSet<&String> = ids.iter().collect();
    assert_eq!(
        unique.len(),
        ids.len(),
        "duplicate Ona check ids among {ids:?}"
    );

    let found: HashSet<&str> = ids.iter().map(|s| s.as_str()).collect();
    let expected: HashSet<&str> = EXPECTED_ONA_CHECK_IDS.iter().copied().collect();
    assert_eq!(
        found, expected,
        "checks/ona/ drifted from the declared check set"
    );
}

#[test]
fn every_ona_check_id_matches_the_naming_convention() {
    // `^ONA-\d+\.\d+[a-z]?$`, checked without pulling in a regex dependency this
    // test file does not otherwise need. The trailing letter is the sub-check
    // suffix (1.01b), which schemas/check.schema.json's own id pattern allows.
    for def in load_all_ona_defs() {
        let rest = def
            .id
            .strip_prefix("ONA-")
            .unwrap_or_else(|| panic!("{}: id must start with 'ONA-'", def.id));

        let (numeric, suffix) = match rest.chars().last() {
            Some(c) if c.is_ascii_lowercase() => (&rest[..rest.len() - 1], Some(c)),
            _ => (rest, None),
        };

        let mut parts = numeric.split('.');
        let major = parts.next().unwrap_or("");
        let minor = parts.next().unwrap_or("");
        assert!(
            parts.next().is_none(),
            "{}: expected ONA-N.NN[a-z], got extra dot-segments",
            def.id
        );
        assert!(
            !major.is_empty() && major.chars().all(|c| c.is_ascii_digit()),
            "{}: major segment '{major}' is not numeric",
            def.id
        );
        assert!(
            !minor.is_empty() && minor.chars().all(|c| c.is_ascii_digit()),
            "{}: minor segment '{minor}' is not numeric",
            def.id
        );
        if let Some(c) = suffix {
            assert!(
                c.is_ascii_lowercase(),
                "{}: suffix '{c}' must be a lowercase letter",
                def.id
            );
        }
    }
}

#[test]
fn every_ona_check_declares_the_required_metadata() {
    for def in load_all_ona_defs() {
        assert_eq!(def.source, "ona", "{}: source should be 'ona'", def.id);
        assert!(
            !def.references.hth.is_empty(),
            "{}: references.hth is mandatory for Ona checks",
            def.id
        );
        assert!(
            def.references.hth.starts_with("ona:"),
            "{}: references.hth should be 'ona:N.N', got '{}'",
            def.id,
            def.references.hth
        );
        assert!(
            matches!(def.profile.as_str(), "L1" | "L2" | "L3"),
            "{}: profile must be L1/L2/L3, got '{}'",
            def.id,
            def.profile
        );
        assert!(!def.steps.is_empty(), "{}: check has no steps", def.id);
        assert!(
            !def.assertions.is_empty(),
            "{}: check has no assertions",
            def.id
        );
        assert!(
            def.remediation.is_some(),
            "{}: every Ona check must carry remediation",
            def.id
        );
        // Every shipped Ona check is read-only. These run against a real
        // organization; promoting one to `type: active` is a safety decision that
        // must be made deliberately, not by omission.
        assert_eq!(
            def.check_type,
            CheckType::Passive,
            "{}: no active Ona check has been authorised",
            def.id
        );
    }
}

#[test]
fn every_ona_check_declares_ona_token_and_the_org_input() {
    for def in load_all_ona_defs() {
        let cred = def
            .credentials
            .get("ONA_TOKEN")
            .unwrap_or_else(|| panic!("{}: must declare the ONA_TOKEN credential", def.id));
        assert_eq!(
            cred.cred_type, "api_token",
            "{}: wrong credential type",
            def.id
        );
        assert!(cred.required, "{}: ONA_TOKEN must be required", def.id);
        assert_eq!(
            def.credentials.len(),
            1,
            "{}: Ona authenticates every method with one bearer token; a second \
             declared credential means something drifted",
            def.id
        );

        let org = def
            .inputs
            .get("org")
            .unwrap_or_else(|| panic!("{}: must declare the 'org' input", def.id));
        assert_eq!(
            org.env, "ONA_ORGANIZATION_ID",
            "{}: the org input must read ONA_ORGANIZATION_ID",
            def.id
        );
        assert!(org.required, "{}: the org input must be required", def.id);
    }
}

#[test]
fn every_ona_step_addresses_the_redirect_safe_host_over_connect_rpc() {
    // The documented base `https://app.ona.com/api` 308-redirects to
    // app.gitpod.io, and HTTP clients drop the Authorization header across that
    // cross-origin hop — so a check pointed at app.ona.com arrives
    // unauthenticated and fails with a 401 that reads like a bad credential.
    // Pinning the host here keeps a well-meaning "fix the legacy hostname" edit
    // from silently breaking every check in the vendor.
    for def in load_all_ona_defs() {
        for step in &def.steps {
            assert_eq!(
                step.request.method, "POST",
                "{}/{}: Connect RPC unary methods are POST-only",
                def.id, step.id
            );
            assert!(
                step.request
                    .url
                    .starts_with("https://app.gitpod.io/api/gitpod.v1."),
                "{}/{}: expected a Connect RPC path on app.gitpod.io, got '{}'",
                def.id,
                step.id,
                step.request.url
            );
            assert!(
                !step.request.url.contains("app.ona.com"),
                "{}/{}: app.ona.com 308-redirects and clients drop the bearer on the hop",
                def.id,
                step.id
            );
            assert_eq!(
                step.request
                    .headers
                    .get("Authorization")
                    .map(String::as_str),
                Some("Bearer {{ONA_TOKEN}}"),
                "{}/{}: missing or malformed bearer header",
                def.id,
                step.id
            );
            assert!(
                !step.note.is_empty(),
                "{}/{}: every step must carry the note explaining the host choice",
                def.id,
                step.id
            );
        }
    }
}

#[test]
fn every_ona_check_binds_the_always_bound_reachability_anchors() {
    // `body_root` (`$`) and `body_is_object` (`$is_object`) are the JSONPaths
    // `jsonpath_extract` binds for EVERY response shape. Every guard in this
    // vendor is written against them, so a check that stopped extracting one
    // would leave its verdict dereferencing a name that may be unbound — and the
    // interpreter's fail-closed `.unwrap_or(false)` would publish that as a
    // finding against an organization it never read.
    for def in load_all_ona_defs() {
        for step in &def.steps {
            assert_eq!(
                step.extract.get("body_root").map(String::as_str),
                Some("$"),
                "{}/{}: must extract body_root as '$'",
                def.id,
                step.id
            );
            assert_eq!(
                step.extract.get("body_is_object").map(String::as_str),
                Some("$is_object"),
                "{}/{}: must extract body_is_object as '$is_object'. `!body_is_array` is \
                 NOT a substitute: cel-interpreter answers `has(scalar.field)` with false \
                 rather than an error, so a scalar body is indistinguishable from an \
                 object that omits the key — and those need opposite verdicts",
                def.id,
                step.id
            );
        }
    }
}

#[test]
fn no_ona_extraction_uses_a_nested_array_wildcard() {
    // `jsonpath_extract` resolves the wildcard `$[*].field` only at the body ROOT,
    // and `navigate_fields` walks objects only — so `$.serviceAccounts[*].validUntil`
    // silently binds NOTHING. Ona's list responses are objects with the array
    // nested under a key, which makes this the easy mistake to make here; the
    // shipped checks extract the array whole and iterate in CEL instead.
    for def in load_all_ona_defs() {
        for step in &def.steps {
            for (name, path) in &step.extract {
                if path.starts_with("$[*]") {
                    continue; // root wildcard is supported
                }
                assert!(
                    !path.contains("[*]"),
                    "{}/{}: extraction '{name}' uses a NESTED array wildcard ('{path}'), \
                     which jsonpath_extract cannot resolve — it would bind nothing",
                    def.id,
                    step.id
                );
            }
        }
    }
}

#[test]
fn no_ona_check_declares_a_native_implementation() {
    // `implementation: native` routes a check to a compiled Rust observer via
    // `modules::native_observer()`. No native Ona observer exists, so the field
    // could only be vestigial here — and setting it would make the check fail to
    // dispatch rather than degrade.
    for def in load_all_ona_defs() {
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
fn every_ona_assertion_expression_compiles_as_cel() {
    // The interpreter compiles assertion expressions lazily, at evaluation time,
    // and `evaluate_all_assertions` swallows the error into `unwrap_or(false)` —
    // so an un-compilable expression ships as a PERMANENT false accusation rather
    // than as a loud failure. Compile them all up front.
    let mut failures = Vec::new();
    let mut compiled = 0;
    for def in load_all_ona_defs() {
        for assertion in &def.assertions {
            compiled += 1;
            if let Err(e) = Program::compile(&assertion.expr) {
                failures.push(format!(
                    "{}/{}: {e}\n    expr: {}",
                    def.id, assertion.id, assertion.expr
                ));
            }
        }
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
        "Ona CEL expressions failed to compile:\n{}",
        failures.join("\n")
    );
    assert!(
        compiled >= 2 * EXPECTED_ONA_CHECK_IDS.len(),
        "expected at least a discriminator plus a verdict per check, compiled only {compiled}"
    );
}

#[test]
fn every_ona_check_pairs_a_discriminator_with_a_guarded_verdict() {
    // The abstention contract in structural form: each check carries exactly one
    // INFO-severity readability assertion and at least one verdict, and every
    // verdict's expression references the always-bound `body_root`. A verdict
    // that never mentions `body_root` cannot be guarded from the response root
    // down, which is the whole mechanism.
    for def in load_all_ona_defs() {
        let info_count = def
            .assertions
            .iter()
            .filter(|a| {
                a.severity == "info" && a.id.ends_with("readable")
                    || a.id == "oidc_endpoint_answered"
            })
            .count();
        assert_eq!(
            info_count, 1,
            "{}: expected exactly one readability discriminator, found {info_count}",
            def.id
        );

        assert!(
            def.assertions.len() >= 2,
            "{}: a discriminator without a verdict asserts nothing",
            def.id
        );

        for assertion in &def.assertions {
            assert!(
                !assertion.pass_message.is_empty() && !assertion.fail_message.is_empty(),
                "{}/{}: both messages are required — OCEAN prints pass_message on every \
                 Effective status, including an abstention",
                def.id,
                assertion.id
            );
            assert!(
                assertion.finding.is_some(),
                "{}/{}: every assertion needs a finding description, or a failure \
                 degrades to echoing its own fail_message",
                def.id,
                assertion.id
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Fleet credential allowlist
// ---------------------------------------------------------------------------

fn fleet_manifest_yaml(credentials: &[String]) -> String {
    let mut yaml = String::from(
        "fleet:\n  name: \"ona parity\"\ntargets:\n  - id: \"ona-parity\"\n    source: ona\n    credentials:\n",
    );
    for name in credentials {
        // Literal values (not `${VAR}` refs) are returned as-is by
        // `resolve_env_ref`, so this exercises the allowlist without touching the
        // process environment.
        yaml.push_str(&format!("      {name}: \"test-value\"\n"));
    }
    yaml
}

#[test]
fn ona_is_a_known_fleet_source_and_its_credentials_are_allowlisted() {
    let mut declared: Vec<String> = load_all_ona_defs()
        .iter()
        .flat_map(|def| def.credentials.keys().cloned().collect::<Vec<_>>())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    // The org UUID travels as a fleet credential value too — it is what
    // `fleet::executor` hands the module as config, and without it on the
    // allowlist the `org` input is unsettable in fleet mode.
    declared.push("ONA_ORGANIZATION_ID".to_string());
    declared.sort();

    let yaml = fleet_manifest_yaml(&declared);
    let manifest = FleetManifest::from_yaml(yaml.as_bytes()).unwrap_or_else(|e| {
        panic!("credentials declared by checks/ona are not fleet-allowlisted: {e}\n{yaml}")
    });
    assert_eq!(manifest.targets.len(), 1);
    assert_eq!(manifest.targets[0].source, "ona");
    for name in &declared {
        assert!(
            manifest.targets[0].credentials.contains_key(name),
            "credential '{name}' did not survive fleet validation"
        );
    }
}

#[test]
fn fleet_rejects_a_credential_the_ona_allowlist_does_not_carry() {
    // Negative control: proves the assertion above has teeth rather than the
    // allowlist simply accepting anything for this source.
    let yaml = fleet_manifest_yaml(&["ONA_NOT_A_REAL_CREDENTIAL".to_string()]);
    let err = FleetManifest::from_yaml(yaml.as_bytes())
        .expect_err("an unlisted credential must be rejected for source 'ona'");
    assert!(
        err.to_string().contains("not allowed"),
        "unexpected error: {err}"
    );
}

// ===========================================================================
// Control wiring: controls/ai-platform/ observers must resolve to real check ids
// ===========================================================================

const EXPECTED_ONA_CONTROL_IDS: &[&str] = &[
    "ai-platform.ona_agent_guardrails",
    "ai-platform.ona_credential_hygiene",
    "ai-platform.ona_environment_policy",
    "ai-platform.ona_identity",
    "ai-platform.ona_network_exposure",
    "ai-platform.ona_workload_identity",
];

fn load_ai_platform_controls() -> Vec<(PathBuf, Control)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("controls/ai-platform");
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
fn ai_platform_controls_deserialize() {
    let controls = load_ai_platform_controls();
    assert!(!controls.is_empty(), "controls/ai-platform/ is empty");

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
        assert!(
            !control.framework_mappings.is_empty(),
            "{}: control declares no framework mappings",
            control.id
        );
    }
}

#[test]
fn every_ona_control_observer_resolves_to_a_shipped_check_in_bijection() {
    // The defect this locks out shipped once already in this repo, for Buildkite:
    // controls naming dotted `vendor.*` observers that no registry entry could
    // ever resolve, so each control looked wired while being incapable of
    // returning a finding. `register_check` keys a YAML observer on `def.id`, and
    // `YamlObserver::id()` returns that id verbatim — so the ONLY ids that can
    // resolve are the check ids themselves.
    let check_ids: HashSet<String> = load_all_ona_defs()
        .iter()
        .map(|def| def.id.clone())
        .collect();

    let controls = load_ai_platform_controls();
    let ona_controls: Vec<&Control> = controls
        .iter()
        .map(|(_, c)| c)
        .filter(|c| c.id.starts_with("ai-platform.ona_"))
        .collect();

    let control_ids: HashSet<&str> = ona_controls.iter().map(|c| c.id.as_str()).collect();
    let expected_control_ids: HashSet<&str> = EXPECTED_ONA_CONTROL_IDS.iter().copied().collect();
    assert_eq!(
        control_ids, expected_control_ids,
        "controls/ai-platform/ drifted from the declared Ona control set"
    );

    let mut referenced: Vec<String> = Vec::new();
    for control in &ona_controls {
        assert!(
            !control.observers.is_empty(),
            "{}: control declares no observers",
            control.id
        );
        assert!(
            control.testers.is_empty(),
            "{}: no active Ona tester has been authorised",
            control.id
        );
        for observer in &control.observers {
            assert!(
                !observer.module_id.starts_with("ona."),
                "{}: observer '{}' uses the dotted vendor prefix that resolves to no \
                 registered module — YAML checks register under their own ONA-* id",
                control.id,
                observer.module_id
            );
            assert!(
                check_ids.contains(&observer.module_id),
                "{}: observer '{}' does not resolve to any checks/ona/ check id",
                control.id,
                observer.module_id
            );
            referenced.push(observer.module_id.clone());
        }
    }

    // Bijection: every check is wired to exactly one control, and every control
    // observer points at a check. Neither an orphaned check nor a double-wired one
    // can slip back in.
    let unique: HashSet<String> = referenced.iter().cloned().collect();
    assert_eq!(
        unique.len(),
        referenced.len(),
        "an Ona check is referenced by more than one control: {referenced:?}"
    );
    assert_eq!(
        unique, check_ids,
        "checks/ona/ and controls/ai-platform/ observers are not in bijection"
    );
}

#[test]
fn ona_controls_keep_their_scope_ceiling_abstention_and_invocation_disclosures() {
    // Three paragraphs in every Ona control description are load-bearing:
    //   SCOPE CEILING — dotfiles have no org control AND no admin visibility,
    //   automation guardrails have zero API surface, and environment runtime
    //   behaviour is not a control-plane fact, so a pass is not full coverage.
    //   ABSTENTION — an abstaining verdict evaluates Effective, so an individual
    //   check's rows must be read as a pair.
    //   INVOCATION — these resolve under `--target '*'`, not `--target ona`,
    //   because target_matches_module compares the first dot-segment of a
    //   module_id and "ONA-1" is never "ona".
    // Dropping any of them turns a documented limitation back into a silent one.
    for (path, control) in load_ai_platform_controls() {
        if !control.id.starts_with("ai-platform.ona_") {
            continue;
        }
        for marker in ["SCOPE CEILING", "ABSTENTION", "INVOCATION"] {
            assert!(
                control.description.contains(marker),
                "{}: lost the {marker} paragraph",
                path.display()
            );
        }
    }
}
