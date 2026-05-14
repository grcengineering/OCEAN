// Shared test utilities for OCEAN unit tests.
// Only compiled during `cargo test` via #[cfg(test)] in lib.rs.
//
// Provides: make_evidence(), MockObserver, MockTester, DenyAuthorizer.

use std::collections::HashMap;

use anyhow::Result;
use chrono::Utc;
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo as EvidenceModuleInfo, Observable,
    SourceInfo, StatusId,
};
use crate::module::{
    AuthorizationLevel, Authorizer, Observer, CredentialReq, EnvironmentScope, Module,
    SafetyClassification, Tester,
};

// ---------------------------------------------------------------------------
// Evidence builder
// ---------------------------------------------------------------------------

/// Returns a minimal valid Evidence record populated with test data.
pub fn make_evidence() -> Evidence {
    Evidence {
        id: Uuid::new_v4(),
        control_id: "test.control".to_string(),
        class_uid: 1001,
        category_uid: 10,
        activity_id: 1,
        time: Utc::now(),
        confidence_level: ConfidenceLevel::PassiveObservation,
        metadata: Metadata {
            module: EvidenceModuleInfo {
                name: "test.module".to_string(),
                version: "0.1.0".to_string(),
                module_type: "observer".to_string(),
            },
            source: SourceInfo {
                system: "mock".to_string(),
                api_version: "v1".to_string(),
                endpoint: "mock://endpoint".to_string(),
            },
            original_time: None,
            processed_time: Utc::now(),
            safety_classification: None,
        },
        observables: vec![Observable {
            obs_type: "resource".to_string(),
            value: "arn:aws:s3:::my-bucket".to_string(),
            name: String::new(),
        }],
        status_id: StatusId::Effective,
        status: "effective".to_string(),
        raw_data: serde_json::json!({"bucket": "my-bucket", "public": false}),
        findings: vec![Finding {
            title: "Test Finding".to_string(),
            description: "A test finding".to_string(),
            severity_id: 2,
        }],
        test_transcript: None,
        enrichments: vec![],
    }
}

// ---------------------------------------------------------------------------
// MockObserver
// ---------------------------------------------------------------------------

/// A minimal Observer implementation for unit testing.
pub struct MockObserver {
    pub id: &'static str,
    pub name: &'static str,
    pub source: &'static str,
    /// If true, `observe()` returns an error instead of evidence.
    pub fail: bool,
}

impl MockObserver {
    pub fn new(id: &'static str) -> Self {
        Self {
            id,
            name: "Mock Observer",
            source: "mock",
            fail: false,
        }
    }

    pub fn failing(id: &'static str) -> Self {
        Self {
            id,
            name: "Mock Observer",
            source: "mock",
            fail: true,
        }
    }

    /// Observer with empty id — used to test validation.
    pub fn empty_id() -> Self {
        Self {
            id: "",
            name: "Bad Observer",
            source: "mock",
            fail: false,
        }
    }

    /// Observer with empty name — used to test validation.
    pub fn empty_name(id: &'static str) -> Self {
        Self {
            id,
            name: "",
            source: "mock",
            fail: false,
        }
    }

    /// Observer with empty source_system — used to test validation.
    pub fn empty_source(id: &'static str) -> Self {
        Self {
            id,
            name: "Bad Observer",
            source: "",
            fail: false,
        }
    }
}

impl Module for MockObserver {
    fn id(&self) -> &str {
        self.id
    }
    fn name(&self) -> &str {
        self.name
    }
    fn version(&self) -> &str {
        "0.1.0"
    }
    fn source_system(&self) -> &str {
        self.source
    }
    fn evidence_types(&self) -> &[i32] {
        &[1001]
    }
    fn credential_requirements(&self) -> Vec<CredentialReq> {
        vec![]
    }
}

impl Observer for MockObserver {
    fn observe(&self, _: &HashMap<String, String>) -> Result<Vec<Evidence>> {
        if self.fail {
            anyhow::bail!("mock observer failure");
        }
        Ok(vec![make_evidence()])
    }
}

// ---------------------------------------------------------------------------
// MockTester
// ---------------------------------------------------------------------------

/// A minimal Tester implementation for unit testing.
pub struct MockTester {
    pub id: &'static str,
    pub safety: SafetyClassification,
    pub scope: EnvironmentScope,
    pub fail: bool,
}

impl MockTester {
    pub fn safe(id: &'static str) -> Self {
        Self {
            id,
            safety: SafetyClassification::Safe,
            scope: EnvironmentScope::Production,
            fail: false,
        }
    }

    pub fn observable(id: &'static str) -> Self {
        Self {
            id,
            safety: SafetyClassification::Observable,
            scope: EnvironmentScope::Staging,
            fail: false,
        }
    }

    pub fn reversible(id: &'static str) -> Self {
        Self {
            id,
            safety: SafetyClassification::Reversible,
            scope: EnvironmentScope::Isolated,
            fail: false,
        }
    }

    pub fn destructive(id: &'static str) -> Self {
        Self {
            id,
            safety: SafetyClassification::Destructive,
            scope: EnvironmentScope::Isolated,
            fail: false,
        }
    }

    pub fn failing(id: &'static str) -> Self {
        Self {
            id,
            safety: SafetyClassification::Safe,
            scope: EnvironmentScope::Production,
            fail: true,
        }
    }

    pub fn empty_id() -> Self {
        Self {
            id: "",
            safety: SafetyClassification::Safe,
            scope: EnvironmentScope::Production,
            fail: false,
        }
    }

    pub fn empty_name_id(id: &'static str) -> Self {
        // We need a tester with an empty name — done via a different approach since
        // MockTester::name() returns a static string. Use TesterEmptyName struct instead.
        Self {
            id,
            safety: SafetyClassification::Safe,
            scope: EnvironmentScope::Production,
            fail: false,
        }
    }
}

impl Module for MockTester {
    fn id(&self) -> &str {
        self.id
    }
    fn name(&self) -> &str {
        "Mock Tester"
    }
    fn version(&self) -> &str {
        "0.1.0"
    }
    fn source_system(&self) -> &str {
        "mock"
    }
    fn evidence_types(&self) -> &[i32] {
        &[1001]
    }
    fn credential_requirements(&self) -> Vec<CredentialReq> {
        vec![]
    }
}

impl Tester for MockTester {
    fn safety_class(&self) -> SafetyClassification {
        self.safety
    }
    fn environment_scope(&self) -> EnvironmentScope {
        self.scope
    }
    fn pre_flight_checks(&self) -> Vec<String> {
        vec!["check connectivity".into()]
    }
    fn cleanup_procedures(&self) -> Vec<String> {
        vec!["restore state".into()]
    }
    fn test(&self, _: &HashMap<String, String>) -> Result<Vec<Evidence>> {
        if self.fail {
            anyhow::bail!("mock tester failure");
        }
        let mut ev = make_evidence();
        ev.confidence_level = ConfidenceLevel::ActiveVerification;
        Ok(vec![ev])
    }
}

// Tester with empty name for validation tests.
pub struct TesterBadMeta {
    pub id: &'static str,
    pub name: &'static str,
    pub source: &'static str,
}

impl Module for TesterBadMeta {
    fn id(&self) -> &str {
        self.id
    }
    fn name(&self) -> &str {
        self.name
    }
    fn version(&self) -> &str {
        "0.1.0"
    }
    fn source_system(&self) -> &str {
        self.source
    }
    fn evidence_types(&self) -> &[i32] {
        &[]
    }
    fn credential_requirements(&self) -> Vec<CredentialReq> {
        vec![]
    }
}

impl Tester for TesterBadMeta {
    fn safety_class(&self) -> SafetyClassification {
        SafetyClassification::Safe
    }
    fn environment_scope(&self) -> EnvironmentScope {
        EnvironmentScope::Production
    }
    fn pre_flight_checks(&self) -> Vec<String> {
        vec![]
    }
    fn cleanup_procedures(&self) -> Vec<String> {
        vec![]
    }
    fn test(&self, _: &HashMap<String, String>) -> Result<Vec<Evidence>> {
        Ok(vec![make_evidence()])
    }
}

// ---------------------------------------------------------------------------
// DenyAuthorizer
// ---------------------------------------------------------------------------

/// An Authorizer that always returns false — used to test auth-denied paths.
pub struct DenyAuthorizer;

impl Authorizer for DenyAuthorizer {
    fn authorize(&self, _: &str, _: SafetyClassification, _: AuthorizationLevel) -> Result<bool> {
        Ok(false)
    }
}

// ---------------------------------------------------------------------------
// FailingWriter
// ---------------------------------------------------------------------------

/// A `Write` impl that succeeds for the first `succeed_before_fail` calls
/// to `write_fmt` (i.e. the first N `writeln!`/`write!` macro invocations),
/// then returns `Err` for every subsequent macro invocation. Used to drive
/// the `?` continuation paths after each `writeln!`/`write!` in handler
/// code that would otherwise be unreachable when writing to a `Vec<u8>`.
///
/// Counts at the `write_fmt` level (not raw `write`) because each
/// `writeln!` typically expands into many small `write` calls — one per
/// format token. Failing per macro-invocation gives stable test semantics.
pub struct FailingWriter {
    pub succeed_before_fail: usize,
    pub call_count: usize,
}

impl FailingWriter {
    pub fn new(succeed_before_fail: usize) -> Self {
        Self {
            succeed_before_fail,
            call_count: 0,
        }
    }

    /// Always fail on the very first write_fmt.
    pub fn always() -> Self {
        Self::new(0)
    }
}

impl std::io::Write for FailingWriter {
    /// Underlying byte-level write. Always succeeds — failure decision lives
    /// at the `write_fmt` boundary.
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        if self.call_count < self.succeed_before_fail {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "FailingWriter: simulated flush failure",
            ))
        }
    }
    fn write_fmt(&mut self, _args: std::fmt::Arguments<'_>) -> std::io::Result<()> {
        let n = self.call_count;
        self.call_count += 1;
        if n < self.succeed_before_fail {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "FailingWriter: simulated write_fmt failure",
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// MockHTTPServer
// ---------------------------------------------------------------------------

/// A reusable mock HTTP server for unit/integration tests.
///
/// Spins up a real TCP listener on an ephemeral port and serves a queue of
/// pre-programmed `(status_code, body)` responses in order.
pub struct MockHTTPServer {
    pub base_url: String,
}

impl MockHTTPServer {
    /// Create a server that will serve each `(status, body)` pair in order.
    pub fn new(responses: Vec<(u16, String)>) -> Self {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock HTTP server");
        let addr = listener.local_addr().expect("local addr");
        let queue = Arc::new(Mutex::new(responses));

        std::thread::spawn(move || {
            loop {
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
            }
        });

        Self {
            base_url: format!("http://127.0.0.1:{}", addr.port()),
        }
    }

    /// Returns the base URL for injecting into module configs.
    pub fn url(&self) -> &str {
        &self.base_url
    }
}

// ---------------------------------------------------------------------------
// Meta-tests: exercise every constructor and method in this file.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::module::{AuthorizationLevel, Module, SafetyClassification};

    // ── make_evidence ────────────────────────────────────────────────────────

    #[test]
    fn make_evidence_returns_valid_record() {
        let ev = make_evidence();
        assert_eq!(ev.control_id, "test.control");
        assert_eq!(ev.class_uid, 1001);
        assert!(!ev.observables.is_empty());
        assert!(!ev.findings.is_empty());
    }

    // ── FailingWriter ────────────────────────────────────────────────────────

    #[test]
    fn failing_writer_fails_first_writeln() {
        use std::io::Write;
        let mut w = FailingWriter::always();
        let r = writeln!(w, "hi");
        assert!(r.is_err());
    }

    #[test]
    fn failing_writer_succeeds_then_fails() {
        use std::io::Write;
        let mut w = FailingWriter::new(2);
        assert!(writeln!(w, "a").is_ok());
        assert!(writeln!(w, "b").is_ok());
        assert!(writeln!(w, "c").is_err());
    }

    #[test]
    fn failing_writer_flush_ok_when_under_limit() {
        use std::io::Write;
        let mut w = FailingWriter::new(5);
        assert!(w.flush().is_ok());
    }

    #[test]
    fn failing_writer_flush_err_when_at_limit() {
        use std::io::Write;
        let mut w = FailingWriter::always();
        assert!(w.flush().is_err());
    }

    #[test]
    fn failing_writer_byte_write_always_succeeds() {
        use std::io::Write;
        let mut w = FailingWriter::always();
        assert_eq!(w.write(b"hi").unwrap(), 2);
    }

    // ── MockObserver constructors ─────────────────────────────────────────────

    #[test]
    fn mock_observer_new_fields() {
        let obs = MockObserver::new("obs.id");
        assert_eq!(obs.id, "obs.id");
        assert_eq!(obs.name, "Mock Observer");
        assert_eq!(obs.source, "mock");
        assert!(!obs.fail);
    }

    #[test]
    fn mock_observer_failing_sets_fail_flag() {
        let obs = MockObserver::failing("obs.fail");
        assert!(obs.fail);
        assert_eq!(obs.id, "obs.fail");
    }

    #[test]
    fn mock_observer_empty_id_has_empty_id() {
        let obs = MockObserver::empty_id();
        assert_eq!(obs.id, "");
        assert_eq!(obs.name, "Bad Observer");
    }

    #[test]
    fn mock_observer_empty_name_has_empty_name() {
        let obs = MockObserver::empty_name("obs.empty_name");
        assert_eq!(obs.id, "obs.empty_name");
        assert_eq!(obs.name, "");
        assert!(!obs.fail);
    }

    #[test]
    fn mock_observer_empty_source_has_empty_source() {
        let obs = MockObserver::empty_source("obs.empty_source");
        assert_eq!(obs.source, "");
    }

    // ── MockObserver Module + Observer trait methods ──────────────────────────

    #[test]
    fn mock_observer_module_trait_methods() {
        let obs = MockObserver::new("obs.trait");
        assert_eq!(obs.id(), "obs.trait");
        assert_eq!(obs.name(), "Mock Observer");
        assert_eq!(obs.version(), "0.1.0");
        assert_eq!(obs.source_system(), "mock");
        assert_eq!(obs.evidence_types(), &[1001]);
        assert!(obs.credential_requirements().is_empty());
    }

    #[test]
    fn mock_observer_observe_returns_evidence() {
        let obs = MockObserver::new("obs.ok");
        let creds = HashMap::new();
        let result = obs.observe(&creds).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn mock_observer_failing_observe_returns_error() {
        let obs = MockObserver::failing("obs.err");
        let creds = HashMap::new();
        assert!(obs.observe(&creds).is_err());
    }

    // ── MockTester constructors ───────────────────────────────────────────────

    #[test]
    fn mock_tester_safe_fields() {
        let t = MockTester::safe("t.safe");
        assert_eq!(t.id, "t.safe");
        assert!(matches!(t.safety, SafetyClassification::Safe));
        assert!(matches!(t.scope, crate::module::EnvironmentScope::Production));
        assert!(!t.fail);
    }

    #[test]
    fn mock_tester_observable_fields() {
        let t = MockTester::observable("t.obs");
        assert_eq!(t.id, "t.obs");
        assert!(matches!(t.safety, SafetyClassification::Observable));
        assert!(matches!(t.scope, crate::module::EnvironmentScope::Staging));
        assert!(!t.fail);
    }

    #[test]
    fn mock_tester_reversible_fields() {
        let t = MockTester::reversible("t.rev");
        assert_eq!(t.id, "t.rev");
        assert!(matches!(t.safety, SafetyClassification::Reversible));
        assert!(matches!(t.scope, crate::module::EnvironmentScope::Isolated));
        assert!(!t.fail);
    }

    #[test]
    fn mock_tester_destructive_fields() {
        let t = MockTester::destructive("t.dest");
        assert!(matches!(t.safety, SafetyClassification::Destructive));
        assert!(matches!(t.scope, crate::module::EnvironmentScope::Isolated));
    }

    #[test]
    fn mock_tester_failing_sets_fail_flag() {
        let t = MockTester::failing("t.fail");
        assert!(t.fail);
    }

    #[test]
    fn mock_tester_empty_id_has_empty_id() {
        let t = MockTester::empty_id();
        assert_eq!(t.id, "");
    }

    #[test]
    fn mock_tester_empty_name_id_constructor() {
        let t = MockTester::empty_name_id("t.eni");
        assert_eq!(t.id, "t.eni");
        assert!(matches!(t.safety, SafetyClassification::Safe));
    }

    // ── MockTester Module + Tester trait methods ──────────────────────────────

    #[test]
    fn mock_tester_module_trait_methods() {
        let t = MockTester::safe("t.trait");
        assert_eq!(t.id(), "t.trait");
        assert_eq!(t.name(), "Mock Tester");
        assert_eq!(t.version(), "0.1.0");
        assert_eq!(t.source_system(), "mock");
        assert_eq!(t.evidence_types(), &[1001]);
        assert!(t.credential_requirements().is_empty());
    }

    #[test]
    fn mock_tester_tester_trait_methods() {
        let t = MockTester::safe("t.tester");
        assert!(matches!(t.safety_class(), SafetyClassification::Safe));
        assert!(matches!(t.environment_scope(), crate::module::EnvironmentScope::Production));
        assert!(!t.pre_flight_checks().is_empty());
        assert!(!t.cleanup_procedures().is_empty());
    }

    #[test]
    fn mock_tester_test_returns_evidence() {
        let t = MockTester::safe("t.ok");
        let creds = HashMap::new();
        let result = t.test(&creds).unwrap();
        assert_eq!(result.len(), 1);
        assert!(matches!(result[0].confidence_level, crate::evidence::ConfidenceLevel::ActiveVerification));
    }

    #[test]
    fn mock_tester_failing_test_returns_error() {
        let t = MockTester::failing("t.err");
        let creds = HashMap::new();
        assert!(t.test(&creds).is_err());
    }

    // ── TesterBadMeta ─────────────────────────────────────────────────────────

    #[test]
    fn tester_bad_meta_module_trait_methods() {
        let t = TesterBadMeta { id: "tbm.id", name: "", source: "mock" };
        assert_eq!(t.id(), "tbm.id");
        assert_eq!(t.name(), "");
        assert_eq!(t.version(), "0.1.0");
        assert_eq!(t.source_system(), "mock");
        assert!(t.evidence_types().is_empty());
        assert!(t.credential_requirements().is_empty());
    }

    #[test]
    fn tester_bad_meta_tester_trait_methods() {
        let t = TesterBadMeta { id: "tbm.tester", name: "bad", source: "mock" };
        assert!(matches!(t.safety_class(), SafetyClassification::Safe));
        assert!(matches!(t.environment_scope(), crate::module::EnvironmentScope::Production));
        assert!(t.pre_flight_checks().is_empty());
        assert!(t.cleanup_procedures().is_empty());
    }

    #[test]
    fn tester_bad_meta_test_returns_evidence() {
        let t = TesterBadMeta { id: "tbm.test", name: "bad", source: "mock" };
        let creds = HashMap::new();
        let result = t.test(&creds).unwrap();
        assert_eq!(result.len(), 1);
    }

    // ── DenyAuthorizer ────────────────────────────────────────────────────────

    #[test]
    fn deny_authorizer_always_returns_false() {
        let auth = DenyAuthorizer;
        let result = auth
            .authorize("t.deny", SafetyClassification::Safe, AuthorizationLevel::Auto)
            .unwrap();
        assert!(!result);
    }

    #[test]
    fn deny_authorizer_returns_false_for_all_safety_levels() {
        let auth = DenyAuthorizer;
        for safety in [
            SafetyClassification::Safe,
            SafetyClassification::Observable,
            SafetyClassification::Reversible,
            SafetyClassification::Destructive,
        ] {
            assert!(!auth.authorize("x", safety, AuthorizationLevel::Auto).unwrap());
        }
    }

    // ── MockHTTPServer ────────────────────────────────────────────────────────

    #[test]
    fn mock_http_server_url_is_localhost() {
        let server = MockHTTPServer::new(vec![(200, r#"{"ok":true}"#.to_string())]);
        assert!(server.url().starts_with("http://127.0.0.1:"));
    }

    #[test]
    fn mock_http_server_serves_response() {
        let server = MockHTTPServer::new(vec![(200, r#"{"ok":true}"#.to_string())]);
        let resp = ureq::get(server.url()).call().unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.into_json().unwrap();
        assert_eq!(body["ok"], true);
    }

    #[test]
    fn mock_http_server_serves_non_200_status() {
        let server = MockHTTPServer::new(vec![(404, r#"{"error":"not found"}"#.to_string())]);
        // ureq treats 4xx as errors by default — use call_with_settings or check via http()
        // We use ureq::get(...).call() which returns Err for 4xx; just verify the status via
        // the ErrorKind::Status variant.
        let err = ureq::get(server.url()).call().unwrap_err();
        if let ureq::Error::Status(code, _) = err {
            assert_eq!(code, 404);
        } else {
            panic!("Expected HTTP status error, got: {err:?}");
        }
    }
}
