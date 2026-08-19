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
    AuthorizationLevel, Authorizer, CredentialReq, EnvironmentScope, Module, Observer,
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

    /// Returns the base URL for injecting into module configs.
    pub fn url(&self) -> &str {
        &self.base_url
    }
}
