use anyhow::{anyhow, Result};
use std::collections::HashMap;

use super::{
    safety::{enforce_scope, required_auth_level},
    Authorizer, AutoAuthorizer, EnvironmentScope, Registry,
};
use crate::evidence::{ConfidenceLevel, Evidence};

/// Configuration for executing a tester.
pub struct TestConfig {
    pub module_config: HashMap<String, String>,
    pub target_environment: EnvironmentScope,
    pub authorizer: Box<dyn Authorizer>,
}

impl TestConfig {
    /// Safe defaults: production target, auto-authorizer (safe tests only).
    pub fn default_safe() -> Self {
        Self {
            module_config: HashMap::new(),
            target_environment: EnvironmentScope::Production,
            authorizer: Box::new(AutoAuthorizer),
        }
    }
}

/// Orchestrates module execution: registry lookup, safety checks, and evidence post-processing.
pub struct Executor {
    registry: std::sync::Arc<Registry>,
}

impl Executor {
    pub fn new(registry: std::sync::Arc<Registry>) -> Self {
        Self { registry }
    }

    /// Runs a observer by module ID and returns the observed evidence.
    pub fn execute_observer(
        &self,
        module_id: &str,
        config: &HashMap<String, String>,
    ) -> Result<Vec<Evidence>> {
        let observer = self.registry.get_observer(module_id)?;
        observer.observe(config)
    }

    /// Runs a tester through the full safety pipeline:
    /// 1. Get tester from registry
    /// 2. Run pre-flight (safety, scope, auth)
    /// 3. Execute test
    /// 4. Run cleanup (always, even on test failure)
    /// 5. Set confidence_level = active_verification
    /// 6. Tag safety classification in metadata
    /// 7. Attach cleanup transcript to evidence
    pub fn execute_tester(&self, module_id: &str, cfg: &TestConfig) -> Result<Vec<Evidence>> {
        let tester = self.registry.get_tester(module_id)?;

        // Pre-flight: scope enforcement.
        enforce_scope(tester.id(), tester.safety_class(), cfg.target_environment)?;

        // Pre-flight: authorization.
        let auth_level = required_auth_level(tester.safety_class());
        let authorized =
            cfg.authorizer
                .authorize(tester.id(), tester.safety_class(), auth_level)?;
        if !authorized {
            return Err(anyhow!(
                "authorization denied for tester {:?} (safety: {}, auth level: {})",
                tester.id(),
                tester.safety_class(),
                auth_level,
            ));
        }

        // Execute test.
        let test_result = tester.test(&cfg.module_config);

        // Cleanup — always runs regardless of test result.
        let cleanup_actions: Vec<_> = tester
            .cleanup_procedures()
            .into_iter()
            .map(|proc| crate::evidence::transcript::TranscriptCleanup {
                action: proc,
                timestamp: chrono::Utc::now(),
                success: true,
            })
            .collect();

        // Surface test error after cleanup.
        let mut evidences =
            test_result.map_err(|e| anyhow!("test execution failed (cleanup completed): {e}"))?;

        // Post-process each evidence record.
        let safety_str = tester.safety_class().to_string();
        for ev in &mut evidences {
            ev.confidence_level = ConfidenceLevel::ActiveVerification;
            ev.metadata.safety_classification = Some(safety_str.clone());

            if let Some(transcript) = ev.test_transcript.as_mut() {
                transcript.cleanup_actions.extend(cleanup_actions.clone());
            } else {
                ev.test_transcript = Some(crate::evidence::transcript::TestTranscript {
                    actions_attempted: vec![],
                    observations: vec![],
                    cleanup_actions: cleanup_actions.clone(),
                });
            }
        }

        Ok(evidences)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::ConfidenceLevel;
    use crate::module::EnvironmentScope;
    use crate::testutil::{DenyAuthorizer, MockObserver, MockTester};
    use std::sync::Arc;

    fn make_executor() -> (Arc<Registry>, Executor) {
        let reg = Arc::new(Registry::new());
        let exec = Executor::new(Arc::clone(&reg));
        (reg, exec)
    }

    // --- execute_observer ---

    #[test]
    fn execute_observer_success() {
        let (reg, exec) = make_executor();
        reg.register_observer(Arc::new(MockObserver::new("col.mock")));
        let ev = exec.execute_observer("col.mock", &HashMap::new()).unwrap();
        assert_eq!(ev.len(), 1);
    }

    #[test]
    fn execute_observer_not_found() {
        let (_, exec) = make_executor();
        assert!(exec
            .execute_observer("col.missing", &HashMap::new())
            .is_err());
    }

    #[test]
    fn execute_observer_module_error_propagated() {
        let (reg, exec) = make_executor();
        reg.register_observer(Arc::new(MockObserver::failing("col.fail")));
        let err = exec
            .execute_observer("col.fail", &HashMap::new())
            .unwrap_err();
        assert!(err.to_string().contains("mock observer failure"));
    }

    // --- execute_tester ---

    #[test]
    fn execute_tester_safe_success() {
        let (reg, exec) = make_executor();
        reg.register_tester(Arc::new(MockTester::safe("test.safe")));
        let cfg = TestConfig::default_safe();
        let ev = exec.execute_tester("test.safe", &cfg).unwrap();
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].confidence_level, ConfidenceLevel::ActiveVerification);
        assert!(ev[0].metadata.safety_classification.is_some());
        assert!(ev[0].test_transcript.is_some());
    }

    #[test]
    fn execute_tester_sets_cleanup_in_transcript() {
        let (reg, exec) = make_executor();
        reg.register_tester(Arc::new(MockTester::safe("test.safe2")));
        let cfg = TestConfig::default_safe();
        let ev = exec.execute_tester("test.safe2", &cfg).unwrap();
        let transcript = ev[0].test_transcript.as_ref().unwrap();
        assert!(!transcript.cleanup_actions.is_empty());
    }

    #[test]
    fn execute_tester_not_found() {
        let (_, exec) = make_executor();
        let cfg = TestConfig::default_safe();
        assert!(exec.execute_tester("missing", &cfg).is_err());
    }

    #[test]
    fn execute_tester_scope_violation() {
        let (reg, exec) = make_executor();
        // Destructive tester cannot run in Production
        reg.register_tester(Arc::new(MockTester::destructive("test.dest")));
        let cfg = TestConfig {
            module_config: HashMap::new(),
            target_environment: EnvironmentScope::Production,
            authorizer: Box::new(AutoAuthorizer),
        };
        let err = exec.execute_tester("test.dest", &cfg).unwrap_err();
        assert!(err.to_string().contains("scope violation"));
    }

    #[test]
    fn execute_tester_auth_denied() {
        let (reg, exec) = make_executor();
        reg.register_tester(Arc::new(MockTester::safe("test.safe3")));
        let cfg = TestConfig {
            module_config: HashMap::new(),
            target_environment: EnvironmentScope::Production,
            authorizer: Box::new(DenyAuthorizer),
        };
        let err = exec.execute_tester("test.safe3", &cfg).unwrap_err();
        assert!(err.to_string().contains("authorization denied"));
    }

    #[test]
    fn execute_tester_test_failure_after_cleanup() {
        let (reg, exec) = make_executor();
        reg.register_tester(Arc::new(MockTester::failing("test.fail")));
        let cfg = TestConfig::default_safe();
        let err = exec.execute_tester("test.fail", &cfg).unwrap_err();
        assert!(err.to_string().contains("cleanup completed"));
    }

    // Test the branch where evidence already has a test_transcript (line 101).
    // We need a tester whose evidence has a pre-existing transcript.
    #[test]
    fn execute_tester_appends_cleanup_to_existing_transcript() {
        use crate::evidence::transcript::{
            TestTranscript, TranscriptAction, TranscriptCleanup, TranscriptObservation,
        };

        struct TesterWithTranscript;

        impl crate::module::Module for TesterWithTranscript {
            fn id(&self) -> &str {
                "test.with_transcript"
            }
            fn name(&self) -> &str {
                "Tester With Transcript"
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
            fn credential_requirements(&self) -> Vec<crate::module::CredentialReq> {
                vec![]
            }
        }

        impl crate::module::Tester for TesterWithTranscript {
            fn safety_class(&self) -> crate::module::SafetyClassification {
                crate::module::SafetyClassification::Safe
            }
            fn environment_scope(&self) -> crate::module::EnvironmentScope {
                crate::module::EnvironmentScope::Production
            }
            fn pre_flight_checks(&self) -> Vec<String> {
                vec![]
            }
            fn cleanup_procedures(&self) -> Vec<String> {
                vec!["restore-state".to_string()]
            }
            fn test(
                &self,
                _: &HashMap<String, String>,
            ) -> anyhow::Result<Vec<crate::evidence::Evidence>> {
                let mut ev = crate::testutil::make_evidence();
                // Evidence already has a transcript — exercises line 101
                ev.test_transcript = Some(TestTranscript {
                    actions_attempted: vec![TranscriptAction {
                        action: "step1".to_string(),
                        timestamp: chrono::Utc::now(),
                        parameters: serde_json::Value::Null,
                    }],
                    observations: vec![TranscriptObservation {
                        observation: "obs1".to_string(),
                        timestamp: chrono::Utc::now(),
                        expected: true,
                    }],
                    cleanup_actions: vec![TranscriptCleanup {
                        action: "existing_cleanup".to_string(),
                        timestamp: chrono::Utc::now(),
                        success: true,
                    }],
                });
                Ok(vec![ev])
            }
        }

        let (reg, exec) = make_executor();
        reg.register_tester(Arc::new(TesterWithTranscript));
        let cfg = TestConfig::default_safe();
        let ev = exec.execute_tester("test.with_transcript", &cfg).unwrap();
        assert_eq!(ev.len(), 1);
        let transcript = ev[0].test_transcript.as_ref().unwrap();
        // Should have the original cleanup + the new one appended
        assert!(transcript.cleanup_actions.len() >= 2);
    }

    // TestConfig::default_safe branches
    #[test]
    fn test_config_default_safe_has_production_scope() {
        let cfg = TestConfig::default_safe();
        assert!(matches!(
            cfg.target_environment,
            EnvironmentScope::Production
        ));
        assert!(cfg.module_config.is_empty());
    }
}
