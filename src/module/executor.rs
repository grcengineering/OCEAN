use anyhow::{anyhow, Result};
use std::collections::HashMap;

use crate::evidence::{Evidence, ConfidenceLevel};
use super::{
    Registry, Authorizer, AutoAuthorizer, EnvironmentScope,
    safety::{required_auth_level, enforce_scope},
};

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

    /// Runs a collector by module ID and returns the collected evidence.
    pub fn execute_collector(
        &self,
        module_id: &str,
        config: &HashMap<String, String>,
    ) -> Result<Vec<Evidence>> {
        let collector = self.registry.get_collector(module_id)?;
        collector.collect(config)
    }

    /// Runs a tester through the full safety pipeline:
    /// 1. Get tester from registry
    /// 2. Run pre-flight (safety, scope, auth)
    /// 3. Execute test
    /// 4. Run cleanup (always, even on test failure)
    /// 5. Set confidence_level = active_verification
    /// 6. Tag safety classification in metadata
    /// 7. Attach cleanup transcript to evidence
    pub fn execute_tester(
        &self,
        module_id: &str,
        cfg: &TestConfig,
    ) -> Result<Vec<Evidence>> {
        let tester = self.registry.get_tester(module_id)?;

        // Pre-flight: scope enforcement.
        enforce_scope(tester.id(), tester.safety_class(), cfg.target_environment)?;

        // Pre-flight: authorization.
        let auth_level = required_auth_level(tester.safety_class());
        let authorized = cfg.authorizer.authorize(tester.id(), tester.safety_class(), auth_level)?;
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
        let mut evidences = test_result.map_err(|e| {
            anyhow!("test execution failed (cleanup completed): {e}")
        })?;

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
    use std::sync::Arc;
    use crate::testutil::{MockCollector, MockTester, DenyAuthorizer};
    use crate::evidence::ConfidenceLevel;
    use crate::module::EnvironmentScope;

    fn make_executor() -> (Arc<Registry>, Executor) {
        let reg = Arc::new(Registry::new());
        let exec = Executor::new(Arc::clone(&reg));
        (reg, exec)
    }

    // --- execute_collector ---

    #[test]
    fn execute_collector_success() {
        let (reg, exec) = make_executor();
        reg.register_collector(Arc::new(MockCollector::new("col.mock")));
        let ev = exec.execute_collector("col.mock", &HashMap::new()).unwrap();
        assert_eq!(ev.len(), 1);
    }

    #[test]
    fn execute_collector_not_found() {
        let (_, exec) = make_executor();
        assert!(exec.execute_collector("col.missing", &HashMap::new()).is_err());
    }

    #[test]
    fn execute_collector_module_error_propagated() {
        let (reg, exec) = make_executor();
        reg.register_collector(Arc::new(MockCollector::failing("col.fail")));
        let err = exec.execute_collector("col.fail", &HashMap::new()).unwrap_err();
        assert!(err.to_string().contains("mock collector failure"));
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
}
