use anyhow::Result;
use std::collections::HashMap;

use crate::evidence::Evidence;
use super::{Module, SafetyClassification, EnvironmentScope};

/// Performs active control verification by interacting with target systems.
/// Testers produce evidence at the "active_verification" confidence level and
/// must declare their safety classification and cleanup procedures.
pub trait Tester: Module {
    fn safety_class(&self) -> SafetyClassification;
    fn environment_scope(&self) -> EnvironmentScope;
    fn pre_flight_checks(&self) -> Vec<String>;
    fn cleanup_procedures(&self) -> Vec<String>;
    fn test(&self, config: &HashMap<String, String>) -> Result<Vec<Evidence>>;
}
