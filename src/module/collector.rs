use anyhow::Result;
use std::collections::HashMap;

use super::Module;
use crate::evidence::Evidence;

/// Gathers passive evidence from source systems. Collectors are read-only
/// modules that observe system state without modifying it, producing evidence
/// at the "passive_observation" confidence level.
pub trait Collector: Module {
    fn collect(&self, config: &HashMap<String, String>) -> Result<Vec<Evidence>>;
}
