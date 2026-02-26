use anyhow::{anyhow, Result};

use super::{Collector, Tester};

/// Validates that a collector has all required metadata fields populated.
pub fn validate_collector(c: &dyn Collector) -> Result<()> {
    if c.id().is_empty() {
        return Err(anyhow!("collector ID must not be empty"));
    }
    if c.name().is_empty() {
        return Err(anyhow!("collector name must not be empty (id: {})", c.id()));
    }
    if c.source_system().is_empty() {
        return Err(anyhow!("collector source_system must not be empty (id: {})", c.id()));
    }
    Ok(())
}

/// Validates that a tester has all required metadata fields and a valid safety classification.
pub fn validate_tester(t: &dyn Tester) -> Result<()> {
    if t.id().is_empty() {
        return Err(anyhow!("tester ID must not be empty"));
    }
    if t.name().is_empty() {
        return Err(anyhow!("tester name must not be empty (id: {})", t.id()));
    }
    if t.source_system().is_empty() {
        return Err(anyhow!("tester source_system must not be empty (id: {})", t.id()));
    }
    Ok(())
}
