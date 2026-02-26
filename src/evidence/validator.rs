use anyhow::{anyhow, Result};

use super::Evidence;

/// Validates that an Evidence record has required fields populated.
pub fn validate_evidence(ev: &Evidence) -> Result<()> {
    if ev.control_id.is_empty() {
        return Err(anyhow!("evidence is missing control_id"));
    }
    if ev.status.is_empty() {
        return Err(anyhow!("evidence is missing status"));
    }
    if ev.metadata.module.name.is_empty() {
        return Err(anyhow!("evidence metadata is missing module name"));
    }
    Ok(())
}
