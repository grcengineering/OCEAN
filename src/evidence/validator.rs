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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_evidence_passes() {
        let ev = crate::testutil::make_evidence();
        assert!(validate_evidence(&ev).is_ok());
    }

    #[test]
    fn missing_control_id_fails() {
        let mut ev = crate::testutil::make_evidence();
        ev.control_id = String::new();
        let err = validate_evidence(&ev).unwrap_err();
        assert!(err.to_string().contains("control_id"));
    }

    #[test]
    fn missing_status_fails() {
        let mut ev = crate::testutil::make_evidence();
        ev.status = String::new();
        let err = validate_evidence(&ev).unwrap_err();
        assert!(err.to_string().contains("status"));
    }

    #[test]
    fn missing_module_name_fails() {
        let mut ev = crate::testutil::make_evidence();
        ev.metadata.module.name = String::new();
        let err = validate_evidence(&ev).unwrap_err();
        assert!(err.to_string().contains("module name"));
    }
}
