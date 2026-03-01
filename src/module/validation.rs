use anyhow::{anyhow, Result};

use super::{Observer, Tester};

/// Validates that a observer has all required metadata fields populated.
pub fn validate_observer(c: &dyn Observer) -> Result<()> {
    if c.id().is_empty() {
        return Err(anyhow!("observer ID must not be empty"));
    }
    if c.name().is_empty() {
        return Err(anyhow!("observer name must not be empty (id: {})", c.id()));
    }
    if c.source_system().is_empty() {
        return Err(anyhow!(
            "observer source_system must not be empty (id: {})",
            c.id()
        ));
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
        return Err(anyhow!(
            "tester source_system must not be empty (id: {})",
            t.id()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{MockObserver, MockTester, TesterBadMeta};

    // --- validate_observer ---

    #[test]
    fn observer_valid_passes() {
        let c = MockObserver::new("col.valid");
        assert!(validate_observer(&c).is_ok());
    }

    #[test]
    fn observer_empty_id_fails() {
        let c = MockObserver::empty_id();
        let err = validate_observer(&c).unwrap_err();
        assert!(err.to_string().contains("ID must not be empty"));
    }

    #[test]
    fn observer_empty_name_fails() {
        let c = MockObserver::empty_name("col.bad");
        let err = validate_observer(&c).unwrap_err();
        assert!(err.to_string().contains("name must not be empty"));
    }

    #[test]
    fn observer_empty_source_system_fails() {
        let c = MockObserver::empty_source("col.nosrc");
        let err = validate_observer(&c).unwrap_err();
        assert!(err.to_string().contains("source_system must not be empty"));
    }

    // --- validate_tester ---

    #[test]
    fn tester_valid_passes() {
        let t = MockTester::safe("test.valid");
        assert!(validate_tester(&t).is_ok());
    }

    #[test]
    fn tester_empty_id_fails() {
        let t = MockTester::empty_id();
        let err = validate_tester(&t).unwrap_err();
        assert!(err.to_string().contains("ID must not be empty"));
    }

    #[test]
    fn tester_empty_name_fails() {
        let t = TesterBadMeta {
            id: "t.bad",
            name: "",
            source: "mock",
        };
        let err = validate_tester(&t).unwrap_err();
        assert!(err.to_string().contains("name must not be empty"));
    }

    #[test]
    fn tester_empty_source_system_fails() {
        let t = TesterBadMeta {
            id: "t.nosrc",
            name: "Bad",
            source: "",
        };
        let err = validate_tester(&t).unwrap_err();
        assert!(err.to_string().contains("source_system must not be empty"));
    }
}
