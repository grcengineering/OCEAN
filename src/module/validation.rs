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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{MockCollector, MockTester, TesterBadMeta};

    // --- validate_collector ---

    #[test]
    fn collector_valid_passes() {
        let c = MockCollector::new("col.valid");
        assert!(validate_collector(&c).is_ok());
    }

    #[test]
    fn collector_empty_id_fails() {
        let c = MockCollector::empty_id();
        let err = validate_collector(&c).unwrap_err();
        assert!(err.to_string().contains("ID must not be empty"));
    }

    #[test]
    fn collector_empty_name_fails() {
        let c = MockCollector::empty_name("col.bad");
        let err = validate_collector(&c).unwrap_err();
        assert!(err.to_string().contains("name must not be empty"));
    }

    #[test]
    fn collector_empty_source_system_fails() {
        let c = MockCollector::empty_source("col.nosrc");
        let err = validate_collector(&c).unwrap_err();
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
        let t = TesterBadMeta { id: "t.bad", name: "", source: "mock" };
        let err = validate_tester(&t).unwrap_err();
        assert!(err.to_string().contains("name must not be empty"));
    }

    #[test]
    fn tester_empty_source_system_fails() {
        let t = TesterBadMeta { id: "t.nosrc", name: "Bad", source: "" };
        let err = validate_tester(&t).unwrap_err();
        assert!(err.to_string().contains("source_system must not be empty"));
    }
}
