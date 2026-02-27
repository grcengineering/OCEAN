use crate::evidence::{ConfidenceLevel, Evidence, StatusId};

/// Returns true when every evidence record is Effective.
/// Returns false for empty slices (no evidence → cannot confirm).
pub fn all_effective(evidence: &[Evidence]) -> bool {
    !evidence.is_empty() && evidence.iter().all(|e| e.status_id == StatusId::Effective)
}

/// Returns true when at least one evidence record is Effective.
pub fn any_effective(evidence: &[Evidence]) -> bool {
    evidence.iter().any(|e| e.status_id == StatusId::Effective)
}

/// Returns true when at least one evidence record is both Effective
/// and collected via active verification (a tester, not a collector).
pub fn active_verified(evidence: &[Evidence]) -> bool {
    evidence.iter().any(|e| {
        e.status_id == StatusId::Effective
            && e.confidence_level == ConfidenceLevel::ActiveVerification
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{ConfidenceLevel, StatusId};
    use crate::testutil::make_evidence;

    fn ev_effective() -> Evidence {
        let mut e = make_evidence();
        e.status_id = StatusId::Effective;
        e.confidence_level = ConfidenceLevel::PassiveObservation;
        e
    }

    fn ev_ineffective() -> Evidence {
        let mut e = make_evidence();
        e.status_id = StatusId::Ineffective;
        e.confidence_level = ConfidenceLevel::PassiveObservation;
        e
    }

    fn ev_active_effective() -> Evidence {
        let mut e = make_evidence();
        e.status_id = StatusId::Effective;
        e.confidence_level = ConfidenceLevel::ActiveVerification;
        e
    }

    // --- all_effective ---

    #[test]
    fn all_effective_empty_returns_false() {
        assert!(!all_effective(&[]));
    }

    #[test]
    fn all_effective_all_pass() {
        let ev = vec![ev_effective(), ev_effective()];
        assert!(all_effective(&ev));
    }

    #[test]
    fn all_effective_one_fails() {
        let ev = vec![ev_effective(), ev_ineffective()];
        assert!(!all_effective(&ev));
    }

    #[test]
    fn all_effective_all_ineffective() {
        let ev = vec![ev_ineffective()];
        assert!(!all_effective(&ev));
    }

    // --- any_effective ---

    #[test]
    fn any_effective_empty_returns_false() {
        assert!(!any_effective(&[]));
    }

    #[test]
    fn any_effective_one_passes() {
        let ev = vec![ev_ineffective(), ev_effective()];
        assert!(any_effective(&ev));
    }

    #[test]
    fn any_effective_none_pass() {
        let ev = vec![ev_ineffective()];
        assert!(!any_effective(&ev));
    }

    // --- active_verified ---

    #[test]
    fn active_verified_empty_returns_false() {
        assert!(!active_verified(&[]));
    }

    #[test]
    fn active_verified_passive_effective_not_enough() {
        let ev = vec![ev_effective()]; // passive only
        assert!(!active_verified(&ev));
    }

    #[test]
    fn active_verified_active_effective_passes() {
        let ev = vec![ev_active_effective()];
        assert!(active_verified(&ev));
    }

    #[test]
    fn active_verified_active_ineffective_not_enough() {
        let mut e = make_evidence();
        e.status_id = StatusId::Ineffective;
        e.confidence_level = ConfidenceLevel::ActiveVerification;
        assert!(!active_verified(&[e]));
    }

    #[test]
    fn active_verified_mixed_finds_active_effective() {
        let ev = vec![ev_ineffective(), ev_active_effective()];
        assert!(active_verified(&ev));
    }
}
