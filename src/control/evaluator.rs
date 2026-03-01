use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::control::definition::{Control, ControlStatus, UptimeResult};
use crate::eval::CelEngine;
use crate::evidence::{ConfidenceLevel, Evidence};

/// Evaluate a control against a slice of evidence and produce a ControlStatus.
///
/// - No evidence → status "unknown", confidence "low"
/// - Eval passes → status "effective"; confidence "high" if any active verification
/// - Eval fails → status "ineffective"; confidence "medium" (passive) or "high" (active)
pub fn evaluate_control(control: &Control, evidence: &[Evidence]) -> ControlStatus {
    if evidence.is_empty() {
        return ControlStatus {
            id: Uuid::new_v4(),
            control_id: control.id.clone(),
            timestamp: Utc::now(),
            status: "unknown".to_string(),
            confidence: "low".to_string(),
            evidence_ids: vec![],
            evaluation_details: "no evidence available".to_string(),
        };
    }

    let passing = CelEngine::evaluate(&control.evaluation_logic, evidence).unwrap_or(false);
    let has_active = evidence
        .iter()
        .any(|e| e.confidence_level == ConfidenceLevel::ActiveVerification);

    let status = if passing { "effective" } else { "ineffective" };
    let confidence = if has_active { "high" } else { "medium" };
    let evidence_ids = evidence.iter().map(|e| e.id).collect();

    ControlStatus {
        id: Uuid::new_v4(),
        control_id: control.id.clone(),
        timestamp: Utc::now(),
        status: status.to_string(),
        confidence: confidence.to_string(),
        evidence_ids,
        evaluation_details: format!(
            "{} evidence records evaluated; {}",
            evidence.len(),
            if passing {
                "control effective"
            } else {
                "control ineffective"
            }
        ),
    }
}

/// Calculate the uptime of a control over a time range.
///
/// Each ControlStatus record in the range is treated as one bucket.
/// Uptime percent = effective_buckets / total_buckets * 100.
pub fn calculate_uptime(
    control_id: &str,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    statuses: &[ControlStatus],
) -> UptimeResult {
    let in_range: Vec<&ControlStatus> = statuses
        .iter()
        .filter(|s| s.control_id == control_id && s.timestamp >= from && s.timestamp <= to)
        .collect();

    let total = in_range.len() as i32;
    let effective = in_range.iter().filter(|s| s.status == "effective").count() as i32;
    let ineffective = in_range
        .iter()
        .filter(|s| s.status == "ineffective")
        .count() as i32;
    let gap = total - effective - ineffective; // unknown or partial

    let uptime_percent = if total == 0 {
        0.0
    } else {
        (effective as f64 / total as f64) * 100.0
    };

    UptimeResult {
        control_id: control_id.to_string(),
        from_time: from,
        to_time: to,
        total_buckets: total,
        effective_buckets: effective,
        ineffective_buckets: ineffective,
        gap_buckets: gap,
        uptime_percent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::definition::{Control, EvaluationLogic};
    use crate::evidence::{ConfidenceLevel, StatusId};
    use crate::testutil::make_evidence;
    use chrono::Duration;

    fn make_control(preset: &str) -> Control {
        Control {
            id: "test.control".to_string(),
            name: "Test Control".to_string(),
            description: "A test control".to_string(),
            evaluation_logic: EvaluationLogic {
                preset: preset.to_string(),
                cel_expression: String::new(),
            },
            framework_mappings: vec![],
            observers: vec![],
            testers: vec![],
            component_controls: vec![],
            components: vec![],
            evaluation_expression_hash: String::new(),
        }
    }

    fn ev_effective_passive() -> Evidence {
        let mut e = make_evidence();
        e.status_id = StatusId::Effective;
        e.confidence_level = ConfidenceLevel::PassiveObservation;
        e
    }

    fn ev_effective_active() -> Evidence {
        let mut e = make_evidence();
        e.status_id = StatusId::Effective;
        e.confidence_level = ConfidenceLevel::ActiveVerification;
        e
    }

    fn ev_ineffective() -> Evidence {
        let mut e = make_evidence();
        e.status_id = StatusId::Ineffective;
        e
    }

    // --- evaluate_control ---

    #[test]
    fn evaluate_no_evidence_returns_unknown() {
        let control = make_control("all_effective");
        let cs = evaluate_control(&control, &[]);
        assert_eq!(cs.status, "unknown");
        assert_eq!(cs.confidence, "low");
        assert_eq!(cs.control_id, "test.control");
        assert!(cs.evidence_ids.is_empty());
    }

    #[test]
    fn evaluate_passing_returns_effective() {
        let control = make_control("all_effective");
        let ev = vec![ev_effective_passive()];
        let cs = evaluate_control(&control, &ev);
        assert_eq!(cs.status, "effective");
        assert_eq!(cs.confidence, "medium"); // passive only
        assert_eq!(cs.evidence_ids.len(), 1);
    }

    #[test]
    fn evaluate_active_verification_raises_confidence_to_high() {
        let control = make_control("all_effective");
        let ev = vec![ev_effective_active()];
        let cs = evaluate_control(&control, &ev);
        assert_eq!(cs.status, "effective");
        assert_eq!(cs.confidence, "high");
    }

    #[test]
    fn evaluate_failing_returns_ineffective() {
        let control = make_control("all_effective");
        let ev = vec![ev_ineffective()];
        let cs = evaluate_control(&control, &ev);
        assert_eq!(cs.status, "ineffective");
    }

    #[test]
    fn evaluate_sets_control_id_and_evidence_ids() {
        let control = make_control("any_effective");
        let ev = vec![ev_effective_passive(), ev_ineffective()];
        let cs = evaluate_control(&control, &ev);
        assert_eq!(cs.control_id, "test.control");
        assert_eq!(cs.evidence_ids.len(), 2);
    }

    #[test]
    fn evaluate_invalid_preset_returns_ineffective() {
        // Bad preset name → CelEngine returns error → unwrap_or(false) → ineffective
        let mut control = make_control("nonexistent_preset");
        control.evaluation_logic.preset = "nonexistent_preset".to_string();
        let ev = vec![ev_effective_passive()];
        let cs = evaluate_control(&control, &ev);
        assert_eq!(cs.status, "ineffective");
    }

    // --- calculate_uptime ---

    #[test]
    fn uptime_empty_returns_zero_percent() {
        let now = Utc::now();
        let result = calculate_uptime("ctrl", now, now, &[]);
        assert_eq!(result.total_buckets, 0);
        assert_eq!(result.uptime_percent, 0.0);
    }

    #[test]
    fn uptime_all_effective() {
        let now = Utc::now();
        let statuses = vec![
            make_status("ctrl", "effective", now),
            make_status("ctrl", "effective", now),
        ];
        let result = calculate_uptime(
            "ctrl",
            now - Duration::seconds(1),
            now + Duration::seconds(1),
            &statuses,
        );
        assert_eq!(result.total_buckets, 2);
        assert_eq!(result.effective_buckets, 2);
        assert_eq!(result.ineffective_buckets, 0);
        assert_eq!(result.gap_buckets, 0);
        assert!((result.uptime_percent - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn uptime_mixed_buckets() {
        let now = Utc::now();
        let statuses = vec![
            make_status("ctrl", "effective", now),
            make_status("ctrl", "ineffective", now),
            make_status("ctrl", "unknown", now),
        ];
        let result = calculate_uptime(
            "ctrl",
            now - Duration::seconds(1),
            now + Duration::seconds(1),
            &statuses,
        );
        assert_eq!(result.total_buckets, 3);
        assert_eq!(result.effective_buckets, 1);
        assert_eq!(result.ineffective_buckets, 1);
        assert_eq!(result.gap_buckets, 1); // unknown bucket
        assert!((result.uptime_percent - 33.333_333_333_333_336).abs() < 0.001);
    }

    #[test]
    fn uptime_filters_by_control_id() {
        let now = Utc::now();
        let statuses = vec![
            make_status("ctrl.a", "effective", now),
            make_status("ctrl.b", "ineffective", now),
        ];
        let result = calculate_uptime(
            "ctrl.a",
            now - Duration::seconds(1),
            now + Duration::seconds(1),
            &statuses,
        );
        assert_eq!(result.total_buckets, 1);
        assert_eq!(result.effective_buckets, 1);
    }

    #[test]
    fn uptime_filters_by_time_range() {
        let now = Utc::now();
        let old = now - Duration::days(30);
        let statuses = vec![
            make_status("ctrl", "effective", old),   // outside range
            make_status("ctrl", "ineffective", now), // inside range
        ];
        let result = calculate_uptime(
            "ctrl",
            now - Duration::seconds(1),
            now + Duration::seconds(1),
            &statuses,
        );
        assert_eq!(result.total_buckets, 1);
        assert_eq!(result.effective_buckets, 0);
        assert_eq!(result.ineffective_buckets, 1);
    }

    fn make_status(control_id: &str, status: &str, ts: DateTime<Utc>) -> ControlStatus {
        ControlStatus {
            id: Uuid::new_v4(),
            control_id: control_id.to_string(),
            timestamp: ts,
            status: status.to_string(),
            confidence: "medium".to_string(),
            evidence_ids: vec![],
            evaluation_details: String::new(),
        }
    }
}
