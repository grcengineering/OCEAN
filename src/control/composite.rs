use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::control::definition::Control;

/// The evaluation result of a single component control within a composite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentResult {
    pub control_id: String,
    /// "effective", "ineffective", "unknown"
    pub status: String,
    pub evidence_ids: Vec<Uuid>,
}

/// Evaluate a composite control given the status of its component controls.
///
/// - All components effective → "effective"
/// - Any component ineffective → "ineffective"
/// - Control has no component_controls → "unknown"
/// - Any component missing from results → treated as "unknown" → "ineffective"
pub fn evaluate_composite(control: &Control, component_results: &[ComponentResult]) -> String {
    if control.component_controls.is_empty() {
        return "unknown".to_string();
    }

    for comp_id in &control.component_controls {
        let found = component_results
            .iter()
            .find(|r| &r.control_id == comp_id);

        match found {
            Some(r) if r.status == "effective" => {}
            _ => return "ineffective".to_string(),
        }
    }

    "effective".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::definition::{Control, EvaluationLogic};

    fn make_composite(components: Vec<&str>) -> Control {
        Control {
            id: "composite.ctrl".to_string(),
            name: "Composite".to_string(),
            description: String::new(),
            evaluation_logic: EvaluationLogic::default(),
            framework_mappings: vec![],
            component_controls: components.into_iter().map(String::from).collect(),
            evaluation_expression_hash: String::new(),
        }
    }

    fn result(id: &str, status: &str) -> ComponentResult {
        ComponentResult {
            control_id: id.to_string(),
            status: status.to_string(),
            evidence_ids: vec![],
        }
    }

    #[test]
    fn component_result_serde_round_trip() {
        let r = ComponentResult {
            control_id: "ctrl.a".to_string(),
            status: "effective".to_string(),
            evidence_ids: vec![Uuid::new_v4()],
        };
        let json = serde_json::to_string(&r).unwrap();
        let decoded: ComponentResult = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.control_id, r.control_id);
        assert_eq!(decoded.status, r.status);
        assert_eq!(decoded.evidence_ids.len(), 1);
    }

    #[test]
    fn composite_no_components_returns_unknown() {
        let ctrl = make_composite(vec![]);
        let status = evaluate_composite(&ctrl, &[]);
        assert_eq!(status, "unknown");
    }

    #[test]
    fn composite_all_effective_returns_effective() {
        let ctrl = make_composite(vec!["ctrl.a", "ctrl.b"]);
        let results = vec![result("ctrl.a", "effective"), result("ctrl.b", "effective")];
        assert_eq!(evaluate_composite(&ctrl, &results), "effective");
    }

    #[test]
    fn composite_one_ineffective_returns_ineffective() {
        let ctrl = make_composite(vec!["ctrl.a", "ctrl.b"]);
        let results = vec![result("ctrl.a", "effective"), result("ctrl.b", "ineffective")];
        assert_eq!(evaluate_composite(&ctrl, &results), "ineffective");
    }

    #[test]
    fn composite_missing_component_returns_ineffective() {
        let ctrl = make_composite(vec!["ctrl.a", "ctrl.b"]);
        // only ctrl.a provided, ctrl.b missing
        let results = vec![result("ctrl.a", "effective")];
        assert_eq!(evaluate_composite(&ctrl, &results), "ineffective");
    }

    #[test]
    fn composite_unknown_component_returns_ineffective() {
        let ctrl = make_composite(vec!["ctrl.a"]);
        let results = vec![result("ctrl.a", "unknown")];
        assert_eq!(evaluate_composite(&ctrl, &results), "ineffective");
    }

    #[test]
    fn composite_empty_results_all_missing_returns_ineffective() {
        let ctrl = make_composite(vec!["ctrl.a"]);
        assert_eq!(evaluate_composite(&ctrl, &[]), "ineffective");
    }
}
