use anyhow::{anyhow, Result};
use cel_interpreter::{Context as CelContext, Program, Value as CelValue};

use crate::control::EvaluationLogic;
use crate::evidence::{Evidence, StatusId, ConfidenceLevel};
use super::presets;

/// Evaluates a control's evaluation logic against a slice of evidence.
///
/// Dispatches to native presets for known preset names, or to the
/// cel-interpreter for arbitrary CEL expressions. Returns true when the
/// control is operating effectively according to the logic.
pub struct CelEngine;

impl CelEngine {
    /// Evaluate the given logic against the evidence slice.
    ///
    /// - If `logic.preset` is set → dispatch to the matching native preset.
    /// - If `logic.cel_expression` is set → evaluate via `cel-interpreter`.
    /// - If both are empty → returns an error.
    pub fn evaluate(logic: &EvaluationLogic, evidence: &[Evidence]) -> Result<bool> {
        if !logic.preset.is_empty() {
            return Self::run_preset(&logic.preset, evidence);
        }
        if !logic.cel_expression.is_empty() {
            return Self::run_cel(&logic.cel_expression, evidence);
        }
        Err(anyhow!("evaluation logic has neither preset nor cel_expression"))
    }

    fn run_preset(name: &str, evidence: &[Evidence]) -> Result<bool> {
        match name {
            "all_effective" => Ok(presets::all_effective(evidence)),
            "any_effective" => Ok(presets::any_effective(evidence)),
            "active_verified" => Ok(presets::active_verified(evidence)),
            other => Err(anyhow!("unknown evaluation preset: {}", other)),
        }
    }

    fn run_cel(expr: &str, evidence: &[Evidence]) -> Result<bool> {
        let program = Program::compile(expr)
            .map_err(|e| anyhow!("CEL compile error: {}", e))?;

        let mut ctx = CelContext::default();

        // Aggregate counts for CEL context variables.
        let total = evidence.len() as i64;
        let effective = evidence.iter().filter(|e| e.status_id == StatusId::Effective).count() as i64;
        let ineffective = evidence.iter().filter(|e| e.status_id == StatusId::Ineffective).count() as i64;
        let unknown = evidence.iter().filter(|e| e.status_id == StatusId::Unknown).count() as i64;
        let active = evidence.iter()
            .filter(|e| e.confidence_level == ConfidenceLevel::ActiveVerification)
            .count() as i64;

        ctx.add_variable("evidence_count", total)
            .map_err(|e| anyhow!("adding evidence_count: {}", e))?;
        ctx.add_variable("effective_count", effective)
            .map_err(|e| anyhow!("adding effective_count: {}", e))?;
        ctx.add_variable("ineffective_count", ineffective)
            .map_err(|e| anyhow!("adding ineffective_count: {}", e))?;
        ctx.add_variable("unknown_count", unknown)
            .map_err(|e| anyhow!("adding unknown_count: {}", e))?;
        ctx.add_variable("active_count", active)
            .map_err(|e| anyhow!("adding active_count: {}", e))?;
        ctx.add_variable("has_active", active > 0)
            .map_err(|e| anyhow!("adding has_active: {}", e))?;

        let result = program.execute(&ctx)
            .map_err(|e| anyhow!("CEL execution error: {}", e))?;

        match result {
            CelValue::Bool(b) => Ok(b),
            other => Err(anyhow!("CEL expression must return bool, got: {:?}", other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::make_evidence;
    use crate::control::definition::EvaluationLogic;
    use crate::evidence::{StatusId, ConfidenceLevel};

    fn logic_preset(name: &str) -> EvaluationLogic {
        EvaluationLogic { preset: name.to_string(), cel_expression: String::new() }
    }

    fn logic_cel(expr: &str) -> EvaluationLogic {
        EvaluationLogic { cel_expression: expr.to_string(), preset: String::new() }
    }

    fn logic_empty() -> EvaluationLogic {
        EvaluationLogic::default()
    }

    fn ev_effective() -> Evidence {
        let mut e = make_evidence();
        e.status_id = StatusId::Effective;
        e.confidence_level = ConfidenceLevel::PassiveObservation;
        e
    }

    fn ev_active() -> Evidence {
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

    // --- preset dispatch ---

    #[test]
    fn preset_all_effective_passes() {
        let ev = vec![ev_effective()];
        assert!(CelEngine::evaluate(&logic_preset("all_effective"), &ev).unwrap());
    }

    #[test]
    fn preset_any_effective_passes() {
        let ev = vec![ev_ineffective(), ev_effective()];
        assert!(CelEngine::evaluate(&logic_preset("any_effective"), &ev).unwrap());
    }

    #[test]
    fn preset_active_verified_passes() {
        let ev = vec![ev_active()];
        assert!(CelEngine::evaluate(&logic_preset("active_verified"), &ev).unwrap());
    }

    #[test]
    fn preset_unknown_returns_error() {
        let ev = vec![ev_effective()];
        let err = CelEngine::evaluate(&logic_preset("nonexistent"), &ev).unwrap_err();
        assert!(err.to_string().contains("unknown evaluation preset"));
    }

    // --- CEL expression ---

    #[test]
    fn cel_effective_count_gt_zero() {
        let ev = vec![ev_effective()];
        let result = CelEngine::evaluate(&logic_cel("effective_count > 0"), &ev).unwrap();
        assert!(result);
    }

    #[test]
    fn cel_no_ineffective() {
        let ev = vec![ev_effective()];
        let result = CelEngine::evaluate(&logic_cel("ineffective_count == 0"), &ev).unwrap();
        assert!(result);
    }

    #[test]
    fn cel_has_active_flag() {
        let ev = vec![ev_active()];
        let result = CelEngine::evaluate(&logic_cel("has_active"), &ev).unwrap();
        assert!(result);
    }

    #[test]
    fn cel_compound_expression() {
        let ev = vec![ev_effective(), ev_active()];
        let result = CelEngine::evaluate(
            &logic_cel("effective_count > 0 && ineffective_count == 0"),
            &ev,
        ).unwrap();
        assert!(result);
    }

    #[test]
    fn cel_expression_returns_false() {
        let ev = vec![ev_ineffective()];
        let result = CelEngine::evaluate(&logic_cel("effective_count > 0"), &ev).unwrap();
        assert!(!result);
    }

    #[test]
    fn cel_parse_error_returns_err() {
        let err = CelEngine::evaluate(&logic_cel("&&& invalid"), &[]).unwrap_err();
        assert!(err.to_string().contains("CEL compile error"));
    }

    #[test]
    fn cel_non_bool_result_returns_err() {
        // Expression that returns an integer, not a bool
        let ev = vec![ev_effective()];
        let err = CelEngine::evaluate(&logic_cel("effective_count"), &ev).unwrap_err();
        assert!(err.to_string().contains("must return bool"));
    }

    // --- empty logic ---

    #[test]
    fn empty_logic_returns_error() {
        let err = CelEngine::evaluate(&logic_empty(), &[]).unwrap_err();
        assert!(err.to_string().contains("neither preset nor cel_expression"));
    }
}
