/// GRC-17 §5.5 — Cross-module evaluation and composite control tests

use chrono::Utc;
use uuid::Uuid;

use ocean::control::EvaluationLogic;
use ocean::eval::CelEngine;
use ocean::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn make_evidence(control_id: &str, source: &str, status: StatusId) -> Evidence {
    Evidence {
        id: Uuid::new_v4(),
        control_id: control_id.to_string(),
        class_uid: 1001,
        category_uid: 10,
        activity_id: 1,
        time: Utc::now(),
        confidence_level: ConfidenceLevel::PassiveObservation,
        metadata: Metadata {
            module: ModuleInfo {
                name: format!("eval.{}", source),
                version: "0.1.0".to_string(),
                module_type: "observer".to_string(),
            },
            source: SourceInfo {
                system: source.to_string(),
                api_version: "v1".to_string(),
                endpoint: format!("mock://{}", source),
            },
            original_time: None,
            processed_time: Utc::now(),
            safety_classification: None,
        },
        observables: vec![Observable {
            obs_type: "resource".to_string(),
            value: format!("{}:resource", source),
            name: String::new(),
        }],
        status_id: status.clone(),
        status: match status {
            StatusId::Effective => "effective".to_string(),
            StatusId::Ineffective => "ineffective".to_string(),
            _ => "unknown".to_string(),
        },
        raw_data: serde_json::json!({"source": source}),
        findings: vec![Finding {
            title: "Eval Finding".to_string(),
            description: format!("Finding from {}", source),
            severity_id: 0,
        }],
        test_transcript: None,
        enrichments: vec![],
    }
}

fn make_active_evidence(control_id: &str, source: &str) -> Evidence {
    let mut ev = make_evidence(control_id, source, StatusId::Effective);
    ev.confidence_level = ConfidenceLevel::ActiveVerification;
    ev
}

// ─── 5.5: CEL expression evaluation ─────────────────────────────────────────

/// CEL expression `effective_count >= 2` passes when 3 of 3 are effective.
#[test]
fn eval_cel_all_effective_passes_threshold() {
    let logic = EvaluationLogic {
        preset: String::new(),
        cel_expression: "effective_count >= 2".to_string(),
    };
    let evidence = vec![
        make_evidence("CTRL-1", "github", StatusId::Effective),
        make_evidence("CTRL-1", "okta", StatusId::Effective),
        make_evidence("CTRL-1", "aws", StatusId::Effective),
    ];
    assert!(CelEngine::evaluate(&logic, &evidence).unwrap());
}

/// CEL expression fails when effective_count is below threshold.
#[test]
fn eval_cel_below_threshold_fails() {
    let logic = EvaluationLogic {
        preset: String::new(),
        cel_expression: "effective_count >= 3".to_string(),
    };
    let evidence = vec![
        make_evidence("CTRL-2", "github", StatusId::Effective),
        make_evidence("CTRL-2", "okta", StatusId::Ineffective),
    ];
    assert!(!CelEngine::evaluate(&logic, &evidence).unwrap());
}

/// `has_active` is true when at least one ActiveVerification evidence exists.
#[test]
fn eval_cel_has_active_with_active_evidence() {
    let logic = EvaluationLogic {
        preset: String::new(),
        cel_expression: "has_active".to_string(),
    };
    let evidence = vec![
        make_evidence("CTRL-3", "github", StatusId::Effective),
        make_active_evidence("CTRL-3", "tester"),
    ];
    assert!(CelEngine::evaluate(&logic, &evidence).unwrap());
}

/// `has_active` is false when no ActiveVerification evidence.
#[test]
fn eval_cel_has_active_false_without_active() {
    let logic = EvaluationLogic {
        preset: String::new(),
        cel_expression: "has_active".to_string(),
    };
    let evidence = vec![
        make_evidence("CTRL-4", "github", StatusId::Effective),
        make_evidence("CTRL-4", "okta", StatusId::Effective),
    ];
    assert!(!CelEngine::evaluate(&logic, &evidence).unwrap());
}

/// Mixed: effective > ineffective passes CEL expression.
#[test]
fn eval_cel_effective_exceeds_ineffective() {
    let logic = EvaluationLogic {
        preset: String::new(),
        cel_expression: "effective_count > ineffective_count".to_string(),
    };
    let evidence = vec![
        make_evidence("CTRL-5", "github", StatusId::Effective),
        make_evidence("CTRL-5", "okta", StatusId::Effective),
        make_evidence("CTRL-5", "aws", StatusId::Ineffective),
    ];
    assert!(CelEngine::evaluate(&logic, &evidence).unwrap());
}

/// Unknown preset returns an error.
#[test]
fn eval_unknown_preset_returns_err() {
    let logic = EvaluationLogic {
        preset: "nonexistent_preset".to_string(),
        cel_expression: String::new(),
    };
    let result = CelEngine::evaluate(&logic, &[]);
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("unknown"), "error should mention 'unknown': {}", msg);
}

/// Empty logic (neither preset nor cel_expression) returns an error.
#[test]
fn eval_empty_logic_returns_err() {
    let logic = EvaluationLogic {
        preset: String::new(),
        cel_expression: String::new(),
    };
    let result = CelEngine::evaluate(&logic, &[]);
    assert!(result.is_err());
}

// ─── 5.5: Preset evaluation ──────────────────────────────────────────────────

/// `all_effective` preset passes when all evidence is effective.
#[test]
fn eval_preset_all_effective_passes() {
    let logic = EvaluationLogic {
        preset: "all_effective".to_string(),
        cel_expression: String::new(),
    };
    let evidence = vec![
        make_evidence("CTRL-6", "github", StatusId::Effective),
        make_evidence("CTRL-6", "okta", StatusId::Effective),
    ];
    assert!(CelEngine::evaluate(&logic, &evidence).unwrap());
}

/// `all_effective` preset fails when any evidence is ineffective.
#[test]
fn eval_preset_all_effective_fails_on_partial() {
    let logic = EvaluationLogic {
        preset: "all_effective".to_string(),
        cel_expression: String::new(),
    };
    let evidence = vec![
        make_evidence("CTRL-7", "github", StatusId::Effective),
        make_evidence("CTRL-7", "okta", StatusId::Ineffective),
    ];
    assert!(!CelEngine::evaluate(&logic, &evidence).unwrap());
}

/// `any_effective` preset passes when at least one evidence is effective.
#[test]
fn eval_preset_any_effective_passes_on_partial() {
    let logic = EvaluationLogic {
        preset: "any_effective".to_string(),
        cel_expression: String::new(),
    };
    let evidence = vec![
        make_evidence("CTRL-8", "github", StatusId::Effective),
        make_evidence("CTRL-8", "okta", StatusId::Ineffective),
    ];
    assert!(CelEngine::evaluate(&logic, &evidence).unwrap());
}

/// `active_verified` preset passes when at least one ActiveVerification evidence.
#[test]
fn eval_preset_active_verified_with_active() {
    let logic = EvaluationLogic {
        preset: "active_verified".to_string(),
        cel_expression: String::new(),
    };
    let evidence = vec![
        make_evidence("CTRL-9", "github", StatusId::Effective),
        make_active_evidence("CTRL-9", "tester"),
    ];
    assert!(CelEngine::evaluate(&logic, &evidence).unwrap());
}

// ─── 5.5: Cross-module composite evaluation ──────────────────────────────────

/// Composite control spanning GitHub + Okta sub-controls.
/// Both sub-controls have effective evidence → composite passes.
#[test]
fn eval_composite_cross_module_all_pass() {
    use ocean::storage::{EvidenceQuery, SqliteStore, Store};

    let store = SqliteStore::open(":memory:").unwrap();

    let github_ev = make_evidence("GH-1.1", "github", StatusId::Effective);
    let okta_ev = make_evidence("OKTA-1.1", "okta", StatusId::Effective);
    store.store_evidence(&github_ev).unwrap();
    store.store_evidence(&okta_ev).unwrap();

    let gh_evidence = store.query_evidence(&EvidenceQuery {
        control_id: Some("GH-1.1".to_string()),
        ..Default::default()
    }).unwrap();
    let okta_evidence = store.query_evidence(&EvidenceQuery {
        control_id: Some("OKTA-1.1".to_string()),
        ..Default::default()
    }).unwrap();

    let gh_result = CelEngine::evaluate(
        &EvaluationLogic { preset: "all_effective".to_string(), cel_expression: String::new() },
        &gh_evidence,
    ).unwrap();
    let okta_result = CelEngine::evaluate(
        &EvaluationLogic { preset: "all_effective".to_string(), cel_expression: String::new() },
        &okta_evidence,
    ).unwrap();

    assert!(gh_result, "GitHub sub-control must pass");
    assert!(okta_result, "Okta sub-control must pass");

    // Both must pass for composite to be effective.
    let composite_effective = gh_result && okta_result;
    assert!(composite_effective);
}

/// Composite control: one sub-control fails → composite is not fully effective.
#[test]
fn eval_composite_cross_module_partial_fail() {
    use ocean::storage::{EvidenceQuery, SqliteStore, Store};

    let store = SqliteStore::open(":memory:").unwrap();

    let github_ev = make_evidence("GH-2.1", "github", StatusId::Effective);
    let okta_ev = make_evidence("OKTA-2.1", "okta", StatusId::Ineffective);
    store.store_evidence(&github_ev).unwrap();
    store.store_evidence(&okta_ev).unwrap();

    let gh_evidence = store.query_evidence(&EvidenceQuery {
        control_id: Some("GH-2.1".to_string()),
        ..Default::default()
    }).unwrap();
    let okta_evidence = store.query_evidence(&EvidenceQuery {
        control_id: Some("OKTA-2.1".to_string()),
        ..Default::default()
    }).unwrap();

    let gh_result = CelEngine::evaluate(
        &EvaluationLogic { preset: "all_effective".to_string(), cel_expression: String::new() },
        &gh_evidence,
    ).unwrap();
    let okta_result = CelEngine::evaluate(
        &EvaluationLogic { preset: "all_effective".to_string(), cel_expression: String::new() },
        &okta_evidence,
    ).unwrap();

    assert!(gh_result, "GitHub sub-control passes");
    assert!(!okta_result, "Okta sub-control fails");
    assert!(!(gh_result && okta_result), "composite must not pass when any sub-control fails");
}
