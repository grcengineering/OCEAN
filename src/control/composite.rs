use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::control::definition::{ComponentSpec, Control, CrossCheckAssertion};
use crate::evidence::{Evidence, StatusId};

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
        let found = component_results.iter().find(|r| &r.control_id == comp_id);

        match found {
            Some(r) if r.status == "effective" => {}
            _ => return "ineffective".to_string(),
        }
    }

    "effective".to_string()
}

// ---------------------------------------------------------------------------
// Rich component evaluation with observable exports and cross-checks
// ---------------------------------------------------------------------------

/// Result of a single cross-check assertion evaluated between two components.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossCheckResult {
    /// Human-readable label from the cross_check spec.
    pub label: String,
    /// Whether the assertion passed.
    pub passed: bool,
    /// Reason string for surfacing in evaluation details.
    pub reason: String,
}

/// Evaluate a composite control using rich [`ComponentSpec`] definitions.
///
/// For each component, evidence is looked up by `(evidence_class, activity_id)` key.
/// Observables marked as exports are observed into a named map and made available
/// to subsequent components' cross-checks.
///
/// Returns `("effective" | "ineffective", cross_check_results)`.
pub fn evaluate_composite_with_components(
    components: &[ComponentSpec],
    evidence_by_class: &HashMap<(i32, Option<i32>), Vec<Evidence>>,
) -> (String, Vec<CrossCheckResult>) {
    // Accumulated named export sets: export_name → set of values
    let mut exports: HashMap<String, HashSet<String>> = HashMap::new();
    let mut cross_check_results: Vec<CrossCheckResult> = Vec::new();
    let mut overall_effective = true;

    for component in components {
        let key = (component.evidence_class, component.activity_id);
        let evidence_list: &[Evidence] = evidence_by_class
            .get(&key)
            .map(|v| v.as_slice())
            .unwrap_or(&[]);

        // Is this component effective?
        let component_effective = evidence_list
            .iter()
            .any(|e| e.status_id == StatusId::Effective);

        if !component_effective && component.required {
            overall_effective = false;
        }

        // Collect observable exports from this component's evidence.
        for export_spec in &component.exports {
            let values: HashSet<String> = evidence_list
                .iter()
                .flat_map(|e| &e.observables)
                .filter(|obs| obs.obs_type == export_spec.obs_type)
                .map(|obs| obs.value.clone())
                .collect();
            exports.insert(export_spec.name.clone(), values);
        }

        // Evaluate cross-checks — compare this component's observables against a
        // previously observed export set.
        for cross_check in &component.cross_checks {
            let local_values: HashSet<String> = evidence_list
                .iter()
                .flat_map(|e| &e.observables)
                .filter(|obs| obs.obs_type == cross_check.obs_type)
                .map(|obs| obs.value.clone())
                .collect();

            let referenced = exports.get(&cross_check.uses).cloned().unwrap_or_default();

            let (passed, reason) = evaluate_assertion(
                &cross_check.assertion,
                &local_values,
                &referenced,
                &cross_check.label,
                &cross_check.uses,
            );

            if !passed {
                overall_effective = false;
            }

            cross_check_results.push(CrossCheckResult {
                label: cross_check.label.clone(),
                passed,
                reason,
            });
        }
    }

    let status = if overall_effective {
        "effective"
    } else {
        "ineffective"
    }
    .to_string();

    (status, cross_check_results)
}

fn evaluate_assertion(
    assertion: &CrossCheckAssertion,
    local: &HashSet<String>,
    referenced: &HashSet<String>,
    label: &str,
    uses: &str,
) -> (bool, String) {
    match assertion {
        CrossCheckAssertion::SubsetOf => {
            let violations: Vec<&String> =
                local.iter().filter(|v| !referenced.contains(*v)).collect();
            if violations.is_empty() {
                (true, format!("All local values are in '{uses}' export"))
            } else {
                (
                    false,
                    format!(
                        "{label}: {} local value(s) not found in '{uses}' export",
                        violations.len()
                    ),
                )
            }
        }
        CrossCheckAssertion::SupersetOf => {
            let missing: Vec<&String> = referenced.iter().filter(|v| !local.contains(*v)).collect();
            if missing.is_empty() {
                (true, format!("Local values cover all of '{uses}' export"))
            } else {
                (
                    false,
                    format!(
                        "{label}: {} value(s) from '{uses}' export not found locally",
                        missing.len()
                    ),
                )
            }
        }
        CrossCheckAssertion::ContainsAny => {
            let has_overlap = local.iter().any(|v| referenced.contains(v));
            if has_overlap {
                (
                    true,
                    format!("At least one local value found in '{uses}' export"),
                )
            } else {
                (
                    false,
                    format!("{label}: no overlap between local values and '{uses}' export"),
                )
            }
        }
        CrossCheckAssertion::Nonempty => {
            if !referenced.is_empty() {
                (
                    true,
                    format!("'{uses}' export is non-empty ({} values)", referenced.len()),
                )
            } else {
                (false, format!("{label}: '{uses}' export is empty"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::definition::{
        ComponentSpec, Control, CrossCheck, CrossCheckAssertion, EvaluationLogic, ExportSpec,
    };
    use crate::evidence::{
        ConfidenceLevel, Evidence, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
    };
    use chrono::Utc;

    fn make_composite(components: Vec<&str>) -> Control {
        Control {
            id: "composite.ctrl".to_string(),
            name: "Composite".to_string(),
            description: String::new(),
            evaluation_logic: EvaluationLogic::default(),
            framework_mappings: vec![],
            observers: vec![],
            testers: vec![],
            component_controls: components.into_iter().map(String::from).collect(),
            components: vec![],
            evaluation_expression_hash: String::new(),
        }
    }

    fn make_evidence(class_uid: i32, activity_id: i32, effective: bool) -> Evidence {
        make_evidence_with_observables(class_uid, activity_id, effective, vec![])
    }

    fn make_evidence_with_observables(
        class_uid: i32,
        activity_id: i32,
        effective: bool,
        observables: Vec<Observable>,
    ) -> Evidence {
        Evidence {
            id: uuid::Uuid::new_v4(),
            control_id: "test.ctrl".to_string(),
            class_uid,
            category_uid: class_uid / 1000,
            activity_id,
            time: Utc::now(),
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "test".to_string(),
                    version: "0.1.0".to_string(),
                    module_type: "observer".to_string(),
                },
                source: SourceInfo {
                    system: "mock".to_string(),
                    api_version: "v1".to_string(),
                    endpoint: "mock://ep".to_string(),
                },
                original_time: None,
                processed_time: Utc::now(),
                safety_classification: None,
            },
            observables,
            status_id: if effective {
                StatusId::Effective
            } else {
                StatusId::Ineffective
            },
            status: if effective {
                "effective".to_string()
            } else {
                "ineffective".to_string()
            },
            raw_data: serde_json::Value::Null,
            findings: vec![],
            test_transcript: None,
            enrichments: vec![],
        }
    }

    fn obs(obs_type: &str, value: &str) -> Observable {
        Observable {
            obs_type: obs_type.to_string(),
            value: value.to_string(),
            name: String::new(),
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
        let results = vec![
            result("ctrl.a", "effective"),
            result("ctrl.b", "ineffective"),
        ];
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

    // --- evaluate_composite_with_components ---

    #[test]
    fn components_empty_returns_effective() {
        let (status, checks) = evaluate_composite_with_components(&[], &HashMap::new());
        assert_eq!(status, "effective");
        assert!(checks.is_empty());
    }

    #[test]
    fn components_all_effective_no_crosschecks_returns_effective() {
        let ev = make_evidence(3002, 1, true);
        let key = (3002, Some(1));
        let mut map = HashMap::new();
        map.insert(key, vec![ev]);

        let components = vec![ComponentSpec {
            id: "waf".to_string(),
            evidence_class: 3002,
            activity_id: Some(1),
            required: true,
            exports: vec![],
            cross_checks: vec![],
        }];

        let (status, _) = evaluate_composite_with_components(&components, &map);
        assert_eq!(status, "effective");
    }

    #[test]
    fn components_required_missing_evidence_returns_ineffective() {
        let components = vec![ComponentSpec {
            id: "waf".to_string(),
            evidence_class: 3002,
            activity_id: Some(1),
            required: true,
            exports: vec![],
            cross_checks: vec![],
        }];

        let (status, _) = evaluate_composite_with_components(&components, &HashMap::new());
        assert_eq!(status, "ineffective");
    }

    #[test]
    fn components_optional_missing_does_not_fail() {
        let components = vec![ComponentSpec {
            id: "waf".to_string(),
            evidence_class: 3002,
            activity_id: Some(1),
            required: false,
            exports: vec![],
            cross_checks: vec![],
        }];

        let (status, _) = evaluate_composite_with_components(&components, &HashMap::new());
        assert_eq!(status, "effective");
    }

    #[test]
    fn cross_check_subset_of_passes() {
        // WAF exports egress IPs; firewall rules are a subset of those IPs.
        let waf_ev = make_evidence_with_observables(
            3002,
            1,
            true,
            vec![obs("ip_range", "10.0.0.1"), obs("ip_range", "10.0.0.2")],
        );
        let fw_ev = make_evidence_with_observables(
            3001,
            1,
            true,
            vec![obs("ip_range", "10.0.0.1")], // subset of WAF IPs
        );

        let mut map = HashMap::new();
        map.insert((3002, Some(1)), vec![waf_ev]);
        map.insert((3001, Some(1)), vec![fw_ev]);

        let components = vec![
            ComponentSpec {
                id: "waf".to_string(),
                evidence_class: 3002,
                activity_id: Some(1),
                required: true,
                exports: vec![ExportSpec {
                    name: "waf_egress_ips".to_string(),
                    obs_type: "ip_range".to_string(),
                }],
                cross_checks: vec![],
            },
            ComponentSpec {
                id: "firewall".to_string(),
                evidence_class: 3001,
                activity_id: Some(1),
                required: true,
                exports: vec![],
                cross_checks: vec![CrossCheck {
                    uses: "waf_egress_ips".to_string(),
                    obs_type: "ip_range".to_string(),
                    assertion: CrossCheckAssertion::SubsetOf,
                    label: "Firewall allows only WAF egress IPs".to_string(),
                }],
            },
        ];

        let (status, checks) = evaluate_composite_with_components(&components, &map);
        assert_eq!(status, "effective");
        assert_eq!(checks.len(), 1);
        assert!(checks[0].passed);
    }

    #[test]
    fn cross_check_subset_of_fails_when_extra_ip() {
        // Firewall allows an IP not in WAF egress — cross-check fails.
        let waf_ev =
            make_evidence_with_observables(3002, 1, true, vec![obs("ip_range", "10.0.0.1")]);
        let fw_ev = make_evidence_with_observables(
            3001,
            1,
            true,
            vec![
                obs("ip_range", "10.0.0.1"),
                obs("ip_range", "10.0.0.99"), // not in WAF set — violation
            ],
        );

        let mut map = HashMap::new();
        map.insert((3002, Some(1)), vec![waf_ev]);
        map.insert((3001, Some(1)), vec![fw_ev]);

        let components = vec![
            ComponentSpec {
                id: "waf".to_string(),
                evidence_class: 3002,
                activity_id: Some(1),
                required: true,
                exports: vec![ExportSpec {
                    name: "waf_egress_ips".to_string(),
                    obs_type: "ip_range".to_string(),
                }],
                cross_checks: vec![],
            },
            ComponentSpec {
                id: "firewall".to_string(),
                evidence_class: 3001,
                activity_id: Some(1),
                required: true,
                exports: vec![],
                cross_checks: vec![CrossCheck {
                    uses: "waf_egress_ips".to_string(),
                    obs_type: "ip_range".to_string(),
                    assertion: CrossCheckAssertion::SubsetOf,
                    label: "Firewall allows only WAF egress IPs".to_string(),
                }],
            },
        ];

        let (status, checks) = evaluate_composite_with_components(&components, &map);
        assert_eq!(status, "ineffective");
        assert!(!checks[0].passed);
    }

    #[test]
    fn cross_check_nonempty_passes() {
        let waf_ev =
            make_evidence_with_observables(3002, 1, true, vec![obs("ip_range", "10.0.0.1")]);
        let mut map = HashMap::new();
        map.insert((3002, Some(1)), vec![waf_ev]);

        let components = vec![
            ComponentSpec {
                id: "waf".to_string(),
                evidence_class: 3002,
                activity_id: Some(1),
                required: true,
                exports: vec![ExportSpec {
                    name: "waf_ips".to_string(),
                    obs_type: "ip_range".to_string(),
                }],
                cross_checks: vec![],
            },
            ComponentSpec {
                id: "checker".to_string(),
                evidence_class: 3001,
                activity_id: Some(1),
                required: false,
                exports: vec![],
                cross_checks: vec![CrossCheck {
                    uses: "waf_ips".to_string(),
                    obs_type: "ip_range".to_string(),
                    assertion: CrossCheckAssertion::Nonempty,
                    label: "WAF has at least one egress IP".to_string(),
                }],
            },
        ];

        let (status, checks) = evaluate_composite_with_components(&components, &map);
        assert_eq!(status, "effective");
        assert!(checks[0].passed);
    }

    #[test]
    fn cross_check_nonempty_fails_when_export_empty() {
        // WAF evidence has no ip_range observables → export is empty.
        let waf_ev = make_evidence(3002, 1, true); // no observables
        let mut map = HashMap::new();
        map.insert((3002, Some(1)), vec![waf_ev]);

        let components = vec![
            ComponentSpec {
                id: "waf".to_string(),
                evidence_class: 3002,
                activity_id: Some(1),
                required: true,
                exports: vec![ExportSpec {
                    name: "waf_ips".to_string(),
                    obs_type: "ip_range".to_string(),
                }],
                cross_checks: vec![],
            },
            ComponentSpec {
                id: "checker".to_string(),
                evidence_class: 3001,
                activity_id: Some(1),
                required: false,
                exports: vec![],
                cross_checks: vec![CrossCheck {
                    uses: "waf_ips".to_string(),
                    obs_type: "ip_range".to_string(),
                    assertion: CrossCheckAssertion::Nonempty,
                    label: "WAF has at least one egress IP".to_string(),
                }],
            },
        ];

        let (status, checks) = evaluate_composite_with_components(&components, &map);
        assert_eq!(status, "ineffective");
        assert!(!checks[0].passed);
    }

    #[test]
    fn cross_check_contains_any_passes() {
        let export_ev = make_evidence_with_observables(
            3002,
            1,
            true,
            vec![
                obs("domain", "example.com"),
                obs("domain", "cdn.example.com"),
            ],
        );
        let local_ev =
            make_evidence_with_observables(3001, 1, true, vec![obs("domain", "cdn.example.com")]);
        let mut map = HashMap::new();
        map.insert((3002, Some(1)), vec![export_ev]);
        map.insert((3001, Some(1)), vec![local_ev]);

        let components = vec![
            ComponentSpec {
                id: "src".to_string(),
                evidence_class: 3002,
                activity_id: Some(1),
                required: true,
                exports: vec![ExportSpec {
                    name: "known_domains".to_string(),
                    obs_type: "domain".to_string(),
                }],
                cross_checks: vec![],
            },
            ComponentSpec {
                id: "dst".to_string(),
                evidence_class: 3001,
                activity_id: Some(1),
                required: true,
                exports: vec![],
                cross_checks: vec![CrossCheck {
                    uses: "known_domains".to_string(),
                    obs_type: "domain".to_string(),
                    assertion: CrossCheckAssertion::ContainsAny,
                    label: "At least one known domain is referenced".to_string(),
                }],
            },
        ];

        let (status, checks) = evaluate_composite_with_components(&components, &map);
        assert_eq!(status, "effective");
        assert!(checks[0].passed);
    }

    #[test]
    fn cross_check_superset_of_passes() {
        let export_ev =
            make_evidence_with_observables(3002, 1, true, vec![obs("ip_range", "10.0.0.1")]);
        let local_ev = make_evidence_with_observables(
            3001,
            1,
            true,
            vec![obs("ip_range", "10.0.0.1"), obs("ip_range", "10.0.0.2")],
        );
        let mut map = HashMap::new();
        map.insert((3002, Some(1)), vec![export_ev]);
        map.insert((3001, Some(1)), vec![local_ev]);

        let components = vec![
            ComponentSpec {
                id: "src".to_string(),
                evidence_class: 3002,
                activity_id: Some(1),
                required: true,
                exports: vec![ExportSpec {
                    name: "required_ips".to_string(),
                    obs_type: "ip_range".to_string(),
                }],
                cross_checks: vec![],
            },
            ComponentSpec {
                id: "dst".to_string(),
                evidence_class: 3001,
                activity_id: Some(1),
                required: true,
                exports: vec![],
                cross_checks: vec![CrossCheck {
                    uses: "required_ips".to_string(),
                    obs_type: "ip_range".to_string(),
                    assertion: CrossCheckAssertion::SupersetOf,
                    label: "Local covers all required IPs".to_string(),
                }],
            },
        ];

        let (status, checks) = evaluate_composite_with_components(&components, &map);
        assert_eq!(status, "effective");
        assert!(checks[0].passed);
    }

    #[test]
    fn cross_check_result_serde_round_trip() {
        let r = CrossCheckResult {
            label: "test label".to_string(),
            passed: true,
            reason: "all good".to_string(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let decoded: CrossCheckResult = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.label, "test label");
        assert!(decoded.passed);
    }
}
