// YAML check interpreter — executes .check.yaml files at runtime.
//
// YamlObserver implements Observer for passive checks.
// YamlTester implements Tester for active checks.
//
// Both types:
//   1. Resolve template variables ({{key}}) from config
//   2. Execute HTTP steps via ureq
//   3. Extract variables from responses using JSONPath
//   4. Evaluate CEL assertions against extracted variables
//   5. Wrap results as Evidence

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use cel_interpreter::{Context as CelContext, Program, Value as CelValue};
use serde_json::Value as JsonValue;
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo as EvidenceModuleInfo, Observable,
    SourceInfo, StatusId,
};
use crate::module::{
    observer::Observer, CredentialReq, EnvironmentScope, Module, SafetyClassification, Tester,
};

use super::definition::{CheckAssertion, CheckDefinition, CheckStep};

// ─── Template variable resolution ─────────────────────────────────────────────

/// Replaces `{{key}}` placeholders with values from `ctx`.
fn resolve_template(template: &str, ctx: &HashMap<String, String>) -> String {
    let mut result = template.to_string();
    for (key, value) in ctx {
        let placeholder = format!("{{{{{}}}}}", key);
        result = result.replace(&placeholder, value);
    }
    result
}

/// Resolve all headers in a map, substituting template variables.
fn resolve_headers(
    headers: &HashMap<String, String>,
    ctx: &HashMap<String, String>,
) -> HashMap<String, String> {
    headers
        .iter()
        .map(|(k, v)| (k.clone(), resolve_template(v, ctx)))
        .collect()
}

// ─── JSONPath evaluation ───────────────────────────────────────────────────────

/// Extract a value from a JSON body using a simplified JSONPath expression.
///
/// Supported patterns:
/// - `$status_code`         → special: numeric status code (set separately in ctx)
/// - `$length`              → length of the root array (or 1 for a non-array)
/// - `$.field`              → field on root object
/// - `$.field.nested`       → nested field access
/// - `$[*].field`           → collect `field` from every element of root array
/// - `$[*]`                 → whole array as-is
fn jsonpath_extract(path: &str, body: &JsonValue) -> Option<JsonValue> {
    if path == "$length" {
        let len = match body {
            JsonValue::Array(arr) => arr.len() as i64,
            _ => 1,
        };
        return Some(JsonValue::Number(len.into()));
    }

    if path == "$status_code" {
        // Caller sets this in the extracted map directly; skip here.
        return None;
    }

    if path == "$" {
        return Some(body.clone());
    }

    // Array wildcard: `$[*].field` or `$[*]`
    if let Some(rest) = path.strip_prefix("$[*]") {
        let arr = body.as_array()?;
        if rest.is_empty() {
            return Some(JsonValue::Array(arr.clone()));
        }
        // rest is like `.field` or `.field.nested`
        let field_path = rest.strip_prefix('.')?;
        let values: Vec<JsonValue> = arr
            .iter()
            .filter_map(|item| navigate_fields(field_path, item))
            .collect();
        return Some(JsonValue::Array(values));
    }

    // Object path: `$.field` or `$.field.nested`
    if let Some(rest) = path.strip_prefix("$.") {
        return navigate_fields(rest, body);
    }

    None
}

/// Navigate a dot-separated field path on a JSON value.
fn navigate_fields(path: &str, val: &JsonValue) -> Option<JsonValue> {
    let mut current = val;
    let mut owned: JsonValue;

    for part in path.split('.') {
        match current {
            JsonValue::Object(map) => {
                owned = map.get(part)?.clone();
                current = &owned;
            }
            _ => return None,
        }
    }
    Some(current.clone())
}

// ─── HTTP execution ────────────────────────────────────────────────────────────

struct StepResult {
    status_code: u16,
    body: JsonValue,
}

/// Execute a single API step, returning the status code and parsed JSON body.
fn execute_step(step: &CheckStep, ctx: &HashMap<String, String>) -> Result<StepResult> {
    let url = resolve_template(&step.request.url, ctx);
    let headers = resolve_headers(&step.request.headers, ctx);
    let method = step.request.method.to_uppercase();

    let mut req = match method.as_str() {
        "GET" => ureq::get(&url),
        "POST" => ureq::post(&url),
        "PUT" => ureq::put(&url),
        "PATCH" => ureq::patch(&url),
        "DELETE" => ureq::delete(&url),
        other => return Err(anyhow!("unsupported HTTP method: {}", other)),
    };

    for (k, v) in &headers {
        req = req.set(k, v);
    }

    let response = if let Some(body) = &step.request.body {
        let resolved_body = resolve_json_template(body, ctx);
        match method.as_str() {
            "GET" | "DELETE" => req.call(),
            _ => req.send_json(resolved_body),
        }
    } else {
        req.call()
    };

    let (status_code, body) = match response {
        Ok(r) => {
            let code = r.status();
            let b = r.into_json::<JsonValue>().unwrap_or(JsonValue::Null);
            (code, b)
        }
        Err(ureq::Error::Status(code, r)) => {
            let b = r.into_json::<JsonValue>().unwrap_or(JsonValue::Null);
            (code, b)
        }
        Err(e) => return Err(anyhow!("HTTP request failed for step '{}': {}", step.id, e)),
    };

    // Pagination: follow Link headers for GitHub-style cursor pagination.
    if step.request.paginate {
        // For now, return first page. Full pagination support is Phase 2.
        // TODO(GRC-28): implement Link header pagination
        return Ok(StepResult { status_code, body });
    }

    Ok(StepResult { status_code, body })
}

/// Recursively substitute `{{key}}` in JSON values.
fn resolve_json_template(val: &JsonValue, ctx: &HashMap<String, String>) -> JsonValue {
    match val {
        JsonValue::String(s) => JsonValue::String(resolve_template(s, ctx)),
        JsonValue::Object(map) => {
            let resolved = map
                .iter()
                .map(|(k, v)| (k.clone(), resolve_json_template(v, ctx)))
                .collect();
            JsonValue::Object(resolved)
        }
        JsonValue::Array(arr) => {
            JsonValue::Array(arr.iter().map(|v| resolve_json_template(v, ctx)).collect())
        }
        other => other.clone(),
    }
}

// ─── CEL evaluation ───────────────────────────────────────────────────────────

/// Evaluate a CEL assertion against the extracted variable context.
/// Returns `true` when the assertion passes.
fn evaluate_assertion(
    assertion: &CheckAssertion,
    extracted: &HashMap<String, JsonValue>,
) -> Result<bool> {
    let program =
        Program::compile(&assertion.expr).map_err(|e| anyhow!("CEL compile error: {}", e))?;

    let mut ctx = CelContext::default();

    for (name, value) in extracted {
        // Convert serde_json::Value to a type CEL can accept (via Serialize).
        ctx.add_variable(name.as_str(), value.clone())
            .map_err(|e| anyhow!("CEL variable '{}': {}", name, e))?;
    }

    let result = program
        .execute(&ctx)
        .map_err(|e| anyhow!("CEL execution error for '{}': {}", assertion.expr, e))?;

    match result {
        CelValue::Bool(b) => Ok(b),
        other => Err(anyhow!(
            "assertion '{}' returned non-bool: {:?}",
            assertion.id,
            other
        )),
    }
}

// ─── Core execution ────────────────────────────────────────────────────────────

/// Build a config context from the check definition's inputs, resolving env vars.
fn build_input_context(
    def: &CheckDefinition,
    config: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut ctx = config.clone();

    // Resolve declared inputs: prefer config[name], fall back to config[env_var].
    for (name, input_def) in &def.inputs {
        if !ctx.contains_key(name) {
            if !input_def.env.is_empty() {
                if let Some(v) = config.get(&input_def.env) {
                    ctx.insert(name.clone(), v.clone());
                }
            }
        }
    }

    ctx
}

/// Execute all steps and return the accumulated extracted variables.
fn run_steps(
    steps: &[CheckStep],
    ctx: &mut HashMap<String, String>,
) -> Result<HashMap<String, JsonValue>> {
    let mut extracted: HashMap<String, JsonValue> = HashMap::new();

    for step in steps {
        // Evaluate `when` guard if present.
        if !step.when.is_empty() {
            let should_run = evaluate_assertion(
                &CheckAssertion {
                    id: format!("{}_when", step.id),
                    expr: step.when.clone(),
                    severity: "info".to_string(),
                    title: String::new(),
                    pass_message: String::new(),
                    fail_message: String::new(),
                    finding: None,
                },
                &extracted,
            )
            .unwrap_or(false);

            if !should_run {
                continue;
            }
        }

        let result = execute_step(step, ctx)?;

        // Inject status code as a special extracted variable.
        extracted.insert(
            "status_code".to_string(),
            JsonValue::Number(result.status_code.into()),
        );

        // Alias the step's status code as `{step_id}_status_code` for multi-step checks.
        extracted.insert(
            format!("{}_status_code", step.id),
            JsonValue::Number(result.status_code.into()),
        );

        // Also make it available in the string context for template resolution.
        ctx.insert("status_code".to_string(), result.status_code.to_string());

        // Check on_error handlers.
        let code_str = result.status_code.to_string();
        if let Some(action) = step.on_error.get(&code_str) {
            if action == "continue" {
                // Record the status but skip extraction.
                continue;
            }
        }

        // Extract variables from the response body.
        for (var_name, path) in &step.extract {
            if path == "$status_code" {
                // Already handled above.
                extracted.insert(
                    var_name.clone(),
                    JsonValue::Number(result.status_code.into()),
                );
                continue;
            }
            if let Some(value) = jsonpath_extract(path, &result.body) {
                // Also expose as string in the template context for subsequent steps.
                if let Some(s) = json_to_string(&value) {
                    ctx.insert(var_name.clone(), s);
                }
                extracted.insert(var_name.clone(), value);
            }
        }
    }

    Ok(extracted)
}

/// Convert a JSON scalar to a string for use in template substitution.
fn json_to_string(val: &JsonValue) -> Option<String> {
    match val {
        JsonValue::String(s) => Some(s.clone()),
        JsonValue::Bool(b) => Some(b.to_string()),
        JsonValue::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Run all assertions and return one Evidence per assertion.
fn evaluate_all_assertions(
    def: &CheckDefinition,
    extracted: &HashMap<String, JsonValue>,
    ctx: &HashMap<String, String>,
    confidence: ConfidenceLevel,
) -> Vec<Evidence> {
    let mut results = Vec::new();

    for assertion in &def.assertions {
        let passed = evaluate_assertion(assertion, extracted).unwrap_or(false);

        let status_id = if passed {
            StatusId::Effective
        } else {
            StatusId::Ineffective
        };

        let message = if passed {
            resolve_template(&assertion.pass_message, ctx)
        } else {
            resolve_template(&assertion.fail_message, ctx)
        };

        let mut findings = Vec::new();
        if !passed {
            let description = assertion
                .finding
                .as_ref()
                .map(|f| f.description.clone())
                .unwrap_or_else(|| message.clone());

            let severity_id = match assertion.severity.as_str() {
                "critical" => 5,
                "high" => 4,
                "medium" => 3,
                "low" => 2,
                "info" => 1,
                _ => 0,
            };

            findings.push(Finding {
                title: assertion.title.clone(),
                description,
                severity_id,
            });
        }

        let observables: Vec<Observable> = extracted
            .iter()
            .filter_map(|(k, v)| {
                Some(Observable {
                    obs_type: "extracted".to_string(),
                    name: k.clone(),
                    value: json_to_string(v)?,
                })
            })
            .collect();

        let now = chrono::Utc::now();
        let endpoint = ctx
            .get("org")
            .or_else(|| ctx.get("owner"))
            .or_else(|| ctx.get("GITHUB_ORG"))
            .cloned()
            .unwrap_or_default();

        let ev = Evidence {
            id: Uuid::new_v4(),
            control_id: def.id.clone(),
            class_uid: 0,
            category_uid: 0,
            activity_id: 0,
            time: now,
            status_id,
            status: message,
            confidence_level: confidence.clone(),
            metadata: Metadata {
                module: EvidenceModuleInfo {
                    name: def.name.clone(),
                    version: def.version.clone(),
                    module_type: match confidence {
                        ConfidenceLevel::PassiveObservation => "observer".to_string(),
                        ConfidenceLevel::ActiveVerification => "tester".to_string(),
                    },
                },
                source: SourceInfo {
                    system: def.source.clone(),
                    api_version: def.version.clone(),
                    endpoint,
                },
                original_time: None,
                processed_time: now,
                safety_classification: if def.safety.is_empty() {
                    None
                } else {
                    Some(def.safety.clone())
                },
            },
            raw_data: serde_json::to_value(extracted).unwrap_or(JsonValue::Null),
            observables,
            findings,
            test_transcript: None,
            enrichments: vec![],
        };

        results.push(ev);
    }

    results
}

// ─── YamlObserver ─────────────────────────────────────────────────────────────

/// A passive Observer loaded from a `.check.yaml` file.
pub struct YamlObserver {
    def: Arc<CheckDefinition>,
}

impl YamlObserver {
    pub fn new(def: CheckDefinition) -> Self {
        Self {
            def: Arc::new(def),
        }
    }
}

impl Module for YamlObserver {
    fn id(&self) -> &str {
        &self.def.id
    }
    fn name(&self) -> &str {
        &self.def.name
    }
    fn version(&self) -> &str {
        &self.def.version
    }
    fn source_system(&self) -> &str {
        &self.def.source
    }
    fn evidence_types(&self) -> &[i32] {
        &[]
    }
    fn credential_requirements(&self) -> Vec<CredentialReq> {
        self.def
            .credentials
            .iter()
            .map(|(name, c)| CredentialReq {
                name: name.clone(),
                cred_type: c.cred_type.clone(),
                description: format!("Required for {}", self.def.id),
                required: c.required,
            })
            .collect()
    }
}

impl Observer for YamlObserver {
    fn observe(&self, config: &HashMap<String, String>) -> Result<Vec<Evidence>> {
        let mut ctx = build_input_context(&self.def, config);
        let extracted = run_steps(&self.def.steps, &mut ctx)
            .with_context(|| format!("executing steps for {}", self.def.id))?;
        Ok(evaluate_all_assertions(
            &self.def,
            &extracted,
            &ctx,
            ConfidenceLevel::PassiveObservation,
        ))
    }
}

// ─── YamlTester ───────────────────────────────────────────────────────────────

/// An active Tester loaded from a `.check.yaml` file.
pub struct YamlTester {
    def: Arc<CheckDefinition>,
}

impl YamlTester {
    pub fn new(def: CheckDefinition) -> Self {
        Self {
            def: Arc::new(def),
        }
    }
}

impl Module for YamlTester {
    fn id(&self) -> &str {
        &self.def.id
    }
    fn name(&self) -> &str {
        &self.def.name
    }
    fn version(&self) -> &str {
        &self.def.version
    }
    fn source_system(&self) -> &str {
        &self.def.source
    }
    fn evidence_types(&self) -> &[i32] {
        &[]
    }
    fn credential_requirements(&self) -> Vec<CredentialReq> {
        self.def
            .credentials
            .iter()
            .map(|(name, c)| CredentialReq {
                name: name.clone(),
                cred_type: c.cred_type.clone(),
                description: format!("Required for {}", self.def.id),
                required: c.required,
            })
            .collect()
    }
}

impl Tester for YamlTester {
    fn safety_class(&self) -> SafetyClassification {
        match self.def.safety.as_str() {
            "observable" => SafetyClassification::Observable,
            "reversible" => SafetyClassification::Reversible,
            _ => SafetyClassification::Observable,
        }
    }

    fn environment_scope(&self) -> EnvironmentScope {
        match self.def.environment.as_str() {
            "production" | "prod" => EnvironmentScope::Production,
            "staging" | "stage" => EnvironmentScope::Staging,
            _ => EnvironmentScope::Isolated,
        }
    }

    fn pre_flight_checks(&self) -> Vec<String> {
        self.def.pre_flight.clone()
    }

    fn cleanup_procedures(&self) -> Vec<String> {
        // Cleanup is handled via `when` conditions in steps (e.g., cleanup step
        // runs only when previous step didn't return 422).
        vec!["Cleanup steps are embedded in the check definition.".to_string()]
    }

    fn test(&self, config: &HashMap<String, String>) -> Result<Vec<Evidence>> {
        let mut ctx = build_input_context(&self.def, config);
        let extracted = run_steps(&self.def.steps, &mut ctx)
            .with_context(|| format!("executing steps for {}", self.def.id))?;
        Ok(evaluate_all_assertions(
            &self.def,
            &extracted,
            &ctx,
            ConfidenceLevel::ActiveVerification,
        ))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_template_basic() {
        let mut ctx = HashMap::new();
        ctx.insert("org".to_string(), "acme".to_string());
        ctx.insert("GITHUB_TOKEN".to_string(), "ghp_abc".to_string());
        let result =
            resolve_template("https://api.github.com/orgs/{{org}}", &ctx);
        assert_eq!(result, "https://api.github.com/orgs/acme");
    }

    #[test]
    fn resolve_template_multiple_vars() {
        let mut ctx = HashMap::new();
        ctx.insert("owner".to_string(), "acme".to_string());
        ctx.insert("repo".to_string(), "app".to_string());
        let result = resolve_template(
            "https://api.github.com/repos/{{owner}}/{{repo}}/contents/test.txt",
            &ctx,
        );
        assert_eq!(
            result,
            "https://api.github.com/repos/acme/app/contents/test.txt"
        );
    }

    #[test]
    fn resolve_template_unknown_var_left_as_is() {
        let ctx = HashMap::new();
        let result = resolve_template("{{unknown}}", &ctx);
        assert_eq!(result, "{{unknown}}");
    }

    #[test]
    fn jsonpath_simple_field() {
        let body = serde_json::json!({"two_factor_requirement_enabled": true, "login": "acme"});
        let val = jsonpath_extract("$.two_factor_requirement_enabled", &body).unwrap();
        assert_eq!(val, JsonValue::Bool(true));
    }

    #[test]
    fn jsonpath_nested_field() {
        let body = serde_json::json!({"content": {"sha": "abc123"}});
        let val = jsonpath_extract("$.content.sha", &body).unwrap();
        assert_eq!(val, JsonValue::String("abc123".to_string()));
    }

    #[test]
    fn jsonpath_array_wildcard() {
        let body = serde_json::json!([{"login": "alice"}, {"login": "bob"}]);
        let val = jsonpath_extract("$[*].login", &body).unwrap();
        assert_eq!(
            val,
            JsonValue::Array(vec![
                JsonValue::String("alice".to_string()),
                JsonValue::String("bob".to_string()),
            ])
        );
    }

    #[test]
    fn jsonpath_length() {
        let body = serde_json::json!([{"login": "alice"}, {"login": "bob"}]);
        let val = jsonpath_extract("$length", &body).unwrap();
        assert_eq!(val, serde_json::json!(2_i64));
    }

    #[test]
    fn jsonpath_length_empty_array() {
        let body = serde_json::json!([]);
        let val = jsonpath_extract("$length", &body).unwrap();
        assert_eq!(val, serde_json::json!(0_i64));
    }

    #[test]
    fn jsonpath_missing_field_returns_none() {
        let body = serde_json::json!({"login": "acme"});
        assert!(jsonpath_extract("$.missing_field", &body).is_none());
    }

    #[test]
    fn evaluate_assertion_true() {
        let assertion = CheckAssertion {
            id: "test".to_string(),
            expr: "mfa_enforced == true".to_string(),
            severity: "critical".to_string(),
            title: "MFA".to_string(),
            pass_message: "pass".to_string(),
            fail_message: "fail".to_string(),
            finding: None,
        };
        let mut extracted = HashMap::new();
        extracted.insert("mfa_enforced".to_string(), serde_json::json!(true));
        assert!(evaluate_assertion(&assertion, &extracted).unwrap());
    }

    #[test]
    fn evaluate_assertion_false() {
        let assertion = CheckAssertion {
            id: "test".to_string(),
            expr: "count == 0".to_string(),
            severity: "high".to_string(),
            title: "Zero Count".to_string(),
            pass_message: "pass".to_string(),
            fail_message: "fail".to_string(),
            finding: None,
        };
        let mut extracted = HashMap::new();
        extracted.insert("count".to_string(), serde_json::json!(3_i64));
        assert!(!evaluate_assertion(&assertion, &extracted).unwrap());
    }

    #[test]
    fn resolve_json_template_recursively() {
        let mut ctx = HashMap::new();
        ctx.insert("org".to_string(), "acme".to_string());
        let body = serde_json::json!({"name": "{{org}}", "nested": {"key": "{{org}}"}});
        let resolved = resolve_json_template(&body, &ctx);
        assert_eq!(resolved["name"], "acme");
        assert_eq!(resolved["nested"]["key"], "acme");
    }
}
