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
use cel::{Context as CelContext, Program, Value as CelValue};
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
/// - `$is_object`           → special: true when the body is a JSON object
/// - `$length`              → length of the root array (or 1 for a non-array)
/// - `$is_array`            → special: boolean, true iff the root is a JSON array
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

    // Root-shape discriminator. `$[*].field` and `$[*]` are only defined when
    // the response body is a JSON array; on any other shape (an object, a
    // string, null, a number — the error-response shapes a REST endpoint can
    // return with a 200 status) they return `None`, leaving the extracted
    // variable UNBOUND rather than defaulted. Referencing an unbound variable
    // in a CEL assertion raises "Undeclared reference", and the interpreter's
    // fail-closed `.unwrap_or(false)` turns that into an assertion FAILURE —
    // a false accusation against a response that was never actually read as
    // the expected array.
    //
    // `$is_array` exists so a check can guard against exactly that, the same
    // way `$length` already lets every REST check bind a count unconditionally.
    // It is ALWAYS bound (mirrors `$length` and `$`), so a guard written
    // `!body_is_array || <real assertion>` can short-circuit before ever
    // dereferencing a wildcard extraction that might be unbound — closing the
    // gap for REST-backed checks the same way `body_root`-based guards closed
    // it for the GraphQL-backed ones (those are object-shaped, not
    // array-shaped, so `has(body_root.field)` was the right primitive there;
    // this is the array-shaped equivalent).
    if path == "$is_array" {
        return Some(JsonValue::Bool(matches!(body, JsonValue::Array(_))));
    }

    // Object-shape discriminator, and the counterpart `$is_array` could not
    // substitute for.
    //
    // `has(x.field)` cannot itself tell those two cases apart. Under `cel` 0.14
    // a non-object receiver RAISES ("No such overload"; verified against string,
    // number, bool, null and array receivers), and the fail-closed default turns
    // that raise into an accusation. A well-formed object that simply has no
    // `items` key answers `false`. Those two cases need
    // opposite verdicts. An object without the key is a real, readable EMPTY
    // result (Protobuf-JSON omits empty repeated fields, so it is the normal
    // shape for "none configured") and must FAIL the control. A scalar body was
    // never a response at all and must ABSTAIN. Without this primitive a check
    // reading a nested collection has no way to tell them apart, and the
    // fail-closed default resolves the ambiguity as an accusation.
    //
    // Always bound, like `$`, `$length` and `$is_array`, so a guard written
    // `!body_is_object || <real assertion>` can short-circuit before touching
    // anything that depends on the body being a map.
    if path == "$is_object" {
        return Some(JsonValue::Bool(matches!(body, JsonValue::Object(_))));
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

    let response = if let Some(form) = &step.request.body_form {
        // Form-urlencoded send (OAuth token endpoints are form-only).
        let pairs: Vec<(String, String)> = form
            .iter()
            .map(|(k, v)| (k.clone(), resolve_template(v, ctx)))
            .collect();
        let borrowed: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        match method.as_str() {
            "GET" | "DELETE" => req.call(),
            _ => req.send_form(&borrowed),
        }
    } else if let Some(body) = &step.request.body {
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
    evaluate_assertion_with_inputs(assertion, extracted, &HashMap::new())
}

/// CEL identifiers are `[A-Za-z_][A-Za-z0-9_]*`. A declared input whose name is
/// not a legal identifier can never be referenced from an assertion, so it is
/// skipped rather than surfaced as a binding error.
fn is_cel_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Coerce a declared input's string value into the JSON type an assertion will
/// compare against. Inputs arrive as strings (env vars and YAML `default:` are
/// both textual), but a threshold input is only useful to CEL as a number:
/// `size(admins) <= max_admins` is a type error when `max_admins` is the string
/// `"3"`, and a type error is evaluated fail-closed as an accusation.
fn coerce_input_value(raw: &str) -> JsonValue {
    if let Ok(i) = raw.parse::<i64>() {
        return JsonValue::Number(i.into());
    }
    if let Ok(f) = raw.parse::<f64>() {
        if let Some(n) = serde_json::Number::from_f64(f) {
            return JsonValue::Number(n);
        }
    }
    match raw {
        "true" => JsonValue::Bool(true),
        "false" => JsonValue::Bool(false),
        other => JsonValue::String(other.to_string()),
    }
}

/// Build the CEL bindings contributed by a check's declared `inputs:` block.
///
/// Before this existed, `inputs` were visible only to `{{template}}` substitution
/// in step URLs, headers and bodies — an input declared purely as a policy
/// threshold (`max_admins`, `max_rules`, `max_maintainers`) advertised an `env:`
/// contract through the loader and the docs while being unreachable from every
/// assertion, so setting it was a silent no-op.
///
/// Extractions always win: a name produced by a step is observed truth, and an
/// input must never be able to shadow it.
fn input_cel_bindings(
    def: &CheckDefinition,
    ctx: &HashMap<String, String>,
    extracted: &HashMap<String, JsonValue>,
) -> HashMap<String, JsonValue> {
    let mut bindings = HashMap::new();
    for name in def.inputs.keys() {
        if extracted.contains_key(name) || !is_cel_identifier(name) {
            continue;
        }
        if let Some(raw) = ctx.get(name) {
            bindings.insert(name.clone(), coerce_input_value(raw));
        }
    }
    bindings
}

fn evaluate_assertion_with_inputs(
    assertion: &CheckAssertion,
    extracted: &HashMap<String, JsonValue>,
    inputs: &HashMap<String, JsonValue>,
) -> Result<bool> {
    let program =
        Program::compile(&assertion.expr).map_err(|e| anyhow!("CEL compile error: {}", e))?;

    let mut ctx = CelContext::default();

    for (name, value) in inputs {
        if extracted.contains_key(name) {
            continue; // extraction wins; see input_cel_bindings
        }
        ctx.add_variable(name.as_str(), value.clone())
            .map_err(|e| anyhow!("CEL input variable '{}': {}", name, e))?;
    }

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

    // Resolve declared inputs: prefer config[name], fall back to config[env_var],
    // and finally to the input's declared `default:`.
    //
    // The `default:` arm was previously absent, so a declared default never took
    // effect: an unset input left `{{name}}` in the template verbatim and left the
    // name unbound in CEL. Checks that depend on a default had to duplicate the
    // value as a literal and keep the two in sync by hand.
    for (name, input_def) in &def.inputs {
        if ctx.contains_key(name) {
            continue;
        }
        if !input_def.env.is_empty() {
            if let Some(v) = config.get(&input_def.env) {
                ctx.insert(name.clone(), v.clone());
                continue;
            }
        }
        if !input_def.default.is_empty() {
            ctx.insert(name.clone(), input_def.default.clone());
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

    let input_bindings = input_cel_bindings(def, ctx, extracted);

    for assertion in &def.assertions {
        let passed =
            evaluate_assertion_with_inputs(assertion, extracted, &input_bindings).unwrap_or(false);

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
        Self { def: Arc::new(def) }
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
        Self { def: Arc::new(def) }
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
        let result = resolve_template("https://api.github.com/orgs/{{org}}", &ctx);
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
    fn jsonpath_is_array_true_for_array_root() {
        let body = serde_json::json!([{"role": "admin"}]);
        let val = jsonpath_extract("$is_array", &body).unwrap();
        assert_eq!(val, serde_json::json!(true));
    }

    #[test]
    fn jsonpath_is_array_true_for_empty_array_root() {
        let body = serde_json::json!([]);
        let val = jsonpath_extract("$is_array", &body).unwrap();
        assert_eq!(val, serde_json::json!(true));
    }

    #[test]
    fn jsonpath_is_array_false_for_object_root() {
        // The failure shape this exists to catch: an HTTP 200 whose body is an
        // error object rather than the expected array (e.g. a proxy/gateway
        // rewriting an upstream error, or an API returning `{"message": ...}`
        // with a 200 status). `$[*].field` would leave the wildcard extraction
        // unbound on this body; `$is_array` stays bound and reports false so a
        // check's guard can abstain instead of dereferencing the unbound var.
        let body = serde_json::json!({"message": "not found"});
        let val = jsonpath_extract("$is_array", &body).unwrap();
        assert_eq!(val, serde_json::json!(false));
    }

    #[test]
    fn jsonpath_is_array_false_for_scalar_and_null_root() {
        assert_eq!(
            jsonpath_extract("$is_array", &serde_json::json!("just a string")).unwrap(),
            serde_json::json!(false)
        );
        assert_eq!(
            jsonpath_extract("$is_array", &serde_json::json!(null)).unwrap(),
            serde_json::json!(false)
        );
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

    // ── CEL assertion: != operator ───────────────────────────────────────────

    #[test]
    fn evaluate_assertion_not_equal() {
        let assertion = CheckAssertion {
            id: "ne_test".to_string(),
            expr: "status != \"disabled\"".to_string(),
            severity: "high".to_string(),
            title: String::new(),
            pass_message: String::new(),
            fail_message: String::new(),
            finding: None,
        };
        let mut extracted = HashMap::new();
        extracted.insert("status".to_string(), serde_json::json!("enabled"));
        assert!(evaluate_assertion(&assertion, &extracted).unwrap());

        extracted.insert("status".to_string(), serde_json::json!("disabled"));
        assert!(!evaluate_assertion(&assertion, &extracted).unwrap());
    }

    // ── CEL assertion: > operator ────────────────────────────────────────────

    #[test]
    fn evaluate_assertion_greater_than() {
        let assertion = CheckAssertion {
            id: "gt_test".to_string(),
            expr: "member_count > 0".to_string(),
            severity: "medium".to_string(),
            title: String::new(),
            pass_message: String::new(),
            fail_message: String::new(),
            finding: None,
        };
        let mut extracted = HashMap::new();
        extracted.insert("member_count".to_string(), serde_json::json!(5));
        assert!(evaluate_assertion(&assertion, &extracted).unwrap());

        extracted.insert("member_count".to_string(), serde_json::json!(0));
        assert!(!evaluate_assertion(&assertion, &extracted).unwrap());
    }

    // ── CEL assertion: compile error ─────────────────────────────────────────

    #[test]
    fn evaluate_assertion_cel_compile_error() {
        let assertion = CheckAssertion {
            id: "bad_cel".to_string(),
            expr: "this is not valid CEL %%% !!!".to_string(),
            severity: "medium".to_string(),
            title: String::new(),
            pass_message: String::new(),
            fail_message: String::new(),
            finding: None,
        };
        let extracted = HashMap::new();
        let result = evaluate_assertion(&assertion, &extracted);
        assert!(result.is_err());
        let err = format!("{:#}", result.unwrap_err());
        assert!(
            err.contains("CEL compile error"),
            "expected CEL compile error, got: {err}"
        );
    }

    // ── resolve_headers ──────────────────────────────────────────────────────

    #[test]
    fn resolve_headers_substitutes_values() {
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), "Bearer {{token}}".to_string());
        headers.insert("Accept".to_string(), "application/json".to_string());

        let mut ctx = HashMap::new();
        ctx.insert("token".to_string(), "ghp_secret".to_string());

        let resolved = resolve_headers(&headers, &ctx);
        assert_eq!(resolved["Authorization"], "Bearer ghp_secret");
        assert_eq!(resolved["Accept"], "application/json");
    }

    // ── json_to_string ───────────────────────────────────────────────────────

    #[test]
    fn json_to_string_scalars() {
        assert_eq!(
            json_to_string(&serde_json::json!("hello")),
            Some("hello".to_string())
        );
        assert_eq!(
            json_to_string(&serde_json::json!(true)),
            Some("true".to_string())
        );
        assert_eq!(
            json_to_string(&serde_json::json!(42)),
            Some("42".to_string())
        );
    }

    #[test]
    fn json_to_string_non_scalars_return_none() {
        assert!(json_to_string(&serde_json::json!({"key": "val"})).is_none());
        assert!(json_to_string(&serde_json::json!([1, 2, 3])).is_none());
        assert!(json_to_string(&serde_json::json!(null)).is_none());
    }

    // ── declared inputs: defaults + CEL visibility ───────────────────────────

    fn def_with_threshold(name: &str, env: &str, default: &str) -> CheckDefinition {
        let mut inputs = HashMap::new();
        inputs.insert(
            name.to_string(),
            super::super::definition::InputDef {
                description: String::new(),
                env: env.to_string(),
                default: default.to_string(),
                required: false,
            },
        );
        CheckDefinition {
            inputs,
            ..default_check_def()
        }
    }

    #[test]
    fn build_input_context_applies_declared_default() {
        let def = def_with_threshold("max_admins", "BUILDKITE_MAX_ADMINS", "3");
        let ctx = build_input_context(&def, &HashMap::new());
        assert_eq!(ctx.get("max_admins").map(String::as_str), Some("3"));
    }

    #[test]
    fn build_input_context_env_beats_default() {
        let def = def_with_threshold("max_admins", "BUILDKITE_MAX_ADMINS", "3");
        let mut config = HashMap::new();
        config.insert("BUILDKITE_MAX_ADMINS".to_string(), "7".to_string());
        let ctx = build_input_context(&def, &config);
        assert_eq!(ctx.get("max_admins").map(String::as_str), Some("7"));
    }

    #[test]
    fn coerce_input_value_types() {
        assert_eq!(coerce_input_value("3"), serde_json::json!(3));
        assert_eq!(coerce_input_value("true"), serde_json::json!(true));
        assert_eq!(coerce_input_value("acme"), serde_json::json!("acme"));
    }

    #[test]
    fn threshold_input_is_visible_to_cel_and_changes_the_verdict() {
        let def = def_with_threshold("max_admins", "BUILDKITE_MAX_ADMINS", "3");
        let mut extracted = HashMap::new();
        extracted.insert(
            "member_roles".to_string(),
            serde_json::json!(["ADMIN", "ADMIN", "ADMIN", "member"]),
        );
        let assertion = CheckAssertion {
            id: "admin_count_within_bound".to_string(),
            expr: "size(member_roles.filter(r, r == \"ADMIN\")) <= max_admins".to_string(),
            severity: "high".to_string(),
            title: String::new(),
            pass_message: String::new(),
            fail_message: String::new(),
            finding: None,
        };

        // Default 3: three admins is within bound.
        let ctx = build_input_context(&def, &HashMap::new());
        let bindings = input_cel_bindings(&def, &ctx, &extracted);
        assert_eq!(bindings.get("max_admins"), Some(&serde_json::json!(3)));
        assert!(evaluate_assertion_with_inputs(&assertion, &extracted, &bindings).unwrap());

        // Operator tightens the bound via the env var the input advertises.
        let mut config = HashMap::new();
        config.insert("BUILDKITE_MAX_ADMINS".to_string(), "2".to_string());
        let ctx = build_input_context(&def, &config);
        let bindings = input_cel_bindings(&def, &ctx, &extracted);
        assert!(!evaluate_assertion_with_inputs(&assertion, &extracted, &bindings).unwrap());
    }

    #[test]
    fn extraction_always_shadows_an_input_of_the_same_name() {
        let def = def_with_threshold("count", "SOME_ENV", "99");
        let ctx = build_input_context(&def, &HashMap::new());
        let mut extracted = HashMap::new();
        extracted.insert("count".to_string(), serde_json::json!(1));
        let bindings = input_cel_bindings(&def, &ctx, &extracted);
        assert!(!bindings.contains_key("count"));
    }

    #[test]
    fn non_identifier_input_names_are_skipped() {
        assert!(is_cel_identifier("max_admins"));
        assert!(!is_cel_identifier("2bad"));
        assert!(!is_cel_identifier("has-dash"));
        let def = def_with_threshold("has-dash", "X", "1");
        let ctx = build_input_context(&def, &HashMap::new());
        assert!(input_cel_bindings(&def, &ctx, &HashMap::new()).is_empty());
    }

    #[test]
    fn checks_without_inputs_bind_nothing() {
        let def = default_check_def();
        let ctx = build_input_context(&def, &HashMap::new());
        assert!(input_cel_bindings(&def, &ctx, &HashMap::new()).is_empty());
    }

    // ── jsonpath edge cases ──────────────────────────────────────────────────

    #[test]
    fn jsonpath_root_dollar_returns_whole_body() {
        let body = serde_json::json!({"a": 1});
        let val = jsonpath_extract("$", &body).unwrap();
        assert_eq!(val, body);
    }

    #[test]
    fn jsonpath_array_wildcard_no_field() {
        let body = serde_json::json!([1, 2, 3]);
        let val = jsonpath_extract("$[*]", &body).unwrap();
        assert_eq!(val, serde_json::json!([1, 2, 3]));
    }

    #[test]
    fn jsonpath_is_object_discriminates_every_body_shape() {
        // Always bound, and true for exactly one shape. This is what lets a check
        // separate "a readable response whose collection is empty" (object, key
        // omitted by Protobuf-JSON — a real FAIL) from "not a response at all"
        // (scalar or array body — must ABSTAIN). `has()` cannot: it answers false
        // for both.
        assert_eq!(
            jsonpath_extract("$is_object", &serde_json::json!({"a": 1})),
            Some(JsonValue::Bool(true))
        );
        assert_eq!(
            jsonpath_extract("$is_object", &serde_json::json!({})),
            Some(JsonValue::Bool(true))
        );
        for non_object in [
            serde_json::json!([]),
            serde_json::json!([{"a": 1}]),
            serde_json::json!("unexpected"),
            serde_json::json!(42),
            serde_json::json!(true),
            serde_json::Value::Null,
        ] {
            assert_eq!(
                jsonpath_extract("$is_object", &non_object),
                Some(JsonValue::Bool(false)),
                "expected false for {non_object}"
            );
        }
    }

    #[test]
    fn jsonpath_is_object_and_is_array_are_mutually_exclusive() {
        for body in [
            serde_json::json!({"a": 1}),
            serde_json::json!([1, 2]),
            serde_json::json!("s"),
            serde_json::Value::Null,
        ] {
            let is_object = jsonpath_extract("$is_object", &body);
            let is_array = jsonpath_extract("$is_array", &body);
            assert!(
                is_object.is_some() && is_array.is_some(),
                "both discriminators must be bound for every body shape"
            );
            assert!(
                !((is_object == Some(JsonValue::Bool(true)))
                    && (is_array == Some(JsonValue::Bool(true)))),
                "a body cannot be both an object and an array: {body}"
            );
        }
    }

    #[test]
    fn jsonpath_status_code_returns_none() {
        let body = serde_json::json!({"status": 200});
        assert!(jsonpath_extract("$status_code", &body).is_none());
    }

    #[test]
    fn jsonpath_length_non_array() {
        let body = serde_json::json!({"key": "val"});
        let val = jsonpath_extract("$length", &body).unwrap();
        assert_eq!(val, serde_json::json!(1));
    }

    #[test]
    fn jsonpath_nested_field_on_non_object_returns_none() {
        let body = serde_json::json!("just a string");
        assert!(jsonpath_extract("$.field", &body).is_none());
    }

    #[test]
    fn jsonpath_array_wildcard_on_non_array_returns_none() {
        let body = serde_json::json!({"not": "an_array"});
        assert!(jsonpath_extract("$[*].field", &body).is_none());
    }

    #[test]
    fn jsonpath_invalid_prefix_returns_none() {
        let body = serde_json::json!({"a": 1});
        assert!(jsonpath_extract("no_dollar_prefix", &body).is_none());
    }

    // ── resolve_json_template edge cases ─────────────────────────────────────

    #[test]
    fn resolve_json_template_array() {
        let mut ctx = HashMap::new();
        ctx.insert("x".to_string(), "y".to_string());
        let body = serde_json::json!(["{{x}}", "plain"]);
        let resolved = resolve_json_template(&body, &ctx);
        assert_eq!(resolved, serde_json::json!(["y", "plain"]));
    }

    #[test]
    fn resolve_json_template_non_string_passthrough() {
        let ctx = HashMap::new();
        let body = serde_json::json!(42);
        let resolved = resolve_json_template(&body, &ctx);
        assert_eq!(resolved, serde_json::json!(42));

        let body_bool = serde_json::json!(true);
        assert_eq!(
            resolve_json_template(&body_bool, &ctx),
            serde_json::json!(true)
        );

        let body_null = serde_json::json!(null);
        assert_eq!(
            resolve_json_template(&body_null, &ctx),
            serde_json::json!(null)
        );
    }

    // ── build_input_context ──────────────────────────────────────────────────

    #[test]
    fn build_input_context_resolves_env_alias() {
        let def = make_minimal_def_with_inputs();
        let mut config = HashMap::new();
        config.insert("GITHUB_ORG".to_string(), "acme-corp".to_string());

        let ctx = build_input_context(&def, &config);
        // "org" should be resolved from GITHUB_ORG since config doesn't have "org" directly
        assert_eq!(ctx.get("org").unwrap(), "acme-corp");
    }

    #[test]
    fn build_input_context_direct_name_takes_precedence() {
        let def = make_minimal_def_with_inputs();
        let mut config = HashMap::new();
        config.insert("org".to_string(), "direct-org".to_string());
        config.insert("GITHUB_ORG".to_string(), "env-org".to_string());

        let ctx = build_input_context(&def, &config);
        // Direct name "org" should take precedence over env alias
        assert_eq!(ctx.get("org").unwrap(), "direct-org");
    }

    #[test]
    fn build_input_context_preserves_existing_config() {
        let def = make_minimal_def_with_inputs();
        let mut config = HashMap::new();
        config.insert("GITHUB_TOKEN".to_string(), "ghp_test".to_string());

        let ctx = build_input_context(&def, &config);
        assert_eq!(ctx.get("GITHUB_TOKEN").unwrap(), "ghp_test");
    }

    // ── evaluate_all_assertions ──────────────────────────────────────────────

    #[test]
    fn evaluate_all_assertions_passing() {
        let def = make_def_with_assertions();
        let mut extracted = HashMap::new();
        extracted.insert("mfa_enforced".to_string(), serde_json::json!(true));

        let ctx = HashMap::new();
        let results =
            evaluate_all_assertions(&def, &extracted, &ctx, ConfidenceLevel::PassiveObservation);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status_id, StatusId::Effective);
        assert!(results[0].findings.is_empty());
    }

    #[test]
    fn evaluate_all_assertions_failing_creates_finding() {
        let def = make_def_with_assertions();
        let mut extracted = HashMap::new();
        extracted.insert("mfa_enforced".to_string(), serde_json::json!(false));

        let ctx = HashMap::new();
        let results =
            evaluate_all_assertions(&def, &extracted, &ctx, ConfidenceLevel::PassiveObservation);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status_id, StatusId::Ineffective);
        assert_eq!(results[0].findings.len(), 1);
        assert_eq!(results[0].findings[0].severity_id, 5); // critical
    }

    #[test]
    fn evaluate_all_assertions_severity_mapping() {
        // Test that all severity strings map to expected numeric IDs
        let severity_map = vec![
            ("critical", 5),
            ("high", 4),
            ("medium", 3),
            ("low", 2),
            ("info", 1),
            ("unknown", 0),
        ];

        for (severity_str, expected_id) in severity_map {
            let def = CheckDefinition {
                id: "SEV-TEST".to_string(),
                name: "Severity Test".to_string(),
                assertions: vec![CheckAssertion {
                    id: "sev_assert".to_string(),
                    expr: "val == true".to_string(),
                    severity: severity_str.to_string(),
                    title: "Sev Test".to_string(),
                    pass_message: String::new(),
                    fail_message: String::new(),
                    finding: None,
                }],
                ..default_check_def()
            };

            let mut extracted = HashMap::new();
            extracted.insert("val".to_string(), serde_json::json!(false)); // force failure

            let results = evaluate_all_assertions(
                &def,
                &extracted,
                &HashMap::new(),
                ConfidenceLevel::PassiveObservation,
            );
            assert_eq!(
                results[0].findings[0].severity_id, expected_id,
                "severity '{}' should map to {}",
                severity_str, expected_id
            );
        }
    }

    #[test]
    fn evaluate_all_assertions_active_verification_confidence() {
        let def = make_def_with_assertions();
        let mut extracted = HashMap::new();
        extracted.insert("mfa_enforced".to_string(), serde_json::json!(true));

        let results = evaluate_all_assertions(
            &def,
            &extracted,
            &HashMap::new(),
            ConfidenceLevel::ActiveVerification,
        );

        assert_eq!(
            results[0].confidence_level,
            ConfidenceLevel::ActiveVerification
        );
        assert_eq!(results[0].metadata.module.module_type, "tester");
    }

    #[test]
    fn evaluate_all_assertions_passive_observation_confidence() {
        let def = make_def_with_assertions();
        let mut extracted = HashMap::new();
        extracted.insert("mfa_enforced".to_string(), serde_json::json!(true));

        let results = evaluate_all_assertions(
            &def,
            &extracted,
            &HashMap::new(),
            ConfidenceLevel::PassiveObservation,
        );

        assert_eq!(
            results[0].confidence_level,
            ConfidenceLevel::PassiveObservation
        );
        assert_eq!(results[0].metadata.module.module_type, "observer");
    }

    #[test]
    fn evaluate_all_assertions_observables_populated() {
        let def = make_def_with_assertions();
        let mut extracted = HashMap::new();
        extracted.insert("mfa_enforced".to_string(), serde_json::json!(true));
        extracted.insert("org_name".to_string(), serde_json::json!("acme"));

        let results = evaluate_all_assertions(
            &def,
            &extracted,
            &HashMap::new(),
            ConfidenceLevel::PassiveObservation,
        );

        // Should have observables for scalar values
        assert!(results[0].observables.len() >= 2);
    }

    #[test]
    fn evaluate_all_assertions_endpoint_from_org() {
        let def = make_def_with_assertions();
        let extracted = HashMap::new();
        let mut ctx = HashMap::new();
        ctx.insert("org".to_string(), "my-org".to_string());

        let results =
            evaluate_all_assertions(&def, &extracted, &ctx, ConfidenceLevel::PassiveObservation);

        assert_eq!(results[0].metadata.source.endpoint, "my-org");
    }

    #[test]
    fn evaluate_all_assertions_finding_description_from_finding_def() {
        let def = CheckDefinition {
            id: "FIND-TEST".to_string(),
            name: "Finding Test".to_string(),
            assertions: vec![CheckAssertion {
                id: "with_finding".to_string(),
                expr: "val == true".to_string(),
                severity: "high".to_string(),
                title: "Test Finding".to_string(),
                pass_message: String::new(),
                fail_message: "default fail message".to_string(),
                finding: Some(super::super::definition::FindingDef {
                    description: "custom finding description".to_string(),
                }),
            }],
            ..default_check_def()
        };

        let mut extracted = HashMap::new();
        extracted.insert("val".to_string(), serde_json::json!(false));

        let results = evaluate_all_assertions(
            &def,
            &extracted,
            &HashMap::new(),
            ConfidenceLevel::PassiveObservation,
        );

        assert_eq!(
            results[0].findings[0].description,
            "custom finding description"
        );
    }

    // ── YamlObserver Module trait ─────────────────────────────────────────────

    #[test]
    fn yaml_observer_module_trait() {
        let def = CheckDefinition {
            id: "OBS-1".to_string(),
            name: "Test Observer".to_string(),
            version: "2.0".to_string(),
            source: "github".to_string(),
            credentials: {
                let mut m = HashMap::new();
                m.insert(
                    "GITHUB_TOKEN".to_string(),
                    super::super::definition::CredentialDef {
                        cred_type: "api_token".to_string(),
                        scopes: vec!["read:org".to_string()],
                        required: true,
                    },
                );
                m
            },
            ..default_check_def()
        };

        let observer = YamlObserver::new(def);
        assert_eq!(observer.id(), "OBS-1");
        assert_eq!(observer.name(), "Test Observer");
        assert_eq!(observer.version(), "2.0");
        assert_eq!(observer.source_system(), "github");
        assert!(observer.evidence_types().is_empty());

        let creds = observer.credential_requirements();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].name, "GITHUB_TOKEN");
        assert_eq!(creds[0].cred_type, "api_token");
        assert!(creds[0].required);
    }

    // ── YamlTester Module + Tester traits ────────────────────────────────────

    #[test]
    fn yaml_tester_module_trait() {
        let def = CheckDefinition {
            id: "TST-1".to_string(),
            name: "Test Tester".to_string(),
            version: "1.0".to_string(),
            source: "github".to_string(),
            check_type: super::super::definition::CheckType::Active,
            safety: "observable".to_string(),
            environment: "staging".to_string(),
            pre_flight: vec!["Check token scopes".to_string()],
            ..default_check_def()
        };

        let tester = YamlTester::new(def);
        assert_eq!(tester.id(), "TST-1");
        assert_eq!(tester.name(), "Test Tester");
        assert_eq!(tester.source_system(), "github");
    }

    #[test]
    fn yaml_tester_safety_classification_observable() {
        let def = CheckDefinition {
            safety: "observable".to_string(),
            ..default_check_def()
        };
        let tester = YamlTester::new(def);
        assert_eq!(tester.safety_class(), SafetyClassification::Observable);
    }

    #[test]
    fn yaml_tester_safety_classification_reversible() {
        let def = CheckDefinition {
            safety: "reversible".to_string(),
            ..default_check_def()
        };
        let tester = YamlTester::new(def);
        assert_eq!(tester.safety_class(), SafetyClassification::Reversible);
    }

    #[test]
    fn yaml_tester_safety_classification_default() {
        let def = CheckDefinition {
            safety: String::new(),
            ..default_check_def()
        };
        let tester = YamlTester::new(def);
        // Default should be Observable
        assert_eq!(tester.safety_class(), SafetyClassification::Observable);
    }

    #[test]
    fn yaml_tester_environment_scope_production() {
        let def = CheckDefinition {
            environment: "production".to_string(),
            ..default_check_def()
        };
        let tester = YamlTester::new(def);
        assert_eq!(tester.environment_scope(), EnvironmentScope::Production);
    }

    #[test]
    fn yaml_tester_environment_scope_prod_alias() {
        let def = CheckDefinition {
            environment: "prod".to_string(),
            ..default_check_def()
        };
        let tester = YamlTester::new(def);
        assert_eq!(tester.environment_scope(), EnvironmentScope::Production);
    }

    #[test]
    fn yaml_tester_environment_scope_staging() {
        let def = CheckDefinition {
            environment: "staging".to_string(),
            ..default_check_def()
        };
        let tester = YamlTester::new(def);
        assert_eq!(tester.environment_scope(), EnvironmentScope::Staging);
    }

    #[test]
    fn yaml_tester_environment_scope_default_isolated() {
        let def = CheckDefinition {
            environment: String::new(),
            ..default_check_def()
        };
        let tester = YamlTester::new(def);
        assert_eq!(tester.environment_scope(), EnvironmentScope::Isolated);
    }

    #[test]
    fn yaml_tester_pre_flight_checks() {
        let def = CheckDefinition {
            pre_flight: vec![
                "Ensure admin scope".to_string(),
                "Verify org membership".to_string(),
            ],
            ..default_check_def()
        };
        let tester = YamlTester::new(def);
        let checks = tester.pre_flight_checks();
        assert_eq!(checks.len(), 2);
        assert_eq!(checks[0], "Ensure admin scope");
    }

    #[test]
    fn yaml_tester_cleanup_procedures() {
        let def = default_check_def();
        let tester = YamlTester::new(def);
        let cleanup = tester.cleanup_procedures();
        assert_eq!(cleanup.len(), 1);
        assert!(cleanup[0].contains("Cleanup steps"));
    }

    // ── resolve_template edge cases ──────────────────────────────────────────

    #[test]
    fn resolve_template_empty_string() {
        let ctx = HashMap::new();
        assert_eq!(resolve_template("", &ctx), "");
    }

    #[test]
    fn resolve_template_no_placeholders() {
        let ctx = HashMap::new();
        assert_eq!(resolve_template("plain text here", &ctx), "plain text here");
    }

    #[test]
    fn resolve_template_adjacent_placeholders() {
        let mut ctx = HashMap::new();
        ctx.insert("a".to_string(), "X".to_string());
        ctx.insert("b".to_string(), "Y".to_string());
        assert_eq!(resolve_template("{{a}}{{b}}", &ctx), "XY");
    }

    // ── navigate_fields ──────────────────────────────────────────────────────

    #[test]
    fn jsonpath_deeply_nested() {
        let body = serde_json::json!({"a": {"b": {"c": 42}}});
        let val = jsonpath_extract("$.a.b.c", &body).unwrap();
        assert_eq!(val, serde_json::json!(42));
    }

    #[test]
    fn jsonpath_array_wildcard_nested_field() {
        let body = serde_json::json!([
            {"user": {"name": "alice"}},
            {"user": {"name": "bob"}}
        ]);
        let val = jsonpath_extract("$[*].user.name", &body).unwrap();
        assert_eq!(val, serde_json::json!(["alice", "bob"]));
    }

    // ── execute_step via mock HTTP server ────────────────────────────────────

    /// Build a minimal CheckStep for a given method and URL.
    fn make_step(id: &str, method: &str, url: &str) -> CheckStep {
        CheckStep {
            id: id.to_string(),
            action: "api_call".to_string(),
            when: String::new(),
            request: super::super::definition::RequestDef {
                method: method.to_string(),
                url: url.to_string(),
                headers: HashMap::new(),
                body: None,
                body_form: None,
                paginate: false,
            },
            extract: HashMap::new(),
            on_error: HashMap::new(),
            note: String::new(),
        }
    }

    fn make_step_with_body(
        id: &str,
        method: &str,
        url: &str,
        body: serde_json::Value,
    ) -> CheckStep {
        CheckStep {
            id: id.to_string(),
            action: "api_call".to_string(),
            when: String::new(),
            request: super::super::definition::RequestDef {
                method: method.to_string(),
                url: url.to_string(),
                headers: HashMap::new(),
                body: Some(body),
                body_form: None,
                paginate: false,
            },
            extract: HashMap::new(),
            on_error: HashMap::new(),
            note: String::new(),
        }
    }

    /// Spin up a one-shot mock HTTP server and return its base URL.
    fn one_shot_server(status: u16, body: &str) -> String {
        crate::modules::github_common::mock_server(status, body)
    }

    #[test]
    fn execute_step_get_ok_parses_body() {
        let url = one_shot_server(200, r#"{"two_factor_requirement_enabled":true}"#);
        let step = make_step("s1", "GET", &format!("{url}/orgs/test"));
        let ctx = HashMap::new();
        let result = execute_step(&step, &ctx).unwrap();
        assert_eq!(result.status_code, 200);
        assert_eq!(result.body["two_factor_requirement_enabled"], true);
    }

    #[test]
    fn execute_step_post_without_body() {
        let url = one_shot_server(201, r#"{"created":true}"#);
        let step = make_step("s_post", "POST", &format!("{url}/repos"));
        let ctx = HashMap::new();
        let result = execute_step(&step, &ctx).unwrap();
        assert_eq!(result.status_code, 201);
    }

    #[test]
    fn execute_step_put_without_body() {
        let url = one_shot_server(200, r#"{"ok":true}"#);
        let step = make_step("s_put", "PUT", &format!("{url}/resource"));
        let ctx = HashMap::new();
        let result = execute_step(&step, &ctx).unwrap();
        assert_eq!(result.status_code, 200);
    }

    #[test]
    fn execute_step_patch_method() {
        let url = one_shot_server(200, r#"{"updated":true}"#);
        let step = make_step("s_patch", "PATCH", &format!("{url}/resource"));
        let ctx = HashMap::new();
        let result = execute_step(&step, &ctx).unwrap();
        assert_eq!(result.status_code, 200);
    }

    #[test]
    fn execute_step_delete_method() {
        let url = one_shot_server(204, r#"{}"#);
        let step = make_step("s_delete", "DELETE", &format!("{url}/resource"));
        let ctx = HashMap::new();
        let result = execute_step(&step, &ctx).unwrap();
        assert_eq!(result.status_code, 204);
    }

    #[test]
    fn execute_step_unsupported_method_returns_err() {
        let step = make_step("s_bad", "CONNECT", "http://127.0.0.1:9/test");
        let ctx = HashMap::new();
        let result = execute_step(&step, &ctx);
        assert!(result.is_err());
        // Extract the error message without unwrap_err() (which requires T: Debug).
        let msg = result.err().unwrap().to_string();
        assert!(
            msg.contains("unsupported HTTP method"),
            "error should explain problem: {msg}"
        );
        assert!(
            msg.contains("CONNECT"),
            "error should name the bad method: {msg}"
        );
    }

    #[test]
    fn execute_step_error_status_code_captured() {
        // 4xx responses are captured as Err(Status) by ureq but we handle them.
        let url = one_shot_server(403, r#"{"error":"forbidden"}"#);
        let step = make_step("s_err", "GET", &format!("{url}/resource"));
        let ctx = HashMap::new();
        let result = execute_step(&step, &ctx).unwrap();
        // Our execute_step converts ureq::Error::Status into a StepResult.
        assert_eq!(result.status_code, 403);
    }

    #[test]
    fn execute_step_paginate_flag_returns_first_page() {
        // paginate=true currently returns the first page without following Link headers.
        let url = one_shot_server(200, r#"[{"login":"alice"},{"login":"bob"}]"#);
        let step = CheckStep {
            id: "s_page".to_string(),
            action: "api_call".to_string(),
            when: String::new(),
            request: super::super::definition::RequestDef {
                method: "GET".to_string(),
                url: format!("{url}/users"),
                headers: HashMap::new(),
                body: None,
                body_form: None,
                paginate: true,
            },
            extract: HashMap::new(),
            on_error: HashMap::new(),
            note: String::new(),
        };
        let ctx = HashMap::new();
        let result = execute_step(&step, &ctx).unwrap();
        assert_eq!(result.status_code, 200);
        assert!(
            result.body.is_array(),
            "paginated response should be an array"
        );
    }

    #[test]
    fn execute_step_get_with_body_field_ignores_body() {
        // GET requests with a body defined should call req.call() (ignore body).
        let url = one_shot_server(200, r#"{"ok":true}"#);
        let step = make_step_with_body(
            "s_get_body",
            "GET",
            &format!("{url}/resource"),
            serde_json::json!({"should":"be ignored"}),
        );
        let ctx = HashMap::new();
        let result = execute_step(&step, &ctx).unwrap();
        assert_eq!(result.status_code, 200);
    }

    #[test]
    fn execute_step_delete_with_body_ignores_body() {
        // DELETE requests with a body defined should also call req.call().
        let url = one_shot_server(200, r#"{"deleted":true}"#);
        let step = make_step_with_body(
            "s_del_body",
            "DELETE",
            &format!("{url}/resource"),
            serde_json::json!({"should":"be ignored"}),
        );
        let ctx = HashMap::new();
        let result = execute_step(&step, &ctx).unwrap();
        assert_eq!(result.status_code, 200);
    }

    // ── evaluate_assertion non-bool return ───────────────────────────────────

    #[test]
    fn evaluate_assertion_non_bool_cel_returns_err() {
        // CEL expression that evaluates to a non-bool value should return Err.
        let assertion = CheckAssertion {
            id: "non_bool".to_string(),
            expr: "1 + 1".to_string(), // Returns an integer, not a bool
            severity: "medium".to_string(),
            title: String::new(),
            pass_message: String::new(),
            fail_message: String::new(),
            finding: None,
        };
        let extracted = HashMap::new();
        let result = evaluate_assertion(&assertion, &extracted);
        assert!(result.is_err(), "non-bool CEL result should return Err");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("non-bool"),
            "error should describe non-bool result: {msg}"
        );
    }

    #[test]
    fn evaluate_assertion_string_result_returns_err() {
        let assertion = CheckAssertion {
            id: "str_result".to_string(),
            expr: "\"hello\"".to_string(), // Returns a string
            severity: "medium".to_string(),
            title: String::new(),
            pass_message: String::new(),
            fail_message: String::new(),
            finding: None,
        };
        let extracted = HashMap::new();
        let result = evaluate_assertion(&assertion, &extracted);
        assert!(result.is_err(), "string CEL result should return Err");
    }

    // ── build_input_context env alias not found ──────────────────────────────

    #[test]
    fn build_input_context_env_alias_not_in_config() {
        // Input declares an env alias, but the value isn't in config at all.
        // The context should not contain the input key.
        let def = make_minimal_def_with_inputs();
        let config = HashMap::new(); // Neither "org" nor "GITHUB_ORG" present

        let ctx = build_input_context(&def, &config);
        // "org" should not be set since neither direct name nor env alias is available.
        assert!(
            !ctx.contains_key("org"),
            "org should not be in context when neither direct name nor env alias is in config"
        );
    }

    #[test]
    fn build_input_context_env_empty_string_not_added() {
        // If env is an empty string in the InputDef, the env alias lookup is skipped.
        let def = CheckDefinition {
            inputs: {
                let mut m = HashMap::new();
                m.insert(
                    "myvar".to_string(),
                    super::super::definition::InputDef {
                        description: "Some var".to_string(),
                        env: String::new(), // empty env — no alias lookup
                        default: String::new(),
                        required: false,
                    },
                );
                m
            },
            ..default_check_def()
        };
        let mut config = HashMap::new();
        config.insert("OTHER_VAR".to_string(), "val".to_string());

        let ctx = build_input_context(&def, &config);
        // "myvar" should not appear since it's neither in config directly nor via env
        assert!(!ctx.contains_key("myvar"));
    }

    // ── run_steps: when guard, on_error handler, $status_code extract ────────

    #[test]
    fn run_steps_skips_step_when_guard_fails() {
        // Step with a `when` guard that evaluates to false should be skipped.
        let url = one_shot_server(200, r#"{"value":42}"#);
        let step = CheckStep {
            id: "s_guard".to_string(),
            action: "api_call".to_string(),
            when: "false".to_string(), // Always false — step is skipped
            request: super::super::definition::RequestDef {
                method: "GET".to_string(),
                url: format!("{url}/resource"),
                headers: HashMap::new(),
                body: None,
                body_form: None,
                paginate: false,
            },
            extract: {
                let mut m = HashMap::new();
                m.insert("value".to_string(), "$.value".to_string());
                m
            },
            on_error: HashMap::new(),
            note: String::new(),
        };

        let mut ctx = HashMap::new();
        // extracted should be empty since the step was skipped.
        let extracted = run_steps(&[step], &mut ctx).unwrap();
        assert!(
            !extracted.contains_key("value"),
            "variable should not be extracted when step is guarded off"
        );
    }

    #[test]
    fn run_steps_executes_step_when_guard_true() {
        // Step with `when: true` should run normally.
        let url = one_shot_server(200, r#"{"setting":true}"#);
        let step = CheckStep {
            id: "s_run".to_string(),
            action: "api_call".to_string(),
            when: "true".to_string(),
            request: super::super::definition::RequestDef {
                method: "GET".to_string(),
                url: format!("{url}/resource"),
                headers: HashMap::new(),
                body: None,
                body_form: None,
                paginate: false,
            },
            extract: {
                let mut m = HashMap::new();
                m.insert("setting".to_string(), "$.setting".to_string());
                m
            },
            on_error: HashMap::new(),
            note: String::new(),
        };

        let mut ctx = HashMap::new();
        let extracted = run_steps(&[step], &mut ctx).unwrap();
        assert!(
            extracted.contains_key("setting"),
            "setting should be extracted when guard passes"
        );
    }

    #[test]
    fn run_steps_on_error_continue_skips_extraction() {
        // When a step returns an error-status that has `continue` in on_error,
        // extraction is skipped but run_steps succeeds.
        let url = one_shot_server(422, r#"{"message":"already exists"}"#);
        let mut on_error = HashMap::new();
        on_error.insert("422".to_string(), "continue".to_string());

        let step = CheckStep {
            id: "s_err_cont".to_string(),
            action: "api_call".to_string(),
            when: String::new(),
            request: super::super::definition::RequestDef {
                method: "POST".to_string(),
                url: format!("{url}/resource"),
                headers: HashMap::new(),
                body: None,
                body_form: None,
                paginate: false,
            },
            extract: {
                let mut m = HashMap::new();
                m.insert("message".to_string(), "$.message".to_string());
                m
            },
            on_error,
            note: String::new(),
        };

        let mut ctx = HashMap::new();
        let extracted = run_steps(&[step], &mut ctx).unwrap();
        // status_code is always set even for continue
        assert!(
            extracted.contains_key("status_code"),
            "status_code should be set"
        );
        // But extraction of body fields should be skipped
        assert!(
            !extracted.contains_key("message"),
            "body extraction should be skipped on continue"
        );
    }

    #[test]
    fn run_steps_status_code_extracted_as_special_var() {
        // $status_code as extract path should put the numeric status code into extracted.
        let url = one_shot_server(200, r#"{"ok":true}"#);
        let step = CheckStep {
            id: "s_status".to_string(),
            action: "api_call".to_string(),
            when: String::new(),
            request: super::super::definition::RequestDef {
                method: "GET".to_string(),
                url: format!("{url}/resource"),
                headers: HashMap::new(),
                body: None,
                body_form: None,
                paginate: false,
            },
            extract: {
                let mut m = HashMap::new();
                m.insert("code".to_string(), "$status_code".to_string());
                m
            },
            on_error: HashMap::new(),
            note: String::new(),
        };

        let mut ctx = HashMap::new();
        let extracted = run_steps(&[step], &mut ctx).unwrap();
        assert!(
            extracted.contains_key("code"),
            "code should be extracted via $status_code"
        );
        assert_eq!(extracted["code"], serde_json::json!(200));
    }

    #[test]
    fn run_steps_populates_step_id_status_code_alias() {
        // step_id_status_code alias should be available in extracted after step runs.
        let url = one_shot_server(200, r#"{"ok":true}"#);
        let step = make_step("my_step", "GET", &format!("{url}/resource"));

        let mut ctx = HashMap::new();
        let extracted = run_steps(&[step], &mut ctx).unwrap();
        assert!(
            extracted.contains_key("my_step_status_code"),
            "per-step status alias should be set"
        );
    }

    // ── evaluate_all_assertions: safety field non-empty ──────────────────────

    #[test]
    fn evaluate_all_assertions_safety_field_non_empty_sets_classification() {
        // When def.safety is non-empty, metadata.safety_classification should be Some.
        let def = CheckDefinition {
            safety: "observable".to_string(),
            assertions: vec![CheckAssertion {
                id: "a1".to_string(),
                expr: "val == true".to_string(),
                severity: "medium".to_string(),
                title: String::new(),
                pass_message: String::new(),
                fail_message: String::new(),
                finding: None,
            }],
            ..default_check_def()
        };

        let mut extracted = HashMap::new();
        extracted.insert("val".to_string(), serde_json::json!(true));

        let results = evaluate_all_assertions(
            &def,
            &extracted,
            &HashMap::new(),
            ConfidenceLevel::PassiveObservation,
        );

        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].metadata.safety_classification,
            Some("observable".to_string()),
            "non-empty safety field should be Some"
        );
    }

    #[test]
    fn evaluate_all_assertions_safety_field_empty_is_none() {
        // When def.safety is empty, metadata.safety_classification should be None.
        let def = CheckDefinition {
            safety: String::new(),
            assertions: vec![CheckAssertion {
                id: "a1".to_string(),
                expr: "val == true".to_string(),
                severity: "medium".to_string(),
                title: String::new(),
                pass_message: String::new(),
                fail_message: String::new(),
                finding: None,
            }],
            ..default_check_def()
        };

        let mut extracted = HashMap::new();
        extracted.insert("val".to_string(), serde_json::json!(true));

        let results = evaluate_all_assertions(
            &def,
            &extracted,
            &HashMap::new(),
            ConfidenceLevel::PassiveObservation,
        );

        assert_eq!(results[0].metadata.safety_classification, None);
    }

    // ── YamlObserver::observe via mock server ─────────────────────────────────

    #[test]
    fn yaml_observer_observe_runs_steps_and_evaluates_assertions() {
        let url = one_shot_server(200, r#"{"two_factor_requirement_enabled":true}"#);

        let def = CheckDefinition {
            id: "OBS-MOCK".to_string(),
            name: "Mock Observer Test".to_string(),
            source: "github".to_string(),
            steps: vec![CheckStep {
                id: "get_org".to_string(),
                action: "api_call".to_string(),
                when: String::new(),
                request: super::super::definition::RequestDef {
                    method: "GET".to_string(),
                    url: format!("{url}/orgs/test"),
                    headers: HashMap::new(),
                    body: None,
                    body_form: None,
                    paginate: false,
                },
                extract: {
                    let mut m = HashMap::new();
                    m.insert(
                        "mfa_enforced".to_string(),
                        "$.two_factor_requirement_enabled".to_string(),
                    );
                    m
                },
                on_error: HashMap::new(),
                note: String::new(),
            }],
            assertions: vec![CheckAssertion {
                id: "mfa_check".to_string(),
                expr: "mfa_enforced == true".to_string(),
                severity: "critical".to_string(),
                title: "MFA Enforcement".to_string(),
                pass_message: "MFA is enforced".to_string(),
                fail_message: "MFA is NOT enforced".to_string(),
                finding: None,
            }],
            ..default_check_def()
        };

        let observer = YamlObserver::new(def);
        let config = HashMap::new();
        let results = observer.observe(&config).unwrap();

        assert_eq!(
            results.len(),
            1,
            "should produce one Evidence per assertion"
        );
        assert_eq!(
            results[0].status_id,
            StatusId::Effective,
            "MFA enforced → should pass"
        );
    }

    #[test]
    fn yaml_observer_observe_failing_assertion() {
        let url = one_shot_server(200, r#"{"two_factor_requirement_enabled":false}"#);

        let def = CheckDefinition {
            id: "OBS-FAIL".to_string(),
            name: "Failing Observer Test".to_string(),
            source: "github".to_string(),
            steps: vec![CheckStep {
                id: "get_org".to_string(),
                action: "api_call".to_string(),
                when: String::new(),
                request: super::super::definition::RequestDef {
                    method: "GET".to_string(),
                    url: format!("{url}/orgs/test"),
                    headers: HashMap::new(),
                    body: None,
                    body_form: None,
                    paginate: false,
                },
                extract: {
                    let mut m = HashMap::new();
                    m.insert(
                        "mfa_enforced".to_string(),
                        "$.two_factor_requirement_enabled".to_string(),
                    );
                    m
                },
                on_error: HashMap::new(),
                note: String::new(),
            }],
            assertions: vec![CheckAssertion {
                id: "mfa_check".to_string(),
                expr: "mfa_enforced == true".to_string(),
                severity: "critical".to_string(),
                title: "MFA Enforcement".to_string(),
                pass_message: "MFA is enforced".to_string(),
                fail_message: "MFA is NOT enforced".to_string(),
                finding: None,
            }],
            ..default_check_def()
        };

        let observer = YamlObserver::new(def);
        let config = HashMap::new();
        let results = observer.observe(&config).unwrap();

        assert_eq!(
            results[0].status_id,
            StatusId::Ineffective,
            "MFA disabled → should fail"
        );
        assert!(
            !results[0].findings.is_empty(),
            "failing assertion should create a finding"
        );
    }

    // ── Helper functions ─────────────────────────────────────────────────────

    fn default_check_def() -> CheckDefinition {
        CheckDefinition {
            id: "TEST-1".to_string(),
            name: "Test Check".to_string(),
            description: String::new(),
            author: String::new(),
            version: "1.0".to_string(),
            source: "github".to_string(),
            check_type: super::super::definition::CheckType::Passive,
            safety: String::new(),
            environment: String::new(),
            severity: String::new(),
            profile: String::new(),
            tags: vec![],
            references: super::super::definition::CheckReferences::default(),
            credentials: HashMap::new(),
            inputs: HashMap::new(),
            pre_flight: vec![],
            steps: vec![],
            assertions: vec![],
            remediation: None,
            implementation: String::new(),
            native_module: String::new(),
        }
    }

    fn make_minimal_def_with_inputs() -> CheckDefinition {
        let mut inputs = HashMap::new();
        inputs.insert(
            "org".to_string(),
            super::super::definition::InputDef {
                description: "GitHub org".to_string(),
                env: "GITHUB_ORG".to_string(),
                default: String::new(),
                required: true,
            },
        );
        CheckDefinition {
            inputs,
            ..default_check_def()
        }
    }

    fn make_def_with_assertions() -> CheckDefinition {
        CheckDefinition {
            id: "GH-1.01".to_string(),
            name: "MFA Check".to_string(),
            source: "github".to_string(),
            assertions: vec![CheckAssertion {
                id: "mfa_enforcement".to_string(),
                expr: "mfa_enforced == true".to_string(),
                severity: "critical".to_string(),
                title: "MFA Enforcement".to_string(),
                pass_message: "MFA is enforced".to_string(),
                fail_message: "MFA is NOT enforced".to_string(),
                finding: None,
            }],
            ..default_check_def()
        }
    }

    // ─── Additional coverage tests ───────────────────────────────────────────

    // ── YamlTester::test() via mock server ───────────────────────────────────

    #[test]
    fn yaml_tester_test_runs_steps_and_evaluates_assertions() {
        let url = one_shot_server(200, r#"{"two_factor_requirement_enabled":true}"#);

        let def = CheckDefinition {
            id: "TST-MOCK".to_string(),
            name: "Mock Tester Test".to_string(),
            source: "github".to_string(),
            check_type: super::super::definition::CheckType::Active,
            safety: "observable".to_string(),
            environment: "staging".to_string(),
            steps: vec![CheckStep {
                id: "get_org".to_string(),
                action: "api_call".to_string(),
                when: String::new(),
                request: super::super::definition::RequestDef {
                    method: "GET".to_string(),
                    url: format!("{url}/orgs/test"),
                    headers: HashMap::new(),
                    body: None,
                    body_form: None,
                    paginate: false,
                },
                extract: {
                    let mut m = HashMap::new();
                    m.insert(
                        "mfa_enforced".to_string(),
                        "$.two_factor_requirement_enabled".to_string(),
                    );
                    m
                },
                on_error: HashMap::new(),
                note: String::new(),
            }],
            assertions: vec![CheckAssertion {
                id: "mfa_check".to_string(),
                expr: "mfa_enforced == true".to_string(),
                severity: "critical".to_string(),
                title: "MFA Enforcement".to_string(),
                pass_message: "MFA is enforced".to_string(),
                fail_message: "MFA is NOT enforced".to_string(),
                finding: None,
            }],
            ..default_check_def()
        };

        let tester = YamlTester::new(def);
        let config = HashMap::new();
        let results = tester.test(&config).unwrap();

        assert_eq!(
            results.len(),
            1,
            "should produce one Evidence per assertion"
        );
        assert_eq!(
            results[0].status_id,
            StatusId::Effective,
            "MFA enforced → should pass"
        );
        assert_eq!(
            results[0].confidence_level,
            ConfidenceLevel::ActiveVerification
        );
        assert_eq!(results[0].metadata.module.module_type, "tester");
    }

    #[test]
    fn yaml_tester_test_failing_assertion() {
        let url = one_shot_server(200, r#"{"two_factor_requirement_enabled":false}"#);

        let def = CheckDefinition {
            id: "TST-FAIL".to_string(),
            name: "Failing Tester".to_string(),
            source: "github".to_string(),
            check_type: super::super::definition::CheckType::Active,
            safety: "reversible".to_string(),
            environment: "production".to_string(),
            steps: vec![CheckStep {
                id: "get_org".to_string(),
                action: "api_call".to_string(),
                when: String::new(),
                request: super::super::definition::RequestDef {
                    method: "GET".to_string(),
                    url: format!("{url}/orgs/test"),
                    headers: HashMap::new(),
                    body: None,
                    body_form: None,
                    paginate: false,
                },
                extract: {
                    let mut m = HashMap::new();
                    m.insert(
                        "mfa_enforced".to_string(),
                        "$.two_factor_requirement_enabled".to_string(),
                    );
                    m
                },
                on_error: HashMap::new(),
                note: String::new(),
            }],
            assertions: vec![CheckAssertion {
                id: "mfa_check".to_string(),
                expr: "mfa_enforced == true".to_string(),
                severity: "critical".to_string(),
                title: "MFA Enforcement".to_string(),
                pass_message: "MFA is enforced".to_string(),
                fail_message: "MFA is NOT enforced".to_string(),
                finding: None,
            }],
            ..default_check_def()
        };

        let tester = YamlTester::new(def);
        let config = HashMap::new();
        let results = tester.test(&config).unwrap();

        assert_eq!(results[0].status_id, StatusId::Ineffective);
        assert!(!results[0].findings.is_empty());
    }

    // ── endpoint fallbacks: "owner" and "GITHUB_ORG" ─────────────────────────

    #[test]
    fn evaluate_all_assertions_endpoint_from_owner() {
        let def = make_def_with_assertions();
        let extracted = HashMap::new();
        let mut ctx = HashMap::new();
        ctx.insert("owner".to_string(), "repo-owner".to_string());

        let results =
            evaluate_all_assertions(&def, &extracted, &ctx, ConfidenceLevel::PassiveObservation);

        assert_eq!(results[0].metadata.source.endpoint, "repo-owner");
    }

    #[test]
    fn evaluate_all_assertions_endpoint_from_github_org() {
        let def = make_def_with_assertions();
        let extracted = HashMap::new();
        let mut ctx = HashMap::new();
        ctx.insert("GITHUB_ORG".to_string(), "gh-org".to_string());

        let results =
            evaluate_all_assertions(&def, &extracted, &ctx, ConfidenceLevel::PassiveObservation);

        assert_eq!(results[0].metadata.source.endpoint, "gh-org");
    }

    #[test]
    fn evaluate_all_assertions_endpoint_org_takes_priority_over_owner() {
        let def = make_def_with_assertions();
        let extracted = HashMap::new();
        let mut ctx = HashMap::new();
        ctx.insert("org".to_string(), "org-name".to_string());
        ctx.insert("owner".to_string(), "owner-name".to_string());
        ctx.insert("GITHUB_ORG".to_string(), "github-org-name".to_string());

        let results =
            evaluate_all_assertions(&def, &extracted, &ctx, ConfidenceLevel::PassiveObservation);

        // "org" is first in the chain, so it should take priority.
        assert_eq!(results[0].metadata.source.endpoint, "org-name");
    }

    #[test]
    fn evaluate_all_assertions_endpoint_empty_when_no_context() {
        let def = make_def_with_assertions();
        let extracted = HashMap::new();
        let ctx = HashMap::new(); // No org, owner, or GITHUB_ORG

        let results =
            evaluate_all_assertions(&def, &extracted, &ctx, ConfidenceLevel::PassiveObservation);

        assert_eq!(results[0].metadata.source.endpoint, "");
    }

    // ── execute_step with PATCH+body and PUT+body ────────────────────────────

    #[test]
    fn execute_step_patch_with_body() {
        let url = one_shot_server(200, r#"{"updated":true}"#);
        let step = make_step_with_body(
            "s_patch_body",
            "PATCH",
            &format!("{url}/resource"),
            serde_json::json!({"setting": true}),
        );
        let ctx = HashMap::new();
        let result = execute_step(&step, &ctx).unwrap();
        assert_eq!(result.status_code, 200);
    }

    #[test]
    fn execute_step_put_with_body() {
        let url = one_shot_server(200, r#"{"updated":true}"#);
        let step = make_step_with_body(
            "s_put_body",
            "PUT",
            &format!("{url}/resource"),
            serde_json::json!({"name": "new-name"}),
        );
        let ctx = HashMap::new();
        let result = execute_step(&step, &ctx).unwrap();
        assert_eq!(result.status_code, 200);
    }

    // ── execute_step connection failure ───────────────────────────────────────

    #[test]
    fn execute_step_connection_failure_returns_err() {
        let step = make_step("s_conn_fail", "GET", "http://127.0.0.1:1/nonexistent");
        let ctx = HashMap::new();
        let result = execute_step(&step, &ctx);
        assert!(result.is_err(), "connection failure should return Err");
    }

    // ── run_steps: multi-step with extracted values propagated ────────────────

    #[test]
    fn run_steps_propagates_extracted_values_to_ctx() {
        // First step extracts a string value, second step should see it in ctx.
        let url1 = one_shot_server(200, r#"{"org_name":"acme"}"#);
        let url2 = one_shot_server(200, r#"{"ok":true}"#);

        let step1 = CheckStep {
            id: "s1".to_string(),
            action: "api_call".to_string(),
            when: String::new(),
            request: super::super::definition::RequestDef {
                method: "GET".to_string(),
                url: format!("{url1}/org"),
                headers: HashMap::new(),
                body: None,
                body_form: None,
                paginate: false,
            },
            extract: {
                let mut m = HashMap::new();
                m.insert("org_name".to_string(), "$.org_name".to_string());
                m
            },
            on_error: HashMap::new(),
            note: String::new(),
        };

        let step2 = CheckStep {
            id: "s2".to_string(),
            action: "api_call".to_string(),
            when: String::new(),
            request: super::super::definition::RequestDef {
                method: "GET".to_string(),
                url: format!("{url2}/orgs/{{{{org_name}}}}"),
                headers: HashMap::new(),
                body: None,
                body_form: None,
                paginate: false,
            },
            extract: HashMap::new(),
            on_error: HashMap::new(),
            note: String::new(),
        };

        let mut ctx = HashMap::new();
        let extracted = run_steps(&[step1, step2], &mut ctx).unwrap();

        // org_name should be available as both extracted value and in ctx.
        assert_eq!(extracted["org_name"], serde_json::json!("acme"));
        assert_eq!(ctx.get("org_name").unwrap(), "acme");
    }

    // ── run_steps: when guard with invalid CEL expression defaults to false ──

    #[test]
    fn run_steps_when_guard_undefined_var_defaults_to_skip() {
        let url = one_shot_server(200, r#"{"val":42}"#);
        let step = CheckStep {
            id: "s_bad_guard".to_string(),
            action: "api_call".to_string(),
            when: "undefined_guard_var == true".to_string(), // Undefined var → CEL exec error → unwrap_or(false) → skip
            request: super::super::definition::RequestDef {
                method: "GET".to_string(),
                url: format!("{url}/resource"),
                headers: HashMap::new(),
                body: None,
                body_form: None,
                paginate: false,
            },
            extract: {
                let mut m = HashMap::new();
                m.insert("val".to_string(), "$.val".to_string());
                m
            },
            on_error: HashMap::new(),
            note: String::new(),
        };

        let mut ctx = HashMap::new();
        let extracted = run_steps(&[step], &mut ctx).unwrap();
        // CEL execution error defaults to false (unwrap_or(false)), so step is skipped.
        assert!(
            !extracted.contains_key("val"),
            "step with failing guard should be skipped"
        );
    }

    // ── run_steps: extraction of boolean and number to ctx ───────────────────

    #[test]
    fn run_steps_extracts_bool_and_number_to_ctx() {
        let url = one_shot_server(200, r#"{"enabled":true,"count":42}"#);
        let step = CheckStep {
            id: "s_types".to_string(),
            action: "api_call".to_string(),
            when: String::new(),
            request: super::super::definition::RequestDef {
                method: "GET".to_string(),
                url: format!("{url}/resource"),
                headers: HashMap::new(),
                body: None,
                body_form: None,
                paginate: false,
            },
            extract: {
                let mut m = HashMap::new();
                m.insert("enabled".to_string(), "$.enabled".to_string());
                m.insert("count".to_string(), "$.count".to_string());
                m
            },
            on_error: HashMap::new(),
            note: String::new(),
        };

        let mut ctx = HashMap::new();
        let extracted = run_steps(&[step], &mut ctx).unwrap();

        assert_eq!(extracted["enabled"], serde_json::json!(true));
        assert_eq!(extracted["count"], serde_json::json!(42));
        // json_to_string converts bool and number to string in ctx.
        assert_eq!(ctx.get("enabled").unwrap(), "true");
        assert_eq!(ctx.get("count").unwrap(), "42");
    }

    // ── run_steps: extraction of non-scalar (object/array) skips ctx insert ──

    #[test]
    fn run_steps_non_scalar_extraction_skips_ctx_string() {
        let url = one_shot_server(200, r#"{"nested":{"key":"val"}}"#);
        let step = CheckStep {
            id: "s_nested".to_string(),
            action: "api_call".to_string(),
            when: String::new(),
            request: super::super::definition::RequestDef {
                method: "GET".to_string(),
                url: format!("{url}/resource"),
                headers: HashMap::new(),
                body: None,
                body_form: None,
                paginate: false,
            },
            extract: {
                let mut m = HashMap::new();
                m.insert("nested".to_string(), "$.nested".to_string());
                m
            },
            on_error: HashMap::new(),
            note: String::new(),
        };

        let mut ctx = HashMap::new();
        let extracted = run_steps(&[step], &mut ctx).unwrap();

        // nested is an object — should be in extracted but NOT in ctx string map.
        assert!(extracted.contains_key("nested"));
        assert!(
            !ctx.contains_key("nested"),
            "object values should not be added to string ctx"
        );
    }

    // ── run_steps: extraction with path that doesn't match body ──────────────

    #[test]
    fn run_steps_extraction_no_match_not_inserted() {
        let url = one_shot_server(200, r#"{"key":"val"}"#);
        let step = CheckStep {
            id: "s_nomatch".to_string(),
            action: "api_call".to_string(),
            when: String::new(),
            request: super::super::definition::RequestDef {
                method: "GET".to_string(),
                url: format!("{url}/resource"),
                headers: HashMap::new(),
                body: None,
                body_form: None,
                paginate: false,
            },
            extract: {
                let mut m = HashMap::new();
                m.insert("missing".to_string(), "$.nonexistent_field".to_string());
                m
            },
            on_error: HashMap::new(),
            note: String::new(),
        };

        let mut ctx = HashMap::new();
        let extracted = run_steps(&[step], &mut ctx).unwrap();

        assert!(
            !extracted.contains_key("missing"),
            "non-matching path should not insert variable"
        );
    }

    // ── YamlTester credential_requirements ────────────────────────────────────

    #[test]
    fn yaml_tester_credential_requirements() {
        let def = CheckDefinition {
            credentials: {
                let mut m = HashMap::new();
                m.insert(
                    "OKTA_API_TOKEN".to_string(),
                    super::super::definition::CredentialDef {
                        cred_type: "api_token".to_string(),
                        scopes: vec!["okta.apps.read".to_string()],
                        required: true,
                    },
                );
                m
            },
            ..default_check_def()
        };
        let tester = YamlTester::new(def);
        let creds = tester.credential_requirements();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].name, "OKTA_API_TOKEN");
        assert!(creds[0].required);
    }

    // ── YamlTester environment_scope "stage" alias ───────────────────────────

    #[test]
    fn yaml_tester_environment_scope_stage_alias() {
        let def = CheckDefinition {
            environment: "stage".to_string(),
            ..default_check_def()
        };
        let tester = YamlTester::new(def);
        assert_eq!(tester.environment_scope(), EnvironmentScope::Staging);
    }

    // ── evaluate_assertion CEL execution error (undefined variable) ──────────

    #[test]
    fn evaluate_assertion_execution_error() {
        // Expression that references a variable not in the context causes execution error.
        let assertion = CheckAssertion {
            id: "exec_err".to_string(),
            expr: "undefined_var == true".to_string(),
            severity: "medium".to_string(),
            title: String::new(),
            pass_message: String::new(),
            fail_message: String::new(),
            finding: None,
        };
        let extracted = HashMap::new();
        let result = evaluate_assertion(&assertion, &extracted);
        assert!(
            result.is_err(),
            "referencing undefined var should return Err"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("CEL execution error"),
            "error should mention CEL execution: {msg}"
        );
    }

    // ── evaluate_all_assertions with pass_message template resolution ────────

    #[test]
    fn evaluate_all_assertions_resolves_pass_message_template() {
        let def = CheckDefinition {
            id: "MSG-TEST".to_string(),
            name: "Message Test".to_string(),
            source: "github".to_string(),
            assertions: vec![CheckAssertion {
                id: "msg_assert".to_string(),
                expr: "val == true".to_string(),
                severity: "medium".to_string(),
                title: "Msg Test".to_string(),
                pass_message: "org {{org}} passed".to_string(),
                fail_message: "org {{org}} failed".to_string(),
                finding: None,
            }],
            ..default_check_def()
        };

        let mut extracted = HashMap::new();
        extracted.insert("val".to_string(), serde_json::json!(true));
        let mut ctx = HashMap::new();
        ctx.insert("org".to_string(), "acme".to_string());

        let results =
            evaluate_all_assertions(&def, &extracted, &ctx, ConfidenceLevel::PassiveObservation);
        assert_eq!(results[0].status, "org acme passed");
    }

    #[test]
    fn evaluate_all_assertions_resolves_fail_message_template() {
        let def = CheckDefinition {
            id: "MSG-FAIL".to_string(),
            name: "Fail Msg Test".to_string(),
            source: "github".to_string(),
            assertions: vec![CheckAssertion {
                id: "msg_fail".to_string(),
                expr: "val == true".to_string(),
                severity: "medium".to_string(),
                title: "Fail Msg".to_string(),
                pass_message: "passed".to_string(),
                fail_message: "org {{org}} failed".to_string(),
                finding: None,
            }],
            ..default_check_def()
        };

        let mut extracted = HashMap::new();
        extracted.insert("val".to_string(), serde_json::json!(false)); // force failure
        let mut ctx = HashMap::new();
        ctx.insert("org".to_string(), "my-org".to_string());

        let results =
            evaluate_all_assertions(&def, &extracted, &ctx, ConfidenceLevel::PassiveObservation);
        assert_eq!(results[0].status, "org my-org failed");
    }

    // ── execute_step with headers template resolution ────────────────────────

    #[test]
    fn execute_step_resolves_headers() {
        let url = one_shot_server(200, r#"{"ok":true}"#);
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), "Bearer {{token}}".to_string());

        let step = CheckStep {
            id: "s_headers".to_string(),
            action: "api_call".to_string(),
            when: String::new(),
            request: super::super::definition::RequestDef {
                method: "GET".to_string(),
                url: format!("{url}/resource"),
                headers,
                body: None,
                body_form: None,
                paginate: false,
            },
            extract: HashMap::new(),
            on_error: HashMap::new(),
            note: String::new(),
        };

        let mut ctx = HashMap::new();
        ctx.insert("token".to_string(), "ghp_test_token".to_string());
        let result = execute_step(&step, &ctx).unwrap();
        assert_eq!(result.status_code, 200);
    }

    // ── execute_step URL template resolution ─────────────────────────────────

    #[test]
    fn execute_step_resolves_url_template() {
        let url = one_shot_server(200, r#"{"ok":true}"#);
        // Extract just the port from the mock server URL.
        let port = url.rsplit(':').next().unwrap();

        let step = make_step(
            "s_url_tmpl",
            "GET",
            &format!("http://127.0.0.1:{port}/orgs/{{{{org}}}}"),
        );

        let mut ctx = HashMap::new();
        ctx.insert("org".to_string(), "test-org".to_string());
        let result = execute_step(&step, &ctx).unwrap();
        assert_eq!(result.status_code, 200);
    }

    // ── navigate_fields with mid-path non-object ─────────────────────────────

    #[test]
    fn jsonpath_nested_mid_path_non_object() {
        // If a middle segment is not an object, navigation should return None.
        let body = serde_json::json!({"a": "not_an_object"});
        assert!(jsonpath_extract("$.a.b", &body).is_none());
    }

    // ── jsonpath array wildcard with nested missing field ─────────────────────

    #[test]
    fn jsonpath_array_wildcard_missing_nested_field() {
        let body = serde_json::json!([
            {"user": {"name": "alice"}},
            {"user": {}},  // missing "name"
            {"other": "value"},  // missing "user"
        ]);
        let val = jsonpath_extract("$[*].user.name", &body).unwrap();
        // Only the first element has user.name; the others are filtered out.
        assert_eq!(val, serde_json::json!(["alice"]));
    }

    // ── jsonpath $[*] with dot but missing field ────────────────────────────

    #[test]
    fn jsonpath_array_wildcard_without_dot_prefix_returns_none() {
        // "$[*]field" (no dot after [*]) should fail the strip_prefix('.').
        let body = serde_json::json!([1, 2, 3]);
        assert!(jsonpath_extract("$[*]field", &body).is_none());
    }
}
