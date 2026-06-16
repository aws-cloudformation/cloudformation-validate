use diagnostics::{
    DetailLevel, Diagnostic, PerformanceMetrics, Phase, PhaseMetric, RegisteredDiagnostic, RelatedResource,
    ReportMetadata, ReportStatus, ResourceRef, SourceSpan, Summary, UNKNOWN_SPAN, ValidationReport, ViolationContext,
    apply_filters, is_sam_transform_error_message, phase_metric, resolve_section_span,
};
use rules::{FilterConfig, RuleInfo, RuleMetadataEntry, RuleOrigin, Severity, is_fatal_rule, section_for_rule_id};
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;
use std::error;
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use template_model::{ParseConfig, ParseError, ParseResult, PseudoParameterOverrides, SemanticModel};
use web_time::Instant;

fn span_to_option(span: SourceSpan) -> Option<SourceSpan> {
    if span == UNKNOWN_SPAN { None } else { Some(span) }
}

#[derive(Debug)]
pub enum ValidationError {
    Parse(ParseError),
    Engine(String),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::Parse(e) => write!(f, "{}", e),
            ValidationError::Engine(msg) => write!(f, "{}", msg),
        }
    }
}

impl error::Error for ValidationError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ValidationError::Parse(e) => Some(e),
            ValidationError::Engine(_) => None,
        }
    }
}

impl From<ParseError> for ValidationError {
    fn from(e: ParseError) -> Self {
        ValidationError::Parse(e)
    }
}

impl From<String> for ValidationError {
    fn from(s: String) -> Self {
        ValidationError::Engine(s)
    }
}

impl From<&str> for ValidationError {
    fn from(s: &str) -> Self {
        ValidationError::Engine(s.to_string())
    }
}

/// Selects which validation engine evaluates rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Enum))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EngineType {
    #[default]
    Rego,
    Cel,
}

impl EngineType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            EngineType::Rego => "Rego",
            EngineType::Cel => "CEL",
        }
    }

    /// Parses an engine selector, accepting `rego`/`cel` case-insensitively.
    /// Returns an error describing the valid options rather than panicking, so a
    /// bad selector becomes a handleable failure instead of a process abort.
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.to_lowercase().as_str() {
            "rego" => Ok(EngineType::Rego),
            "cel" => Ok(EngineType::Cel),
            other => Err(format!("Unknown engine type '{other}'; expected 'rego' or 'cel'")),
        }
    }
}

impl fmt::Display for EngineType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A pre-read rule file provided by the caller (custom Rego/CEL or Guard DSL).
///
/// `name` identifies the rule source in error messages and logging. In the CLI
/// this is the filesystem path; in WASM/JVM it is whatever label the caller provides.
///
/// `content` is the full source text of the rule file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm-bindings", tsify(from_wasm_abi))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct ExternalRuleSource {
    pub name: String,
    pub content: String,
}

#[derive(Default, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm-bindings", tsify(from_wasm_abi))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct EngineConfig {
    /// Engine-native custom rules (Rego or CEL depending on engine).
    #[serde(default)]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub custom_rules: Vec<ExternalRuleSource>,
    /// Guard DSL rules as raw source text — each engine parses and translates internally.
    #[serde(default)]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub guard_rules: Vec<ExternalRuleSource>,
}

#[derive(Clone)]
pub struct ValidateConfig {
    pub filters: FilterConfig,
    pub detail_level: DetailLevel,
    pub severity_level: Severity,
    pub parameter_overrides: HashMap<String, String>,
    pub pseudo_parameter_overrides: PseudoParameterOverrides,
    /// When true, Warn-severity diagnostics are upgraded to Error.
    pub strict: bool,
    /// When true (default), emit all diagnostics including `RuleOrigin::Engine`.
    /// When false, `RuleOrigin::Engine` diagnostics are suppressed.
    pub include_engine_rules: bool,
}

impl Default for ValidateConfig {
    fn default() -> Self {
        Self {
            filters: FilterConfig::default(),
            detail_level: DetailLevel::default(),
            severity_level: Severity::default(),
            parameter_overrides: HashMap::new(),
            pseudo_parameter_overrides: PseudoParameterOverrides::default(),
            strict: false,
            include_engine_rules: true,
        }
    }
}

pub trait ValidationEngine {
    fn engine_name(&self) -> &str;

    fn evaluate_rules(
        &self,
        model: &Arc<SemanticModel>,
        config: &ValidateConfig,
    ) -> Result<Vec<Diagnostic>, ValidationError>;

    fn list_rules(&self) -> Vec<RuleInfo>;

    /// Built-in rule metadata from the rules registry only.
    fn rule_metadata(&self) -> &HashMap<String, RuleMetadataEntry>;

    /// Metadata for rules not in the registry: custom user rules and translated guard rules.
    fn external_rule_metadata(&self) -> HashMap<String, RuleMetadataEntry>;

    fn init_metric(&self) -> &PhaseMetric;
}

pub(crate) fn validate(
    engine: &dyn ValidationEngine,
    schema_validator: &schema_validator::SchemaValidator,
    result: ParseResult,
    config: ValidateConfig,
    file_path: String,
) -> Result<ValidationReport, ValidationError> {
    let model = Arc::new(result.model);
    let model_build = result.model_build;
    log::info!(
        "Validating: {} resources, {} types (engine={})",
        model.resources.len(),
        model.resources_by_type.len(),
        engine.engine_name()
    );

    let schema_result = schema_validator.validate(&model, config.pseudo_parameter_overrides.region());
    let mut all_diagnostics = schema_result.diagnostics;

    let t_eval = Instant::now();
    let engine_diags = engine.evaluate_rules(&model, &config)?;
    all_diagnostics.extend(engine_diags);
    let eval_metric = phase_metric(t_eval);

    let t_post = Instant::now();
    all_diagnostics.extend(crate::step_functions::validate_all_state_machines(&model));

    all_diagnostics.extend(model.diagnostics.iter().cloned());

    gate_sam_transform_errors(&mut all_diagnostics);

    let registry_metadata = engine.rule_metadata();
    let external_metadata = engine.external_rule_metadata();
    enrich_diagnostics(&mut all_diagnostics, &model, registry_metadata, &external_metadata, &config.detail_level);

    if config.detail_level.needs_context() {
        schema_validator.enrich_context(&mut all_diagnostics, &model);
        for d in all_diagnostics.iter_mut() {
            if d.context.is_none() && !is_fatal_rule(&d.rule_id) {
                d.context = build_context(
                    &d.rule_id,
                    d.resource.as_ref().and_then(|r| r.id.as_deref()),
                    d.property_path.as_deref().unwrap_or(""),
                    &model,
                );
            }
        }
    }

    let (total_before, suppressed) = finalize_diagnostics(&mut all_diagnostics, &config, registry_metadata);

    if suppressed > 0 {
        log::info!("Filtered {} -> {} diagnostics ({} suppressed)", total_before, all_diagnostics.len(), suppressed);
    }

    let excluded_cats = config.filters.excluded_categories();
    let active_rule_count = registry_metadata
        .iter()
        .filter(|(_, entry)| !entry.category.as_deref().is_some_and(|c| excluded_cats.contains(c)))
        .count() as u32;

    let mut report = build_report(
        all_diagnostics,
        &model,
        suppressed,
        Some(active_rule_count),
        config.strict,
        config.severity_level,
        file_path,
    );
    let finalize_metric = phase_metric(t_post);

    report.performance.schema_init = schema_validator.init_metric().clone();
    report.performance.engine_init = engine.init_metric().clone();
    report.performance.model_build = model_build;
    report.performance.schema_validate = schema_result.metric;
    report.performance.rule_evaluation = eval_metric;
    report.performance.diagnostic_finalize = finalize_metric;

    Ok(report)
}

#[cfg(any(test, feature = "test"))]
pub fn validate_bytes(
    engine: &dyn ValidationEngine,
    schema_validator: &schema_validator::SchemaValidator,
    bytes: &[u8],
    config: ValidateConfig,
) -> Result<ValidationReport, ValidationError> {
    validate_bytes_with_path(engine, schema_validator, bytes, config, String::new())
}

pub fn validate_bytes_with_path(
    engine: &dyn ValidationEngine,
    schema_validator: &schema_validator::SchemaValidator,
    bytes: &[u8],
    config: ValidateConfig,
    file_path: String,
) -> Result<ValidationReport, ValidationError> {
    let total_start = Instant::now();
    let result = match SemanticModel::parse(
        bytes,
        ParseConfig {
            parameters: config.parameter_overrides.clone(),
            pseudo_parameters: config.pseudo_parameter_overrides.clone(),
        },
    ) {
        Ok(r) => r,
        Err(e) => {
            let span = match (e.line, e.column) {
                (Some(l), Some(c)) => SourceSpan { start_line: l, start_column: c, end_line: l, end_column: c },
                _ => UNKNOWN_SPAN,
            };
            let mut diag = RegisteredDiagnostic::new("F1101", e.message).location(span).phase(Phase::Parse).build();
            diag.section = Some("Template".into());
            let diags = vec![diag];
            let report = ValidationReport {
                file_path,
                status: ReportStatus::Error,
                engine_version: env!("CARGO_PKG_VERSION").to_string(),
                diagnostics: diags,
                metadata: ReportMetadata {
                    rules_evaluated: None,
                    resources_scanned: 0,
                    counts: Summary { fatal: 1, errors: 0, warnings: 0, informational: 0, debug: 0 },
                    suppressed: 0,
                    strict: config.strict,
                    severity_level: config.severity_level,
                },
                performance: PerformanceMetrics {
                    schema_init: PhaseMetric { duration_ms: 0.0 },
                    engine_init: PhaseMetric { duration_ms: 0.0 },
                    model_build: PhaseMetric { duration_ms: 0.0 },
                    schema_validate: PhaseMetric { duration_ms: 0.0 },
                    rule_evaluation: PhaseMetric { duration_ms: 0.0 },
                    diagnostic_finalize: PhaseMetric { duration_ms: 0.0 },
                    validate_total: phase_metric(total_start),
                },
            };
            return Ok(report);
        }
    };
    let mut report = validate(engine, schema_validator, result, config, file_path)?;
    report.performance.validate_total = phase_metric(total_start);
    Ok(report)
}

/// Runs `operation`, converting any unwinding panic into an error produced by
/// `on_panic` instead of letting it escape into the caller. Every embedding
/// boundary — the CLI, the WASM bindings, and the JVM bindings — routes through
/// this guard, so an internal invariant violation on adversarial input becomes a
/// structured, catchable error rather than crashing or trapping the host.
///
/// `on_panic` receives the panic's message and maps it to the caller's own error
/// type (a [`ValidationError`], a binding `JsValue`, a JVM error, …), keeping the
/// guard reusable across every binding without coupling it to one error type.
///
/// The guard only works under the `unwind` panic strategy — [`catch_unwind`]
/// intercepts unwinding panics, not aborts. The workspace pins `panic = "unwind"`
/// in both the dev and release profiles (`src/Cargo.toml`), so on native targets
/// (the CLI binary and the JVM native library) a panic is caught here before it
/// can unwind across the FFI boundary into JNI frames — which would be undefined
/// behavior.
///
/// On `wasm32-unknown-unknown` the standard library is compiled with
/// `panic = "abort"`: a panic traps the instance and `catch_unwind` cannot
/// intercept it, so the only recovery is to recreate the instance. There this
/// guard is a no-op that becomes effective only if the wasm build opts into the
/// unwind strategy. Wrapping the wasm path is therefore harmless and
/// forward-compatible rather than load-bearing today.
pub fn catch_panics<T, E>(
    operation: impl FnOnce() -> Result<T, E>,
    on_panic: impl FnOnce(String) -> E,
) -> Result<T, E> {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(result) => result,
        Err(payload) => Err(on_panic(panic_message(payload.as_ref()))),
    }
}

/// Convenience wrapper over [`catch_panics`] for the core validation flow: a
/// panic becomes a structured [`ValidationError::Engine`] carrying the message.
pub fn validate_catching_panics<F>(validate: F) -> Result<ValidationReport, ValidationError>
where
    F: FnOnce() -> Result<ValidationReport, ValidationError>,
{
    catch_panics(validate, |message| ValidationError::Engine(format!("Internal validation error: {message}")))
}

pub fn semantic_model_to_input_json(model: &SemanticModel) -> Result<serde_json::Value, ValidationError> {
    serde_json::to_value(model.to_diagnostic_json()).map_err(|e| {
        ValidationError::Engine(format!("Failed to serialize the semantic model for rule evaluation: {e}"))
    })
}

fn panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "Panic payload was not a string".to_string()
    }
}

pub(crate) fn parse_diagnostic(
    val: &serde_json::Value,
    model: &SemanticModel,
    source_override: Option<&RuleOrigin>,
) -> Result<Diagnostic, String> {
    let rule_id =
        val.get("rule_id").and_then(|v| v.as_str()).ok_or("Diagnostic missing required field 'rule_id'")?.to_string();
    let severity_str = val
        .get("severity")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("Diagnostic '{}' missing required field 'severity'", rule_id))?;
    let severity = severity_str.parse::<Severity>()?;
    let message = val
        .get("message")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("Diagnostic '{}' missing required field 'message'", rule_id))?
        .to_string();
    let resource_id = val.get("resource_id").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(|s| s.to_string());
    let resource = resource_id.as_ref().map(|rid| ResourceRef {
        id: Some(rid.clone()),
        resource_type: model.resources.get(rid.as_str()).map(|r| r.resource_type.clone()),
    });
    let property_path =
        val.get("resource_path").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(|s| s.to_string());

    let span = if let Some(ref rid) = resource_id {
        model.resource_span(rid, property_path.as_deref().unwrap_or(""))
    } else {
        let sl = val.get("start_line").and_then(|v| v.as_u64());
        let sc = val.get("start_column").and_then(|v| v.as_u64());
        match (sl, sc) {
            (Some(l), Some(c)) => SourceSpan {
                start_line: l as u32,
                start_column: c as u32,
                end_line: val.get("end_line").and_then(|v| v.as_u64()).unwrap_or(l) as u32,
                end_column: val.get("end_column").and_then(|v| v.as_u64()).unwrap_or(c) as u32,
            },
            _ => resolve_section_span(&rule_id, model),
        }
    };

    let is_custom_or_guard = source_override.is_some_and(|o| matches!(o, RuleOrigin::Custom | RuleOrigin::Guard));

    let suggested_fix = val.get("suggested_fix").and_then(|v| v.as_str()).map(|s| s.to_string());
    let documentation_url = val.get("documentation_url").and_then(|v| v.as_str()).map(|s| s.to_string());
    let related_resources = val.get("related_locations").and_then(|v| v.as_array()).map(|arr| {
        arr.iter()
            .filter_map(|r| {
                let rel_rid = r.get("resource_id").and_then(|v| v.as_str()).map(|s| s.to_string());
                let rel_resource = rel_rid.as_ref().map(|rid| ResourceRef {
                    id: Some(rid.clone()),
                    resource_type: model.resources.get(rid.as_str()).map(|res| res.resource_type.clone()),
                });
                Some(RelatedResource {
                    resource: rel_resource,
                    location: Some(SourceSpan {
                        start_line: r.get("start_line")?.as_u64()? as u32,
                        start_column: r.get("start_column")?.as_u64()? as u32,
                        end_line: r.get("end_line")?.as_u64()? as u32,
                        end_column: r.get("end_column")?.as_u64()? as u32,
                    }),
                    message: r.get("message")?.as_str()?.to_string(),
                })
            })
            .collect()
    });
    let condition_scenario = val
        .get("condition_scenario")
        .and_then(|v| v.as_object())
        .map(|m| m.iter().filter_map(|(k, v)| v.as_bool().map(|b| (k.clone(), b))).collect());

    if is_custom_or_guard {
        // Custom and Guard rules are deliberately absent from the rule registry.
        // Their severity, category, and origin come straight from the parsed rule
        // output — never the registry — so the diagnostic is assembled directly
        // here rather than through the registry-driven builder.
        let severity = if is_fatal_rule(&rule_id) { Severity::Fatal } else { severity };
        let category = val.get("category").and_then(|v| v.as_str()).map(|c| c.to_string());
        let source = *source_override.expect("custom/guard branch is only reached with a source override");
        return Ok(Diagnostic {
            rule_id,
            severity,
            message,
            resource,
            property_path,
            suggested_fix,
            documentation_url,
            category,
            location: span_to_option(span),
            related_resources,
            condition_scenario,
            rule_description: None,
            phase: None,
            section: None,
            context: None,
            source,
        });
    }

    // Built-in rules: severity, category, origin, and description are sourced from
    // the rule registry through the shared builder. The engine's JSON output
    // supplies only the contextual fields (location, resource, related findings).
    let mut diagnostic = RegisteredDiagnostic::new(rule_id, message)
        .location(span)
        .suggested_fix(suggested_fix)
        .condition_scenario(condition_scenario)
        .related_resources(related_resources)
        .build();
    diagnostic.resource = resource;
    diagnostic.property_path = property_path;
    diagnostic.documentation_url = documentation_url;
    Ok(diagnostic)
}

pub fn extract_diagnostics(
    json_str: &str,
    model: &SemanticModel,
    out: &mut Vec<Diagnostic>,
    source_override: Option<&RuleOrigin>,
) -> Result<(), String> {
    let json_val: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| format!("Failed to parse diagnostic JSON: {}", e))?;
    let items = json_val.as_array().ok_or("Diagnostic output must be a JSON array")?;
    for item in items {
        out.push(parse_diagnostic(item, model, source_override)?);
    }
    Ok(())
}

pub(crate) fn build_report(
    diagnostics: Vec<Diagnostic>,
    model: &SemanticModel,
    suppressed: u32,
    rules_evaluated: Option<u32>,
    strict: bool,
    severity_level: Severity,
    file_path: String,
) -> ValidationReport {
    let fatal = diagnostics.iter().filter(|d| d.severity == Severity::Fatal).count() as u32;
    let errors = diagnostics.iter().filter(|d| d.severity == Severity::Error).count() as u32;
    let warnings = diagnostics.iter().filter(|d| d.severity == Severity::Warn).count() as u32;
    let debug = diagnostics.iter().filter(|d| d.severity == Severity::Debug).count() as u32;
    let informational = diagnostics.len() as u32 - fatal - errors - warnings - debug;
    ValidationReport {
        file_path,
        status: ReportStatus::Ok,
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
        diagnostics,
        metadata: ReportMetadata {
            rules_evaluated,
            resources_scanned: model.resources.len() as u32,
            counts: Summary { fatal, errors, warnings, informational, debug },
            suppressed,
            strict,
            severity_level,
        },
        performance: PerformanceMetrics {
            schema_init: PhaseMetric { duration_ms: 0.0 },
            engine_init: PhaseMetric { duration_ms: 0.0 },
            model_build: PhaseMetric { duration_ms: 0.0 },
            schema_validate: PhaseMetric { duration_ms: 0.0 },
            rule_evaluation: PhaseMetric { duration_ms: 0.0 },
            diagnostic_finalize: PhaseMetric { duration_ms: 0.0 },
            validate_total: PhaseMetric { duration_ms: 0.0 },
        },
    }
}

pub(crate) fn finalize_diagnostics(
    diagnostics: &mut Vec<Diagnostic>,
    config: &ValidateConfig,
    registry_metadata: &HashMap<String, RuleMetadataEntry>,
) -> (u32, u32) {
    let total_before = diagnostics.len() as u32;

    if !config.include_engine_rules {
        diagnostics.retain(|d| {
            registry_metadata.get(&d.rule_id).map(|entry| !matches!(entry.origin, RuleOrigin::Engine)).unwrap_or(true)
        });
    }

    if config.strict {
        for d in diagnostics.iter_mut() {
            if d.severity == Severity::Warn {
                d.severity = Severity::Error;
            }
        }
    }

    apply_filters(diagnostics, &config.filters);

    // Filter by minimum severity. Debug is the lowest severity so it acts as "no filter".
    diagnostics.retain(|d| d.severity >= config.severity_level);

    // Sort key MUST be a superset of the dedup key below. If two diagnostics share the
    // dedup key but are separated by a sibling that compares equal on the sort key,
    // stable sort leaves them non-adjacent and dedup_by silently misses them.
    // Seen in the wild: the same rule fired twice for the same parameter (two distinct usages)
    // with a sibling diagnostic for a different parameter at the same line/col in between —
    // native HashMap iteration order put them in [A, B, A] layout, dedup skipped.
    diagnostics.sort_by(|a, b| {
        a.location
            .as_ref()
            .map(|l| l.start_line)
            .unwrap_or(0)
            .cmp(&b.location.as_ref().map(|l| l.start_line).unwrap_or(0))
            .then(
                a.location
                    .as_ref()
                    .map(|l| l.start_column)
                    .unwrap_or(0)
                    .cmp(&b.location.as_ref().map(|l| l.start_column).unwrap_or(0)),
            )
            .then(b.severity.cmp(&a.severity))
            .then(a.rule_id.cmp(&b.rule_id))
            .then(a.property_path.cmp(&b.property_path))
            .then(a.message.cmp(&b.message))
    });
    diagnostics.dedup_by(|a, b| {
        a.location.as_ref().map(|l| l.start_line).unwrap_or(0) == b.location.as_ref().map(|l| l.start_line).unwrap_or(0)
            && a.location.as_ref().map(|l| l.start_column).unwrap_or(0)
                == b.location.as_ref().map(|l| l.start_column).unwrap_or(0)
            && a.rule_id == b.rule_id
            && a.message == b.message
            && a.property_path == b.property_path
    });

    let suppressed = total_before.saturating_sub(diagnostics.len() as u32);
    (total_before, suppressed)
}

pub(crate) fn build_context(
    rule_id: &str,
    resource_id: Option<&str>,
    property_path: &str,
    model: &SemanticModel,
) -> Option<ViolationContext> {
    let rid = resource_id?;

    let resolve_val = |path: &str| -> Option<serde_json::Value> {
        let scenarios = model.resolve_scenarios_json(rid, path);
        scenarios.into_iter().next().map(|(v, _)| v)
    };

    let mut actual_value: Option<diagnostics::JsonValue> = None;
    let mut property = None;
    let mut lifecycle = None;
    let mut extra: HashMap<String, diagnostics::JsonValue> = HashMap::new();

    match rule_id {
        "F3012" | "E3012" => {
            if !property_path.is_empty() {
                actual_value = resolve_val(property_path).map(Into::into);
            }
        }
        "F3030" | "E3030" | "F3031" | "E3031" | "F3034" | "E3034" | "F3037" | "W3045" | "E1103" | "E1150" | "E1151"
        | "E1152" | "E1153" | "E1154" | "E1155" | "E1156" => {
            actual_value = resolve_val(property_path).map(Into::into);
        }
        "F3033" | "W9006" => {
            if let Some(v) = resolve_val(property_path) {
                if let Some(s) = v.as_str() {
                    extra.insert("actual_length".into(), serde_json::json!(s.len()).into());
                }
                actual_value = Some(v.into());
            }
        }
        "F3032" | "E3032" => {
            if let Some(v) = resolve_val(property_path)
                && let Some(arr) = v.as_array()
            {
                extra.insert("actual_count".into(), serde_json::json!(arr.len()).into());
            }
        }
        "F3002" | "E3002" | "F3020" => {
            let prop = property_path.rsplit('.').next().unwrap_or("");
            if !prop.is_empty() {
                property = Some(prop.to_string());
            }
        }
        "F3003" | "F3021" | "F3014" | "F3058" => {}
        "E3047" => {
            if let Some(v) = resolve_val("Properties.Cpu") {
                extra.insert("cpu".into(), v.into());
            }
            if let Some(v) = resolve_val("Properties.Memory") {
                extra.insert("memory".into(), v.into());
            }
        }
        "E3060" => {
            if let Some(v) = resolve_val("Properties.CidrBlock") {
                extra.insert("cidr".into(), v.into());
            }
        }
        "E9002" => {
            actual_value = resolve_val("Properties.SecurityGroupIngress").map(Into::into);
        }
        "E9001" => {
            if let Some(res) = model.resources.get(rid) {
                extra.insert("resource_type".into(), serde_json::json!(res.resource_type).into());
            }
        }
        "E3501" => {
            if let Some(v) = resolve_val("Properties.QueueName") {
                extra.insert("queue_name".into(), v.into());
            }
        }
        "E3505" => {
            if let Some(v) = resolve_val("Properties.VisibilityTimeout") {
                extra.insert("visibility_timeout".into(), v.into());
            }
        }
        "E3044" => {
            if let Some(v) = resolve_val("Properties.LaunchType") {
                extra.insert("launch_type".into(), v.into());
            }
            if let Some(v) = resolve_val("Properties.SchedulingStrategy") {
                extra.insert("scheduling_strategy".into(), v.into());
            }
        }
        "E3053" => {
            if !property_path.is_empty() {
                actual_value = resolve_val(property_path).map(Into::into);
            }
        }
        "W9009" => {
            lifecycle = Some("deprecated".into());
        }
        "I9001" => {
            lifecycle = Some("create-only".into());
        }
        "W3041" => {
            lifecycle = Some("write-only".into());
        }
        "W2503" | "W2502" => {
            if let Some(res) = model.resources.get(rid)
                && let Some(ref c) = res.condition
            {
                extra.insert("source_condition".into(), serde_json::json!(c).into());
            }
        }
        _ => {}
    }

    if actual_value.is_none() && property.is_none() && lifecycle.is_none() && extra.is_empty() {
        return None;
    }

    Some(ViolationContext {
        actual_value,
        expected_constraint: None,
        property,
        lifecycle,
        resolution_source: None,
        extra: if extra.is_empty() { None } else { Some(extra) },
    })
}

/// Drops every non-transform diagnostic when a SAM transform error is present.
///
/// A failed SAM transform stops CloudFormation before resource validation, so
/// schema and lint findings on the untransformed template are noise. Retaining
/// only the transform errors mirrors that short-circuit.
fn gate_sam_transform_errors(diagnostics: &mut Vec<Diagnostic>) {
    let has_transform_error = diagnostics.iter().any(|d| is_sam_transform_error_message(&d.message));
    if has_transform_error {
        diagnostics.retain(|d| is_sam_transform_error_message(&d.message));
    }
}

pub(crate) fn enrich_diagnostics(
    diagnostics: &mut [Diagnostic],
    model: &SemanticModel,
    registry_metadata: &HashMap<String, RuleMetadataEntry>,
    external_metadata: &HashMap<String, RuleMetadataEntry>,
    format: &DetailLevel,
) {
    if !format.needs_enrichment() {
        return;
    }
    let needs_context = format.needs_context();

    for d in diagnostics.iter_mut() {
        if d.section.is_none() {
            let rid = d.resource.as_ref().and_then(|r| r.id.as_deref());
            d.section = section_for_rule_id(rid, &d.rule_id).map(Into::into);
        }
        if d.phase.is_none() {
            d.phase = Some(if is_fatal_rule(&d.rule_id) { Phase::Schema } else { Phase::Lint });
        }
        if d.rule_description.is_none() {
            d.rule_description = registry_metadata
                .get(&d.rule_id)
                .or_else(|| external_metadata.get(&d.rule_id))
                .map(|entry| entry.description.clone());
        }
        if needs_context && d.context.is_none() {
            d.context = build_context(
                &d.rule_id,
                d.resource.as_ref().and_then(|r| r.id.as_deref()),
                d.property_path.as_deref().unwrap_or(""),
                model,
            );
        }
    }
}

pub fn build_rule_list(
    registry: &HashMap<String, RuleMetadataEntry>,
    external: &HashMap<String, RuleMetadataEntry>,
) -> Vec<RuleInfo> {
    let mut rules: Vec<RuleInfo> = registry
        .iter()
        .chain(external.iter())
        .map(|(id, entry)| RuleInfo {
            id: id.clone(),
            severity: entry.severity,
            category: entry.category.clone(),
            description: entry.description.clone(),
            origin: entry.origin,
        })
        .collect();
    rules.sort_by(|a, b| a.id.cmp(&b.id));
    rules
}

pub fn make_resource_diagnostic(
    rule_id: &str,
    message: &str,
    model: &SemanticModel,
    resource_id: &str,
    prop_path: &str,
    suggested_fix: Option<&str>,
) -> Diagnostic {
    let span = if resource_id.is_empty() {
        resolve_section_span(rule_id, model)
    } else {
        model.resource_span(resource_id, prop_path)
    };
    let mut builder = RegisteredDiagnostic::new(rule_id, message)
        .property_path(prop_path)
        .location(span)
        .suggested_fix(suggested_fix);
    if !resource_id.is_empty() {
        builder = builder.resource(resource_id, model.resources.get(resource_id).map(|r| r.resource_type.clone()));
    }
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use diagnostics::Phase;
    use rules::{Category, lookup_rule};

    fn minimal_model() -> SemanticModel {
        let yaml = br#"
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-bucket
"#;
        SemanticModel::from_bytes(yaml).expect("minimal model should parse")
    }

    fn meta_map() -> HashMap<String, RuleMetadataEntry> {
        rules::build_rule_metadata_map()
    }

    fn default_diag() -> Diagnostic {
        Diagnostic {
            rule_id: String::new(),
            severity: Severity::Info,
            message: String::new(),
            resource: None,
            property_path: None,
            suggested_fix: None,
            documentation_url: None,
            category: None,
            location: None,
            related_resources: None,
            condition_scenario: None,
            rule_description: None,
            phase: None,
            section: None,
            context: None,
            source: RuleOrigin::Engine,
        }
    }

    #[test]
    fn parse_diagnostic_minimal_valid() {
        let model = minimal_model();
        let val: serde_json::Value = serde_json::json!({
            "rule_id": "E3012",
            "severity": Severity::Error.as_str(),
            "message": "Type mismatch",
            "resource_id": "Bucket",
            "resource_path": "Properties.BucketName"
        });
        let diag = parse_diagnostic(&val, &model, None).expect("should parse");
        assert_eq!(diag.rule_id, "E3012");
        assert_eq!(diag.severity, Severity::Error);
        assert_eq!(diag.message, "Type mismatch");
        assert_eq!(diag.resource.as_ref().unwrap().id.as_deref(), Some("Bucket"));
        assert_eq!(diag.resource.as_ref().unwrap().resource_type.as_deref(), Some("AWS::S3::Bucket"));
    }

    #[test]
    fn parse_diagnostic_missing_rule_id_returns_error() {
        let model = minimal_model();
        let val = serde_json::json!({"severity": Severity::Error.as_str(), "message": "x"});
        parse_diagnostic(&val, &model, None).unwrap_err();
    }

    #[test]
    fn parse_diagnostic_missing_severity_returns_error() {
        let model = minimal_model();
        let val = serde_json::json!({"rule_id": "E3012", "message": "x"});
        parse_diagnostic(&val, &model, None).unwrap_err();
    }

    #[test]
    fn parse_diagnostic_missing_message_returns_error() {
        let model = minimal_model();
        let val = serde_json::json!({"rule_id": "E3012", "severity": Severity::Error.as_str()});
        parse_diagnostic(&val, &model, None).unwrap_err();
    }

    #[test]
    fn parse_diagnostic_fatal_prefix_overrides_severity() {
        let model = minimal_model();
        let val = serde_json::json!({
            "rule_id": "F3012",
            "severity": Severity::Error.as_str(),
            "message": "type mismatch"
        });
        let diag = parse_diagnostic(&val, &model, None).unwrap();
        assert_eq!(diag.severity, Severity::Fatal);
    }

    #[test]
    fn parse_diagnostic_warning_severity() {
        let model = minimal_model();
        let val = serde_json::json!({
            "rule_id": "W3045",
            "severity": Severity::Warn.as_str(),
            "message": "warn"
        });
        let diag = parse_diagnostic(&val, &model, None).unwrap();
        assert_eq!(diag.severity, Severity::Warn);
    }

    #[test]
    fn parse_diagnostic_with_suggested_fix_and_doc_url() {
        let model = minimal_model();
        let val = serde_json::json!({
            "rule_id": "E3012",
            "severity": Severity::Error.as_str(),
            "message": "bad",
            "suggested_fix": "fix it",
            "documentation_url": "https://example.com"
        });
        let diag = parse_diagnostic(&val, &model, None).unwrap();
        assert_eq!(diag.suggested_fix.as_deref(), Some("fix it"));
        assert_eq!(diag.documentation_url.as_deref(), Some("https://example.com"));
    }

    #[test]
    fn parse_diagnostic_empty_resource_id_treated_as_none() {
        let model = minimal_model();
        let val = serde_json::json!({
            "rule_id": "E3012",
            "severity": Severity::Error.as_str(),
            "message": "x",
            "resource_id": ""
        });
        let diag = parse_diagnostic(&val, &model, None).unwrap();
        assert!(diag.resource.is_none(), "diagnostic without resource_id should have no resource");
    }

    #[test]
    fn parse_diagnostic_with_explicit_start_line_column() {
        let model = minimal_model();
        let val = serde_json::json!({
            "rule_id": "E3012",
            "severity": Severity::Error.as_str(),
            "message": "x",
            "start_line": 42,
            "start_column": 7
        });
        let diag = parse_diagnostic(&val, &model, None).unwrap();
        assert_eq!(diag.location.as_ref().unwrap().start_line, 42);
        assert_eq!(diag.location.as_ref().unwrap().start_column, 7);
    }

    #[test]
    fn parse_diagnostic_unknown_rule_uses_json_category() {
        let model = minimal_model();
        let val = serde_json::json!({
            "rule_id": "XUNKNOWN",
            "severity": Severity::Error.as_str(),
            "message": "x",
            "category": "my-category"
        });
        let diag = parse_diagnostic(&val, &model, Some(&RuleOrigin::Custom)).unwrap();
        assert_eq!(diag.category.as_deref(), Some("my-category"));
    }

    #[test]
    fn parse_diagnostic_builtin_rule_ignores_json_category_and_uses_registry() {
        let model = minimal_model();
        let val = serde_json::json!({
            "rule_id": "E3012",
            "severity": Severity::Error.as_str(),
            "message": "x",
            "category": "general"
        });
        let diag = parse_diagnostic(&val, &model, None).unwrap();
        let expected = lookup_rule("E3012").unwrap().category.as_str();
        assert_eq!(
            diag.category.as_deref(),
            Some(expected),
            "a built-in rule takes its category from the registry, ignoring any category in the engine JSON"
        );
    }

    #[test]
    fn parse_diagnostic_with_related_locations() {
        let model = minimal_model();
        let val = serde_json::json!({
            "rule_id": "E3012",
            "severity": Severity::Error.as_str(),
            "message": "x",
            "related_locations": [{
                "resource_id": "Bucket",
                "start_line": 1,
                "start_column": 2,
                "end_line": 3,
                "end_column": 4,
                "message": "related"
            }]
        });
        let diag = parse_diagnostic(&val, &model, None).unwrap();
        assert_eq!(diag.related_resources.as_ref().unwrap().len(), 1);
        assert_eq!(diag.related_resources.as_ref().unwrap()[0].message, "related");
    }

    #[test]
    fn parse_diagnostic_with_condition_scenario() {
        let model = minimal_model();
        let val = serde_json::json!({
            "rule_id": "E3012",
            "severity": Severity::Error.as_str(),
            "message": "x",
            "condition_scenario": {"IsProd": true}
        });
        let diag = parse_diagnostic(&val, &model, None).unwrap();
        let scenario = diag.condition_scenario.unwrap();
        assert_eq!(scenario.get("IsProd"), Some(&true));
    }

    #[test]
    fn extract_diagnostics_valid_array() {
        let model = minimal_model();
        let json = serde_json::json!([
            {"rule_id": "E3012", "severity": Severity::Error.as_str(), "message": "a"},
            {"rule_id": "W3045", "severity": Severity::Warn.as_str(), "message": "b"}
        ]);
        let mut out = Vec::new();
        extract_diagnostics(&json.to_string(), &model, &mut out, None).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].rule_id, "E3012");
        assert_eq!(out[1].rule_id, "W3045");
    }

    #[test]
    fn extract_diagnostics_invalid_json_is_error() {
        let model = minimal_model();
        let mut out = Vec::new();
        let result = extract_diagnostics("not json", &model, &mut out, None);
        result.unwrap_err();
    }

    #[test]
    fn extract_diagnostics_non_array_json_is_error() {
        let model = minimal_model();
        let mut out = Vec::new();
        let result = extract_diagnostics(r#"{"key": "value"}"#, &model, &mut out, None);
        result.unwrap_err();
    }

    #[test]
    fn extract_diagnostics_fails_on_missing_required_fields() {
        let model = minimal_model();
        let json = serde_json::json!([
            {"rule_id": "E3012", "severity": Severity::Error.as_str(), "message": "ok"},
            {"bad": "item"},
            {"rule_id": "W3045", "severity": Severity::Warn.as_str(), "message": "ok2"}
        ]);
        let mut out = Vec::new();
        let result = extract_diagnostics(&json.to_string(), &model, &mut out, None);
        result.unwrap_err();
        assert_eq!(out.len(), 1, "first valid item should have been added before failure");
    }

    #[test]
    fn build_report_counts_severities() {
        let model = minimal_model();
        let diags = vec![
            Diagnostic {
                rule_id: "F3012".into(),
                severity: Severity::Fatal,
                message: "fatal".into(),
                ..default_diag()
            },
            Diagnostic {
                rule_id: "E3012".into(),
                severity: Severity::Error,
                message: "error".into(),
                ..default_diag()
            },
            Diagnostic {
                rule_id: "E3013".into(),
                severity: Severity::Error,
                message: "error2".into(),
                ..default_diag()
            },
            Diagnostic { rule_id: "W3045".into(), severity: Severity::Warn, message: "warn".into(), ..default_diag() },
            Diagnostic { severity: Severity::Info, message: "info".into(), ..default_diag() },
        ];
        let report = build_report(diags, &model, 3, Some(50), false, Severity::Info, String::new());
        assert_eq!(report.metadata.counts.fatal, 1);
        assert_eq!(report.metadata.counts.errors, 2);
        assert_eq!(report.metadata.counts.warnings, 1);
        assert_eq!(report.metadata.counts.informational, 1);
        assert_eq!(report.metadata.suppressed, 3);
        assert_eq!(report.metadata.rules_evaluated, Some(50));
        assert!(!report.metadata.strict, "default mode should not be strict");
        assert_eq!(report.metadata.severity_level, Severity::Info);
        assert_eq!(report.metadata.resources_scanned, 1);
        assert_eq!(report.diagnostics.len(), 5);
    }

    #[test]
    fn build_report_empty_diagnostics() {
        let model = minimal_model();
        let report = build_report(vec![], &model, 0, None, true, Severity::Error, String::new());
        assert_eq!(report.metadata.counts.fatal, 0);
        assert_eq!(report.metadata.counts.errors, 0);
        assert_eq!(report.metadata.counts.warnings, 0);
        assert!(report.metadata.strict, "strict mode should be enabled");
        assert_eq!(report.metadata.severity_level, Severity::Error);
        assert!(report.diagnostics.is_empty());
    }

    #[test]
    fn build_report_debug_severity_counted() {
        let model = minimal_model();
        let diags = vec![Diagnostic { severity: Severity::Debug, message: "dbg".into(), ..default_diag() }];
        let report = build_report(diags, &model, 0, None, false, Severity::Debug, String::new());
        assert_eq!(report.metadata.counts.debug, 1);
        assert_eq!(report.metadata.counts.informational, 0);
    }

    #[test]
    fn build_rule_list_sorted_by_id() {
        let mut meta = HashMap::new();
        meta.insert(
            "E3012".into(),
            RuleMetadataEntry {
                category: Some("schema".into()),
                description: "Type check".into(),
                severity: Severity::Error,
                origin: RuleOrigin::Engine,
            },
        );
        meta.insert(
            "E0001".into(),
            RuleMetadataEntry {
                category: Some("structure".into()),
                description: "Resources".into(),
                severity: Severity::Error,
                origin: RuleOrigin::Engine,
            },
        );
        meta.insert(
            "W3045".into(),
            RuleMetadataEntry {
                category: Some("schema".into()),
                description: "Enum".into(),
                severity: Severity::Warn,
                origin: RuleOrigin::Engine,
            },
        );
        let rules = build_rule_list(&meta, &HashMap::new());
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].id, "E0001");
        assert_eq!(rules[1].id, "E3012");
        assert_eq!(rules[2].id, "W3045");
    }

    #[test]
    fn build_rule_list_uses_stored_severity() {
        let mut meta = HashMap::new();
        meta.insert(
            "F3012".into(),
            RuleMetadataEntry {
                category: Some("schema".into()),
                description: "desc".into(),
                severity: Severity::Fatal,
                origin: RuleOrigin::Engine,
            },
        );
        meta.insert(
            "E3012".into(),
            RuleMetadataEntry {
                category: Some("schema".into()),
                description: "desc".into(),
                severity: Severity::Error,
                origin: RuleOrigin::Engine,
            },
        );
        meta.insert(
            "W3045".into(),
            RuleMetadataEntry {
                category: Some("schema".into()),
                description: "desc".into(),
                severity: Severity::Warn,
                origin: RuleOrigin::Engine,
            },
        );
        meta.insert(
            "I9001".into(),
            RuleMetadataEntry {
                category: Some("best-practice".into()),
                description: "desc".into(),
                severity: Severity::Info,
                origin: RuleOrigin::Engine,
            },
        );
        let rules = build_rule_list(&meta, &HashMap::new());
        let find = |id: &str| rules.iter().find(|r| r.id == id).unwrap();
        assert_eq!(find("F3012").severity, Severity::Fatal);
        assert_eq!(find("E3012").severity, Severity::Error);
        assert_eq!(find("W3045").severity, Severity::Warn);
        assert_eq!(find("I9001").severity, Severity::Info);
    }

    #[test]
    fn build_rule_list_schema_category_gets_schema_origin() {
        let mut meta = HashMap::new();
        meta.insert(
            "E3012".into(),
            RuleMetadataEntry {
                category: Some("schema".into()),
                description: "desc".into(),
                severity: Severity::Error,
                origin: RuleOrigin::Schema,
            },
        );
        meta.insert(
            "E0001".into(),
            RuleMetadataEntry {
                category: Some("structure".into()),
                description: "desc".into(),
                severity: Severity::Error,
                origin: RuleOrigin::Engine,
            },
        );
        let rules = build_rule_list(&meta, &HashMap::new());
        let schema_rule = rules.iter().find(|r| r.id == "E3012").unwrap();
        assert!(matches!(schema_rule.origin, RuleOrigin::Schema));
        let struct_rule = rules.iter().find(|r| r.id == "E0001").unwrap();
        assert!(matches!(struct_rule.origin, RuleOrigin::Engine));
    }

    fn make_diag(rule_id: &str, severity: Severity, line: u32, col: u32) -> Diagnostic {
        Diagnostic {
            rule_id: rule_id.into(),
            severity,
            message: format!("msg for {}", rule_id),
            location: Some(SourceSpan { start_line: line, start_column: col, end_line: line, end_column: col }),
            ..default_diag()
        }
    }

    fn make_transform_error_diag() -> Diagnostic {
        Diagnostic {
            message: format!(
                "{} Resource with id [Fn] is invalid. 'AutoPublishAlias' must be a string or a Ref to a template parameter",
                diagnostics::SAM_TRANSFORM_ERROR_PREFIX
            ),
            ..make_diag(diagnostics::SAM_TRANSFORM_ERROR_RULE_ID, Severity::Error, 1, 1)
        }
    }

    #[test]
    fn gate_drops_non_transform_diagnostics_when_transform_error_present() {
        let mut diags = vec![
            make_diag("E3012", Severity::Error, 5, 1),
            make_transform_error_diag(),
            make_diag("I9040", Severity::Info, 7, 1),
        ];
        gate_sam_transform_errors(&mut diags);
        assert_eq!(diags.len(), 1);
        assert!(is_sam_transform_error_message(&diags[0].message));
    }

    #[test]
    fn gate_keeps_all_diagnostics_when_no_transform_error() {
        let mut diags = vec![make_diag("E3012", Severity::Error, 5, 1), make_diag("I9040", Severity::Info, 7, 1)];
        gate_sam_transform_errors(&mut diags);
        assert_eq!(diags.len(), 2);
    }

    #[test]
    fn finalize_sorts_by_location_then_severity() {
        let config = ValidateConfig::default();
        let mut diags = vec![
            make_diag("W3045", Severity::Warn, 10, 1),
            make_diag("E3012", Severity::Error, 5, 1),
            make_diag("F3012", Severity::Fatal, 5, 1),
        ];
        finalize_diagnostics(&mut diags, &config, &HashMap::new());
        assert_eq!(diags.len(), 3);
        assert_eq!(diags[0].rule_id, "F3012");
        assert_eq!(diags[1].rule_id, "E3012");
        assert_eq!(diags[2].location.as_ref().unwrap().start_line, 10);
    }

    #[test]
    fn finalize_deduplicates_same_span_rule_message() {
        let config = ValidateConfig::default();
        let d = make_diag("E3012", Severity::Error, 5, 1);
        let mut diags = vec![d.clone(), d];
        let (total_before, suppressed) = finalize_diagnostics(&mut diags, &config, &HashMap::new());
        assert_eq!(total_before, 2);
        assert_eq!(suppressed, 1);
        assert_eq!(diags.len(), 1);
    }

    #[test]
    fn finalize_keeps_f_and_e_as_separate_diagnostics() {
        let config = ValidateConfig::default();
        let mut diags = vec![make_diag("F3012", Severity::Fatal, 5, 1), make_diag("E3012", Severity::Error, 5, 1)];
        let (_, suppressed) = finalize_diagnostics(&mut diags, &config, &HashMap::new());
        assert_eq!(suppressed, 0);
        assert_eq!(diags.len(), 2);
        assert_eq!(diags[0].rule_id, "F3012");
        assert_eq!(diags[1].rule_id, "E3012");
    }

    #[test]
    fn finalize_severity_filter_retains_fatal_always() {
        let config = ValidateConfig { severity_level: Severity::Error, strict: false, ..Default::default() };
        let mut diags = vec![
            make_diag("F3012", Severity::Fatal, 1, 1),
            make_diag("E3012", Severity::Error, 2, 1),
            make_diag("W3045", Severity::Warn, 3, 1),
            Diagnostic { severity: Severity::Info, message: "info".into(), location: None, ..default_diag() },
        ];
        finalize_diagnostics(&mut diags, &config, &HashMap::new());
        assert!(
            diags.iter().all(|d| d.severity >= Severity::Error),
            "all diagnostics should be Error or above after filtering"
        );
        assert_eq!(diags.len(), 2);
    }

    #[test]
    fn finalize_different_messages_not_deduped() {
        let config = ValidateConfig::default();
        let mut d1 = make_diag("E3012", Severity::Error, 5, 1);
        let mut d2 = make_diag("E3012", Severity::Error, 5, 1);
        d1.message = "message A".into();
        d2.message = "message B".into();
        let mut diags = vec![d1, d2];
        finalize_diagnostics(&mut diags, &config, &HashMap::new());
        assert_eq!(diags.len(), 2);
    }

    /// Regression for the CEL WASM-vs-native parity bug.
    ///
    /// Two diagnostics for rule X message M at the same line/col, separated by a sibling
    /// for the same rule but a different message M', must still be deduped. Before the fix
    /// the sort key was (line, col, severity, rule_id) which treated all three as equal;
    /// stable sort preserved insertion order [M, M', M] and `dedup_by` (consecutive-only)
    /// skipped the outer pair. HashMap iteration order means insertion order is random,
    /// so the dedup worked or failed per-process — native fired twice, WASM once.
    #[test]
    fn finalize_dedups_same_rule_message_across_sibling_with_different_message() {
        let config = ValidateConfig::default();
        let mut a1 = make_diag("W2506", Severity::Warn, 125, 1);
        let mut sib = make_diag("W2506", Severity::Warn, 125, 1);
        let mut a2 = make_diag("W2506", Severity::Warn, 125, 1);
        a1.message = "param pWebServerAMI".into();
        sib.message = "param pAppAmi".into();
        a2.message = "param pWebServerAMI".into();
        let mut diags = vec![a1, sib, a2];
        finalize_diagnostics(&mut diags, &config, &HashMap::new());
        assert_eq!(diags.len(), 2, "W2506 pWebServerAMI must dedup across sibling");
        let msgs: Vec<&str> = diags.iter().map(|d| d.message.as_str()).collect();
        assert!(msgs.contains(&"param pAppAmi"));
        assert!(msgs.contains(&"param pWebServerAMI"));
    }

    #[test]
    fn finalize_strict_upgrades_warnings_to_errors() {
        let config = ValidateConfig { strict: true, ..Default::default() };
        let mut diags = vec![
            make_diag("W3045", Severity::Warn, 1, 1),
            make_diag("E3012", Severity::Error, 2, 1),
            make_diag("F3012", Severity::Fatal, 3, 1),
        ];
        finalize_diagnostics(&mut diags, &config, &HashMap::new());
        assert_eq!(diags[0].severity, Severity::Error, "Warn should be upgraded to Error");
        assert_eq!(diags[1].severity, Severity::Error, "Error should stay Error");
        assert_eq!(diags[2].severity, Severity::Fatal, "Fatal should stay Fatal");
    }

    #[test]
    fn finalize_non_strict_preserves_warning_severity() {
        let config = ValidateConfig { strict: false, ..Default::default() };
        let mut diags = vec![make_diag("W3045", Severity::Warn, 1, 1), make_diag("E3012", Severity::Error, 2, 1)];
        finalize_diagnostics(&mut diags, &config, &HashMap::new());
        assert_eq!(diags[0].severity, Severity::Warn, "Warn should be preserved");
        assert_eq!(diags[1].severity, Severity::Error, "Error should stay Error");
    }

    #[test]
    fn finalize_exclude_engine_rules_drops_engine_origin_only() {
        let mut meta = HashMap::new();
        meta.insert(
            "E9001".into(),
            RuleMetadataEntry {
                category: Some("custom".into()),
                description: "engine rule".into(),
                severity: Severity::Error,
                origin: RuleOrigin::Engine,
            },
        );
        meta.insert(
            "E3012".into(),
            RuleMetadataEntry {
                category: Some("schema".into()),
                description: "Schema validation rule".into(),
                severity: Severity::Error,
                origin: RuleOrigin::CfnLint,
            },
        );
        let config = ValidateConfig { include_engine_rules: false, ..Default::default() };
        let mut diags = vec![make_diag("E9001", Severity::Error, 1, 1), make_diag("E3012", Severity::Error, 2, 1)];
        finalize_diagnostics(&mut diags, &config, &meta);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].rule_id, "E3012");
    }

    #[test]
    fn finalize_include_engine_rules_keeps_all() {
        let mut meta = HashMap::new();
        meta.insert(
            "E9001".into(),
            RuleMetadataEntry {
                category: Some("custom".into()),
                description: "engine rule".into(),
                severity: Severity::Error,
                origin: RuleOrigin::Engine,
            },
        );
        let config = ValidateConfig::default();
        let mut diags = vec![make_diag("E9001", Severity::Error, 1, 1)];
        finalize_diagnostics(&mut diags, &config, &meta);
        assert_eq!(diags.len(), 1);
    }

    #[test]
    fn enrich_adds_phase_and_description() {
        let model = minimal_model();
        let meta = meta_map();
        let mut diags = vec![Diagnostic {
            rule_id: "E3012".into(),
            severity: Severity::Error,
            message: "x".into(),
            resource: Some(ResourceRef { id: Some("Bucket".into()), resource_type: Some("AWS::S3::Bucket".into()) }),
            category: Some(Category::Schema.as_str().into()),
            ..default_diag()
        }];
        enrich_diagnostics(&mut diags, &model, &meta, &HashMap::new(), &DetailLevel::Detailed);
        assert_eq!(diags[0].phase, Some(Phase::Lint));
        assert!(diags[0].rule_description.is_some(), "enriched diagnostic should have rule_description");
    }

    #[test]
    fn enrich_parse_category_gets_parse_phase() {
        let model = minimal_model();
        let meta = meta_map();
        let mut diags = vec![Diagnostic {
            rule_id: "F0000".into(),
            severity: Severity::Fatal,
            message: "dup".into(),
            category: Some(Category::Structure.as_str().into()),
            phase: Some(Phase::Parse),
            ..default_diag()
        }];
        enrich_diagnostics(&mut diags, &model, &meta, &HashMap::new(), &DetailLevel::Detailed);
        assert_eq!(diags[0].phase, Some(Phase::Parse));
    }

    #[test]
    fn enrich_fatal_rule_gets_schema_phase() {
        let model = minimal_model();
        let meta = meta_map();
        let mut diags = vec![Diagnostic {
            rule_id: "F3012".into(),
            severity: Severity::Fatal,
            message: "x".into(),
            ..default_diag()
        }];
        enrich_diagnostics(&mut diags, &model, &meta, &HashMap::new(), &DetailLevel::Detailed);
        assert_eq!(diags[0].phase, Some(Phase::Schema));
    }

    #[test]
    fn enrich_full_format_builds_context() {
        let model = minimal_model();
        let meta = meta_map();
        let mut diags = vec![Diagnostic {
            rule_id: "E3012".into(),
            severity: Severity::Error,
            message: "x".into(),
            resource: Some(ResourceRef { id: Some("Bucket".into()), resource_type: Some("AWS::S3::Bucket".into()) }),
            property_path: Some("Properties.BucketName".into()),
            ..default_diag()
        }];
        enrich_diagnostics(&mut diags, &model, &meta, &HashMap::new(), &DetailLevel::Detailed);
        assert!(diags[0].context.is_some(), "enriched diagnostic should have context");
    }

    #[test]
    fn enrich_standard_format_skips_enrichment() {
        let model = minimal_model();
        let meta = meta_map();
        let mut diags = vec![Diagnostic {
            rule_id: "E3012".into(),
            severity: Severity::Error,
            message: "x".into(),
            resource: Some(ResourceRef { id: Some("Bucket".into()), resource_type: Some("AWS::S3::Bucket".into()) }),
            property_path: Some("Properties.BucketName".into()),
            ..default_diag()
        }];
        enrich_diagnostics(&mut diags, &model, &meta, &HashMap::new(), &DetailLevel::Standard);
        assert!(diags[0].phase.is_none(), "unenriched diagnostic should have no phase");
        assert!(diags[0].rule_description.is_none(), "unenriched diagnostic should have no rule_description");
        assert!(diags[0].section.is_none(), "unenriched diagnostic should have no section");
        assert!(diags[0].context.is_none(), "unenriched diagnostic should have no context");
    }

    #[test]
    fn make_resource_diagnostic_known_rule() {
        let model = minimal_model();
        let diag = make_resource_diagnostic(
            "E3012",
            "Type mismatch on BucketName",
            &model,
            "Bucket",
            "Properties.BucketName",
            Some("Use a string"),
        );
        assert_eq!(diag.rule_id, "E3012");
        assert_eq!(diag.severity, Severity::Error);
        assert_eq!(diag.resource.as_ref().unwrap().id.as_deref(), Some("Bucket"));
        assert_eq!(diag.suggested_fix.as_deref(), Some("Use a string"));
    }

    #[test]
    #[should_panic(expected = "Rule 'XBOGUS' not found in RULE_REGISTRY")]
    fn make_resource_diagnostic_unknown_rule_panics() {
        let model = minimal_model();
        make_resource_diagnostic("XBOGUS", "msg", &model, "Bucket", "", None);
    }

    #[test]
    fn make_resource_diagnostic_empty_resource_id() {
        let model = minimal_model();
        let diag = make_resource_diagnostic("E3012", "msg", &model, "", "", None);
        assert!(diag.resource.is_none(), "diagnostic without resource_id should have no resource");
    }

    #[test]
    fn build_context_no_resource_returns_none() {
        let model = minimal_model();
        assert!(build_context("E3012", None, "Properties.X", &model).is_none(), "no resource should return None");
    }

    #[test]
    fn build_context_unknown_rule_returns_none() {
        let model = minimal_model();
        assert!(
            build_context("XUNKNOWN", Some("Bucket"), "Properties.X", &model).is_none(),
            "unknown rule should return None"
        );
    }

    #[test]
    fn build_context_e3012_with_property_path() {
        let model = minimal_model();
        let ctx = build_context("E3012", Some("Bucket"), "Properties.BucketName", &model)
            .expect("E3012 with property path should return context");
        assert!(ctx.actual_value.is_some(), "context should have actual_value");
    }

    #[test]
    fn build_context_e3012_empty_path_returns_none() {
        let model = minimal_model();
        let ctx = build_context("E3012", Some("Bucket"), "", &model);
        assert!(ctx.is_none(), "E3012 with empty path should return None");
    }

    #[test]
    fn build_context_f3002_extracts_property_name() {
        let model = minimal_model();
        let ctx = build_context("F3002", Some("Bucket"), "Properties.BucketName", &model)
            .expect("F3002 should return context");
        assert_eq!(ctx.property.as_deref(), Some("BucketName"));
    }

    #[test]
    fn build_context_w3042_sets_deprecated_lifecycle() {
        let model = minimal_model();
        let ctx = build_context("W9009", Some("Bucket"), "", &model).expect("W9009 should return context");
        assert_eq!(ctx.lifecycle.as_deref(), Some("deprecated"));
    }

    #[test]
    fn build_context_i3043_sets_create_only_lifecycle() {
        let model = minimal_model();
        let ctx = build_context("I9001", Some("Bucket"), "", &model).expect("I9001 should return context");
        assert_eq!(ctx.lifecycle.as_deref(), Some("create-only"));
    }

    #[test]
    fn build_context_w3041_sets_write_only_lifecycle() {
        let model = minimal_model();
        let ctx = build_context("W3041", Some("Bucket"), "", &model).expect("W3041 should return context");
        assert_eq!(ctx.lifecycle.as_deref(), Some("write-only"));
    }

    #[test]
    fn parse_diagnostic_debug_severity() {
        let model = minimal_model();
        let val = serde_json::json!({
            "rule_id": "D9999",
            "severity": Severity::Debug.as_str(),
            "message": "dbg"
        });
        let diag = parse_diagnostic(&val, &model, Some(&RuleOrigin::Custom)).unwrap();
        assert_eq!(diag.severity, Severity::Debug);
    }

    #[test]
    fn parse_diagnostic_no_resource_no_location_resolves_via_section_span() {
        let model = minimal_model();
        let val = serde_json::json!({
            "rule_id": "F0001",
            "severity": Severity::Fatal.as_str(),
            "message": "no resources"
        });
        let diag = parse_diagnostic(&val, &model, None).unwrap();
        assert_eq!(diag.rule_id, "F0001");
    }

    #[test]
    fn parse_diagnostic_builtin_rule_category_comes_from_registry() {
        let model = minimal_model();
        let val = serde_json::json!({
            "rule_id": "E3012",
            "severity": Severity::Error.as_str(),
            "message": "x"
        });
        let diag = parse_diagnostic(&val, &model, None).unwrap();
        let expected = lookup_rule("E3012").unwrap().category.as_str();
        assert_eq!(diag.category.as_deref(), Some(expected));
    }

    #[test]
    fn build_context_e3030_resolves_actual_value() {
        let model = minimal_model();
        let ctx = build_context("E3030", Some("Bucket"), "Properties.BucketName", &model)
            .expect("E3030 should return context");
        assert!(ctx.actual_value.is_some(), "E3030 context should have actual_value");
    }

    #[test]
    fn build_context_e3037_adds_resource_type() {
        let model = minimal_model();
        let ctx = build_context("E9001", Some("Bucket"), "", &model).expect("E9001 should return context");
        let extra = ctx.extra.unwrap();
        assert_eq!(extra.get("resource_type").and_then(|v| v.as_str()), Some("AWS::S3::Bucket"));
    }

    #[test]
    fn build_context_f3003_noop_returns_none() {
        let model = minimal_model();
        assert!(build_context("F3003", Some("Bucket"), "", &model).is_none(), "F3003 should return None");
    }

    #[test]
    fn build_context_e3053_with_property_path() {
        let model = minimal_model();
        let ctx = build_context("E3053", Some("Bucket"), "Properties.BucketName", &model)
            .expect("E3053 should return context");
        assert!(ctx.actual_value.is_some(), "E3053 context should have actual_value");
    }

    #[test]
    fn build_context_e3053_empty_path_returns_none() {
        let model = minimal_model();
        assert!(
            build_context("E3053", Some("Bucket"), "", &model).is_none(),
            "E3053 with empty path should return None"
        );
    }

    #[test]
    fn build_context_e2501_with_condition() {
        let yaml = br#"
AWSTemplateFormatVersion: "2010-09-09"
Conditions:
  IsProd:
    !Equals [!Ref "AWS::Region", "us-east-1"]
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Condition: IsProd
"#;
        let model = SemanticModel::from_bytes(yaml).expect("model with condition");
        let ctx =
            build_context("W2503", Some("Bucket"), "", &model).expect("W2503 with condition should return context");
        let extra = ctx.extra.unwrap();
        assert!(extra.contains_key("source_condition"));
    }

    #[test]
    fn build_context_e2501_without_condition_returns_none() {
        let model = minimal_model();
        assert!(
            build_context("W2503", Some("Bucket"), "", &model).is_none(),
            "W2503 without condition should return None"
        );
    }

    #[test]
    fn enrich_preserves_existing_section_phase_description() {
        let model = minimal_model();
        let meta = meta_map();
        let mut diags = vec![Diagnostic {
            rule_id: "E3012".into(),
            severity: Severity::Error,
            message: "x".into(),
            section: Some("CustomSection".into()),
            phase: Some(Phase::Lint),
            rule_description: Some("custom desc".into()),
            ..default_diag()
        }];
        enrich_diagnostics(&mut diags, &model, &meta, &HashMap::new(), &DetailLevel::Standard);
        assert_eq!(diags[0].section.as_deref(), Some("CustomSection"));
        assert_eq!(diags[0].phase, Some(Phase::Lint));
        assert_eq!(diags[0].rule_description.as_deref(), Some("custom desc"));
    }

    #[test]
    fn finalize_warning_level_filters_info() {
        let config = ValidateConfig { severity_level: Severity::Warn, ..Default::default() };
        let mut diags = vec![
            make_diag("F3012", Severity::Fatal, 1, 1),
            make_diag("E3012", Severity::Error, 2, 1),
            make_diag("W3045", Severity::Warn, 3, 1),
            Diagnostic { severity: Severity::Info, message: "info".into(), location: None, ..default_diag() },
        ];
        finalize_diagnostics(&mut diags, &config, &HashMap::new());
        assert!(
            diags.iter().all(|d| d.severity >= Severity::Warn),
            "all diagnostics should be Warn or above after filtering"
        );
        assert_eq!(diags.len(), 3);
    }

    #[test]
    fn finalize_different_property_paths_not_deduped() {
        let config = ValidateConfig::default();
        let mut d1 = make_diag("E3012", Severity::Error, 5, 1);
        let mut d2 = make_diag("E3012", Severity::Error, 5, 1);
        d1.property_path = Some("Properties.A".into());
        d2.property_path = Some("Properties.B".into());
        let mut diags = vec![d1, d2];
        finalize_diagnostics(&mut diags, &config, &HashMap::new());
        assert_eq!(diags.len(), 2);
    }

    #[test]
    fn build_rule_list_uses_stored_severity_for_any_rule_id() {
        let mut meta = HashMap::new();
        meta.insert(
            "X9999".into(),
            RuleMetadataEntry {
                category: Some("custom".into()),
                description: "desc".into(),
                severity: Severity::Error,
                origin: RuleOrigin::Engine,
            },
        );
        let rules = build_rule_list(&meta, &HashMap::new());
        assert_eq!(rules[0].severity, Severity::Error);
    }

    #[test]
    fn engine_type_default_is_rego() {
        assert_eq!(EngineType::default(), EngineType::Rego);
    }

    #[test]
    fn engine_type_as_str_returns_lowercase() {
        assert_eq!(EngineType::Rego.as_str(), "Rego");
        assert_eq!(EngineType::Cel.as_str(), "CEL");
    }

    #[test]
    fn engine_type_parse_accepts_case_insensitive_input() {
        assert_eq!(EngineType::parse("rego"), Ok(EngineType::Rego));
        assert_eq!(EngineType::parse("REGO"), Ok(EngineType::Rego));
        assert_eq!(EngineType::parse("Cel"), Ok(EngineType::Cel));
        assert_eq!(EngineType::parse("CEL"), Ok(EngineType::Cel));
    }

    #[test]
    fn engine_type_parse_returns_error_for_unknown_value() {
        let error =
            EngineType::parse("unknown").expect_err("an unknown engine selector must return an error, not a default");
        assert!(
            error.contains("Unknown engine type 'unknown'") && error.contains("rego"),
            "the error must name the bad selector and the valid options, got: {error}"
        );
    }

    #[test]
    fn validate_catching_panics_converts_panic_to_structured_error() {
        let error = validate_catching_panics(|| panic!("simulated invariant violation"))
            .expect_err("a panic must be converted into a structured error, not propagated");
        match error {
            ValidationError::Engine(message) => assert!(
                message.contains("Internal validation error") && message.contains("simulated invariant violation"),
                "error must wrap the panic payload as a structured engine error, got: {message}"
            ),
            other => panic!("expected ValidationError::Engine, got {other:?}"),
        }
    }

    #[test]
    fn validate_catching_panics_passes_success_through_unchanged() {
        let model = minimal_model();
        let report = validate_catching_panics(|| {
            Ok(build_report(vec![], &model, 0, Some(7), false, Severity::Info, "inline".to_string()))
        })
        .expect("a non-panicking Ok result must pass through the guard unchanged");
        assert_eq!(report.metadata.rules_evaluated, Some(7), "the guard must return the closure's report verbatim");
    }

    /// A test engine that fails on demand, to prove that engine failures surface
    /// as errors (exceptions) and are never absorbed into the diagnostics list.
    enum Explosion {
        Panic,
        ReturnErr,
    }

    struct ExplodingEngine {
        mode: Explosion,
        metadata: HashMap<String, RuleMetadataEntry>,
        metric: PhaseMetric,
    }

    impl ExplodingEngine {
        fn new(mode: Explosion) -> Self {
            Self { mode, metadata: HashMap::new(), metric: PhaseMetric { duration_ms: 0.0 } }
        }
    }

    impl ValidationEngine for ExplodingEngine {
        fn engine_name(&self) -> &str {
            "exploding-test-engine"
        }

        fn evaluate_rules(
            &self,
            _model: &Arc<SemanticModel>,
            _config: &ValidateConfig,
        ) -> Result<Vec<Diagnostic>, ValidationError> {
            match self.mode {
                Explosion::Panic => panic!("simulated engine invariant violation"),
                Explosion::ReturnErr => Err(ValidationError::Engine("Simulated engine evaluation failure".to_string())),
            }
        }

        fn list_rules(&self) -> Vec<RuleInfo> {
            Vec::new()
        }

        fn rule_metadata(&self) -> &HashMap<String, RuleMetadataEntry> {
            &self.metadata
        }

        fn external_rule_metadata(&self) -> HashMap<String, RuleMetadataEntry> {
            HashMap::new()
        }

        fn init_metric(&self) -> &PhaseMetric {
            &self.metric
        }
    }

    const WELL_FORMED_TEMPLATE: &[u8] = b"Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n";

    #[test]
    fn engine_exception_surfaces_as_error_never_as_diagnostic() {
        let schema_validator = schema_validator::SchemaValidator::new();
        let engine = ExplodingEngine::new(Explosion::ReturnErr);
        let result = validate_bytes_with_path(
            &engine,
            &schema_validator,
            WELL_FORMED_TEMPLATE,
            ValidateConfig::default(),
            "inline".to_string(),
        );
        match result {
            Err(ValidationError::Engine(message)) => assert!(
                message.contains("Simulated engine evaluation failure"),
                "an engine exception must surface verbatim as an error, got: {message}"
            ),
            Ok(report) => panic!(
                "an engine exception must surface as Err, never as an Ok report with \
                 diagnostics; got {} diagnostics",
                report.diagnostics.len()
            ),
            Err(other) => panic!("expected ValidationError::Engine, got {other:?}"),
        }
    }

    #[test]
    fn engine_panic_is_caught_as_error_never_as_diagnostic() {
        let schema_validator = schema_validator::SchemaValidator::new();
        let engine = ExplodingEngine::new(Explosion::Panic);
        let result = validate_catching_panics(|| {
            validate_bytes_with_path(
                &engine,
                &schema_validator,
                WELL_FORMED_TEMPLATE,
                ValidateConfig::default(),
                "inline".to_string(),
            )
        });
        match result {
            Err(ValidationError::Engine(message)) => assert!(
                message.contains("Internal validation error")
                    && message.contains("simulated engine invariant violation"),
                "a panic must surface as a structured internal error, got: {message}"
            ),
            Ok(report) => panic!(
                "a panic must surface as Err, never as an Ok report with diagnostics; got {} \
                 diagnostics",
                report.diagnostics.len()
            ),
            Err(other) => panic!("expected ValidationError::Engine, got {other:?}"),
        }
    }
}
