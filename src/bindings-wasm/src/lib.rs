use cel_engine::CelEngine;
use composite_engine::CompositeEngine;
use diagnostics::DetailLevel;
use rego_engine::RegoEngine;
use rules::{FilterConfig, RuleFilterConfig, Severity};
use schema_validator::{SchemaValidator, SchemaValidatorConfig};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::cell::{Cell, RefCell};
use std::sync::Once;
use template_model::{PseudoParameterOverrides, SemanticModel};
use validation_engine::{
    AwsCliCommand, CompositeEngineConfig, EngineConfig, ValidationEngine, catch_panics, panic_message,
    validate_aws_cli_command, validate_bytes_with_path,
};
use wasm_bindgen::prelude::*;

const SERIALIZER: serde_wasm_bindgen::Serializer = serde_wasm_bindgen::Serializer::json_compatible();

#[wasm_bindgen]
extern "C" {
    /// Host callback told the message of a panic before the instance traps.
    #[wasm_bindgen(typescript_type = "(message: string) => void")]
    pub type PanicListener;

    #[wasm_bindgen(method, catch, js_name = call)]
    fn notify(this: &PanicListener, receiver: &JsValue, message: &str) -> Result<JsValue, JsValue>;
}

thread_local! {
    static PANIC_LISTENER: RefCell<Option<PanicListener>> = const { RefCell::new(None) };
}

static PANIC_HOOK: Once = Once::new();

thread_local! {
    /// Export bodies entered but not yet returned. Nonzero between host calls
    /// means an exception or trap left an export without running its cleanup.
    static ACTIVE_CALLS: Cell<u32> = const { Cell::new(0) };
}

struct CallScope;

impl CallScope {
    fn enter() -> Self {
        ACTIVE_CALLS.with(|calls| calls.set(calls.get().saturating_add(1)));
        CallScope
    }
}

impl Drop for CallScope {
    fn drop(&mut self) {
        ACTIVE_CALLS.with(|calls| calls.set(calls.get().saturating_sub(1)));
    }
}

/// Number of export bodies that were entered and never returned. The host
/// reads it after a failed call to tell a returned error from an interrupted
/// call that left the instance inconsistent.
#[wasm_bindgen(js_name = "activeCalls")]
pub fn active_calls() -> u32 {
    ACTIVE_CALLS.with(Cell::get)
}

/// Runs an export body inside the active-call scope and the panic guard.
fn guarded<T>(operation: impl FnOnce() -> Result<T, JsValue>) -> Result<T, JsValue> {
    let _scope = CallScope::enter();
    catch_panics(operation, wasm_panic_err)
}

#[wasm_bindgen(start)]
pub fn init() {
    PANIC_HOOK.call_once(|| {
        std::panic::set_hook(Box::new(|info| {
            let message = panic_message(info.payload());
            PANIC_LISTENER.with(|slot| {
                if let Ok(slot) = slot.try_borrow()
                    && let Some(listener) = slot.as_ref()
                {
                    let _ = listener.notify(&JsValue::NULL, &message);
                }
            });
            console_error_panic_hook::hook(info);
        }));
    });
    schema_validator::prewarm_embedded_data();
}

/// Registers the host callback that receives panic messages. A panic still
/// traps the instance; the callback only lets the host report why.
#[wasm_bindgen(js_name = "setPanicListener")]
pub fn set_panic_listener(listener: PanicListener) {
    PANIC_LISTENER.with(|slot| *slot.borrow_mut() = Some(listener));
}

fn to_js_err<E: std::fmt::Display>(e: E) -> JsValue {
    JsValue::from_str(&e.to_string())
}

/// Deserializes a host argument inside the export body so a malformed value
/// returns an error instead of throwing out of the generated argument glue,
/// which would skip Rust cleanup and leak the receiver borrow and stack frame.
fn from_js<T: DeserializeOwned>(value: JsValue) -> Result<T, JsValue> {
    serde_wasm_bindgen::from_value(value).map_err(|error| wasm_bindgen::JsError::new(&error.to_string()).into())
}

fn to_js<T: serde::Serialize>(val: &T) -> Result<JsValue, JsValue> {
    val.serialize(&SERIALIZER).map_err(to_js_err)
}

/// Maps a caught panic message to a thrown JS error so an internal panic
/// surfaces to the caller as a catchable exception. Pair with [`catch_panics`]
/// at every WASM entry point that runs engine logic.
fn wasm_panic_err(message: String) -> JsValue {
    JsValue::from_str(&format!("Internal validation error: {message}"))
}

#[derive(Deserialize, Default, tsify::Tsify)]
#[serde(rename_all = "camelCase")]
pub struct ValidateConfig {
    #[serde(default)]
    pub include: RuleFilterConfig,
    #[serde(default)]
    pub exclude: RuleFilterConfig,
    #[serde(default)]
    #[tsify(optional)]
    pub detail_level: Option<DetailLevel>,
    #[serde(default)]
    #[tsify(optional)]
    pub severity_level: Option<Severity>,
    #[serde(default)]
    #[tsify(optional, type = "Record<string, string>")]
    pub parameter_overrides: Option<std::collections::HashMap<String, String>>,
    #[serde(default)]
    #[tsify(optional)]
    pub pseudo_parameter_overrides: Option<PseudoParameterOverrides>,
    #[serde(default)]
    #[tsify(optional)]
    pub strict: Option<bool>,
    #[serde(default)]
    #[tsify(optional)]
    pub disable_builtin_rules: Option<bool>,
}

fn build_core_config(opts: ValidateConfig) -> validation_engine::ValidateConfig {
    let defaults = validation_engine::ValidateConfig::default();
    validation_engine::ValidateConfig {
        filters: FilterConfig::new(opts.include, opts.exclude),
        detail_level: opts.detail_level.unwrap_or(defaults.detail_level),
        severity_level: opts.severity_level.unwrap_or(defaults.severity_level),
        parameter_overrides: opts.parameter_overrides.unwrap_or_default(),
        pseudo_parameter_overrides: opts.pseudo_parameter_overrides.unwrap_or_default(),
        strict: opts.strict.unwrap_or(defaults.strict),
        disable_builtin_rules: opts.disable_builtin_rules.unwrap_or(defaults.disable_builtin_rules),
    }
}

#[derive(serde::Serialize, tsify::Tsify)]
#[serde(rename_all = "camelCase")]
pub struct WasmSchemaValidationResult {
    pub diagnostics: Vec<diagnostics::output::Diagnostic>,
    pub metric: diagnostics::PhaseMetric,
}

#[wasm_bindgen]
pub struct WasmSchemaValidator {
    inner: SchemaValidator,
}

#[wasm_bindgen]
impl WasmSchemaValidator {
    #[wasm_bindgen(constructor)]
    pub fn new(
        #[wasm_bindgen(unchecked_param_type = "SchemaValidatorConfig")] config: JsValue,
    ) -> Result<WasmSchemaValidator, JsValue> {
        guarded(|| {
            let config: SchemaValidatorConfig = from_js(config)?;
            let inner = SchemaValidator::new(config).map_err(to_js_err)?;
            Ok(WasmSchemaValidator { inner })
        })
    }

    #[wasm_bindgen(js_name = "listRules")]
    pub fn list_rules(&self) -> Result<JsValue, JsValue> {
        guarded(|| to_js(&self.inner.list_rules()))
    }

    #[wasm_bindgen(js_name = "schemaCount")]
    pub fn schema_count(&self) -> Result<usize, JsValue> {
        guarded(|| Ok(self.inner.schema_count()))
    }

    pub fn validate(&self, model: &WasmSemanticModel, region: Option<String>) -> Result<JsValue, JsValue> {
        guarded(|| {
            let result = self.inner.validate(&model.model, region.as_deref());
            let diagnostics: Vec<_> = result.diagnostics.iter().map(|d| d.to_report(DetailLevel::Standard)).collect();
            to_js(&WasmSchemaValidationResult { diagnostics, metric: result.metric })
        })
    }
}

macro_rules! wasm_engine {
    ($wrapper:ident, $inner:ty, $config:ty, $config_ts:literal) => {
        #[wasm_bindgen]
        pub struct $wrapper {
            engine: $inner,
            schema_validator: SchemaValidator,
        }

        #[wasm_bindgen]
        impl $wrapper {
            #[wasm_bindgen(constructor)]
            pub fn new(
                #[wasm_bindgen(unchecked_param_type = $config_ts)] config: JsValue,
            ) -> Result<$wrapper, JsValue> {
                guarded(|| {
                    let config: $config = from_js(config)?;
                    let schema_config = config.schema_validator_config.clone().unwrap_or_default();
                    let schema_validator = SchemaValidator::new(schema_config).map_err(to_js_err)?;
                    let engine = <$inner>::new_with_schema_validator(config, &schema_validator).map_err(to_js_err)?;
                    Ok($wrapper { engine, schema_validator })
                })
            }

            #[wasm_bindgen(js_name = "validateTemplate")]
            pub fn validate_template(
                &self,
                template: &[u8],
                #[wasm_bindgen(unchecked_param_type = "ValidateConfig")] options: JsValue,
                file_path: String,
            ) -> Result<JsValue, JsValue> {
                guarded(|| {
                    let config = build_core_config(from_js(options)?);
                    let detail_level = config.detail_level.clone();
                    let report =
                        validate_bytes_with_path(&self.engine, &self.schema_validator, template, config, file_path)
                            .map_err(to_js_err)?;
                    to_js(&report.to_report(detail_level))
                })
            }

            #[wasm_bindgen(js_name = "validateAwsCliCommand")]
            pub fn validate_aws_cli_command(&self, request: JsValue) -> Result<JsValue, JsValue> {
                guarded(|| {
                    let request: AwsCliCommand = serde_wasm_bindgen::from_value(request)
                        .map_err(|error| JsValue::from_str(&format!("invalid AWS CLI command: {error}")))?;
                    let validation =
                        validate_aws_cli_command(&self.engine, &self.schema_validator, &request).map_err(to_js_err)?;
                    to_js(&validation)
                })
            }

            #[wasm_bindgen(js_name = "listRules")]
            pub fn list_rules(&self) -> Result<JsValue, JsValue> {
                guarded(|| to_js(&self.engine.list_rules()))
            }

            #[wasm_bindgen(js_name = "engineName")]
            pub fn engine_name(&self) -> Result<String, JsValue> {
                guarded(|| Ok(self.engine.engine_name().to_string()))
            }
        }
    };
}

wasm_engine!(WasmRegoEngine, RegoEngine, EngineConfig, "EngineConfig");
wasm_engine!(WasmCelEngine, CelEngine, EngineConfig, "EngineConfig");
wasm_engine!(WasmCompositeEngine, CompositeEngine, CompositeEngineConfig, "CompositeEngineConfig");

#[wasm_bindgen]
pub struct WasmSemanticModel {
    model: std::sync::Arc<SemanticModel>,
}

#[wasm_bindgen]
impl WasmSemanticModel {
    pub fn parse(template: &[u8]) -> Result<WasmSemanticModel, JsValue> {
        guarded(|| {
            let result = SemanticModel::parse(template, Default::default()).map_err(to_js_err)?;
            Ok(WasmSemanticModel { model: std::sync::Arc::new(result.model) })
        })
    }

    pub fn resources(&self) -> Result<JsValue, JsValue> {
        guarded(|| to_js(&self.model.resources))
    }
    pub fn parameters(&self) -> Result<JsValue, JsValue> {
        guarded(|| to_js(&self.model.parameters))
    }
    pub fn outputs(&self) -> Result<JsValue, JsValue> {
        guarded(|| to_js(&self.model.outputs))
    }

    pub fn conditions(&self) -> Result<JsValue, JsValue> {
        guarded(|| {
            let names: Vec<&str> = self.model.conditions.names().collect();
            to_js(&names)
        })
    }

    pub fn transforms(&self) -> Result<JsValue, JsValue> {
        guarded(|| to_js(&self.model.transforms))
    }

    #[wasm_bindgen(js_name = "formatVersion")]
    pub fn format_version(&self) -> Result<Option<String>, JsValue> {
        guarded(|| Ok(self.model.format_version.clone()))
    }

    pub fn description(&self) -> Result<Option<String>, JsValue> {
        guarded(|| Ok(self.model.description.clone()))
    }

    #[wasm_bindgen(js_name = "toDiagnosticModel")]
    pub fn to_diagnostic_model(&self) -> Result<JsValue, JsValue> {
        guarded(|| to_js(&self.model.to_diagnostic_json()))
    }

    #[wasm_bindgen(js_name = "sourceLocation")]
    pub fn source_location(&self, path: &str) -> Result<JsValue, JsValue> {
        guarded(|| match self.model.source_location(path) {
            Some(span) => to_js(&span),
            None => Ok(JsValue::NULL),
        })
    }
}

#[wasm_bindgen]
pub fn version() -> Result<String, JsValue> {
    guarded(|| Ok(env!("CARGO_PKG_VERSION").to_string()))
}
