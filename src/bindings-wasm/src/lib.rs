use cel_engine::CelEngine;
use diagnostics::DetailLevel;
use rego_engine::RegoEngine;
use rules::{FilterConfig, RuleFilterConfig, Severity};
use schema_validator::{SchemaValidator, SchemaValidatorConfig};
use serde::Deserialize;
use template_model::{PseudoParameterOverrides, SemanticModel};
use validation_engine::{EngineConfig, ValidationEngine, catch_panics, validate_bytes_with_path};
use wasm_bindgen::prelude::*;

const SERIALIZER: serde_wasm_bindgen::Serializer = serde_wasm_bindgen::Serializer::json_compatible();

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
    schema_validator::prewarm_embedded_data();
}

fn to_js_err<E: std::fmt::Display>(e: E) -> JsValue {
    JsValue::from_str(&e.to_string())
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
#[tsify(from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct ValidateConfig {
    #[serde(default)]
    pub include: RuleFilterConfig,
    #[serde(default)]
    pub exclude: RuleFilterConfig,
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

fn build_core_config(opts: ValidateConfig, detail_level: DetailLevel) -> validation_engine::ValidateConfig {
    let defaults = validation_engine::ValidateConfig::default();
    validation_engine::ValidateConfig {
        filters: FilterConfig::new(opts.include, opts.exclude),
        detail_level,
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
    pub diagnostics: Vec<diagnostics::StandardDiagnostic>,
    pub metric: diagnostics::PhaseMetric,
}

#[wasm_bindgen]
pub struct WasmSchemaValidator {
    inner: SchemaValidator,
}

#[wasm_bindgen]
impl WasmSchemaValidator {
    #[wasm_bindgen(constructor)]
    pub fn new(config: SchemaValidatorConfig) -> Result<WasmSchemaValidator, JsValue> {
        catch_panics(
            || {
                let inner = SchemaValidator::new(config).map_err(to_js_err)?;
                Ok(WasmSchemaValidator { inner })
            },
            wasm_panic_err,
        )
    }

    #[wasm_bindgen(js_name = "listRules")]
    pub fn list_rules(&self) -> Result<JsValue, JsValue> {
        catch_panics(|| to_js(&self.inner.list_rules()), wasm_panic_err)
    }

    #[wasm_bindgen(js_name = "schemaCount")]
    pub fn schema_count(&self) -> usize {
        self.inner.schema_count()
    }

    pub fn validate(&self, model: &WasmSemanticModel, region: Option<String>) -> Result<JsValue, JsValue> {
        catch_panics(
            || {
                let result = self.inner.validate(&model.model, region.as_deref());
                let diagnostics: Vec<_> = result.diagnostics.iter().map(|d| d.to_standard()).collect();
                to_js(&WasmSchemaValidationResult { diagnostics, metric: result.metric })
            },
            wasm_panic_err,
        )
    }
}

macro_rules! wasm_engine {
    ($wrapper:ident, $inner:ty) => {
        #[wasm_bindgen]
        pub struct $wrapper {
            engine: $inner,
            schema_validator: SchemaValidator,
        }

        #[wasm_bindgen]
        impl $wrapper {
            #[wasm_bindgen(constructor)]
            pub fn new(config: EngineConfig) -> Result<$wrapper, JsValue> {
                catch_panics(
                    || {
                        let schema_config = config.schema_validator_config.clone().unwrap_or_default();
                        let schema_validator = SchemaValidator::new(schema_config).map_err(to_js_err)?;
                        let engine =
                            <$inner>::new_with_schema_validator(config, &schema_validator).map_err(to_js_err)?;
                        Ok($wrapper { engine, schema_validator })
                    },
                    wasm_panic_err,
                )
            }

            #[wasm_bindgen(js_name = "validateStandard")]
            pub fn validate_standard(
                &self,
                template: &[u8],
                options: ValidateConfig,
                file_path: String,
            ) -> Result<JsValue, JsValue> {
                catch_panics(
                    || {
                        let config = build_core_config(options, DetailLevel::Standard);
                        let report =
                            validate_bytes_with_path(&self.engine, &self.schema_validator, template, config, file_path)
                                .map_err(to_js_err)?;
                        to_js(&report.to_standard())
                    },
                    wasm_panic_err,
                )
            }

            #[wasm_bindgen(js_name = "validateDetailed")]
            pub fn validate_detailed(
                &self,
                template: &[u8],
                options: ValidateConfig,
                file_path: String,
            ) -> Result<JsValue, JsValue> {
                catch_panics(
                    || {
                        let config = build_core_config(options, DetailLevel::Detailed);
                        let report =
                            validate_bytes_with_path(&self.engine, &self.schema_validator, template, config, file_path)
                                .map_err(to_js_err)?;
                        to_js(&report.to_detailed())
                    },
                    wasm_panic_err,
                )
            }

            #[wasm_bindgen(js_name = "listRules")]
            pub fn list_rules(&self) -> Result<JsValue, JsValue> {
                catch_panics(|| to_js(&self.engine.list_rules()), wasm_panic_err)
            }

            #[wasm_bindgen(js_name = "engineName")]
            pub fn engine_name(&self) -> String {
                self.engine.engine_name().to_string()
            }
        }
    };
}

wasm_engine!(WasmRegoEngine, RegoEngine);
wasm_engine!(WasmCelEngine, CelEngine);

#[wasm_bindgen]
pub struct WasmSemanticModel {
    model: std::sync::Arc<SemanticModel>,
}

#[wasm_bindgen]
impl WasmSemanticModel {
    pub fn parse(template: &[u8]) -> Result<WasmSemanticModel, JsValue> {
        catch_panics(
            || {
                let result = SemanticModel::parse(template, Default::default()).map_err(to_js_err)?;
                Ok(WasmSemanticModel { model: std::sync::Arc::new(result.model) })
            },
            wasm_panic_err,
        )
    }

    pub fn resources(&self) -> Result<JsValue, JsValue> {
        catch_panics(|| to_js(&self.model.resources), wasm_panic_err)
    }
    pub fn parameters(&self) -> Result<JsValue, JsValue> {
        catch_panics(|| to_js(&self.model.parameters), wasm_panic_err)
    }
    pub fn outputs(&self) -> Result<JsValue, JsValue> {
        catch_panics(|| to_js(&self.model.outputs), wasm_panic_err)
    }

    pub fn conditions(&self) -> Result<JsValue, JsValue> {
        catch_panics(
            || {
                let names: Vec<&str> = self.model.conditions.names().collect();
                to_js(&names)
            },
            wasm_panic_err,
        )
    }

    pub fn transforms(&self) -> Result<JsValue, JsValue> {
        catch_panics(|| to_js(&self.model.transforms), wasm_panic_err)
    }

    #[wasm_bindgen(js_name = "formatVersion")]
    pub fn format_version(&self) -> Option<String> {
        self.model.format_version.clone()
    }

    pub fn description(&self) -> Option<String> {
        self.model.description.clone()
    }

    #[wasm_bindgen(js_name = "toDiagnosticModel")]
    pub fn to_diagnostic_model(&self) -> Result<JsValue, JsValue> {
        catch_panics(|| to_js(&self.model.to_diagnostic_json()), wasm_panic_err)
    }

    #[wasm_bindgen(js_name = "sourceLocation")]
    pub fn source_location(&self, path: &str) -> Result<JsValue, JsValue> {
        catch_panics(
            || match self.model.source_location(path) {
                Some(span) => to_js(&span),
                None => Ok(JsValue::NULL),
            },
            wasm_panic_err,
        )
    }
}

#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
