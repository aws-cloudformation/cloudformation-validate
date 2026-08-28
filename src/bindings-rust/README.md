# CloudFormation Validate for Rust

Validate AWS CloudFormation templates from Rust and catch schema violations, semantic errors, security risks, and
best-practice findings before deployment - in an editor, build, service, or CI system.

- **Offline** - all rules and CloudFormation resource schemas are bundled.
- **Fast** - engines and schemas compile once and can be reused across validations.
- **Embeddable** - validation accepts template bytes and returns structured Rust types.

Common types are exported from the top-level `cloudformation_validate` crate. The underlying engine, diagnostics,
rules, schema, and template-model crates are also re-exported as modules for advanced use.

## Installation

Available on [crates.io](https://crates.io/crates/cloudformation-validate) as `cloudformation-validate`.

```bash
cargo add cloudformation-validate
```

Or add a version requirement directly:

```toml
[dependencies]
cloudformation-validate = "1.10.0"
```

The library requires Rust 1.96 or later. The repository pins that toolchain in
[`rust-toolchain.toml`](../rust-toolchain.toml). Call `cloudformation_validate::version()` when an application needs the
loaded library version at runtime. The library performs no runtime network requests and needs no AWS credentials.

## Quick start

```rust
use cloudformation_validate::{
    EngineConfig, RegoEngine, SchemaValidator, Severity, ValidateConfig, validate_bytes_with_path,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let schema_validator = SchemaValidator::default();
    let engine = RegoEngine::new(EngineConfig::default())?;
    let template = b"Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n";

    let report = validate_bytes_with_path(
        &engine,
        &schema_validator,
        template,
        ValidateConfig::default(),
        "template.yaml".to_string(),
    )?;

    for diagnostic in &report.diagnostics {
        println!(
            "[{}] {}: {}",
            diagnostic.severity, diagnostic.rule_id, diagnostic.message
        );
    }
    assert!(report.diagnostics.iter().all(|diagnostic| diagnostic.severity != Severity::Fatal));
    Ok(())
}
```

Each diagnostic includes a rule ID, severity, message, source location, affected entity and property path when
available, and optional remediation context. See [`Diagnostic`](#reports-and-diagnostics).

Engines are expensive to construct and cheap to reuse. Construct an engine and `SchemaValidator` once, then retain them
for many calls to `validate_bytes_with_path`.

## Engines

`RegoEngine` and `CelEngine` both implement `ValidationEngine` and are interchangeable. Given the same template and
configuration, they produce the same diagnostics.

```rust
use cloudformation_validate::{CelEngine, EngineConfig, RegoEngine, ValidationEngine};

fn engine_names() -> Result<(String, String), Box<dyn std::error::Error>> {
    let rego = RegoEngine::new(EngineConfig::default())?;
    let cel = CelEngine::new(EngineConfig::default())?;
    Ok((rego.engine_name().to_string(), cel.engine_name().to_string()))
}

assert_eq!(engine_names()?, ("rego".to_string(), "cel".to_string()));
# Ok::<(), Box<dyn std::error::Error>>(())
```

The `ValidationEngine` trait also exposes `list_rules`, built-in and external rule metadata, and initialization metrics.

### EngineConfig

`EngineConfig` controls rules and schema-aware engine construction. `EngineConfig::default()` and
`EngineConfig::new()` use only bundled rules and schemas.

| Field                     | Default | Description                                                                  |
|---------------------------|---------|------------------------------------------------------------------------------|
| `custom_rules`            | empty   | Engine-native rules: Rego source for `RegoEngine`, CEL JSON for `CelEngine`. |
| `guard_rules`             | empty   | CloudFormation Guard DSL source translated by either engine.                 |
| `schema_validator_config` | `None`  | Additional resource provider schemas used for schema-aware metadata.         |

Rule sources are supplied as `ExternalRuleSource { name, content }`. `name` identifies the source in errors and
logging; `content` is the complete rule text.

```rust
use cloudformation_validate::{EngineConfig, ExternalRuleSource, RegoEngine};

let config = EngineConfig::new().with_guard_rules([ExternalRuleSource {
    name: "s3.guard".to_string(),
    content: "rule bucket_name { AWS::S3::Bucket { Properties.BucketName EXISTS } }".to_string(),
}]);
let _engine = RegoEngine::new(config)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

See [Custom Rules](../CUSTOM_RULES.md) for Rego, CEL, and Guard formats.

## Validation configuration

`ValidateConfig` controls each validation call.

| Field                        | Default        | Description                                                                                  |
|------------------------------|----------------|----------------------------------------------------------------------------------------------|
| `filters`                    | no filtering   | Include and exclude rules by ID, category, ranges, resource, logical ID, type, or service.  |
| `detail_level`               | `Detailed`     | Controls standard versus extended diagnostic context.                                        |
| `severity_level`             | `Info`         | Drops diagnostics below the configured severity.                                             |
| `parameter_overrides`        | empty          | Overrides template parameter values during intrinsic resolution.                             |
| `pseudo_parameter_overrides` | built-in values| Overrides `AWS::AccountId`, `AWS::Region`, and other CloudFormation pseudo-parameters.       |
| `strict`                     | `false`        | Upgrades Warn diagnostics to Error.                                                           |
| `disable_builtin_rules`      | `false`        | Runs only custom and Guard rules when enabled.                                                |

`FilterConfig` and its filter types are exported at the top level. See the
[`rules` crate README](../rules/README.md) for rule metadata, severities, categories, and filter behavior.

## Additional resource provider schemas

`SchemaValidatorConfig` accepts `AdditionalSchemaSource` values that merge over bundled schemas or register a resource
type that is not bundled yet. When overlays are used, construct the engine and validator from the same schema config so
schema-aware rule metadata stays consistent.

```rust
use cloudformation_validate::{
    AdditionalSchemaSource, EngineConfig, RegoEngine, SchemaValidator, SchemaValidatorConfig, ValidationEngine,
};

let additional_schema = AdditionalSchemaSource {
    type_name: None,
    schema: r#"{
        "typeName": "Example::Service::Resource",
        "properties": {"Name": {"type": "string"}}
    }"#
    .to_string(),
};
let schema_config = SchemaValidatorConfig::new().with_additional_schemas([additional_schema]);
let schema_validator = SchemaValidator::new(schema_config.clone())?;
let engine = RegoEngine::new(EngineConfig::new().with_schema_validator_config(schema_config))?;

assert!(schema_validator.schema_count() > 0);
assert_eq!(engine.engine_name(), "rego");
# Ok::<(), Box<dyn std::error::Error>>(())
```

Malformed, contradictory, cyclic, or unsupported overlays return an error rather than silently weakening validation.
See [Additional Resource Provider Schemas](../validation-engine/API.md#additional-resource-provider-schemas) for the
merge model and constraints.

## Reports and diagnostics

`validate_bytes_with_path` returns `Result<ValidationReport, ValidationError>`.

| Type               | Purpose                                                                                         |
|--------------------|-------------------------------------------------------------------------------------------------|
| `ValidationReport` | File label, status, diagnostics, summary counts, suppression metadata, and performance metrics. |
| `Diagnostic`       | Rule ID, severity, message, origin, entity, property path, source span, and optional context.   |
| `ReportStatus`     | `Ok`, `AnalysisIncomplete`, or `Error`.                                                         |
| `Severity`         | `Debug`, `Info`, `Warn`, `Error`, or `Fatal`.                                                   |
| `DetailLevel`      | `Standard` or `Detailed`.                                                                       |

A template syntax failure is returned as a report with `ReportStatus::Error` and an `F1101` diagnostic, preserving the
structured-report contract. Infrastructure or engine failures return `ValidationError`.

Call `ValidationReport::to_standard()` for flattened diagnostics or `ValidationReport::to_detailed()` for extended
rule descriptions, phase data, documentation URLs, related resources, condition scenarios, and violation context.

## Error handling

- `RegoEngine::new` and `CelEngine::new` return an error if built-in, custom, Guard, or overlay-derived engine setup
  fails.
- `SchemaValidator::new` returns `SchemaValidatorConfigError` when an additional schema cannot be resolved or applied.
- `validate_bytes_with_path` returns `ValidationError` for unexpected pipeline failures.
- Template parse defects remain structured diagnostics instead of process-level errors.

The library does not intentionally panic on caller-controlled input. Language-boundary panic handling is implemented by
the separate binding packages; native Rust callers receive normal `Result` values.

## Advanced modules

The facade re-exports these implementation crates for callers that need APIs beyond the common top-level exports:

| Module                  | Contents                                                              |
|-------------------------|-----------------------------------------------------------------------|
| `cel_engine`            | `CelEngine` implementation.                                           |
| `rego_engine`           | `RegoEngine` implementation.                                          |
| `validation_engine`     | Orchestration, configs, traits, helpers, and validation entry points. |
| `schema_validator`      | Compiled schema store, overlays, and standalone schema validation.    |
| `template_model`        | Parser, semantic model, intrinsic resolution, and source spans.       |
| `diagnostics`           | Reports, diagnostics, metrics, detail levels, and phases.             |
| `rules`                 | Registry metadata, filters, categories, origins, and severities.      |
| `data_source`           | Embedded schema and reference data plus additional schema sources.    |

See the [full Rust embedding API](../validation-engine/API.md) and the repository's
[Custom Rules guide](../CUSTOM_RULES.md) for deeper examples.
