# validation-engine — Public API

## Validating a Template

`validate_bytes_with_path` is the main entry point — pass raw template bytes and get a complete report.
It requires an engine and a `SchemaValidator`, both of which should be created once and reused:

```rust
use rego_engine::RegoEngine;
// or cel_engine::CelEngine
use schema_validator::SchemaValidator;
use validation_engine::{validate_bytes_with_path, EngineConfig, ValidateConfig};

// One-time setup (reuse across validations)
let schema_validator = SchemaValidator::new();
let engine = RegoEngine::new(EngineConfig::default())?;

// Validate
let bytes = std::fs::read("template.yaml")?;
let report = validate_bytes_with_path(
    &engine,
    &schema_validator,
    &bytes,
    ValidateConfig::default(),
    "template.yaml".to_string(),
)?;

for d in &report.diagnostics {
    println!("[{}] {} — {}", d.severity, d.rule_id, d.message);
}
```

On parse failure, `validate_bytes_with_path` returns `Ok(report)` with a synthetic `F1101` diagnostic and
`status=Error` rather than returning `Err`. This ensures callers always get a structured report.

## Constructing an Engine

Both engines take a single `EngineConfig` and return `anyhow::Result`:

```rust
use validation_engine::{EngineConfig, ExternalRuleSource};

// No custom rules — built-in rules only
let engine = RegoEngine::new(EngineConfig::default())?;

// With custom rules
let engine = CelEngine::new(EngineConfig {
    custom_rules: vec![ExternalRuleSource { name: "my_rules.cel".into(), content: cel_source }],
    guard_rules:  vec![ExternalRuleSource { name: "policy.guard".into(), content: guard_source }],
})?;
```

| Engine                                 | `custom_rules` format     | `guard_rules` handling                   |
|----------------------------------------|---------------------------|------------------------------------------|
| [RegoEngine](../rego-engine/README.md) | Native Rego source        | Parsed and translated to Rego internally |
| [CelEngine](../cel-engine/README.md)   | JSON with CEL expressions | Parsed and translated to CEL internally  |

Both engines parse and translate `guard_rules` from raw Guard DSL source text — no pre-parsing needed.

## Configuring Validation

`ValidateConfig` controls per-call behavior:

```rust
use validation_engine::ValidateConfig;
use rules::{FilterConfig, DetailLevel, Severity};

let config = ValidateConfig {
    filters: FilterConfig::default(),                    // include/exclude rules
    detail_level: DetailLevel::Detailed,                 // Standard | Detailed (default: Detailed)
    severity_level: Severity::Info,                      // minimum severity to report (default: Info)
    parameter_overrides: HashMap::from([                 // template parameter values
        ("Env".into(), "prod".into()),
    ]),
    pseudo_parameter_overrides: PseudoParameterOverrides {
        region: Some("us-west-2".into()),                // AWS::Region, etc.
        ..Default::default()
    },
    strict: false,                                       // true: upgrade Warning to Error (default: false)
    disable_builtin_rules: false,                        // true: skip all built-in rules, only evaluate custom/guard rules.
};
```

Performance metrics are always collected unconditionally.

## Reading the Report

`validate_bytes_with_path` returns a `ValidationReport`:

```rust
report.file_path            // path to the validated template
report.status               // ReportStatus::Ok or ReportStatus::Error
report.diagnostics          // Vec<Diagnostic> — all findings
report.metadata.counts      // Summary { fatal, errors, warnings, informational, debug }
report.metadata.suppressed  // diagnostics removed by filters/severity gating
report.metadata.resources_scanned
report.metadata.rules_evaluated
report.metadata.strict      // whether strict mode was enabled
report.metadata.severity_level // minimum severity threshold used
report.performance          // PerformanceMetrics with per-phase timings
```

Convert to output format:

```rust
let standard = report.to_standard();  // StandardReport with StandardDiagnostic (flattened, no context)
let detailed = report.to_detailed();  // DetailedReport with DetailedDiagnostic (includes context)
```

Each `Diagnostic` contains:

```rust
d.rule_id           // e.g. "E3012", "F3002", "W3045"
d.severity          // Fatal | Error | Warn | Info | Debug
d.message           // human-readable description
d.source            // RuleOrigin: Schema | CfnLint | Engine | Custom | Guard
d.resource          // Option<ResourceRef> { id, resource_type }
d.property_path     // e.g. "Properties.BucketName"
d.location          // Option<SourceSpan> { start_line, start_column, end_line, end_column }
d.suggested_fix     // Option<String>
d.documentation_url // Option<String>
d.category          // Option<String> — e.g. "Schema", "Best Practice", "Structure"
d.section           // Option<String> — template section (Resources, Parameters, etc.)
d.phase             // Option<Phase> — Parse, Schema, or Lint
d.rule_description  // Option<String> — human-readable rule description
d.related_resources // Option<Vec<RelatedResource>> — cross-resource references
d.condition_scenario // Option<HashMap<String, bool>> — condition values that trigger this
d.context           // Option<ViolationContext> — resolved values (Detailed level only)
```

## Diagnostic Helpers

For engines that produce JSON diagnostics:

| Function                                                                                   | Description                                                                                                                                                                |
|--------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `extract_diagnostics(json_str, model, registry_metadata, out, source_override)`            | Parse a JSON array string into diagnostics, appending to `out`. `source_override: Option<&RuleOrigin>` allows overriding the origin for custom/guard rules.                |
| `make_resource_diagnostic(rule_id, message, model, resource_id, prop_path, suggested_fix)` | Build a `Diagnostic` for a known rule ID with auto-resolved span and severity. Panics if `rule_id` is not in the registry.                                                |

## Guard Rule Loading

| Function                                                    | Description                                                                                                |
|-------------------------------------------------------------|------------------------------------------------------------------------------------------------------------|
| `guard::resolve_guard_config(rule_source_paths) -> Result<Vec<ExternalRuleSource>, String>` | Reads Guard DSL files from filesystem paths (files or directories, recursive). Returns pre-read rule sources. |

## Types

| Type                 | Description                                                                 |
|--------------------|-----------------------------------------------------------------------------|
| `ValidationEngine` | Trait that engines implement — provides `evaluate_rules` and rule metadata  |
| `EngineType`       | `Rego` (default) or `Cel` — selects which validation engine evaluates rules |
| `EngineConfig`     | Engine construction config: `custom_rules` and `guard_rules` as `ExternalRuleSource` |
| `ValidateConfig`   | Per-call config: filters, detail level, severity level, parameter overrides, strict, disable_builtin_rules |
| `ExternalRuleSource` | `{ name: String, content: String }` — a pre-read rule file's identifier and raw content |
| `ValidationError`  | `Parse(ParseError)` or `Engine(String)`                                     |
