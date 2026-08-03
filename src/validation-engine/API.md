# validation-engine — Public API

## Validating a Template

`validate_bytes_with_path` is the main entry point — pass raw template bytes and get a complete report.
It requires an engine and a `SchemaValidator`, both of which should be created once and reused:

```rust
use rego_engine::RegoEngine;
// or cel_engine::CelEngine
use validation_engine::{schema_validator_from_config, validate_bytes_with_path, EngineConfig, ValidateConfig};

// One-time setup (reuse across validations)
let config = EngineConfig::default();
let schema_validator = schema_validator_from_config(&config)?;
let engine = RegoEngine::new(config)?;

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
use rego_engine::RegoEngine;
use cel_engine::CelEngine;

// No custom rules — built-in rules only
let engine = RegoEngine::new(EngineConfig::default())?;

// With custom rules
let engine = CelEngine::new(EngineConfig {
    custom_rules: vec![ExternalRuleSource { name: "my_rules.cel".into(), content: cel_source }],
    guard_rules:  vec![ExternalRuleSource { name: "policy.guard".into(), content: guard_source }],
    ..Default::default()
})?;
```

`EngineConfig` gains fields as the engine gains options — a field is added whenever one is needed for correctness or
ease of use. The constructor and its `with_*` methods let you name only the options you set:

```rust
let config = EngineConfig::new()
    .with_custom_rules([ExternalRuleSource { name: "my_rules.cel".into(), content: cel_source }])
    .with_guard_rules([ExternalRuleSource { name: "policy.guard".into(), content: guard_source }]);
```

| Engine                                 | `custom_rules` format     | `guard_rules` handling                   |
|----------------------------------------|---------------------------|------------------------------------------|
| [RegoEngine](../rego-engine/README.md) | Native Rego source        | Parsed and translated to Rego internally |
| [CelEngine](../cel-engine/README.md)   | JSON with CEL expressions | Parsed and translated to CEL internally  |

Both engines parse and translate `guard_rules` from raw Guard DSL source text — no pre-parsing needed.

## Additional Resource Provider Schemas

`EngineConfig::additional_schemas` merges caller-supplied CloudFormation resource provider schemas on top of the
bundled ones, so templates using a property or allowed value CloudFormation has not published yet validate without
false findings. A type name with no bundled schema is registered as a new resource type.

```rust
use validation_engine::{schema_validator_from_config, AdditionalSchemaSource, EngineConfig};
use rego_engine::RegoEngine;

let config = EngineConfig {
    additional_schemas: vec![AdditionalSchemaSource {
        // Empty to take the type name from the schema's own `typeName`.
        type_name: String::new(),
        schema: std::fs::read_to_string("aws-lambda-function.json")?,
    }],
    ..Default::default()
};

// Both the validator and the engine must be built from the same config: the
// validator applies the overlay, the engine learns the type names it introduces.
let schema_validator = schema_validator_from_config(&config)?;
let engine = RegoEngine::new(config)?;
```

`schema_validator_from_config` is the only construction path that applies overlays — building a `SchemaValidator::new()`
alongside a configured engine silently validates against the bundled schemas alone. Every language binding and the
`cfn-validate --additional-schema` flag route through it.

Construction fails, rather than degrading quietly, when a schema is malformed, names contradictory or non-canonical
types, nests too deeply, defines an unsafe `$ref` graph, states nothing enforceable, contains conflicting enum
representations, uses an invalid regular expression, or states a keyword/composition constraint the compiled model
cannot enforce. Annotations beside a `$ref` are accepted; constraining siblings are rejected because draft-07 would
ignore them. Apply a separate overlay to the property or referenced definition instead.

**Merge model.** An overlay may add entries to a collection and restate a single-valued constraint or a logical group;
it never silently drops a constraint the bundled schema carries. Adding to `required` or to a dependency list states a
constraint, so it can legitimately produce a finding on a template that violates it.

| Field kind | Rule |
|------------|------|
| `properties`, `definitions`, `patternProperties` | deep-merged by key |
| `required`, `/properties/...` lifecycle metadata lists, each `dependentRequired`/`dependentExcluded` key | unioned |
| single-valued constraints (`type`, `pattern`, bounds, lengths, `uniqueItems`, `format`, `additionalProperties`, …) | replaced when supplied |
| `requiredOr`, `requiredXor`, `primaryIdentifier` | replaced as a whole group when supplied |
| `allOf`/`anyOf`/`oneOf`/`if`-`then`-`else` | replaced when supplied |
| `items` (the schema every array element must satisfy) | deep-merged, like one keyed entry |
| `replacementStrategy`, `documentationUrl`, `sourceUrl` | replaced when supplied; these enrich reporting and constrain nothing |
| `enum` / `enumCaseInsensitive` | one mutually exclusive field; supplying either replaces the other. A plain `enum` over a bundled case-insensitive list keeps case-insensitive comparison, so casings that validate today keep validating; supplying `enumCaseInsensitive` switches comparison to case-insensitive, which only ever accepts more |

A `$ref` is never folded into the property pointing at it: overlay fields are merged beside the reference and combined
with the whole chain at validation time. The table above decides each field within the chain too, so a hop that restates
a single-valued constraint overrides the one further along while collections accumulate across every hop. A
constraint-only overlay therefore applies, chains are followed to their end, and a definition changed by a later overlay
still reaches every property referencing it. A chain longer than the resolver can follow is rejected rather than cut
short. Overlays for one type apply in order.

**Scope limits.** An overlay cannot make a bundled `required` property optional or remove a metadata entry, and cannot
switch a case-insensitive enum to case-sensitive comparison. Runtime composition is limited to the fields the compiled
validator faithfully enforces; unsupported branches and validation keywords are rejected. Conditional constraints from
the separate build-time extension artifact remain independently enforced. Overlay-derived type, GetAtt, Ref, primary
identifier, and schema metadata catalogs are propagated to both engines; regional availability and enum snapshots remain
bundled.

## Configuring Validation

`ValidateConfig` controls per-call behavior:

```rust
use validation_engine::ValidateConfig;
use diagnostics::DetailLevel;
use rules::{FilterConfig, Severity};

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
d.entity            // Option<Entity> { logical_id, entity_type, resource_type }
d.property_path     // e.g. "Properties.BucketName"
d.location          // Option<SourceSpan> { start_line, start_column, end_line, end_column }
d.suggested_fix     // Option<String>
d.documentation_url // Option<String>
d.category          // Option<String> — e.g. "Schema", "Best Practice", "Structure"
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
| `extract_diagnostics(json_str, model, out, source_override)`                               | Parse a JSON array string into diagnostics, appending to `out`. `source_override: Option<&RuleOrigin>` allows overriding the origin for custom/guard rules.                |
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
