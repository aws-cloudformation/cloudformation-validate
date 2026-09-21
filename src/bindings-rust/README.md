# AWS CloudFormation Validate for Rust

Validate AWS CloudFormation templates from Rust and catch schema violations, semantic errors, security risks, and
best-practice findings before deployment - in your editor, build, service, or CI.

- **Offline** - all rules and CloudFormation resource schemas are bundled; nothing is fetched at runtime and no AWS
  credentials are needed.
- **Fast** - engines and schemas compile once and are reused across validations; typical templates validate in under a
  second.
- **Self-contained** - rules and schemas compile into your binary; there is no runtime asset to ship.

The entry points and configuration types are exported from the root of the `cloudformation_validate` crate; the
remaining types are reached through its re-exported modules (`validation_engine` for the AWS CLI command types,
`diagnostics` for report and diagnostic details, `rules` for rule metadata, `template_model` for the semantic model).

## Installation

Available on [crates.io](https://crates.io/crates/cloudformation-validate) as `cloudformation-validate`.

```bash
cargo add cloudformation-validate
```

```toml
[dependencies]
cloudformation-validate = "1.10.0"
```

Requires Rust 1.96 or later (the repository pins that toolchain in [`rust-toolchain.toml`](../rust-toolchain.toml)).

## Quick start

```rust
use cloudformation_validate::{EngineConfig, RegoEngine, SchemaValidator, ValidateConfig, validate_bytes_with_path};

let schema_validator = SchemaValidator::default();
let engine = RegoEngine::new(EngineConfig::default())?;

let template = std::fs::read("template.yaml").unwrap_or_else(|_| b"Resources: {}\n".to_vec());
let report = validate_bytes_with_path(
    &engine,
    &schema_validator,
    &template,
    ValidateConfig::default(),
    "template.yaml".to_string(),
)?;
for d in &report.diagnostics {
    println!("[{}] {}: {}", d.severity, d.rule_id, d.message);
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

Each diagnostic identifies the rule, severity, affected entity and property, and source location - see
[Diagnostic](#diagnostic).

Engines are expensive to construct (rules compile once) and cheap to reuse - create one engine and one
`SchemaValidator` and validate many templates. Every fallible call returns a `Result` - `ValidationError` from
validation, `anyhow::Error` from engine construction, and `SchemaValidatorConfigError` from `SchemaValidator::new`;
the library does not intentionally panic on caller-controlled input (the language bindings additionally wrap every
entry point in a panic-to-error backstop). `version()` returns the version of the crate.

A template is passed as raw bytes together with a path label that is used for diagnostic source locations.

## Engine

`RegoEngine` and `CelEngine` both implement the `ValidationEngine` trait and are interchangeable - they produce
identical diagnostics for the same template and config. `CompositeEngine` implements the same trait and layers custom
Rego, CEL, and Guard rules on top of the built-in rules - see [CompositeEngine](#compositeengine).

### `ValidationEngine` trait

Validation is driven by free functions that take the engine and a `SchemaValidator`; the trait itself exposes the rule
metadata:

```rust,ignore
pub fn validate_bytes_with_path(
    engine: &dyn ValidationEngine, schema_validator: &SchemaValidator,
    bytes: &[u8], config: ValidateConfig, file_path: String,
) -> Result<ValidationReport, ValidationError>;
pub fn validate_aws_cli_command(
    engine: &dyn ValidationEngine, schema_validator: &SchemaValidator, request: &AwsCliCommand,
) -> Result<AwsCliCommandValidation, ValidationError>;

pub trait ValidationEngine {
    fn list_rules(&self) -> Vec<RuleInfo>;
    fn engine_name(&self) -> &str;
    // plus evaluate_rules, rule_metadata, external_rule_metadata, and init_metric, used by the pipeline
}
```

| Function / method                                                          | Returns                                        | Description                                                                                                                                                                                                                       |
|----------------------------------------------------------------------------|------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `validate_bytes_with_path(&engine, &schema_validator, bytes, config, path)` | `Result<ValidationReport, ValidationError>`    | Validates the template and returns a report. `config.detail_level` (default `Detailed`) selects how much per-diagnostic context is populated: `Detailed` adds documentation URLs, rule descriptions, phase tags, and `ViolationContext`; `Standard` leaves those enrichment fields `None` |
| `validate_aws_cli_command(&engine, &schema_validator, &request)`           | `Result<AwsCliCommandValidation, ValidationError>` | Models an AWS CLI command as CloudFormation resource state and validates it - see [AWS CLI command validation](#aws-cli-command-validation)                                                                                    |
| `engine.list_rules()`                                                      | `Vec<RuleInfo>`                                | Returns metadata for every built-in and loaded custom rule                                                                                                                                                                        |
| `engine.engine_name()`                                                     | `&str`                                         | `"rego"`, `"cel"`, or `"composite"`                                                                                                                                                                                               |

### `EngineConfig`

Passed to `RegoEngine::new` / `CelEngine::new`. All fields are optional: the rule lists default to empty and a `None`
`schema_validator_config` uses only the bundled schemas. `EngineConfig::new()` and its `with_*` builder methods set
only the options you name.

```rust,ignore
pub struct EngineConfig {
    pub custom_rules: Vec<ExternalRuleSource>,                  // engine-native rules (Rego for RegoEngine, CEL for CelEngine)
    pub guard_rules: Vec<ExternalRuleSource>,                   // CloudFormation Guard DSL rules - evaluated by the Guard evaluator
    pub schema_validator_config: Option<SchemaValidatorConfig>, // additional resource provider schemas
}

pub struct SchemaValidatorConfig {
    pub additional_schemas: Vec<AdditionalSchemaSource>, // resource provider schemas merged over the bundled schemas
}

pub struct ExternalRuleSource {
    pub name: String,    // identifier shown in diagnostics (e.g. file path)
    pub content: String, // full rule source text
}

pub struct AdditionalSchemaSource {
    pub type_name: Option<String>, // None to use the typeName inside the schema JSON
    pub schema: String,            // complete resource provider schema JSON
}
```

| Field                     | Default  | Description                                                                                    |
|---------------------------|----------|------------------------------------------------------------------------------------------------|
| `custom_rules`            | `vec![]` | Engine-native rules: Rego source for `RegoEngine`, CEL JSON for `CelEngine`                    |
| `guard_rules`             | `vec![]` | CloudFormation Guard DSL rules, evaluated by the Guard evaluator identically in every engine                         |
| `schema_validator_config` | `None`   | Optional `SchemaValidatorConfig` whose `additional_schemas` are merged over the bundled schemas |

Each rule is an `ExternalRuleSource` - `name` identifies the rule in diagnostics and `content` is the full rule source
text; read the file yourself (for example with `std::fs::read_to_string`) and pass its text. Each additional schema is
an `AdditionalSchemaSource` - a complete resource provider schema JSON plus an optional `type_name` that may be `None`
when the schema JSON contains its own `typeName`. Additional schemas extend the bundled schemas or register resource
types CloudFormation has not published yet; a malformed, contradictory, or unsupported schema fails engine construction
rather than silently weakening validation. Guard rules are evaluated by the CloudFormation Guard evaluator itself
against the template as written, so every engine reports exactly what `cfn-guard validate` reports; a Guard file that
does not parse also fails engine construction. When additional schemas are used, build the `SchemaValidator` from the
same `SchemaValidatorConfig` so schema-aware rule metadata stays consistent:

```rust,no_run
use cloudformation_validate::{
    AdditionalSchemaSource, CelEngine, EngineConfig, ExternalRuleSource, SchemaValidator, SchemaValidatorConfig,
};

let schema_config = SchemaValidatorConfig::new().with_additional_schemas([AdditionalSchemaSource {
    type_name: None,
    schema: std::fs::read_to_string("schemas/aws-lambda-function.json")?,
}]);
let schema_validator = SchemaValidator::new(schema_config.clone())?;
let engine = CelEngine::new(
    EngineConfig::new()
        .with_custom_rules([ExternalRuleSource {
            name: "rules/s3_encryption.json".to_string(),
            content: std::fs::read_to_string("rules/s3_encryption.json")?,
        }])
        .with_guard_rules([ExternalRuleSource {
            name: "rules/compliance.guard".to_string(),
            content: std::fs::read_to_string("rules/compliance.guard")?,
        }])
        .with_schema_validator_config(schema_config),
)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

See [Custom Rules](../CUSTOM_RULES.md) for the Rego, CEL, and Guard rule formats and
[Additional Resource Provider Schemas](../validation-engine/API.md#additional-resource-provider-schemas) for the schema
merge model.

### `CompositeEngine`

`CompositeEngine` implements the same `ValidationEngine` trait but takes a `CompositeEngineConfig`. It evaluates every
built-in rule with a fixed built-in CEL evaluator and layers the caller-supplied custom rules on top: custom CEL and
Guard rules run alongside that built-in engine, while custom Rego rules run in a separate external engine that is
constructed only when Rego rules are supplied. With no custom rules it produces the same built-in diagnostics as
`RegoEngine` and `CelEngine`, and `engine_name()` returns `"composite"`. Because the composite fixes which engine owns
the built-ins, the config has no `custom_rules` field - it carries only the custom rules layered on top. `EngineType`
selects `Rego`, `Cel`, or `Composite` (its default) for hosts such as the CLI; when embedding, construct the engine type
directly.

```rust,ignore
pub struct CompositeEngineConfig {
    pub rego_rules: Vec<ExternalRuleSource>,                    // custom Rego rules, run by the external engine
    pub cel_rules: Vec<ExternalRuleSource>,                     // custom CEL rules, run by the built-in engine
    pub guard_rules: Vec<ExternalRuleSource>,                   // CloudFormation Guard DSL rules, evaluated alongside the built-in engine
    pub schema_validator_config: Option<SchemaValidatorConfig>, // additional resource provider schemas, observed by both inner engines
}
```

| Field                     | Default  | Description                                                                                      |
|---------------------------|----------|--------------------------------------------------------------------------------------------------|
| `rego_rules`              | `vec![]` | Custom Rego rules layered on top of the built-in rules, run by the external engine               |
| `cel_rules`               | `vec![]` | Custom CEL rules layered on top of the built-in rules, run by the built-in engine                |
| `guard_rules`             | `vec![]` | CloudFormation Guard DSL rules layered on top of the built-in rules, evaluated alongside the built-in engine |
| `schema_validator_config` | `None`   | Optional `SchemaValidatorConfig`, observed by both inner engines                                 |

```rust,no_run
use cloudformation_validate::{
    CompositeEngine, CompositeEngineConfig, ExternalRuleSource, SchemaValidator, ValidateConfig,
    validate_bytes_with_path,
};

let engine = CompositeEngine::new(
    CompositeEngineConfig::new()
        .with_rego_rules([ExternalRuleSource {
            name: "rules/s3_naming.rego".to_string(),
            content: std::fs::read_to_string("rules/s3_naming.rego")?,
        }])
        .with_guard_rules([ExternalRuleSource {
            name: "rules/compliance.guard".to_string(),
            content: std::fs::read_to_string("rules/compliance.guard")?,
        }]),
)?;
let schema_validator = SchemaValidator::default();
let template = std::fs::read("template.yaml")?;
let report = validate_bytes_with_path(
    &engine,
    &schema_validator,
    &template,
    ValidateConfig::default(),
    "template.yaml".to_string(),
)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## ValidateConfig

Controls filtering, detail, severity, parameter overrides, and behavior for one validation call. All fields have
defaults - `ValidateConfig::default()` uses them.

```rust,no_run
use cloudformation_validate::{
    EngineConfig, FilterConfig, RegoEngine, RuleFilterConfig, SchemaValidator, Severity, ValidateConfig,
    validate_bytes_with_path,
};

let engine = RegoEngine::new(EngineConfig::default())?;
let schema_validator = SchemaValidator::default();
let template = std::fs::read("template.yaml")?;
let report = validate_bytes_with_path(
    &engine,
    &schema_validator,
    &template,
    ValidateConfig {
        filters: FilterConfig::new(
            RuleFilterConfig::default(),
            RuleFilterConfig { ids: vec!["I1002".to_string()], ..Default::default() },
        ),
        severity_level: Severity::Warn,
        ..Default::default()
    },
    "template.yaml".to_string(),
)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

```rust,ignore
pub struct ValidateConfig {
    pub filters: FilterConfig,                                  // FilterConfig { include, exclude }
    pub detail_level: DetailLevel,
    pub severity_level: Severity,
    pub parameter_overrides: HashMap<String, String>,
    pub pseudo_parameter_overrides: PseudoParameterOverrides,
    pub strict: bool,
    pub disable_builtin_rules: bool,
}
```

| Field                        | Default                  | Description                                                                                                                                                              |
|------------------------------|--------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `filters.include`            | empty (all rules)        | When set, only matching rules produce diagnostics. Empty means include everything.                                                                                       |
| `filters.exclude`            | empty (nothing excluded) | Matching rules are suppressed. Applied after `include`.                                                                                                                  |
| `detail_level`               | `Detailed`               | Per-diagnostic context. `Detailed` populates documentation URLs, rule descriptions, phase tags, and `ViolationContext`; `Standard` leaves those enrichment fields `None`. |
| `severity_level`             | `Info`                   | Minimum severity threshold. Diagnostics below this level are dropped. Values: `Debug`, `Info`, `Warn`, `Error`, `Fatal`.                                                 |
| `parameter_overrides`        | empty                    | Override template parameter values during resolution. Keys are parameter logical IDs.                                                                                    |
| `pseudo_parameter_overrides` | all `None`               | Override CloudFormation pseudo-parameters (`AWS::AccountId`, `AWS::Region`, etc.).                                                                                       |
| `strict`                     | `false`                  | When `true`, `Warn`-severity diagnostics are upgraded to `Error`.                                                                                                        |
| `disable_builtin_rules`      | `false`                  | When `true`, all built-in rules (schema validation, Step Functions, engine rules) are skipped; only custom and Guard rules are evaluated.                                |

### RuleFilterConfig

Both `include` and `exclude` use this structure. All fields are additive - a rule matches if it hits any criterion.

```rust,ignore
pub struct RuleFilterConfig {
    pub ids: Vec<String>,                       // exact rule IDs, e.g. ["E3012", "W3010"]
    pub categories: Vec<String>,                // category names, e.g. ["security", "best_practices"]
    pub id_ranges: Vec<IdRange>,                // numeric ranges, e.g. IdRange { prefix: "E", start: 3000, end: 3099 }
    pub id_patterns: Vec<String>,               // regex patterns matched against rule IDs
    pub resource_ids: Vec<ResourceIdFilter>,    // a rule (or every rule) on a logical resource ID
    pub logical_ids: Vec<LogicalIdFilter>,      // a rule (or every rule) on a named template entity
    pub resource_types: Vec<ResourceTypeFilter>,// a rule (or every rule) on a resource type
    pub services: Vec<ServiceFilter>,           // a rule (or every rule) on a service, e.g. "AWS::AutoScaling"
}

// resource_ids / logical_ids / resource_types / services each carry an optional rule_id:
// set it to scope the filter to one rule, or leave it None for every rule on the target.
pub struct ResourceIdFilter   { pub rule_id: Option<String>, pub resource_id: String }
pub struct LogicalIdFilter    { pub rule_id: Option<String>, pub logical_id: String, pub entity_type: Option<EntityType> }
pub struct ResourceTypeFilter { pub rule_id: Option<String>, pub resource_type: String }
pub struct ServiceFilter      { pub rule_id: Option<String>, pub service: String }
```

The `service` is matched verbatim against the `service-provider::service-name` prefix of the resource type - its first
two `::`-delimited segments (e.g. `AWS::AutoScaling` in `AWS::AutoScaling::LaunchConfiguration`).

The `resource_ids` dimension matches only diagnostics attributed to a resource; `logical_ids` additionally matches
diagnostics on parameters, outputs, mappings, conditions, and template rules (for resource diagnostics the two carry
the same value). A `Some` `entity_type` scopes a `LogicalIdFilter` to entities of one type, so `MyThing` as an
`EntityType::Parameter` is matched without touching a same-named entity of another type.

### PseudoParameterOverrides

Override CloudFormation pseudo-parameters used during intrinsic function resolution. All fields are optional - when
`None`, the engine uses built-in defaults (e.g. region defaults to `us-east-1`).

```rust,ignore
pub struct PseudoParameterOverrides {
    pub account_id: Option<String>,        // AWS::AccountId
    pub notification_arns: Option<String>, // AWS::NotificationARNs
    pub partition: Option<String>,         // AWS::Partition
    pub region: Option<String>,            // AWS::Region (default: "us-east-1")
    pub stack_id: Option<String>,          // AWS::StackId
    pub stack_name: Option<String>,        // AWS::StackName
    pub url_suffix: Option<String>,        // AWS::URLSuffix
}
```

## TemplateModel

Parses a template into the resolved `SemanticModel` for direct inspection - the same model the engines evaluate rules
against. In Rust this is the `SemanticModel` type itself, exposing the parsed sections as fields.

```rust
use cloudformation_validate::SemanticModel;

let model = SemanticModel::from_bytes(b"Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n")?;
assert!(model.resources.contains_key("Bucket"));
# Ok::<(), Box<dyn std::error::Error>>(())
```

| Field / method                    | Type / returns                       | Description                                                                                     |
|-----------------------------------|--------------------------------------|-------------------------------------------------------------------------------------------------|
| `SemanticModel::from_bytes(bytes)` | `Result<SemanticModel, ParseError>` | Parses template bytes into a semantic model                                                     |
| `resources`                       | `HashMap<String, ResolvedResource>`  | All resources with resolved property values                                                     |
| `parameters`                      | `HashMap<String, ParameterInfo>`     | Parameter definitions with types, defaults, constraints                                         |
| `outputs`                         | `HashMap<String, ResolvedOutput>`    | Outputs with resolved values and export names                                                   |
| `conditions.names()`              | `impl Iterator<Item = &str>`         | Condition names defined in the template                                                         |
| `transforms`                      | `Vec<String>`                        | Transform declarations (e.g. `AWS::Serverless-2016-10-31`)                                      |
| `format_version`                  | `Option<String>`                     | `AWSTemplateFormatVersion` value                                                                |
| `description`                     | `Option<String>`                     | Template description                                                                            |
| `to_diagnostic_json()`            | `DiagnosticModel`                    | Full diagnostic model including reference graph, condition implications, and resolution sources |
| `source_location(path)`           | `Option<&SourceSpan>`                | Source line/column span for a JSON path (e.g. `Resources/MyBucket/Properties/BucketName`)       |

## SchemaValidator

Runs schema validation independently from the rule engines. Checks each resource against the compiled CloudFormation
provider schemas and produces `Fatal`-severity diagnostics for structural violations. The constructor argument is the
same `SchemaValidatorConfig` accepted by `EngineConfig`; `SchemaValidator::default()` uses only the bundled schemas.

```rust
use std::sync::Arc;
use cloudformation_validate::{SchemaValidator, SemanticModel};

let validator = SchemaValidator::default();
let model = Arc::new(SemanticModel::from_bytes(b"Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n")?);
let diagnostics = validator.validate(&model, Some("us-east-1")).diagnostics;
assert!(diagnostics.is_empty());
# Ok::<(), Box<dyn std::error::Error>>(())
```

| Function / method                         | Returns                                            | Description                                                                                                        |
|-------------------------------------------|----------------------------------------------------|--------------------------------------------------------------------------------------------------------------------|
| `SchemaValidator::new(config)`            | `Result<SchemaValidator, SchemaValidatorConfigError>` | Constructs a validator; `SchemaValidator::default()` uses only the bundled schemas                              |
| `validate(&model, region)`                | `SchemaValidationResult { diagnostics, metric }`   | Schema diagnostics (`diagnostics::Diagnostic`, without rule enrichment) plus the phase timing. A `None` region defaults to `"us-east-1"`. |
| `list_rules()`                            | `Vec<RuleInfo>`                                    | Schema rule metadata                                                                                               |
| `schema_count()`                          | `usize`                                            | Number of compiled provider schemas                                                                                |

## AWS CLI command validation

`validate_aws_cli_command` models an AWS CLI (or SDK) API call as CloudFormation resource state and validates it
offline before it is sent. It classifies the operation, maps it to a CloudFormation resource type through a closed,
generated adapter catalog, synthesizes a template from the supplied parameters, and runs the normal template pipeline
on it. A `TemplateBody` parameter of a CloudFormation operation is validated as-is. Any request that cannot be modeled
exactly - an unregistered operation, a parameter without a lossless property mapping, or a value outside a
CloudFormation constraint the API itself does not enforce - is skipped with a reason, never guessed. The request and
result types live in the `validation_engine` module.

```rust
use cloudformation_validate::validation_engine::{
    AwsCliCommand, AwsCliCommandValidationStatus, AwsCliValue, validate_aws_cli_command,
};
use cloudformation_validate::{EngineConfig, RegoEngine, SchemaValidator};

let engine = RegoEngine::new(EngineConfig::default())?;
let schema_validator = SchemaValidator::default();
let request = AwsCliCommand::new(
    "s3",
    "CreateBucket",
    [("Bucket".to_string(), AwsCliValue::String { value: "example-bucket".to_string() })],
);
let validation = validate_aws_cli_command(&engine, &schema_validator, &request)?;
if validation.status == AwsCliCommandValidationStatus::Validated {
    for d in &validation.report.as_ref().expect("validated requests carry a report").diagnostics {
        println!("[{}] {}: {}", d.severity, d.rule_id, d.message);
    }
} else {
    println!("skipped ({:?}): {}", validation.operation_kind, validation.reason);
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

```rust,ignore
impl AwsCliCommand {
    pub fn new(
        service_name: impl Into<String>,                            // canonical botocore service name, e.g. "s3" or "cloudformation"
        operation_name: impl Into<String>,                          // API operation name, e.g. "CreateBucket"
        parameters: impl IntoIterator<Item = (String, AwsCliValue)>, // request parameters
    ) -> Self;
    pub fn with_service_prefix(self, service_prefix: impl Into<String>) -> Self; // signing prefix; context only
    pub fn with_http_method(self, http_method: impl Into<String>) -> Self;       // classification hint ("GET"/"HEAD"/"DELETE") for unrecognized verbs
    pub fn with_read_only(self, is_read_only: bool) -> Self;                     // true classifies the operation as ReadOnly
}
```

- `service_name` is matched case-insensitively. Signing names, endpoint aliases, and ARN prefixes are never resolved;
  translate an SDK's service identity first.
- `parameters` are `AwsCliValue`s: `Null`, `Boolean`, `Integer` (i64), `UnsignedInteger` (u64), `Number` (f64),
  `String`, `Bytes`, `Array`, `Object`, or an explicit `Unsupported` marker (`AwsCliValue::from_json` converts a
  `serde_json::Value` without losing integer width). Because synthesis is all-or-nothing, an unmappable or unsupported
  parameter skips the request with a reason naming the offending parameter - no parameter is ever silently dropped.

The result is an `AwsCliCommandValidation`:

| Field             | Description                                                                                                                                                       |
|-------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `operation_kind`  | `AwsCliOperationKind`: `ReadOnly`, `CloudFormationCreate`, `CloudFormationUpdate`, `CloudFormationDelete`, `DataPlaneMutation`, or `UnmappedMutation`             |
| `status`          | `AwsCliCommandValidationStatus`: `Validated` when the modeled template ran through the pipeline, `Skipped` otherwise                                               |
| `template_source` | `Option<AwsCliTemplateSource>`: `TemplateBody`, `CloudControlDesiredState`, `SynthesizedCreate`, or `SynthesizedUpdate`; `None` when skipped                      |
| `resource_types`  | `Vec<String>` - CloudFormation resource types the operation maps to                                                                                               |
| `reason`          | `String` - why the request was validated or skipped                                                                                                               |
| `report`          | `Option<diagnostics::output::ValidationReport>` - present when `Validated`. The configuration is fixed: `Standard` detail level and a `Warn` severity floor         |
| `template`        | `Option<Vec<u8>>` - the exact template bytes that were validated (the caller's `TemplateBody` unchanged, or the synthesized JSON); `None` when skipped             |

`validate_aws_cli_command_with_path` additionally labels the report with a caller-chosen path. The full contract - the
adapter catalog, all-or-nothing mapping, and which rules are dropped for synthesized state - is documented in
[validation-engine/API.md](../validation-engine/API.md#validating-an-aws-cli-command).

## Report Types

### ValidationReport

`validate_bytes_with_path` always returns a `ValidationReport` (a template syntax failure is returned as a report with
`ReportStatus::Error` and an `F1101` diagnostic; only infrastructure or engine failures return `Err`):

```rust,ignore
pub struct ValidationReport {
    pub file_path: String,
    pub status: ReportStatus,           // Ok, AnalysisIncomplete (findings may be omitted), or Error (pipeline failure)
    pub version: String,
    pub metadata: ReportMetadata,
    pub performance: PerformanceMetrics,
    pub diagnostics: Vec<Diagnostic>,
}
```

Every finding is a `Diagnostic` (see [Diagnostic](#diagnostic)). Its enrichment fields - `documentation_url`,
`rule_description`, `phase` (`Parse` | `Schema` | `Lint`), and `context` (`ViolationContext` with `actual_value`,
`expected_constraint`, `resolution_source`, etc.) - are populated only at `detail_level` `Detailed` (the default);
validating at `Standard` leaves them `None`, keeping the base diagnostic fields.
`ValidationReport::to_report(DetailLevel)` projects the report into the serializable
`diagnostics::output::ValidationReport`, whose diagnostics flatten the source span into
`start_line`/`start_column`/`end_line`/`end_column` and omit the enrichment fields at `Standard`.

`metadata` carries the summary counts, the number of suppressed diagnostics, the resources scanned and rules
evaluated, the strict flag and severity threshold used, and optional budget-exhaustion records. Each budget-exhaustion
record retains a stable machine-readable kind and also includes a human-readable description sentence, the numeric
limit, and whether that specific exhaustion makes analysis incomplete. `requiredPropertyCombinations` is context-only,
so its `analysis_incomplete` value is `false` and the report can remain `ReportStatus::Ok`.

### Diagnostic

```rust,ignore
pub struct Diagnostic {
    pub rule_id: String,                                // e.g. "E3012", "F1001", "W3010"
    pub severity: Severity,                             // Fatal, Error, Warn, Info, Debug
    pub message: String,
    pub source: RuleOrigin,                             // Schema, CfnLint, Engine, Custom, Guard
    pub entity: Option<Entity>,                         // the named template entity the finding targets, if any
    pub property_path: Option<String>,                  // e.g. "Properties.BucketName", or section-absolute like "Parameters/MyParam/Type"
    pub suggested_fix: Option<String>,
    pub category: Option<String>,
    pub location: Option<SourceSpan>,                   // start_line, start_column, end_line, end_column
    pub related_resources: Option<Vec<RelatedResource>>,
    pub condition_scenario: Option<HashMap<String, bool>>, // condition truth assignment that triggers this diagnostic
    // Enrichment fields: populated at detail_level Detailed (the default), None at Standard.
    pub documentation_url: Option<String>,
    pub rule_description: Option<String>,
    pub phase: Option<Phase>,                           // Parse | Schema | Lint - pipeline stage that produced the finding
    pub context: Option<ViolationContext>,              // actual_value, expected_constraint, resolution_source, etc.
}

// The named template entity a diagnostic is attributed to. The entity type is the
// singular form of the top-level template section the entity is declared in.
pub struct Entity {
    pub logical_id: String,                             // logical ID as declared in the template
    pub entity_type: EntityType,
    pub resource_type: Option<String>,                  // CloudFormation type, when the entity is a resource whose type is known
}

pub enum EntityType {
    Resource, Parameter, Output, Mapping, Metadata, Rule, Condition, Transform, FormatVersion, Description,
}
```

`Severity`, `RuleOrigin`, `DetailLevel`, and `ReportStatus` are enums (`Severity::Warn`, `RuleOrigin::Guard`,
`DetailLevel::Standard`, `ReportStatus::Ok`, ...); their serialized forms are the upper-case strings used by the
language bindings (`"WARN"`, `"GUARD"`, `"STANDARD"`, `"OK"`).
