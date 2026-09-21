# AWS CloudFormation Validate

Validate AWS CloudFormation templates from Go and catch schema violations, semantic errors, security risks, and
best-practice findings before deployment - in your editor, build, service, or CI.

- **Offline** - all rules and CloudFormation resource schemas are bundled; nothing is fetched at runtime and no AWS
  credentials are needed.
- **Fast** - engines and schemas compile once and are reused across validations; typical templates validate in under a
  second.
- **Self-contained** - the Rust core is linked statically via cgo; there are no runtime dependencies.

All types are exported from the `cfnvalidate` package (import path
`github.com/aws-cloudformation/cloudformation-validate/src/bindings-go/go`).

## Installation

Available as a [Go module](https://pkg.go.dev/github.com/aws-cloudformation/cloudformation-validate/src/bindings-go/go)
at `github.com/aws-cloudformation/cloudformation-validate/src/bindings-go/go`.

```bash
go get github.com/aws-cloudformation/cloudformation-validate/src/bindings-go/go
```

```go
import cfnvalidate "github.com/aws-cloudformation/cloudformation-validate/src/bindings-go/go"
```

Requires Go 1.26 or later with cgo enabled (the default) and a C toolchain for linking. The module bundles prebuilt
static libraries for Linux and macOS on x86-64 and ARM64, plus Windows on x86-64, and selects the matching library for
`GOOS`/`GOARCH`. On Windows, link with MinGW-w64; the bundled Windows library uses the GNU ABI and cannot be consumed by
MSVC.

## Quick start

Engines, models, and validators hold off-heap memory - call `Destroy()` when done with each object:

```go
engine, err := cfnvalidate.NewRegoEngine(nil)
if err != nil {
    log.Fatal(err)
}
defer engine.Destroy()

report, err := engine.ValidateTemplateFile("template.yaml", nil)
if err != nil {
    log.Fatal(err)
}
for _, d := range report.Diagnostics {
    fmt.Printf("[%s] %s: %s\n", d.Severity, d.RuleID, d.Message)
}
```

Each diagnostic identifies the rule, severity, affected entity and property, and source location - see
[Diagnostic](#diagnostic).

Engines are expensive to construct (rules compile once) and cheap to reuse - create one engine and validate many
templates. Every fallible call returns an `error` on failure; internal panics are caught at the FFI boundary and
surface the same way, never a process abort. `Version()` returns the version of the bundled validation core, and
`PackageVersion()` the Go module version embedded in the running binary (`"(devel)"` for local module replacements).

A template is passed either as a file path with `ValidateTemplateFile(path, config)` (read from disk; the path is used
for diagnostic source locations) or as raw bytes with `ValidateTemplate(template, config, name)`, where `name`
labels the report (an empty `name` labels it `"template"`).

## Engine

`NewRegoEngine` and `NewCelEngine` both return an `*Engine` and are interchangeable - they produce identical
diagnostics for the same template and config. `NewCompositeEngine` also returns an `*Engine` and layers custom Rego,
CEL, and Guard rules on top of the built-in rules - see [CompositeEngine](#compositeengine).

### `Engine` type

```go
func NewRegoEngine(config *EngineConfig) (*Engine, error)
func NewCelEngine(config *EngineConfig) (*Engine, error)
func NewCompositeEngine(config *CompositeEngineConfig) (*Engine, error)

func (e *Engine) ValidateTemplate(template []byte, config *ValidateConfig, name string) (*ValidationReport, error)
func (e *Engine) ValidateTemplateFile(path string, config *ValidateConfig) (*ValidationReport, error)
func (e *Engine) ValidateAWSCLICommand(request AWSCLICommand) (*AWSCLICommandValidation, error)
func (e *Engine) ListRules() ([]RuleInfo, error)
func (e *Engine) EngineName() string
func (e *Engine) Destroy()
```

| Method                                          | Returns                             | Description                                                                                                                                                                                                                       |
|-------------------------------------------------|-------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `ValidateTemplate(template, config, name)`      | `(*ValidationReport, error)`        | Validates the template and returns a report. `config.DetailLevel` (default `DETAILED`) selects how much per-diagnostic context is populated: `DETAILED` adds documentation URLs, rule descriptions, phase tags, and `ViolationContext`; `STANDARD` leaves those enrichment fields nil |
| `ValidateTemplateFile(path, config)`            | `(*ValidationReport, error)`        | Reads a template from disk, then validates it as above                                                                                                                                                                            |
| `ValidateAWSCLICommand(request)`                | `(*AWSCLICommandValidation, error)` | Models an AWS CLI command as CloudFormation resource state and validates it - see [AWS CLI command validation](#aws-cli-command-validation)                                                                                       |
| `ListRules()`                                   | `([]RuleInfo, error)`               | Returns metadata for every built-in and loaded custom rule                                                                                                                                                                        |
| `EngineName()`                                  | `string`                            | `"rego"`, `"cel"`, or `"composite"`                                                                                                                                                                                               |
| `Destroy()`                                     | -                                   | Releases the engine's off-heap memory; the engine must not be used afterwards                                                                                                                                                     |

### `EngineConfig`

Passed to `NewRegoEngine` / `NewCelEngine`. All fields are optional: the rule slices default to empty and a `nil`
`SchemaValidatorConfig` uses only the bundled schemas (a `nil` config uses only the built-in rules).

```go
type EngineConfig struct {
    CustomRules           []ExternalRuleSource   // engine-native rules (Rego for Rego, CEL for CEL)
    GuardRules            []ExternalRuleSource   // CloudFormation Guard DSL rules - evaluated by the Guard evaluator
    SchemaValidatorConfig *SchemaValidatorConfig // additional resource provider schemas
}

type SchemaValidatorConfig struct {
    AdditionalSchemas []AdditionalSchemaSource // resource provider schemas merged over the bundled schemas
}

type ExternalRuleSource struct {
    Name    string // identifier shown in diagnostics (e.g. file path)
    Content string // full rule source text
}

type AdditionalSchemaSource struct {
    TypeName *string // nil to use the typeName inside the schema JSON
    Schema   string  // complete resource provider schema JSON
}
```

| Field                   | Default | Description                                                                                   |
|-------------------------|---------|-----------------------------------------------------------------------------------------------|
| `CustomRules`           | `nil`   | Engine-native rules: Rego source for `NewRegoEngine`, CEL JSON for `NewCelEngine`             |
| `GuardRules`            | `nil`   | CloudFormation Guard DSL rules, evaluated by the Guard evaluator identically in every engine                        |
| `SchemaValidatorConfig` | `nil`   | Optional `SchemaValidatorConfig` whose `AdditionalSchemas` are merged over the bundled schemas |

Each rule is an `ExternalRuleSource` - `Name` identifies the rule in diagnostics and `Content` is the full rule source
text; read the file yourself (for example with `os.ReadFile`) and pass its text. Each additional schema is an
`AdditionalSchemaSource` - a complete resource provider schema JSON plus an optional `TypeName` that may be left `nil`
when the schema JSON contains its own `typeName`. Additional schemas extend the bundled schemas or register resource
types CloudFormation has not published yet; a malformed, contradictory, or unsupported schema fails engine construction
rather than silently weakening validation. Guard rules are evaluated by the CloudFormation Guard evaluator itself
against the template as written, so every engine reports exactly what `cfn-guard validate` reports; a Guard file that
does not parse also fails engine construction:

```go
custom, _ := os.ReadFile("rules/s3_encryption.json")
guard, _ := os.ReadFile("rules/compliance.guard")
schema, _ := os.ReadFile("schemas/aws-lambda-function.json")
engine, err := cfnvalidate.NewCelEngine(&cfnvalidate.EngineConfig{
    CustomRules: []cfnvalidate.ExternalRuleSource{{Name: "rules/s3_encryption.json", Content: string(custom)}},
    GuardRules:  []cfnvalidate.ExternalRuleSource{{Name: "rules/compliance.guard", Content: string(guard)}},
    SchemaValidatorConfig: &cfnvalidate.SchemaValidatorConfig{
        AdditionalSchemas: []cfnvalidate.AdditionalSchemaSource{{Schema: string(schema)}},
    },
})
```

See [Custom Rules](../CUSTOM_RULES.md) for the Rego, CEL, and Guard rule formats and
[Additional Resource Provider Schemas](../validation-engine/API.md#additional-resource-provider-schemas) for the schema
merge model.

### `CompositeEngine`

`NewCompositeEngine` returns the same `*Engine` type but takes a `CompositeEngineConfig`. It evaluates every built-in
rule with a fixed built-in CEL evaluator and layers the caller-supplied custom rules on top: custom CEL and Guard rules
run alongside that built-in engine, while custom Rego rules run in a separate external engine that is constructed only
when Rego rules are supplied. With no custom rules it produces the same built-in diagnostics as `NewRegoEngine` and
`NewCelEngine`, and `EngineName()` returns `"composite"`. Because the composite fixes which engine owns the built-ins,
the config has no `CustomRules` field - it carries only the custom rules layered on top:

```go
type CompositeEngineConfig struct {
    RegoRules             []ExternalRuleSource   // custom Rego rules, run by the external engine
    CelRules              []ExternalRuleSource   // custom CEL rules, run by the built-in engine
    GuardRules            []ExternalRuleSource   // CloudFormation Guard DSL rules, evaluated alongside the built-in engine
    SchemaValidatorConfig *SchemaValidatorConfig // additional resource provider schemas, observed by both inner engines
}
```

| Field                   | Default | Description                                                                                      |
|-------------------------|---------|--------------------------------------------------------------------------------------------------|
| `RegoRules`             | `nil`   | Custom Rego rules layered on top of the built-in rules, run by the external engine               |
| `CelRules`              | `nil`   | Custom CEL rules layered on top of the built-in rules, run by the built-in engine                |
| `GuardRules`            | `nil`   | CloudFormation Guard DSL rules layered on top of the built-in rules, evaluated alongside the built-in engine |
| `SchemaValidatorConfig` | `nil`   | Optional `SchemaValidatorConfig`, observed by both inner engines                                 |

```go
rego, _ := os.ReadFile("rules/s3_naming.rego")
guard, _ := os.ReadFile("rules/compliance.guard")
engine, err := cfnvalidate.NewCompositeEngine(&cfnvalidate.CompositeEngineConfig{
    RegoRules:  []cfnvalidate.ExternalRuleSource{{Name: "rules/s3_naming.rego", Content: string(rego)}},
    GuardRules: []cfnvalidate.ExternalRuleSource{{Name: "rules/compliance.guard", Content: string(guard)}},
})
if err != nil {
    log.Fatal(err)
}
defer engine.Destroy()
report, err := engine.ValidateTemplateFile("template.yaml", nil)
```

## ValidateConfig

Controls filtering, detail, severity, parameter overrides, and behavior for one validation call. All fields have
defaults - passing a `nil` `*ValidateConfig` uses them.

```go
report, err := engine.ValidateTemplateFile("template.yaml", &cfnvalidate.ValidateConfig{
    Exclude:       &cfnvalidate.RuleFilterConfig{IDs: []string{"I1002"}},
    SeverityLevel: cfnvalidate.SeverityWarn,
})
```

```go
type ValidateConfig struct {
    Include                  *RuleFilterConfig
    Exclude                  *RuleFilterConfig
    DetailLevel              DetailLevel               // "" = DETAILED
    SeverityLevel            Severity                  // "" = INFO
    ParameterOverrides       map[string]string
    PseudoParameterOverrides *PseudoParameterOverrides
    Strict                   *bool                     // nil = false
    DisableBuiltinRules      *bool                     // nil = false
}
```

| Field                      | Default                  | Description                                                                                                                                                              |
|----------------------------|--------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `Include`                  | `nil` (all rules)        | When set, only matching rules produce diagnostics. Empty means include everything.                                                                                       |
| `Exclude`                  | `nil` (nothing excluded) | Matching rules are suppressed. Applied after `Include`.                                                                                                                  |
| `DetailLevel`              | `DETAILED`               | Per-diagnostic context. `DETAILED` populates documentation URLs, rule descriptions, phase tags, and `ViolationContext`; `STANDARD` leaves those enrichment fields nil.    |
| `SeverityLevel`            | `INFO`                   | Minimum severity threshold. Diagnostics below this level are dropped. Values: `DEBUG`, `INFO`, `WARN`, `ERROR`, `FATAL`.                                                 |
| `ParameterOverrides`       | `nil`                    | Override template parameter values during resolution. Keys are parameter logical IDs.                                                                                    |
| `PseudoParameterOverrides` | `nil` (all unset)        | Override CloudFormation pseudo-parameters (`AWS::AccountId`, `AWS::Region`, etc.).                                                                                       |
| `Strict`                   | `false`                  | When `true`, `WARN`-severity diagnostics are upgraded to `ERROR`.                                                                                                        |
| `DisableBuiltinRules`      | `false`                  | When `true`, all built-in rules (schema validation, Step Functions, engine rules) are skipped; only custom and Guard rules are evaluated.                                |

### RuleFilterConfig

Both `Include` and `Exclude` use this structure. All fields are additive - a rule matches if it hits any criterion.

```go
type RuleFilterConfig struct {
    IDs           []string             // exact rule IDs, e.g. ["E3012", "W3010"]
    Categories    []string             // category names, e.g. ["security", "best_practices"]
    IDRanges      []IdRange            // numeric ranges, e.g. IdRange{Prefix: "E", Start: 3000, End: 3099}
    IDPatterns    []string             // regex patterns matched against rule IDs
    ResourceIDs   []ResourceIdFilter   // a rule (or every rule) on a logical resource ID
    LogicalIDs    []LogicalIdFilter    // a rule (or every rule) on a named template entity
    ResourceTypes []ResourceTypeFilter // a rule (or every rule) on a resource type
    Services      []ServiceFilter      // a rule (or every rule) on a service, e.g. "AWS::AutoScaling"
}

// ResourceIDs / LogicalIDs / ResourceTypes / Services each carry an optional *RuleID:
// set it to scope the filter to one rule, or leave it nil for every rule on the target.
type ResourceIdFilter   struct { RuleID *string; ResourceID string }
type LogicalIdFilter    struct { RuleID *string; LogicalID string; EntityType *EntityType }
type ResourceTypeFilter struct { RuleID *string; ResourceType string }
type ServiceFilter      struct { RuleID *string; Service string }
```

The `Service` is matched verbatim against the `service-provider::service-name` prefix of the resource type - its first
two `::`-delimited segments (e.g. `AWS::AutoScaling` in `AWS::AutoScaling::LaunchConfiguration`).

The `ResourceIDs` dimension matches only diagnostics attributed to a resource; `LogicalIDs` additionally matches
diagnostics on parameters, outputs, mappings, conditions, and template rules (for resource diagnostics the two carry
the same value). A non-nil `EntityType` scopes a `LogicalIdFilter` to entities of one type, so `MyThing` as an
`EntityTypeParameter` is matched without touching a same-named entity of another type.

### PseudoParameterOverrides

Override CloudFormation pseudo-parameters used during intrinsic function resolution. All fields are optional - when
`nil`, the engine uses built-in defaults (e.g. region defaults to `us-east-1`).

```go
type PseudoParameterOverrides struct {
    AccountID        *string // AWS::AccountId
    NotificationARNs *string // AWS::NotificationARNs
    Partition        *string // AWS::Partition
    Region           *string // AWS::Region (default: "us-east-1")
    StackID          *string // AWS::StackId
    StackName        *string // AWS::StackName
    URLSuffix        *string // AWS::URLSuffix
}
```

## TemplateModel

Parses a template into the resolved `SemanticModel` for direct inspection - the same model the engines evaluate rules
against. Structured sections are returned as raw JSON (`json.RawMessage`) for the caller to decode.

```go
model, err := cfnvalidate.ParseTemplate(templateBytes)
if err != nil {
    log.Fatal(err)
}
defer model.Destroy()
```

| Method                                       | Returns                    | Description                                                                                     |
|----------------------------------------------|----------------------------|-------------------------------------------------------------------------------------------------|
| `cfnvalidate.ParseTemplate(template []byte)` | `(*TemplateModel, error)`  | Parses template bytes into a semantic model (package function)                                  |
| `Resources()`                                | `(json.RawMessage, error)` | All resources with resolved property values                                                     |
| `Parameters()`                               | `(json.RawMessage, error)` | Parameter definitions with types, defaults, constraints                                         |
| `Outputs()`                                  | `(json.RawMessage, error)` | Outputs with resolved values and export names                                                   |
| `Conditions()`                               | `([]string, error)`        | Condition names defined in the template                                                         |
| `Transforms()`                               | `([]string, error)`        | Transform declarations (e.g. `AWS::Serverless-2016-10-31`)                                      |
| `FormatVersion()`                            | `*string`                  | `AWSTemplateFormatVersion` value                                                                |
| `Description()`                              | `*string`                  | Template description                                                                            |
| `DiagnosticModel()`                          | `(json.RawMessage, error)` | Full diagnostic model including reference graph, condition implications, and resolution sources |
| `SourceLocation(path string)`                | `(*SourceSpan, error)`     | Source line/column span for a JSON path (e.g. `Resources/MyBucket/Properties/BucketName`)       |
| `Destroy()`                                  | -                          | Releases the model's off-heap memory; the model must not be used afterwards                     |

## SchemaValidator

Runs schema validation independently from the rule engines. Checks each resource against the compiled CloudFormation
provider schemas and produces `FATAL`-severity diagnostics for structural violations. The optional constructor argument
is the same `SchemaValidatorConfig` accepted by `EngineConfig`; passing `nil` uses only the bundled schemas.

```go
validator, err := cfnvalidate.NewSchemaValidator(nil)
if err != nil {
    log.Fatal(err)
}
defer validator.Destroy()
diagnostics, err := validator.Validate(templateBytes, nil)
```

| Method                                      | Returns                     | Description                                                                                                   |
|---------------------------------------------|-----------------------------|---------------------------------------------------------------------------------------------------------------|
| `cfnvalidate.NewSchemaValidator(config)`    | `(*SchemaValidator, error)` | Constructs a validator; a `nil` `*SchemaValidatorConfig` uses only the bundled schemas                        |
| `Validate(template []byte, region *string)` | `([]Diagnostic, error)`     | Schema diagnostics at `STANDARD` detail - the enrichment fields are nil. A `nil` region defaults to `"us-east-1"`. |
| `ListRules()`                               | `([]RuleInfo, error)`       | Schema rule metadata                                                                                          |
| `SchemaCount()`                             | `uint32`                    | Number of compiled provider schemas                                                                           |
| `Destroy()`                                 | -                           | Releases the validator's off-heap memory; the validator must not be used afterwards                           |

## AWS CLI command validation

`ValidateAWSCLICommand` models an AWS CLI (or SDK) API call as CloudFormation resource state and validates it offline
before it is sent. It classifies the operation, maps it to a CloudFormation resource type through a closed, generated
adapter catalog, synthesizes a template from the supplied parameters, and runs the normal template pipeline on it. A
`TemplateBody` parameter of a CloudFormation operation is validated as-is. Any request that cannot be modeled exactly -
an unregistered operation, a parameter without a lossless property mapping, or a value outside a CloudFormation
constraint the API itself does not enforce - is skipped with a reason, never guessed.

```go
validation, err := engine.ValidateAWSCLICommand(cfnvalidate.AWSCLICommand{
    ServiceName:   "s3",
    OperationName: "CreateBucket",
    Parameters:    map[string]any{"Bucket": "example-bucket"},
})
if err != nil {
    log.Fatal(err)
}
if validation.Status == cfnvalidate.AWSCLICommandValidationStatusValidated {
    for _, d := range validation.Report.Diagnostics {
        fmt.Printf("[%s] %s: %s\n", d.Severity, d.RuleID, d.Message)
    }
} else {
    fmt.Printf("skipped (%s): %s\n", validation.OperationKind, validation.Reason)
}
```

```go
type AWSCLICommand struct {
    ServiceName   string         // canonical botocore service name, e.g. "s3" or "cloudformation"
    OperationName string         // API operation name, e.g. "CreateBucket"
    Parameters    map[string]any // request parameters
    ServicePrefix string         // signing prefix; context only
    HTTPMethod    string         // classification hint ("GET"/"HEAD"/"DELETE") for unrecognized verbs
    IsReadOnly    *bool          // true classifies the operation as READ_ONLY
}
```

- `ServiceName` is matched case-insensitively. Signing names, endpoint aliases, and ARN prefixes are never resolved;
  translate an SDK's service identity first.
- `Parameters` accepts nested maps and slices, strings, integers, floats, booleans, `nil`, `[]byte`, `json.Number`,
  and `time.Time` (serialized as RFC 3339 UTC). Any other value is carried as an explicit unsupported marker, and
  because synthesis is all-or-nothing the request is then skipped with a reason naming the offending parameter - no
  parameter is ever silently dropped.

The result is an `*AWSCLICommandValidation`:

| Field            | Description                                                                                                                                                       |
|------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `OperationKind`  | `AWSCLIOperationKind`: `READ_ONLY`, `CLOUD_FORMATION_CREATE`, `CLOUD_FORMATION_UPDATE`, `CLOUD_FORMATION_DELETE`, `DATA_PLANE_MUTATION`, or `UNMAPPED_MUTATION` (constants `AWSCLIOperationKindReadOnly`, ...) |
| `Status`         | `AWSCLICommandValidationStatus`: `VALIDATED` when the modeled template ran through the pipeline, `SKIPPED` otherwise                                               |
| `TemplateSource` | `*AWSCLITemplateSource`: `TEMPLATE_BODY`, `CLOUD_CONTROL_DESIRED_STATE`, `SYNTHESIZED_CREATE`, or `SYNTHESIZED_UPDATE`; nil when skipped                          |
| `ResourceTypes`  | `[]string` - CloudFormation resource types the operation maps to                                                                                                  |
| `Reason`         | `string` - why the request was validated or skipped                                                                                                               |
| `Report`         | `*ValidationReport` - present when `VALIDATED`. The configuration is fixed: `STANDARD` detail level and a `WARN` severity floor                                    |
| `Template`       | `[]byte` - the exact template bytes that were validated (the caller's `TemplateBody` unchanged, or the synthesized JSON); nil when skipped                         |

The full contract - the adapter catalog, all-or-nothing mapping, and which rules are dropped for synthesized state -
is documented in [validation-engine/API.md](../validation-engine/API.md#validating-an-aws-cli-command).

## Report Types

### ValidationReport

`ValidateTemplate` and `ValidateTemplateFile` always return a `*ValidationReport` - a template syntax failure is
returned as a report with `StatusError` and an `F1101` diagnostic; only infrastructure or engine failures return an
`error`:

```go
type ValidationReport struct {
    FilePath    string
    Status      ReportStatus         // OK, ANALYSIS_INCOMPLETE (findings may be omitted), or ERROR (pipeline failure)
    Version     string
    Metadata    ReportMetadata
    Performance PerformanceMetrics
    Diagnostics []Diagnostic
}
```

Every finding is a `Diagnostic` (see [Diagnostic](#diagnostic)). Its enrichment fields - `DocumentationURL`,
`RuleDescription`, `Phase` (`PARSE` | `SCHEMA` | `LINT`), and `Context` (`*ViolationContext` with `ActualValue`,
`ExpectedConstraint`, `ResolutionSource`, etc.) - are populated only at `DetailLevel` `DETAILED` (the default);
validating at `STANDARD` leaves them nil, keeping the base diagnostic fields.

`Metadata` carries the summary counts, the number of suppressed diagnostics, the resources scanned and rules
evaluated, the strict flag and severity threshold used, and optional budget-exhaustion records. Each budget-exhaustion
record retains a stable machine-readable kind and also includes a human-readable description sentence, the numeric
limit, and whether that specific exhaustion makes analysis incomplete. `requiredPropertyCombinations` is context-only,
so its `AnalysisIncomplete` value is `false` and the report can remain `StatusOK`.

### Diagnostic

```go
type Diagnostic struct {
    RuleID            string            // e.g. "E3012", "F1001", "W3010"
    Severity          Severity          // FATAL, ERROR, WARN, INFO, DEBUG
    Message           string
    Source            RuleOrigin        // SCHEMA, CFN_LINT, ENGINE, CUSTOM, GUARD
    Entity            *Entity           // the named template entity the finding targets, if any
    PropertyPath      *string           // e.g. "Properties.BucketName", or section-absolute like "Parameters/MyParam/Type"
    SuggestedFix      *string
    Category          *string
    StartLine         *int
    StartColumn       *int
    EndLine           *int
    EndColumn         *int
    RelatedResources  []RelatedResource
    ConditionScenario map[string]bool   // condition truth assignment that triggers this diagnostic
    // Enrichment fields: populated at DetailLevel DETAILED (the default), nil at STANDARD.
    DocumentationURL  *string
    RuleDescription   *string
    Phase             *string           // PARSE | SCHEMA | LINT - pipeline stage that produced the finding
    Context           *ViolationContext // ActualValue, ExpectedConstraint, ResolutionSource, etc.
}

// The named template entity a diagnostic is attributed to. The entity type is the
// singular form of the top-level template section the entity is declared in.
type Entity struct {
    LogicalID    string     // logical ID as declared in the template
    EntityType   EntityType
    ResourceType *string    // CloudFormation type, when the entity is a resource whose type is known
}

// EntityType values: EntityTypeResource, EntityTypeParameter, EntityTypeOutput, EntityTypeMapping,
// EntityTypeMetadata, EntityTypeRule, EntityTypeCondition, EntityTypeTransform,
// EntityTypeFormatVersion, EntityTypeDescription (serialized as "Resource", "Parameter", ...).
```

`Severity`, `RuleOrigin`, `DetailLevel`, and `ReportStatus` are string types with named constants
(`cfnvalidate.SeverityWarn`, `cfnvalidate.RuleOriginGuard`, `cfnvalidate.DetailLevelStandard`, `cfnvalidate.StatusOK`,
...).
