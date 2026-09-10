# CloudFormation Validate for Go

Validate AWS CloudFormation templates from Go and catch schema violations, security risks, and best-practice
findings before deployment - in your editor, build, or CI.

- **Offline** - all rules and resource schemas are bundled.
- **Fast** - sub-second validation per template.
- **Self-contained** - the Rust core is linked statically via cgo; there are no runtime dependencies.

All types are exported from the `cfnvalidate` package (import path
`github.com/aws-cloudformation/cloudformation-validate/src/bindings-go/go`).

## Installation

```bash
go get github.com/aws-cloudformation/cloudformation-validate/src/bindings-go/go
```

```go
import cfnvalidate "github.com/aws-cloudformation/cloudformation-validate/src/bindings-go/go"
```

Requires Go 1.26+ with cgo enabled (the default) and a C toolchain for linking. The module bundles prebuilt static
libraries for Linux and macOS on x86-64 and ARM64, plus Windows on x86-64, and selects the matching library for
`GOOS`/`GOARCH`. On Windows, link with MinGW-w64. The bundled Windows library uses the GNU ABI and cannot be consumed
by MSVC.

## Quick start

Native objects hold off-heap memory - call `Destroy()` when done with each engine, model, or validator:

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

Each diagnostic identifies the rule, severity, affected resource and property, and source location - see
[Diagnostic](#diagnostic). Engines are expensive to construct (rules compile once) and cheap to reuse
- create one engine and validate many templates. Errors from the native side are returned as Go `error` values;
internal panics are caught at the FFI boundary and surface the same way, never a process abort.

## Engine

`NewRegoEngine` and `NewCelEngine` both return an `*Engine` and are interchangeable - they produce identical
diagnostics for the same template and config. A `nil` config uses only the built-in rules.

`NewCompositeEngine` also returns an `*Engine`: it evaluates the built-in rules with one engine and caller-supplied
external Rego and Guard rules with another, producing the same built-in diagnostics plus any external findings. See
[CompositeEngineConfig](#compositeengineconfig).

| Method                                                                       | Returns                             | Description                                                                                     |
|------------------------------------------------------------------------------|-------------------------------------|-------------------------------------------------------------------------------------------------|
| `ValidateTemplate(template []byte, config *ValidateConfig, filePath string)` | `(*ValidationReport, error)`        | Validates bytes; `config.DetailLevel` selects the detail level; `filePath` labels the report.   |
| `ValidateTemplateFile(path string, config *ValidateConfig)`                  | `(*ValidationReport, error)`        | Reads a template from disk, then validates it                                                   |
| `ValidateAWSCLICommand(request AWSCLICommand, config *ValidateConfig)`       | `(*AWSCLICommandValidation, error)` | Classifies and validates an AWS CLI command offline                                             |
| `ListRules()`                                                                | `([]RuleInfo, error)`               | Returns metadata for every built-in and loaded custom rule                                      |
| `EngineName()`                                                               | `string`                            | `"rego"`, `"cel"`, or `"composite"`                                                             |
| `Destroy()`                                                                  | -                                   | Releases the native engine; the engine must not be used afterwards                              |

Validation returns a `*ValidationReport`. `config.DetailLevel` selects the detail: `DETAILED` (the default
when unset) enriches each diagnostic with documentation URLs, rule descriptions, phase tags, and `ViolationContext`,
while `STANDARD` leaves those fields nil. An empty `filePath` labels the report `"template"`.

### EngineConfig

Passed to `NewRegoEngine` / `NewCelEngine`. The zero value (or `nil`) uses only the built-in rules.

```go
type EngineConfig struct {
    CustomRules     []ExternalRuleSource   // engine-native rules (Rego for Rego, CEL for CEL)
    GuardRules      []ExternalRuleSource   // CloudFormation Guard DSL rules - translated internally by each engine
    SchemaValidatorConfig *SchemaValidatorConfig // optional schema validator configuration
}

// Name identifies the rule in diagnostics; Content is the full rule source text.
type ExternalRuleSource struct {
    Name    string
    Content string
}

// TypeName is optional; leave it nil to use the typeName inside Schema.
type AdditionalSchemaSource struct {
    TypeName *string
    Schema   string
}

// SchemaValidatorConfig configures the validator bundled by the engine.
// Additional schemas extend the bundled resource provider schemas or register
// new resource types.
type SchemaValidatorConfig struct {
    AdditionalSchemas []AdditionalSchemaSource
}
```

Read schema and rule content yourself and pass it through the typed config:

```go
schema, _ := os.ReadFile("schemas/aws-lambda-function.json")
guard, _ := os.ReadFile("rules/compliance.guard")
custom, _ := os.ReadFile("rules/s3_encryption.json")
engine, err := cfnvalidate.NewCelEngine(&cfnvalidate.EngineConfig{
    CustomRules: []cfnvalidate.ExternalRuleSource{{Name: "s3_encryption.json", Content: string(custom)}},
    GuardRules:  []cfnvalidate.ExternalRuleSource{{Name: "compliance.guard", Content: string(guard)}},
    SchemaValidatorConfig: &cfnvalidate.SchemaValidatorConfig{
        AdditionalSchemas: []cfnvalidate.AdditionalSchemaSource{{Schema: string(schema)}},
    },
})
```

### CompositeEngineConfig

Passed to `NewCompositeEngine`. The zero value (or `nil`) uses only the built-in rules. Unlike `EngineConfig` it has no
field for engine-native built-in custom rules, because the composite fixes which engine owns the built-ins - it carries
only the external Rego and Guard rules layered on top, plus a schema config observed by both.

```go
type CompositeEngineConfig struct {
    RegoRules             []ExternalRuleSource   // custom Rego rules for the external engine
    CelRules              []ExternalRuleSource   // custom CEL rules for the built-in CEL engine
    GuardRules            []ExternalRuleSource   // CloudFormation Guard DSL rules - translated internally
    SchemaValidatorConfig *SchemaValidatorConfig // optional schema validator configuration, observed by both engines
}
```

```go
guard, _ := os.ReadFile("rules/compliance.guard")
engine, err := cfnvalidate.NewCompositeEngine(&cfnvalidate.CompositeEngineConfig{
    GuardRules: []cfnvalidate.ExternalRuleSource{{Name: "compliance.guard", Content: string(guard)}},
})
```

## ValidateConfig

Controls filtering, severity, parameter overrides, and behavior. A `nil` `*ValidateConfig` uses the defaults.

```go
config := &cfnvalidate.ValidateConfig{
    Exclude:       &cfnvalidate.RuleFilterConfig{IDs: []string{"I1002"}},
    SeverityLevel: cfnvalidate.SeverityWarn,
}
report, err := engine.ValidateTemplateFile("template.yaml", config)
```

```go
type ValidateConfig struct {
    Include                  *RuleFilterConfig
    Exclude                  *RuleFilterConfig
    DetailLevel              DetailLevel
    SeverityLevel            Severity
    ParameterOverrides       map[string]string
    PseudoParameterOverrides *PseudoParameterOverrides
    Strict                   *bool
    DisableBuiltinRules      *bool
}
```

| Field                      | Default                  | Description                                                                                                                               |
|----------------------------|--------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| `Include`                  | `nil` (all rules)        | When set, only matching rules produce diagnostics. Empty means include everything.                                                        |
| `Exclude`                  | `nil` (nothing excluded) | Matching rules are suppressed. Applied after `Include`.                                                                                   |
| `DetailLevel`              | `DETAILED`               | Report detail level. `DETAILED` (the default) adds documentation URLs, rule descriptions, phase tags, and `ViolationContext`; `STANDARD` omits them. |
| `SeverityLevel`            | `INFO`                   | Minimum severity threshold. Diagnostics below this level are dropped. Values: `DEBUG`, `INFO`, `WARN`, `ERROR`, `FATAL`.                  |
| `ParameterOverrides`       | `nil`                    | Override template parameter values during resolution. Keys are parameter logical IDs.                                                     |
| `PseudoParameterOverrides` | `nil`                    | Override CloudFormation pseudo-parameters (`AWS::AccountId`, `AWS::Region`, etc.).                                                        |
| `Strict`                   | `false`                  | When `true`, `WARN`-severity diagnostics are upgraded to `ERROR`.                                                                         |
| `DisableBuiltinRules`      | `false`                  | When `true`, all built-in rules (schema validation, Step Functions, engine rules) are skipped; only custom and Guard rules are evaluated. |

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
type ServiceFilter       struct { RuleID *string; Service string }
```

The `Service` is matched verbatim against the `service-provider::service-name` prefix of the resource type - its first
two `::`-delimited segments (e.g. `AWS::AutoScaling` in `AWS::AutoScaling::LaunchConfiguration`).

The `ResourceIDs` dimension matches only diagnostics attributed to a resource; `LogicalIDs` additionally matches
diagnostics on parameters, outputs, mappings, conditions, and template rules (for resource diagnostics the two carry
the same value). A non-nil `EntityType` scopes a `LogicalIdFilter` to entities of one type, so `MyThing` as a
`EntityTypeParameter` is matched without touching a same-named entity of another type.

### PseudoParameterOverrides

Override CloudFormation pseudo-parameters used during intrinsic function resolution. All fields optional - when `nil`,
the engine uses built-in defaults (e.g. region defaults to `us-east-1`).

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

## AWS CLI Command Validation

Validates an AWS CLI command by classifying the operation, inferring the CloudFormation resource type, and running
schema and rule validation against a synthesized template - entirely offline. The method returns classification
metadata and an optional `ValidationReport` when the request was validated (not skipped for read-only operations). The
report is projected at the `STANDARD` detail level: enrichment fields are nil because a synthesized template has no
user-authored source to annotate.

```go
engine, _ := cfnvalidate.NewRegoEngine(nil)
defer engine.Destroy()

result, err := engine.ValidateAWSCLICommand(cfnvalidate.AWSCLICommand{
    ServiceName:   "s3",
    OperationName: "CreateBucket",
    Parameters:    map[string]any{"Bucket": "my-bucket"},
    HTTPMethod:    "PUT",
}, nil)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Kind: %s  Status: %s  Types: %v\n",
    result.OperationKind, result.Status, result.ResourceTypes)
if result.Report != nil {
    for _, d := range result.Report.Diagnostics {
        fmt.Printf("  [%s] %s: %s\n", d.Severity, d.RuleID, d.Message)
    }
}
```

### AWSCLICommand

```go
type AWSCLICommand struct {
    ServiceName   string         // canonical botocore service name (e.g. "s3") - ASCII case-insensitive
    OperationName string         // operation name (e.g. "CreateBucket") - case-sensitive
    Parameters    map[string]any // request parameters: strings, numbers, booleans, []byte, maps, slices, nil
    ServicePrefix string         // optional signing prefix (e.g. "cloudcontrolapi")
    HTTPMethod    string         // optional HTTP method hint for classification
    IsReadOnly    *bool          // explicit read-only flag - skips validation when true
}
```

`Parameters` values are recursively encoded into the core's tagged value representation. Supported Go types: `nil`,
`bool`, all signed/unsigned integer widths, `float32`/`float64` (finite only), `string`, `[]byte` (as byte arrays),
`time.Time` (as an RFC 3339 UTC string), `json.Number`, slices/arrays, and `map[string]any`. Integer-valued
`json.Number` inputs are preserved across the full signed and unsigned 64-bit range; integer literals outside that range
are represented as unsupported rather than rounded through `float64`. SDK-defined type aliases (e.g.
`types.InstanceType` which is `type InstanceType string`) are handled transparently via their underlying kind.
Non-finite floats, maps with non-string keys, and unsupported types are represented as `UNSUPPORTED` rather than
coerced.

The canonical `ServiceName` is authoritative; the optional `ServicePrefix` is context only and cannot override it.
`ServiceName` must be the exact canonical botocore service name, normalized only for ASCII case. The core does not
guess signing, endpoint, or punctuation aliases and never matches on substrings. Any caller, including a future AWS
SDK adapter in any language, must translate its native service identity to the canonical botocore `ServiceName` before
invoking this API. `TemplateBody` validation is restricted to CloudFormation operations that accept it, and
`TypeName`+`DesiredState` wrapping applies only to exact Cloud Control `CreateResource`.

### AWSCLICommandValidation

```go
type AWSCLICommandValidation struct {
    OperationKind  AWSCLIOperationKind           // READ_ONLY, CLOUD_FORMATION_CREATE, etc.
    Status         AWSCLICommandValidationStatus // VALIDATED or SKIPPED
    TemplateSource *AWSCLITemplateSource         // TEMPLATE_BODY, SYNTHESIZED_CREATE, etc.
    ResourceTypes  []string                      // inferred CloudFormation resource types
    Reason         string                        // human-readable explanation
    Report         *ValidationReport             // present only when Status is VALIDATED
    Template       []byte                        // exact validated/synthesized template bytes; nil when SKIPPED
}
```

`Template` carries the exact bytes that were validated - the caller's original `TemplateBody` without reserializing, or
the synthesized JSON template for adapter-mapped requests - so consumers can display the modeled template that produced
the diagnostics. It is nil when the request was skipped. The core serializes these bytes as a JSON integer array, which
the Go decoder converts back into a `[]byte`.

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
| `Resources()`                                | `(json.RawMessage, error)` | Resolved resources, keyed by logical ID                                                         |
| `Parameters()`                               | `(json.RawMessage, error)` | Parameter definitions with types, defaults, constraints                                         |
| `Outputs()`                                  | `(json.RawMessage, error)` | Outputs with resolved values and export names                                                   |
| `Conditions()`                               | `([]string, error)`        | Condition names defined in the template                                                         |
| `Transforms()`                               | `([]string, error)`        | Transform declarations (e.g. `AWS::Serverless-2016-10-31`)                                      |
| `FormatVersion()`                            | `*string`                  | `AWSTemplateFormatVersion` value                                                                |
| `Description()`                              | `*string`                  | Template description                                                                            |
| `DiagnosticModel()`                          | `(json.RawMessage, error)` | Full diagnostic model including reference graph, condition implications, and resolution sources |
| `SourceLocation(path string)`                | `(*SourceSpan, error)`     | Source line/column span for a JSON path (e.g. `Resources/MyBucket/Properties/BucketName`)       |
| `Destroy()`                                  | -                          | Releases the native model; it must not be used afterwards                                       |

## SchemaValidator

Runs schema validation independently from the rule engines. Checks each resource against compiled CloudFormation
provider schemas and produces `FATAL`-severity diagnostics for structural violations.

```go
validator, err := cfnvalidate.NewSchemaValidator(nil)
if err != nil {
    log.Fatal(err)
}
defer validator.Destroy()
diagnostics, err := validator.Validate(templateBytes, nil)
if err != nil {
    log.Fatal(err)
}
```

| Method                                            | Returns                       | Description                                                   |
|---------------------------------------------------|-------------------------------|---------------------------------------------------------------|
| `cfnvalidate.NewSchemaValidator(config)`          | `(*SchemaValidator, error)`   | Constructs a validator; `nil` uses only the bundled schemas   |
| `Validate(template []byte, region *string)`       | `([]Diagnostic, error)`       | Schema diagnostics. `nil` region defaults to `"us-east-1"`.   |
| `ListRules()`                                     | `([]RuleInfo, error)`         | Schema rule metadata                                          |
| `SchemaCount()`                                   | `uint32`                      | Number of compiled provider schemas                           |
| `Destroy()`                                       | -                             | Releases the native validator; it must not be used afterwards |

## Report Types

### ValidationReport

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

`ValidationReport` is returned by template validation. Its diagnostics are `Diagnostic` - a single flattened finding
that always carries the rule, severity, affected resource and property, and source location, plus the enrichment fields `DocumentationURL`, `RuleDescription`, `Phase` (`PARSE` | `SCHEMA` | `LINT`), and `Context` (a
`*ViolationContext` with `ActualValue`, `ExpectedConstraint`, `ResolutionSource`, etc.). Those enrichment fields are
populated when validation runs at the `DETAILED` detail level and left nil at `STANDARD`.

Each optional budget-exhaustion record retains a stable machine-readable kind and also includes a
human-readable description sentence, the numeric limit, and whether that specific exhaustion makes analysis
incomplete. `requiredPropertyCombinations` is context-only, so its `AnalysisIncomplete` value is `false` and the
report can remain `StatusOK`.

### Diagnostic

```go
type Diagnostic struct {
    RuleID            string          // e.g. "E3012", "F1001", "W3010"
    Severity          Severity        // FATAL, ERROR, WARN, INFO, DEBUG
    Message           string
    Source            RuleOrigin      // SCHEMA, CFN_LINT, ENGINE, CUSTOM, GUARD
    Entity            *Entity         // the named template entity the finding targets, if any
    PropertyPath      *string         // e.g. "Properties.BucketName", or section-absolute like "Parameters/MyParam/Type"
    SuggestedFix      *string
    Category          *string
    StartLine         *int
    StartColumn       *int
    EndLine           *int
    EndColumn         *int
    RelatedResources  []RelatedResource
    ConditionScenario map[string]bool   // condition truth assignment that triggers this diagnostic
    DocumentationURL  *string           // DETAILED level only
    RuleDescription   *string           // DETAILED level only
    Phase             *string           // PARSE | SCHEMA | LINT; DETAILED level only
    Context           *ViolationContext // DETAILED level only
}

// The named template entity a diagnostic is attributed to. The entity type is the
// singular form of the top-level template section the entity is declared in.
type Entity struct {
    LogicalID    string
    EntityType   EntityType
    ResourceType *string // CloudFormation type, when the entity is a resource whose type is known
}

// EntityType values: EntityTypeResource, EntityTypeParameter, EntityTypeOutput, EntityTypeMapping,
// EntityTypeMetadata, EntityTypeRule, EntityTypeCondition, EntityTypeTransform,
// EntityTypeFormatVersion, EntityTypeDescription (serialized as "Resource", "Parameter", …).
```

`Severity` and `RuleOrigin` are string types with named constants (`cfnvalidate.SeverityWarn`,
`cfnvalidate.RuleOriginGuard`, …); `ReportStatus` is `StatusOK`, `StatusAnalysisIncomplete`, or `StatusError`;
`DetailLevel` is `DetailLevelStandard` or `DetailLevelDetailed`.
