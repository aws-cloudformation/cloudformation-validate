# CloudFormation Validate for Go

Validate AWS CloudFormation templates from Go and catch schema violations, security risks, and best-practice
findings before deployment — in your editor, build, or CI.

- **Offline** — all rules and resource schemas are bundled.
- **Fast** — sub-second validation per template.
- **Self-contained** — the Rust core is linked statically via cgo; there are no runtime dependencies.

All types are exported from the `cfnvalidate` package (import path
`github.com/aws-cloudformation/cloudformation-validate/src/bindings-go/go`).

## Installation

```bash
go get github.com/aws-cloudformation/cloudformation-validate/src/bindings-go/go
```

```go
import cfnvalidate "github.com/aws-cloudformation/cloudformation-validate/src/bindings-go/go"
```

Requires Go 1.26+ with cgo enabled (the default) and a C toolchain for linking. The module bundles a prebuilt static
library for each supported platform (Linux x86-64, macOS aarch64, Windows x86-64) and selects the right one per
`GOOS`/`GOARCH`. On Windows, link with the MinGW-w64 toolchain — the bundled Windows library is built for the GNU ABI
and cannot be consumed by MSVC.

## Quick start

Native objects hold off-heap memory — call `Destroy()` when done with each engine, model, or validator:

```go
engine, err := cfnvalidate.NewRegoEngine(nil)
if err != nil {
    log.Fatal(err)
}
defer engine.Destroy()

report, err := engine.ValidateStandardFile("template.yaml", nil)
if err != nil {
    log.Fatal(err)
}
for _, d := range report.Diagnostics {
    fmt.Printf("[%s] %s: %s\n", d.Severity, d.RuleID, d.Message)
}
```

Each diagnostic identifies the rule, severity, affected resource and property, and source location — see
[StandardDiagnostic](#standarddiagnostic). Engines are expensive to construct (rules compile once) and cheap to reuse
— create one engine and validate many templates. Errors from the native side are returned as Go `error` values;
internal panics are caught at the FFI boundary and surface the same way, never a process abort.

## Engine

`NewRegoEngine` and `NewCelEngine` both return an `*Engine` and are interchangeable — they produce identical
diagnostics for the same template and config. A `nil` config uses only the built-in rules.

| Method                                                                       | Returns                    | Description                                                                                     |
|------------------------------------------------------------------------------|----------------------------|-------------------------------------------------------------------------------------------------|
| `ValidateStandard(template []byte, config *ValidateConfig, filePath string)` | `(*StandardReport, error)` | Validates bytes without extended context. `filePath` labels the report; `""` uses `"template"`. |
| `ValidateStandardFile(path string, config *ValidateConfig)`                  | `(*StandardReport, error)` | Reads a template from disk, then validates it                                                   |
| `ValidateDetailed(template []byte, config *ValidateConfig, filePath string)` | `(*DetailedReport, error)` | Validates bytes with documentation URLs, rule descriptions, phase tags, and `ViolationContext`  |
| `ValidateDetailedFile(path string, config *ValidateConfig)`                  | `(*DetailedReport, error)` | Reads a template from disk, then validates it (detailed)                                        |
| `ListRules()`                                                                | `([]RuleInfo, error)`      | Returns metadata for every built-in and loaded custom rule                                      |
| `EngineName()`                                                               | `string`                   | `"rego"` or `"cel"`                                                                             |
| `Destroy()`                                                                  | —                          | Releases the native engine; the engine must not be used afterwards                              |

### EngineConfig

Passed to `NewRegoEngine` / `NewCelEngine`. The zero value (or `nil`) uses only the built-in rules.

```go
type EngineConfig struct {
    CustomRules     []ExternalRuleSource  // engine-native rules (Rego for Rego, CEL for CEL)
    GuardRules      []ExternalRuleSource  // CloudFormation Guard DSL rules — translated internally by each engine
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

## ValidateConfig

Controls filtering, severity, parameter overrides, and behavior. A `nil` `*ValidateConfig` uses the defaults.

```go
config := &cfnvalidate.ValidateConfig{
    Exclude:       &cfnvalidate.RuleFilterConfig{IDs: []string{"I1002"}},
    SeverityLevel: cfnvalidate.SeverityWarn,
}
report, err := engine.ValidateStandardFile("template.yaml", config)
```

```go
type ValidateConfig struct {
    Include                  *RuleFilterConfig
    Exclude                  *RuleFilterConfig
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
| `SeverityLevel`            | `INFO`                   | Minimum severity threshold. Diagnostics below this level are dropped. Values: `DEBUG`, `INFO`, `WARN`, `ERROR`, `FATAL`.                  |
| `ParameterOverrides`       | `nil`                    | Override template parameter values during resolution. Keys are parameter logical IDs.                                                     |
| `PseudoParameterOverrides` | `nil`                    | Override CloudFormation pseudo-parameters (`AWS::AccountId`, `AWS::Region`, etc.).                                                        |
| `Strict`                   | `false`                  | When `true`, `WARN`-severity diagnostics are upgraded to `ERROR`.                                                                         |
| `DisableBuiltinRules`      | `false`                  | When `true`, all built-in rules (schema validation, Step Functions, engine rules) are skipped; only custom and Guard rules are evaluated. |

### RuleFilterConfig

Both `Include` and `Exclude` use this structure. All fields are additive — a rule matches if it hits any criterion.

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

The `Service` is matched verbatim against the `service-provider::service-name` prefix of the resource type — its first
two `::`-delimited segments (e.g. `AWS::AutoScaling` in `AWS::AutoScaling::LaunchConfiguration`).

The `ResourceIDs` dimension matches only diagnostics attributed to a resource; `LogicalIDs` additionally matches
diagnostics on parameters, outputs, mappings, conditions, and template rules (for resource diagnostics the two carry
the same value). A non-nil `EntityType` scopes a `LogicalIdFilter` to entities of one type, so `MyThing` as a
`EntityTypeParameter` is matched without touching a same-named entity of another type.

### PseudoParameterOverrides

Override CloudFormation pseudo-parameters used during intrinsic function resolution. All fields optional — when `nil`,
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

## TemplateModel

Parses a template into the resolved `SemanticModel` for direct inspection — the same model the engines evaluate rules
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
| `Destroy()`                                  | —                          | Releases the native model; it must not be used afterwards                                       |

## SchemaValidator

Runs schema validation independently from the rule engines. Checks each resource against compiled CloudFormation
provider schemas and produces `FATAL`-severity diagnostics for structural violations.

```go
validator := cfnvalidate.NewSchemaValidator()
defer validator.Destroy()
diagnostics, err := validator.Validate(templateBytes, nil)
```

| Method                                      | Returns                         | Description                                                   |
|---------------------------------------------|---------------------------------|---------------------------------------------------------------|
| `cfnvalidate.NewSchemaValidator()`          | `*SchemaValidator`              | Constructs a validator over the compiled schemas              |
| `Validate(template []byte, region *string)` | `([]StandardDiagnostic, error)` | Schema diagnostics. `nil` region defaults to `"us-east-1"`.   |
| `ListRules()`                               | `([]RuleInfo, error)`           | Schema rule metadata                                          |
| `SchemaCount()`                             | `uint32`                        | Number of compiled provider schemas                           |
| `Destroy()`                                 | —                               | Releases the native validator; it must not be used afterwards |

## Report Types

### StandardReport / DetailedReport

```go
type StandardReport struct {
    FilePath    string
    Status      ReportStatus         // StatusOK or StatusError (StatusError when the template fails to parse)
    Version     string
    Metadata    ReportMetadata
    Performance PerformanceMetrics
    Diagnostics []StandardDiagnostic
}
```

`DetailedReport` has the same structure but its diagnostics are `DetailedDiagnostic`, which embed
`StandardDiagnostic` and add `DocumentationURL`, `RuleDescription`, `Phase` (`PARSE` | `SCHEMA` | `LINT`), and
`Context` (a `*ViolationContext` with `ActualValue`, `ExpectedConstraint`, `ResolutionSource`, etc.).

### StandardDiagnostic

```go
type StandardDiagnostic struct {
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
    ConditionScenario map[string]bool // condition truth assignment that triggers this diagnostic
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
`cfnvalidate.RuleOriginGuard`, …); `ReportStatus` is `StatusOK` / `StatusError`.
