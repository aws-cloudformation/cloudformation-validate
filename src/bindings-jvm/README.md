# CloudFormation Validate JVM Bindings

JVM bindings for [`cloudformation-validate`](https://github.com/aws-cloudformation/cloudformation-validate)
via [UniFFI](https://mozilla.github.io/uniffi-rs/). Compiles the full validation pipeline into a native shared library
with auto-generated Kotlin bindings, packaged as a JAR with bundled natives.

All types live in `software.amazon.cloudformation.validate`.

For a complete, runnable example, see
[examples](https://github.com/aws-cloudformation/cloudformation-validate/tree/main/src/bindings-jvm/examples).

## Engine

`RegoEngine` and `CelEngine` both implement the `Engine` interface. They are interchangeable — both produce identical
diagnostics for the same template and config.

```kotlin
import software.amazon.cloudformation.validate.*
import java.io.File

val engine = RegoEngine()
val report = engine.validateStandard(File("template.yaml"))

for (d in report.diagnostics) {
    println("[${d.severity}] ${d.ruleId}: ${d.message}")
}
```

### `Engine` interface

```kotlin
interface Engine {
    fun validateStandard(template: File, config: ValidateConfig = ValidateConfig()): StandardReport
    fun validateDetailed(template: File, config: ValidateConfig = ValidateConfig()): DetailedReport
    fun listRules(): List<RuleInfo>
    fun engineName(): String
}
```

| Method                               | Returns          | Description                                                                                                      |
|--------------------------------------|------------------|------------------------------------------------------------------------------------------------------------------|
| `validateStandard(template, config)` | `StandardReport` | Validates and returns diagnostics without extended context                                                       |
| `validateDetailed(template, config)` | `DetailedReport` | Validates and returns diagnostics with documentation URLs, rule descriptions, phase tags, and `ViolationContext` |
| `listRules()`                        | `List<RuleInfo>` | Returns metadata for every built-in and loaded custom rule                                                       |
| `engineName()`                       | `String`         | `"rego"` or `"cel"`                                                                                              |

`template` is a `java.io.File` — the engine reads the bytes and uses the file path for diagnostic source locations.

### `EngineConfig`

Passed to the constructor. All fields default to empty lists.

```kotlin
val engine = RegoEngine()                                          // default config
val engine = CelEngine(EngineConfig(guardRules = listOf(myRule)))  // with Guard rules
```

| Field         | Default       | Description                                                           |
|---------------|---------------|-----------------------------------------------------------------------|
| `customRules` | `emptyList()` | Engine-native rules (Rego for `RegoEngine`, CEL for `CelEngine`)      |
| `guardRules`  | `emptyList()` | CloudFormation Guard DSL rules — translated internally by each engine |

Each rule is an `ExternalRuleSource(name, content)` where `name` identifies the rule in diagnostics and `content` is the
full source text.

## ValidateConfig

Controls filtering, severity, parameter overrides, and behavior. All fields have defaults — passing `ValidateConfig()`
uses them.

```kotlin
val config = ValidateConfig(
    exclude = RuleFilterConfig(ids = listOf("I1002")),
    severityLevel = Severity.WARN,
)
val report = engine.validateStandard(File("template.yaml"), config)
```

| Field                      | Default                  | Description                                                                                                              |
|----------------------------|--------------------------|--------------------------------------------------------------------------------------------------------------------------|
| `include`                  | empty (all rules)        | When set, only matching rules produce diagnostics. Empty means include everything.                                       |
| `exclude`                  | empty (nothing excluded) | Matching rules are suppressed. Applied after `include`.                                                                  |
| `severityLevel`            | `INFO`                   | Minimum severity threshold. Diagnostics below this level are dropped. Values: `DEBUG`, `INFO`, `WARN`, `ERROR`, `FATAL`. |
| `parameterOverrides`       | `emptyMap()`             | Override template parameter values during resolution. Keys are parameter logical IDs.                                    |
| `pseudoParameterOverrides` | all `null`               | Override CloudFormation pseudo-parameters (`AWS::AccountId`, `AWS::Region`, etc.).                                       |
| `strict`                   | `false`                  | When `true`, `WARN`-severity diagnostics are upgraded to `ERROR`.                                                        |
| `disableBuiltinRules`      | `false`                  | When `true`, all built-in rules (schema validation, Step Functions, engine rules) are skipped; only custom and Guard rules are evaluated. |

### RuleFilterConfig

Both `include` and `exclude` use this structure. All fields are additive — a rule matches if it hits any criterion.

```kotlin
data class RuleFilterConfig(
    val ids: List<String> = emptyList(),                       // exact rule IDs, e.g. ["E3012", "W3010"]
    val categories: List<String> = emptyList(),                // category names, e.g. ["security", "best_practices"]
    val idRanges: List<IdRange> = emptyList(),                 // numeric ranges, e.g. IdRange("E", 3000, 3099)
    val idPatterns: List<String> = emptyList(),                // regex patterns matched against rule IDs
    val resourceIds: List<ResourceIdFilter> = emptyList(),     // a rule (or every rule) on a logical resource ID
    val resourceTypes: List<ResourceTypeFilter> = emptyList(), // a rule (or every rule) on a resource type
    val services: List<ServiceFilter> = emptyList(),           // a rule (or every rule) on a service, e.g. "AWS::AutoScaling"
)

// resourceIds / resourceTypes / services each carry a nullable ruleId:
// set it to scope the filter to one rule, or leave it null for every rule on the target.
data class ResourceIdFilter(val ruleId: String? = null, val resourceId: String)
data class ResourceTypeFilter(val ruleId: String? = null, val resourceType: String)
data class ServiceFilter(val ruleId: String? = null, val service: String)
```

The `service` is matched verbatim against the `service-provider::service-name` prefix of the resource type — its first
two `::`-delimited segments (e.g. `AWS::AutoScaling` in `AWS::AutoScaling::LaunchConfiguration`).

### PseudoParameterOverrides

Override CloudFormation pseudo-parameters used during intrinsic function resolution. All fields optional — when `null`,
the engine uses built-in defaults (e.g. region defaults to `us-east-1`).

```kotlin
data class PseudoParameterOverrides(
    val accountId: String? = null,         // AWS::AccountId
    val notificationArns: String? = null,  // AWS::NotificationARNs
    val partition: String? = null,         // AWS::Partition
    val region: String? = null,            // AWS::Region (default: "us-east-1")
    val stackId: String? = null,           // AWS::StackId
    val stackName: String? = null,         // AWS::StackName
    val urlSuffix: String? = null,         // AWS::URLSuffix
)
```

## TemplateModel

Parses a template into the resolved `SemanticModel` for direct inspection — the same model the engines evaluate rules
against.

```kotlin
val model = TemplateModel(File("template.yaml"))
```

| Method                 | Returns                         | Description                                                                                     |
|------------------------|---------------------------------|-------------------------------------------------------------------------------------------------|
| `resources()`          | `Map<String, ResolvedResource>` | All resources with resolved property values                                                     |
| `parameters()`         | `Map<String, ParameterInfo>`    | Parameter definitions with types, defaults, constraints                                         |
| `outputs()`            | `Map<String, ResolvedOutput>`   | Outputs with resolved values and export names                                                   |
| `conditions()`         | `List<String>`                  | Condition names defined in the template                                                         |
| `transforms()`         | `List<String>`                  | Transform declarations (e.g. `AWS::Serverless-2016-10-31`)                                      |
| `formatVersion()`      | `String?`                       | `AWSTemplateFormatVersion` value                                                                |
| `description()`        | `String?`                       | Template description                                                                            |
| `toDiagnosticModel()`  | `DiagnosticModel`               | Full diagnostic model including reference graph, condition implications, and resolution sources |
| `sourceLocation(path)` | `SourceSpan?`                   | Source line/column span for a JSON path (e.g. `Resources/MyBucket/Properties/BucketName`)       |

## SchemaValidator

Runs schema validation independently from the rule engines. Checks each resource against compiled CloudFormation
provider schemas and produces `FATAL`-severity diagnostics for structural violations.

```kotlin
val validator = SchemaValidator()
val diagnostics = validator.validate(File("template.yaml"))
```

| Method                       | Returns                    | Description                                             |
|------------------------------|----------------------------|---------------------------------------------------------|
| `validate(template, region)` | `List<StandardDiagnostic>` | Schema diagnostics. `region` defaults to `"us-east-1"`. |
| `listRules()`                | `List<RuleInfo>`           | Schema rule metadata                                    |
| `schemaCount()`              | `Int`                      | Number of compiled provider schemas                     |

## Report Types

### StandardReport / DetailedReport

```kotlin
data class StandardReport(
    val filePath: String,
    val status: ReportStatus,            // OK or ERROR (ERROR when template fails to parse)
    val version: String,
    val metadata: ReportMetadata,
    val performance: PerformanceMetrics,
    val diagnostics: List<StandardDiagnostic>,
)
```

`DetailedReport` has the same structure but its diagnostics include additional fields: `documentationUrl`,
`ruleDescription`, `phase` (`PARSE` | `SCHEMA` | `LINT`), `section`, and `context` (`ViolationContext` with
`actualValue`, `expectedConstraint`, `resolutionSource`, etc.).

### StandardDiagnostic

```kotlin
data class StandardDiagnostic(
    val ruleId: String,                    // e.g. "E3012", "F1001", "W3010"
    val severity: Severity,                // FATAL, ERROR, WARN, INFO, DEBUG
    val message: String,
    val source: RuleOrigin,                // SCHEMA, CFN_LINT, ENGINE, CUSTOM, GUARD
    val resourceId: String?,               // logical resource ID
    val resourceType: String?,             // e.g. "AWS::S3::Bucket"
    val propertyPath: String?,             // e.g. "Properties/BucketName"
    val suggestedFix: String?,
    val category: String?,
    val startLine: UInt?,
    val startColumn: UInt?,
    val endLine: UInt?,
    val endColumn: UInt?,
    val relatedResources: List<RelatedResource>?,
    val conditionScenario: Map<String, Boolean>?,  // condition truth assignment that triggers this
)
```
