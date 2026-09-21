# AWS CloudFormation Validate

Validate AWS CloudFormation templates from Kotlin or Java and catch schema violations, semantic errors, security risks,
and best-practice findings before deployment - in your editor, build, service, or CI.

- **Offline** - all rules and CloudFormation resource schemas are bundled; nothing is fetched at runtime and no AWS
  credentials are needed.
- **Fast** - engines and schemas compile once and are reused across validations; typical templates validate in under a
  second.
- **Self-contained** - the jar bundles the native library for every supported platform and loads the matching one at
  runtime.

The entry points - `Engine`, `RegoEngine`, `CelEngine`, `CompositeEngine`, `TemplateModel`, `SchemaValidator`,
`ValidateConfig`, `AwsCliCommand`, `ValidationException`, the `fileTo*` helpers, and `version()` - live in the
`software.amazon.cloudformation.validate` package. The data types they use live in sub-packages: `engine`
(`EngineConfig`, `CompositeEngineConfig`, `ExternalRuleSource`, `AwsCliCommandValidation`), `diagnostics`
(`ValidationReport`, `Diagnostic`, `DetailLevel`, `ReportStatus`), `rules` (`Severity`, `RuleOrigin`, `RuleInfo`,
`RuleFilterConfig` and its filters), `templatemodel` (`PseudoParameterOverrides`, `EntityType`, the semantic model
types), `schemavalidator` (`SchemaValidatorConfig`), and `datasource` (`AdditionalSchemaSource`).

## Installation

Available on [Maven Central](https://central.sonatype.com/artifact/software.amazon.cloudformation/cloudformation-validate)
as `software.amazon.cloudformation:cloudformation-validate`. Both snippets below resolve the latest published version;
substitute a specific version to pin one.

Gradle:

```groovy
implementation 'software.amazon.cloudformation:cloudformation-validate:latest.release'
```

Maven:

```xml

<dependency>
    <groupId>software.amazon.cloudformation</groupId>
    <artifactId>cloudformation-validate</artifactId>
    <version>[0,)</version>
</dependency>
```

Requires Java 8 or later. Maven or Gradle resolves the declared dependencies (JNA, Gson, and the Kotlin standard
library).

## Quick start

```kotlin
import software.amazon.cloudformation.validate.RegoEngine
import java.io.File

val engine = RegoEngine()
val report = engine.validateTemplate(File("template.yaml"))
for (d in report.diagnostics) {
    println("[${d.severity}] ${d.ruleId}: ${d.message}")
}
```

Each diagnostic identifies the rule, severity, affected entity and property, and source location - see
[Diagnostic](#diagnostic). A complete, runnable project is in
[examples](https://github.com/aws-cloudformation/cloudformation-validate/tree/main/src/bindings-jvm/examples).

Engines are expensive to construct (rules compile once) and cheap to reuse - create one engine and validate many
templates. Every fallible call throws `ValidationException` on failure; internal panics are caught at the FFI boundary
and surface as the same exception, never a process abort. `version()` returns the version of the bundled validation
core.

A template is passed as a `java.io.File`: the engine reads the bytes and uses the file path for diagnostic source
locations.

## Engine

`RegoEngine` and `CelEngine` both implement the `Engine` interface and are interchangeable - they produce identical
diagnostics for the same template and config. `CompositeEngine` implements the same interface and layers custom Rego,
CEL, and Guard rules on top of the built-in rules - see [CompositeEngine](#compositeengine).

### `Engine` interface

```kotlin
interface Engine {
    fun validateTemplate(template: File, config: ValidateConfig = ValidateConfig()): ValidationReport
    fun validateAwsCliCommand(request: AwsCliCommand): AwsCliCommandValidation
    fun listRules(): List<RuleInfo>
    fun engineName(): String
}
```

| Method                               | Returns                   | Description                                                                                                                                                                                                                       |
|--------------------------------------|---------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `validateTemplate(template, config)` | `ValidationReport`        | Validates the template and returns a report. `config.detailLevel` (default `DETAILED`) selects how much per-diagnostic context is populated: `DETAILED` adds documentation URLs, rule descriptions, phase tags, and `ViolationContext`; `STANDARD` leaves those enrichment fields absent |
| `validateAwsCliCommand(request)`     | `AwsCliCommandValidation` | Models an AWS CLI command as CloudFormation resource state and validates it - see [AWS CLI command validation](#aws-cli-command-validation)                                                                                       |
| `listRules()`                        | `List<RuleInfo>`          | Returns metadata for every built-in and loaded custom rule                                                                                                                                                                        |
| `engineName()`                       | `String`                  | `"rego"`, `"cel"`, or `"composite"`                                                                                                                                                                                               |

### `EngineConfig`

Passed to the constructor. All fields are optional: the rule lists default to empty and a `null`
`schemaValidatorConfig` uses only the bundled schemas.

```kotlin
data class EngineConfig(
    val customRules: List<ExternalRuleSource> = emptyList(),   // engine-native rules (Rego for RegoEngine, CEL for CelEngine)
    val guardRules: List<ExternalRuleSource> = emptyList(),    // CloudFormation Guard DSL rules - evaluated by the Guard evaluator
    val schemaValidatorConfig: SchemaValidatorConfig? = null,  // additional resource provider schemas
)

data class SchemaValidatorConfig(
    val additionalSchemas: List<AdditionalSchemaSource> = emptyList(), // resource provider schemas merged over the bundled schemas
)

data class ExternalRuleSource(
    val name: String,     // identifier shown in diagnostics (e.g. file path)
    val content: String,  // full rule source text
)

data class AdditionalSchemaSource(
    val typeName: String? = null, // null to use the typeName inside the schema JSON
    val schema: String,           // complete resource provider schema JSON
)

fun fileToExternalRuleSource(file: File): ExternalRuleSource                                  // rule file read from disk; the path becomes the rule source name
fun fileToAdditionalSchemaSource(file: File, typeName: String? = null): AdditionalSchemaSource // schema file; typeName defaults to the value inside the JSON
```

| Field                   | Default       | Description                                                                                   |
|-------------------------|---------------|-----------------------------------------------------------------------------------------------|
| `customRules`           | `emptyList()` | Engine-native rules: Rego source for `RegoEngine`, CEL JSON for `CelEngine`                   |
| `guardRules`            | `emptyList()` | CloudFormation Guard DSL rules, evaluated by the Guard evaluator identically in every engine                        |
| `schemaValidatorConfig` | `null`        | Optional `SchemaValidatorConfig` whose `additionalSchemas` are merged over the bundled schemas |

Each rule is an `ExternalRuleSource` - `name` identifies the rule in diagnostics and `content` is the full rule source
text. Use `fileToExternalRuleSource(file)` to load one from disk (the same pattern as passing a template `File` to
`validateTemplate`), or construct an `ExternalRuleSource(name, content)` when you already have the rule text in memory.
Each additional schema is an `AdditionalSchemaSource` - a complete resource provider schema JSON plus an optional
`typeName` that may be omitted when the schema JSON contains its own `typeName`; `fileToAdditionalSchemaSource(file)`
loads one from disk. Additional schemas extend the bundled schemas or register resource types CloudFormation has not
published yet; a malformed, contradictory, or unsupported schema fails engine construction rather than silently
weakening validation. Guard rules are evaluated by the CloudFormation Guard evaluator itself against the template as
written, so every engine reports exactly what `cfn-guard validate` reports; a Guard file that does not parse also fails
engine construction. The two forms can be mixed freely:

```kotlin
import software.amazon.cloudformation.validate.CelEngine
import software.amazon.cloudformation.validate.fileToAdditionalSchemaSource
import software.amazon.cloudformation.validate.fileToExternalRuleSource
import software.amazon.cloudformation.validate.engine.EngineConfig
import software.amazon.cloudformation.validate.schemavalidator.SchemaValidatorConfig

val engine = CelEngine(
    EngineConfig(
        customRules = listOf(fileToExternalRuleSource(File("rules/s3_encryption.json"))),
        guardRules = listOf(fileToExternalRuleSource(File("rules/compliance.guard"))),
        schemaValidatorConfig = SchemaValidatorConfig(
            additionalSchemas = listOf(fileToAdditionalSchemaSource(File("schemas/aws-lambda-function.json"))),
        ),
    ),
)
```

See [Custom Rules](../CUSTOM_RULES.md) for the Rego, CEL, and Guard rule formats and
[Additional Resource Provider Schemas](../validation-engine/API.md#additional-resource-provider-schemas) for the schema
merge model.

### `CompositeEngine`

`CompositeEngine` implements the same `Engine` interface but takes a `CompositeEngineConfig`. It evaluates every
built-in rule with a fixed built-in CEL evaluator and layers the caller-supplied custom rules on top: custom CEL and
Guard rules run alongside that built-in engine, while custom Rego rules run in a separate external engine that is
constructed only when Rego rules are supplied. With no custom rules it produces the same built-in diagnostics as
`RegoEngine` and `CelEngine`, and `engineName()` returns `"composite"`. Because the composite fixes which engine owns
the built-ins, the config has no `customRules` field - it carries only the custom rules layered on top:

```kotlin
data class CompositeEngineConfig(
    val regoRules: List<ExternalRuleSource> = emptyList(),     // custom Rego rules, run by the external engine
    val celRules: List<ExternalRuleSource> = emptyList(),      // custom CEL rules, run by the built-in engine
    val guardRules: List<ExternalRuleSource> = emptyList(),    // CloudFormation Guard DSL rules, evaluated alongside the built-in engine
    val schemaValidatorConfig: SchemaValidatorConfig? = null,  // additional resource provider schemas, observed by both inner engines
)
```

| Field                   | Default       | Description                                                                                      |
|-------------------------|---------------|--------------------------------------------------------------------------------------------------|
| `regoRules`             | `emptyList()` | Custom Rego rules layered on top of the built-in rules, run by the external engine               |
| `celRules`              | `emptyList()` | Custom CEL rules layered on top of the built-in rules, run by the built-in engine                |
| `guardRules`            | `emptyList()` | CloudFormation Guard DSL rules layered on top of the built-in rules, evaluated alongside the built-in engine |
| `schemaValidatorConfig` | `null`        | Optional `SchemaValidatorConfig`, observed by both inner engines                                 |

```kotlin
import software.amazon.cloudformation.validate.CompositeEngine
import software.amazon.cloudformation.validate.fileToExternalRuleSource
import software.amazon.cloudformation.validate.engine.CompositeEngineConfig

val engine = CompositeEngine(
    CompositeEngineConfig(
        regoRules = listOf(fileToExternalRuleSource(File("rules/s3_naming.rego"))),
        guardRules = listOf(fileToExternalRuleSource(File("rules/compliance.guard"))),
    ),
)
val report = engine.validateTemplate(File("template.yaml"))
```

## ValidateConfig

Controls filtering, detail, severity, parameter overrides, and behavior for one validation call. All fields have
defaults - omitting the config or passing `ValidateConfig()` uses them.

```kotlin
val report = engine.validateTemplate(
    File("template.yaml"),
    ValidateConfig(
        exclude = RuleFilterConfig(ids = listOf("I1002")),
        severityLevel = Severity.WARN,
    ),
)
```

```kotlin
data class ValidateConfig(
    val include: RuleFilterConfig = RuleFilterConfig(),
    val exclude: RuleFilterConfig = RuleFilterConfig(),
    val detailLevel: DetailLevel? = null,          // null = DETAILED
    val severityLevel: Severity? = null,           // null = INFO
    val parameterOverrides: Map<String, String> = emptyMap(),
    val pseudoParameterOverrides: PseudoParameterOverrides = PseudoParameterOverrides(),
    val strict: Boolean? = null,                   // null = false
    val disableBuiltinRules: Boolean? = null,      // null = false
)
```

| Field                      | Default                  | Description                                                                                                                                                              |
|----------------------------|--------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `include`                  | empty (all rules)        | When set, only matching rules produce diagnostics. Empty means include everything.                                                                                       |
| `exclude`                  | empty (nothing excluded) | Matching rules are suppressed. Applied after `include`.                                                                                                                  |
| `detailLevel`              | `DETAILED`               | Per-diagnostic context. `DETAILED` populates documentation URLs, rule descriptions, phase tags, and `ViolationContext`; `STANDARD` leaves those enrichment fields absent. |
| `severityLevel`            | `INFO`                   | Minimum severity threshold. Diagnostics below this level are dropped. Values: `DEBUG`, `INFO`, `WARN`, `ERROR`, `FATAL`.                                                 |
| `parameterOverrides`       | `emptyMap()`             | Override template parameter values during resolution. Keys are parameter logical IDs.                                                                                    |
| `pseudoParameterOverrides` | all `null`               | Override CloudFormation pseudo-parameters (`AWS::AccountId`, `AWS::Region`, etc.).                                                                                       |
| `strict`                   | `false`                  | When `true`, `WARN`-severity diagnostics are upgraded to `ERROR`.                                                                                                        |
| `disableBuiltinRules`      | `false`                  | When `true`, all built-in rules (schema validation, Step Functions, engine rules) are skipped; only custom and Guard rules are evaluated.                                |

### RuleFilterConfig

Both `include` and `exclude` use this structure. All fields are additive - a rule matches if it hits any criterion.

```kotlin
data class RuleFilterConfig(
    val ids: List<String> = emptyList(),                       // exact rule IDs, e.g. ["E3012", "W3010"]
    val categories: List<String> = emptyList(),                // category names, e.g. ["security", "best_practices"]
    val idRanges: List<IdRange> = emptyList(),                 // numeric ranges, e.g. IdRange("E", 3000, 3099)
    val idPatterns: List<String> = emptyList(),                // regex patterns matched against rule IDs
    val resourceIds: List<ResourceIdFilter> = emptyList(),     // a rule (or every rule) on a logical resource ID
    val logicalIds: List<LogicalIdFilter> = emptyList(),       // a rule (or every rule) on a named template entity
    val resourceTypes: List<ResourceTypeFilter> = emptyList(), // a rule (or every rule) on a resource type
    val services: List<ServiceFilter> = emptyList(),           // a rule (or every rule) on a service, e.g. "AWS::AutoScaling"
)

// resourceIds / logicalIds / resourceTypes / services each carry a nullable ruleId:
// set it to scope the filter to one rule, or leave it null for every rule on the target.
data class ResourceIdFilter(val ruleId: String? = null, val resourceId: String)
data class LogicalIdFilter(val ruleId: String? = null, val logicalId: String, val entityType: EntityType? = null)
data class ResourceTypeFilter(val ruleId: String? = null, val resourceType: String)
data class ServiceFilter(val ruleId: String? = null, val service: String)
```

The `service` is matched verbatim against the `service-provider::service-name` prefix of the resource type - its first
two `::`-delimited segments (e.g. `AWS::AutoScaling` in `AWS::AutoScaling::LaunchConfiguration`).

The `resourceIds` dimension matches only diagnostics attributed to a resource; `logicalIds` additionally matches
diagnostics on parameters, outputs, mappings, conditions, and template rules (for resource diagnostics the two carry
the same value). A non-null `entityType` scopes a `LogicalIdFilter` to entities of one type, so `MyThing` as a
`PARAMETER` is matched without touching a same-named entity of another type.

### PseudoParameterOverrides

Override CloudFormation pseudo-parameters used during intrinsic function resolution. All fields are optional - when
`null`, the engine uses built-in defaults (e.g. region defaults to `us-east-1`).

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

Parses a template into the resolved `SemanticModel` for direct inspection - the same model the engines evaluate rules
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

Runs schema validation independently from the rule engines. Checks each resource against the compiled CloudFormation
provider schemas and produces `FATAL`-severity diagnostics for structural violations. The optional constructor argument
is the same `SchemaValidatorConfig` accepted by `EngineConfig`; omitting it uses only the bundled schemas.

```kotlin
val validator = SchemaValidator()
val diagnostics = validator.validate(File("template.yaml"), null)
```

| Method                                              | Returns            | Description                                                                                                                             |
|-----------------------------------------------------|--------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| `SchemaValidator(config = SchemaValidatorConfig())` | `SchemaValidator`  | Constructs a validator; the default `SchemaValidatorConfig` uses only the bundled schemas                                               |
| `validate(template, region)`                        | `List<Diagnostic>` | Schema diagnostics at `STANDARD` detail - the enrichment fields are absent. `region` is a `String?`; `null` defaults to `"us-east-1"`. |
| `listRules()`                                       | `List<RuleInfo>`   | Schema rule metadata                                                                                                                    |
| `schemaCount()`                                     | `Int`              | Number of compiled provider schemas                                                                                                     |

## AWS CLI command validation

`validateAwsCliCommand` models an AWS CLI (or SDK) API call as CloudFormation resource state and validates it offline
before it is sent. It classifies the operation, maps it to a CloudFormation resource type through a closed, generated
adapter catalog, synthesizes a template from the supplied parameters, and runs the normal template pipeline on it. A
`TemplateBody` parameter of a CloudFormation operation is validated as-is. Any request that cannot be modeled exactly -
an unregistered operation, a parameter without a lossless property mapping, or a value outside a CloudFormation
constraint the API itself does not enforce - is skipped with a reason, never guessed.

```kotlin
import software.amazon.cloudformation.validate.AwsCliCommand
import software.amazon.cloudformation.validate.RegoEngine
import software.amazon.cloudformation.validate.engine.AwsCliCommandValidationStatus

val engine = RegoEngine()
val request = AwsCliCommand("s3", "CreateBucket", mapOf("Bucket" to "example-bucket"))
val validation = engine.validateAwsCliCommand(request)
if (validation.status == AwsCliCommandValidationStatus.VALIDATED) {
    for (d in validation.report!!.diagnostics) {
        println("[${d.severity}] ${d.ruleId}: ${d.message}")
    }
} else {
    println("skipped (${validation.operationKind}): ${validation.reason}")
}
```

```kotlin
class AwsCliCommand @JvmOverloads constructor(
    val serviceName: String,             // canonical botocore service name, e.g. "s3" or "cloudformation"
    val operationName: String,           // API operation name, e.g. "CreateBucket"
    parameters: Map<String, Any?>,       // request parameters
    val servicePrefix: String? = null,   // signing prefix; context only
    val httpMethod: String? = null,      // classification hint ("GET"/"HEAD"/"DELETE") for unrecognized verbs
    val isReadOnly: Boolean? = null,     // true classifies the operation as READ_ONLY
)
```

- `serviceName` is matched case-insensitively. Signing names, endpoint aliases, and ARN prefixes are never resolved;
  translate an SDK's service identity first.
- `parameters` accepts nested maps and iterables/arrays, `String`, boxed integers (including unsigned),
  `Float`/`Double`, `Boolean`, `null`, `ByteArray`, and `java.time` values (serialized with `toString()`). Any other
  value is carried as an explicit unsupported marker, and because synthesis is all-or-nothing the request is then
  skipped with a reason naming the offending parameter - no parameter is ever silently dropped.

The result is an `AwsCliCommandValidation`:

| Field            | Description                                                                                                                                                       |
|------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `operationKind`  | `AwsCliOperationKind`: `READ_ONLY`, `CLOUD_FORMATION_CREATE`, `CLOUD_FORMATION_UPDATE`, `CLOUD_FORMATION_DELETE`, `DATA_PLANE_MUTATION`, or `UNMAPPED_MUTATION`   |
| `status`         | `AwsCliCommandValidationStatus`: `VALIDATED` when the modeled template ran through the pipeline, `SKIPPED` otherwise                                               |
| `templateSource` | `AwsCliTemplateSource?`: `TEMPLATE_BODY`, `CLOUD_CONTROL_DESIRED_STATE`, `SYNTHESIZED_CREATE`, or `SYNTHESIZED_UPDATE`; `null` when skipped                       |
| `resourceTypes`  | `List<String>` - CloudFormation resource types the operation maps to                                                                                              |
| `reason`         | `String` - why the request was validated or skipped                                                                                                               |
| `report`         | `ValidationReport?` - present when `VALIDATED`. The configuration is fixed: `STANDARD` detail level and a `WARN` severity floor                                    |
| `template`       | `ByteArray?` - the exact template bytes that were validated (the caller's `TemplateBody` unchanged, or the synthesized JSON); `null` when skipped                  |

The full contract - the adapter catalog, all-or-nothing mapping, and which rules are dropped for synthesized state -
is documented in [validation-engine/API.md](../validation-engine/API.md#validating-an-aws-cli-command).

## Report Types

### ValidationReport

`validateTemplate` always returns a `ValidationReport` - a template syntax failure is returned as a report with
`ReportStatus.ERROR` and an `F1101` diagnostic; only infrastructure or engine failures throw:

```kotlin
data class ValidationReport(
    val filePath: String,
    val status: ReportStatus,            // OK, ANALYSIS_INCOMPLETE (findings may be omitted), or ERROR (pipeline failure)
    val version: String,
    val metadata: ReportMetadata,
    val performance: PerformanceMetrics,
    val diagnostics: List<Diagnostic>,
)
```

Every finding is a `Diagnostic` (see [Diagnostic](#diagnostic)). Its enrichment fields - `documentationUrl`,
`ruleDescription`, `phase` (`PARSE` | `SCHEMA` | `LINT`), and `context` (`ViolationContext` with `actualValue`,
`expectedConstraint`, `resolutionSource`, etc.) - are populated only at `detailLevel` `DETAILED` (the default);
validating at `STANDARD` leaves them `null`, keeping the base diagnostic fields.

`metadata` carries the summary counts, the number of suppressed diagnostics, the resources scanned and rules
evaluated, the strict flag and severity threshold used, and optional budget-exhaustion records. Each budget-exhaustion
record retains a stable machine-readable kind and also includes a human-readable description sentence, the numeric
limit, and whether that specific exhaustion makes analysis incomplete. `requiredPropertyCombinations` is context-only,
so its `analysisIncomplete` value is `false` and the report can remain `ReportStatus.OK`.

### Diagnostic

```kotlin
data class Diagnostic(
    val ruleId: String,                    // e.g. "E3012", "F1001", "W3010"
    val severity: Severity,                // FATAL, ERROR, WARN, INFO, DEBUG
    val message: String,
    val source: RuleOrigin,                // SCHEMA, CFN_LINT, ENGINE, CUSTOM, GUARD
    val entity: Entity?,                   // the named template entity the finding targets, if any
    val propertyPath: String?,             // e.g. "Properties.BucketName", or section-absolute like "Parameters/MyParam/Type"
    val suggestedFix: String?,
    val category: String?,
    val startLine: UInt?,
    val startColumn: UInt?,
    val endLine: UInt?,
    val endColumn: UInt?,
    val relatedResources: List<RelatedResource>?,
    val conditionScenario: Map<String, Boolean>?,  // condition truth assignment that triggers this diagnostic
    // Enrichment fields: populated at detailLevel DETAILED (the default), null at STANDARD.
    val documentationUrl: String?,
    val ruleDescription: String?,
    val phase: Phase?,                     // PARSE | SCHEMA | LINT - pipeline stage that produced the finding
    val context: ViolationContext?,        // actualValue, expectedConstraint, resolutionSource, etc.
)

// The named template entity a diagnostic is attributed to. The entity type is the
// singular form of the top-level template section the entity is declared in.
data class Entity(
    val logicalId: String,                 // logical ID as declared in the template
    val entityType: EntityType,
    val resourceType: String? = null,      // CloudFormation type, when the entity is a resource whose type is known
)

enum class EntityType {
    RESOURCE, PARAMETER, OUTPUT, MAPPING, METADATA, RULE, CONDITION, TRANSFORM, FORMAT_VERSION, DESCRIPTION,
}
```

`Severity`, `RuleOrigin`, `DetailLevel`, and `ReportStatus` are enum classes (`Severity.WARN`, `RuleOrigin.GUARD`,
`DetailLevel.STANDARD`, `ReportStatus.OK`, ...).
