# CloudFormation Validate for Node.js

Validate AWS CloudFormation templates from JavaScript or TypeScript and catch schema violations, semantic errors,
security risks, and best-practice findings before deployment - in your editor, build, service, or CI.

- **Offline** - all rules and CloudFormation resource schemas are bundled; nothing is fetched at runtime and no AWS
  credentials are needed.
- **Fast** - engines and schemas compile once and are reused across validations; typical templates validate in under a
  second.
- **Self-contained** - the WebAssembly module is bundled in the package; there are no native dependencies.

All types are exported from the `@aws/cloudformation-validate` package.

## Installation

Available on [npm](https://www.npmjs.com/package/@aws/cloudformation-validate) as `@aws/cloudformation-validate`.

```bash
npm install @aws/cloudformation-validate
```

Requires Node.js 20 or later. The package has no runtime dependencies.

## Quick start

Engines, models, and validators hold off-heap memory - call `.free()` when done with each object:

```typescript
import { RegoEngine, TemplateFile } from "@aws/cloudformation-validate";

const engine = new RegoEngine();
try {
    const report = engine.validateTemplate(new TemplateFile("template.yaml"));
    for (const d of report.diagnostics) {
        console.log(`[${d.severity}] ${d.ruleId}: ${d.message}`);
    }
} finally {
    engine.free();
}
```

Each diagnostic identifies the rule, severity, affected entity and property, and source location - see
[Diagnostic](#diagnostic). A complete, runnable project is in
[examples](https://github.com/aws-cloudformation/cloudformation-validate/tree/main/src/bindings-wasm/examples).

Engines are expensive to construct (rules compile once) and cheap to reuse - create one engine and validate many
templates. Every fallible call throws on failure - the thrown value is the error message string from the validation
core, so handle it with `catch (error) { String(error) }`; internal panics are caught at the WASM boundary and surface
the same way, never a process abort. `version()` returns the version of the bundled validation core.

A template is passed as a `TemplateFile`, which wraps a filesystem path: the engine reads the bytes and uses the path
for diagnostic source locations.

## Engine

`RegoEngine` and `CelEngine` both implement the `Engine` interface and are interchangeable - they produce identical
diagnostics for the same template and config. `CompositeEngine` implements the same interface and layers custom Rego,
CEL, and Guard rules on top of the built-in rules - see [CompositeEngine](#compositeengine).

### `Engine` interface

```typescript
interface Engine {
    validateTemplate(template: TemplateFile, config?: ValidateConfig): ValidationReport;
    validateAwsCliCommand(request: AwsCliCommand): AwsCliCommandValidation;
    listRules(): RuleInfo[];
    engineName(): string;
    free(): void;
}
```

| Method                                | Returns                   | Description                                                                                                                                                                                                                       |
|---------------------------------------|---------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `validateTemplate(template, config?)` | `ValidationReport`        | Validates the template and returns a report. `config.detailLevel` (default `DETAILED`) selects how much per-diagnostic context is populated: `DETAILED` adds documentation URLs, rule descriptions, phase tags, and `ViolationContext`; `STANDARD` leaves those enrichment fields absent |
| `validateAwsCliCommand(request)`      | `AwsCliCommandValidation` | Models an AWS CLI command as CloudFormation resource state and validates it - see [AWS CLI command validation](#aws-cli-command-validation)                                                                                       |
| `listRules()`                         | `RuleInfo[]`              | Returns metadata for every built-in and loaded custom rule                                                                                                                                                                        |
| `engineName()`                        | `string`                  | `"rego"`, `"cel"`, or `"composite"`                                                                                                                                                                                               |
| `free()`                              | `void`                    | Releases the engine's off-heap memory; the engine must not be used afterwards                                                                                                                                                     |

### `EngineConfig`

Passed to the constructor. All fields are optional: the rule lists default to empty and an omitted
`schemaValidatorConfig` uses only the bundled schemas.

```typescript
interface EngineConfig {
    customRules?: RuleSource[];                      // engine-native rules (Rego for RegoEngine, CEL for CelEngine)
    guardRules?: RuleSource[];                       // CloudFormation Guard DSL rules - evaluated by the Guard evaluator
    schemaValidatorConfig?: SchemaValidatorConfig;   // additional resource provider schemas
}

interface SchemaValidatorConfig {
    additionalSchemas?: SchemaSource[];   // resource provider schemas merged over the bundled schemas
}

type RuleSource = ExternalRuleSource | RuleFile;
type SchemaSource = AdditionalSchemaSource | SchemaFile;

interface ExternalRuleSource {
    name: string;     // identifier shown in diagnostics (e.g. file path)
    content: string;  // full rule source text
}

interface AdditionalSchemaSource {
    typeName?: string; // omit to use the typeName inside the schema JSON
    schema: string;    // complete resource provider schema JSON
}

class RuleFile {
    constructor(path: string);                    // rule file read from disk; the path becomes the rule source name
}

class SchemaFile {
    constructor(path: string, typeName?: string); // schema file; typeName defaults to the value inside the JSON
}
```

| Field                   | Default     | Description                                                                                   |
|-------------------------|-------------|-----------------------------------------------------------------------------------------------|
| `customRules`           | `[]`        | Engine-native rules: Rego source for `RegoEngine`, CEL JSON for `CelEngine`                   |
| `guardRules`            | `[]`        | CloudFormation Guard DSL rules, evaluated by the Guard evaluator identically in every engine                        |
| `schemaValidatorConfig` | `undefined` | Optional `SchemaValidatorConfig` whose `additionalSchemas` are merged over the bundled schemas |

Each rule is an `ExternalRuleSource` - `name` identifies the rule in diagnostics and `content` is the full rule source
text. Pass a `RuleFile` to load one from disk (the same pattern as `TemplateFile` for templates), or an
`ExternalRuleSource` when you already have the rule text in memory. Each additional schema is an
`AdditionalSchemaSource` - a complete resource provider schema JSON plus an optional `typeName` that may be omitted when
the schema JSON contains its own `typeName`; `SchemaFile` loads one from disk. Additional schemas extend the bundled
schemas or register resource types CloudFormation has not published yet; a malformed, contradictory, or unsupported
schema fails engine construction rather than silently weakening validation. Guard rules are evaluated by the
CloudFormation Guard evaluator itself against the template as written, so every engine reports exactly what `cfn-guard
validate` reports; a Guard file that does not parse also fails engine construction. The two forms can be mixed freely:

```typescript
import { CelEngine, RuleFile, SchemaFile } from "@aws/cloudformation-validate";

const engine = new CelEngine({
    customRules: [new RuleFile("rules/s3_encryption.json")],
    guardRules: [new RuleFile("rules/compliance.guard")],
    schemaValidatorConfig: {
        additionalSchemas: [new SchemaFile("schemas/aws-lambda-function.json")],
    },
});
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

```typescript
interface CompositeEngineConfig {
    regoRules?: RuleSource[];                        // custom Rego rules, run by the external engine
    celRules?: RuleSource[];                         // custom CEL rules, run by the built-in engine
    guardRules?: RuleSource[];                       // CloudFormation Guard DSL rules, evaluated alongside the built-in engine
    schemaValidatorConfig?: SchemaValidatorConfig;   // additional resource provider schemas, observed by both inner engines
}
```

| Field                   | Default     | Description                                                                                      |
|-------------------------|-------------|--------------------------------------------------------------------------------------------------|
| `regoRules`             | `[]`        | Custom Rego rules layered on top of the built-in rules, run by the external engine               |
| `celRules`              | `[]`        | Custom CEL rules layered on top of the built-in rules, run by the built-in engine                |
| `guardRules`            | `[]`        | CloudFormation Guard DSL rules layered on top of the built-in rules, evaluated alongside the built-in engine |
| `schemaValidatorConfig` | `undefined` | Optional `SchemaValidatorConfig`, observed by both inner engines                                 |

```typescript
import { CompositeEngine, RuleFile, TemplateFile } from "@aws/cloudformation-validate";

const engine = new CompositeEngine({
    regoRules: [new RuleFile("rules/s3_naming.rego")],
    guardRules: [new RuleFile("rules/compliance.guard")],
});
try {
    const report = engine.validateTemplate(new TemplateFile("template.yaml"));
} finally {
    engine.free();
}
```

## ValidateConfig

Controls filtering, detail, severity, parameter overrides, and behavior for one validation call. All fields have
defaults - omitting the config or passing `{}` uses them.

```typescript
const report = engine.validateTemplate(new TemplateFile("template.yaml"), {
    exclude: { ids: ["I1002"] },
    severityLevel: "WARN",
});
```

```typescript
interface ValidateConfig {
    include?: RuleFilterConfig;
    exclude?: RuleFilterConfig;
    detailLevel?: DetailLevel;
    severityLevel?: Severity;
    parameterOverrides?: Record<string, string>;
    pseudoParameterOverrides?: PseudoParameterOverrides;
    strict?: boolean;
    disableBuiltinRules?: boolean;
}
```

| Field                      | Default                 | Description                                                                                                                                                                  |
|----------------------------|-------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `include`                  | `{}` (all rules)        | When set, only matching rules produce diagnostics. Empty means include everything.                                                                                           |
| `exclude`                  | `{}` (nothing excluded) | Matching rules are suppressed. Applied after `include`.                                                                                                                      |
| `detailLevel`              | `"DETAILED"`            | Per-diagnostic context. `"DETAILED"` populates documentation URLs, rule descriptions, phase tags, and `ViolationContext`; `"STANDARD"` leaves those enrichment fields absent. |
| `severityLevel`            | `"INFO"`                | Minimum severity threshold. Diagnostics below this level are dropped. Values: `DEBUG`, `INFO`, `WARN`, `ERROR`, `FATAL`.                                                     |
| `parameterOverrides`       | `{}`                    | Override template parameter values during resolution. Keys are parameter logical IDs.                                                                                        |
| `pseudoParameterOverrides` | all `undefined`         | Override CloudFormation pseudo-parameters (`AWS::AccountId`, `AWS::Region`, etc.).                                                                                           |
| `strict`                   | `false`                 | When `true`, `WARN`-severity diagnostics are upgraded to `ERROR`.                                                                                                            |
| `disableBuiltinRules`      | `false`                 | When `true`, all built-in rules (schema validation, Step Functions, engine rules) are skipped; only custom and Guard rules are evaluated.                                    |

### RuleFilterConfig

Both `include` and `exclude` use this structure. All fields are additive - a rule matches if it hits any criterion.

```typescript
interface RuleFilterConfig {
    ids?: string[];                       // exact rule IDs, e.g. ["E3012", "W3010"]
    categories?: string[];                // category names, e.g. ["security", "best_practices"]
    idRanges?: IdRange[];                 // numeric ranges, e.g. { prefix: "E", start: 3000, end: 3099 }
    idPatterns?: string[];                // regex patterns matched against rule IDs
    resourceIds?: ResourceIdFilter[];     // a rule (or every rule) on a logical resource ID
    logicalIds?: LogicalIdFilter[];       // a rule (or every rule) on a named template entity
    resourceTypes?: ResourceTypeFilter[]; // a rule (or every rule) on a resource type
    services?: ServiceFilter[];           // a rule (or every rule) on a service, e.g. "AWS::AutoScaling"
}

// resourceIds / logicalIds / resourceTypes / services each carry an optional ruleId:
// set it to scope the filter to one rule, or omit it for every rule on the target.
interface ResourceIdFilter   { ruleId?: string; resourceId: string; }
interface LogicalIdFilter    { ruleId?: string; logicalId: string; entityType?: EntityType; }
interface ResourceTypeFilter { ruleId?: string; resourceType: string; }
interface ServiceFilter      { ruleId?: string; service: string; }
```

The `service` is matched verbatim against the `service-provider::service-name` prefix of the resource type - its first
two `::`-delimited segments (e.g. `AWS::AutoScaling` in `AWS::AutoScaling::LaunchConfiguration`).

The `resourceIds` dimension matches only diagnostics attributed to a resource; `logicalIds` additionally matches
diagnostics on parameters, outputs, mappings, conditions, and template rules (for resource diagnostics the two carry
the same value). An optional `entityType` scopes a `LogicalIdFilter` to entities of one type, so `MyThing` as a
`"Parameter"` is matched without touching a same-named entity of another type.

### PseudoParameterOverrides

Override CloudFormation pseudo-parameters used during intrinsic function resolution. All fields are optional - when
`undefined`, the engine uses built-in defaults (e.g. region defaults to `us-east-1`).

```typescript
interface PseudoParameterOverrides {
    accountId?: string;         // AWS::AccountId
    notificationArns?: string;  // AWS::NotificationARNs
    partition?: string;         // AWS::Partition
    region?: string;            // AWS::Region (default: "us-east-1")
    stackId?: string;           // AWS::StackId
    stackName?: string;         // AWS::StackName
    urlSuffix?: string;         // AWS::URLSuffix
}
```

## TemplateModel

Parses a template into the resolved `SemanticModel` for direct inspection - the same model the engines evaluate rules
against.

```typescript
const model = new TemplateModel(new TemplateFile("template.yaml"));
```

| Method                 | Returns                            | Description                                                                                     |
|------------------------|------------------------------------|-------------------------------------------------------------------------------------------------|
| `resources()`          | `Record<string, ResolvedResource>` | All resources with resolved property values                                                     |
| `parameters()`         | `Record<string, ParameterInfo>`    | Parameter definitions with types, defaults, constraints                                         |
| `outputs()`            | `Record<string, ResolvedOutput>`   | Outputs with resolved values and export names                                                   |
| `conditions()`         | `string[]`                         | Condition names defined in the template                                                         |
| `transforms()`         | `string[]`                         | Transform declarations (e.g. `AWS::Serverless-2016-10-31`)                                      |
| `formatVersion()`      | `string \| undefined`              | `AWSTemplateFormatVersion` value                                                                |
| `description()`        | `string \| undefined`              | Template description                                                                            |
| `toDiagnosticModel()`  | `DiagnosticModel`                  | Full diagnostic model including reference graph, condition implications, and resolution sources |
| `sourceLocation(path)` | `SourceSpan \| null`               | Source line/column span for a JSON path (e.g. `Resources/MyBucket/Properties/BucketName`)       |
| `free()`               | `void`                             | Releases the model's off-heap memory; the model must not be used afterwards                     |

## SchemaValidator

Runs schema validation independently from the rule engines. Checks each resource against the compiled CloudFormation
provider schemas and produces `FATAL`-severity diagnostics for structural violations. The optional constructor argument
is the same `SchemaValidatorConfig` accepted by `EngineConfig`; omitting it uses only the bundled schemas.

```typescript
const validator = new SchemaValidator();
try {
    const diagnostics = validator.validate(new TemplateFile("template.yaml"), "us-east-1");
} finally {
    validator.free();
}
```

| Method                         | Returns           | Description                                                                                                      |
|--------------------------------|-------------------|------------------------------------------------------------------------------------------------------------------|
| `new SchemaValidator(config?)` | `SchemaValidator` | Constructs a validator; an omitted `SchemaValidatorConfig` uses only the bundled schemas                         |
| `validate(template, region?)`  | `Diagnostic[]`    | Schema diagnostics at `STANDARD` detail - the enrichment fields are absent. `region` defaults to `"us-east-1"`.  |
| `listRules()`                  | `RuleInfo[]`      | Schema rule metadata                                                                                             |
| `schemaCount()`                | `number`          | Number of compiled provider schemas                                                                              |
| `free()`                       | `void`            | Releases the validator's off-heap memory; the validator must not be used afterwards                              |

## AWS CLI command validation

`validateAwsCliCommand` models an AWS CLI (or SDK) API call as CloudFormation resource state and validates it offline
before it is sent. It classifies the operation, maps it to a CloudFormation resource type through a closed, generated
adapter catalog, synthesizes a template from the supplied parameters, and runs the normal template pipeline on it. A
`TemplateBody` parameter of a CloudFormation operation is validated as-is. Any request that cannot be modeled exactly -
an unregistered operation, a parameter without a lossless property mapping, or a value outside a CloudFormation
constraint the API itself does not enforce - is skipped with a reason, never guessed.

```typescript
import { AwsCliCommand, RegoEngine } from "@aws/cloudformation-validate";

const engine = new RegoEngine();
try {
    const request = new AwsCliCommand("s3", "CreateBucket", { Bucket: "example-bucket" });
    const validation = engine.validateAwsCliCommand(request);
    if (validation.status === "VALIDATED") {
        for (const d of validation.report!.diagnostics) {
            console.log(`[${d.severity}] ${d.ruleId}: ${d.message}`);
        }
    } else {
        console.log(`skipped (${validation.operationKind}): ${validation.reason}`);
    }
} finally {
    engine.free();
}
```

```typescript
class AwsCliCommand {
    constructor(
        serviceName: string,                 // canonical botocore service name, e.g. "s3" or "cloudformation"
        operationName: string,               // API operation name, e.g. "CreateBucket"
        parameters: Record<string, unknown>, // request parameters (a plain object with string keys)
        options?: AwsCliCommandOptions,
    );
}

interface AwsCliCommandOptions {
    servicePrefix?: string; // signing prefix; context only
    httpMethod?: string;    // classification hint ("GET"/"HEAD"/"DELETE") for unrecognized verbs
    isReadOnly?: boolean;   // true classifies the operation as READ_ONLY
}
```

- `serviceName` is matched case-insensitively. Signing names, endpoint aliases, and ARN prefixes are never resolved;
  translate an SDK's service identity first.
- `parameters` accepts nested plain objects and arrays, strings, numbers, `bigint`, booleans, `null`, `Uint8Array`,
  and `Date` (serialized as ISO 8601). Any other value is carried as an explicit unsupported marker, and because
  synthesis is all-or-nothing the request is then skipped with a reason naming the offending parameter - no parameter
  is ever silently dropped.

The result is an `AwsCliCommandValidation`:

| Field            | Description                                                                                                                                                       |
|------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `operationKind`  | `AwsCliOperationKind`: `"READ_ONLY"`, `"CLOUD_FORMATION_CREATE"`, `"CLOUD_FORMATION_UPDATE"`, `"CLOUD_FORMATION_DELETE"`, `"DATA_PLANE_MUTATION"`, or `"UNMAPPED_MUTATION"` |
| `status`         | `AwsCliCommandValidationStatus`: `"VALIDATED"` when the modeled template ran through the pipeline, `"SKIPPED"` otherwise                                          |
| `templateSource` | `AwsCliTemplateSource \| null`: `"TEMPLATE_BODY"`, `"CLOUD_CONTROL_DESIRED_STATE"`, `"SYNTHESIZED_CREATE"`, or `"SYNTHESIZED_UPDATE"`; `null` when skipped        |
| `resourceTypes`  | `string[]` - CloudFormation resource types the operation maps to                                                                                                  |
| `reason`         | `string` - why the request was validated or skipped                                                                                                               |
| `report`         | `ValidationReport \| null` - present when `"VALIDATED"`. The configuration is fixed: `STANDARD` detail level and a `WARN` severity floor                           |
| `template`       | `Uint8Array \| null` - the exact template bytes that were validated (the caller's `TemplateBody` unchanged, or the synthesized JSON); `null` when skipped          |

The full contract - the adapter catalog, all-or-nothing mapping, and which rules are dropped for synthesized state -
is documented in [validation-engine/API.md](../validation-engine/API.md#validating-an-aws-cli-command).

## Report Types

### ValidationReport

`validateTemplate` always returns a `ValidationReport` - a template syntax failure is returned as a report with
status `"ERROR"` and an `F1101` diagnostic; only infrastructure or engine failures throw:

```typescript
interface ValidationReport {
    filePath: string;
    status: "OK" | "ANALYSIS_INCOMPLETE" | "ERROR"; // ERROR is a pipeline failure; ANALYSIS_INCOMPLETE may omit findings
    version: string;
    metadata: ReportMetadata;
    performance: PerformanceMetrics;
    diagnostics: Diagnostic[];
}
```

Every finding is a `Diagnostic` (see [Diagnostic](#diagnostic)). Its enrichment fields - `documentationUrl`,
`ruleDescription`, `phase` (`PARSE` | `SCHEMA` | `LINT`), and `context` (`ViolationContext` with `actualValue`,
`expectedConstraint`, `resolutionSource`, etc.) - are populated only at `detailLevel` `"DETAILED"` (the default);
validating at `"STANDARD"` leaves them absent, keeping the base diagnostic fields.

`metadata` carries the summary counts, the number of suppressed diagnostics, the resources scanned and rules
evaluated, the strict flag and severity threshold used, and optional budget-exhaustion records. Each budget-exhaustion
record retains a stable machine-readable kind and also includes a human-readable description sentence, the numeric
limit, and whether that specific exhaustion makes analysis incomplete. `requiredPropertyCombinations` is context-only,
so its `analysisIncomplete` value is `false` and the report can remain `"OK"`.

### Diagnostic

```typescript
interface Diagnostic {
    ruleId: string;                    // e.g. "E3012", "F1001", "W3010"
    severity: Severity;                // "FATAL" | "ERROR" | "WARN" | "INFO" | "DEBUG"
    message: string;
    source: RuleOrigin;                // "SCHEMA" | "CFN_LINT" | "ENGINE" | "CUSTOM" | "GUARD"
    entity?: Entity;                   // the named template entity the finding targets, if any
    propertyPath?: string;             // e.g. "Properties.BucketName", or section-absolute like "Parameters/MyParam/Type"
    suggestedFix?: string;
    category?: string;
    startLine?: number;
    startColumn?: number;
    endLine?: number;
    endColumn?: number;
    relatedResources?: RelatedResource[];
    conditionScenario?: Record<string, boolean>;  // condition truth assignment that triggers this diagnostic
    // Enrichment fields: populated at detailLevel "DETAILED" (the default), absent at "STANDARD".
    documentationUrl?: string;
    ruleDescription?: string;
    phase?: "PARSE" | "SCHEMA" | "LINT";           // pipeline stage that produced the finding
    context?: ViolationContext;                    // actualValue, expectedConstraint, resolutionSource, etc.
}

// The named template entity a diagnostic is attributed to. The entity type is the
// singular form of the top-level template section the entity is declared in.
interface Entity {
    logicalId: string;                 // logical ID as declared in the template
    entityType: EntityType;
    resourceType?: string;             // CloudFormation type, when the entity is a resource whose type is known
}

type EntityType = "Resource" | "Parameter" | "Output" | "Mapping" | "Metadata"
                | "Rule" | "Condition" | "Transform" | "FormatVersion" | "Description";
```

`Severity`, `RuleOrigin`, and `DetailLevel` are string-literal union types (`"WARN"`, `"GUARD"`, `"STANDARD"`, ...), as
is the report `status` (`"OK"`, `"ANALYSIS_INCOMPLETE"`, `"ERROR"`).
