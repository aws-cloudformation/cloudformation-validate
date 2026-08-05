# CloudFormation Validate for Node.js

Validate AWS CloudFormation templates from JavaScript or TypeScript and catch schema violations, security risks, and
best-practice findings before deployment — in your editor, build, or CI.

- **Offline** — all rules and resource schemas are bundled.
- **Fast** — sub-second validation per template.

## Installation

Available on [npm](https://www.npmjs.com/package/@aws/cloudformation-validate) as `@aws/cloudformation-validate`.

```bash
npm install @aws/cloudformation-validate
```

## Quick start

Engines, models, and validators hold off-heap memory — call `.free()` when done with each object:

```typescript
import { RegoEngine, TemplateFile } from "@aws/cloudformation-validate";

const engine = new RegoEngine();
try {
    const report = engine.validateStandard(new TemplateFile("template.yaml"));
    for (const d of report.diagnostics) {
        console.log(`[${d.severity}] ${d.ruleId}: ${d.message}`);
    }
} finally {
    engine.free();
}
```

Each diagnostic identifies the rule, severity, affected resource and property, and source location — see
[StandardDiagnostic](#standarddiagnostic). A complete, runnable project is in
[examples](https://github.com/aws-cloudformation/cloudformation-validate/tree/main/src/bindings-wasm/examples).

## Engine

`RegoEngine` and `CelEngine` both implement the `Engine` interface and are interchangeable — they produce identical
diagnostics for the same template and config.

### `Engine` interface

| Method                                | Returns          | Description                                                                                                      |
|---------------------------------------|------------------|------------------------------------------------------------------------------------------------------------------|
| `validateStandard(template, config?)` | `StandardReport` | Validates and returns diagnostics without extended context                                                       |
| `validateDetailed(template, config?)` | `DetailedReport` | Validates and returns diagnostics with documentation URLs, rule descriptions, phase tags, and `ViolationContext` |
| `listRules()`                         | `RuleInfo[]`     | Returns metadata for every built-in and loaded custom rule                                                       |
| `engineName()`                        | `string`         | `"rego"` or `"cel"`                                                                                              |
| `free()`                              | `void`           | Releases the engine's off-heap memory                                                                            |

### `EngineConfig`

Passed to the constructor. All fields are optional; omitted rule arrays are empty and an omitted
`schemaValidatorConfig` uses only the bundled schemas.

```typescript
interface EngineConfig {
    customRules?: RuleSource[];                       // engine-native rules (Rego for RegoEngine, CEL for CelEngine)
    guardRules?: RuleSource[];                        // CloudFormation Guard DSL rules — translated internally
    schemaValidatorConfig?: SchemaValidatorConfig;   // schema validation and overlay configuration
}

interface SchemaValidatorConfig {
    additionalSchemas?: SchemaSource[];   // resource provider schemas merged over the bundled schemas
}

type RuleSource = ExternalRuleSource | RuleFile;
type SchemaSource = AdditionalSchemaSource | SchemaFile;

class RuleFile {
    constructor(path: string);   // rule file read from disk; the path becomes the rule source name
}

class SchemaFile {
    constructor(path: string, typeName?: string); // schema file; typeName defaults to the value inside the JSON
}

interface ExternalRuleSource {
    name: string;     // identifier shown in diagnostics (e.g. file path)
    content: string;  // full rule source text
}

interface AdditionalSchemaSource {
    typeName?: string; // omit to use the typeName inside the schema JSON
    schema: string;    // complete resource provider schema JSON
}
```

Pass a `RuleFile` to load a rule from disk — the same pattern as `TemplateFile` for templates — or an
`ExternalRuleSource` when you already have the rule text in memory. `SchemaFile` does the same for an additional
resource provider schema. Its optional constructor `typeName` may be omitted when the schema JSON contains its own
`typeName`.

The generated `AdditionalSchemaSource` record exposes `typeName` as an optional field. Omit it (or leave the
`SchemaFile` constructor argument unset) for an in-memory schema whose JSON already contains its own `typeName`.

```typescript
const engine = new CelEngine({
    customRules: [new RuleFile("rules/s3_encryption.json")],
    guardRules: [new RuleFile("rules/compliance.guard")],
    schemaValidatorConfig: {
        additionalSchemas: [new SchemaFile("schemas/aws-lambda-function.json")],
    },
});
```

## ValidateConfig

Controls filtering, severity, parameter overrides, and behavior. All fields optional — omitting the config or passing
`{}` uses defaults.

```typescript
interface ValidateConfig {
    include?: RuleFilterConfig;
    exclude?: RuleFilterConfig;
    severityLevel?: Severity;
    parameterOverrides?: Record<string, string>;
    pseudoParameterOverrides?: PseudoParameterOverrides;
    strict?: boolean;
    disableBuiltinRules?: boolean;
}
```

| Field                      | Default                 | Description                                                                                                              |
|----------------------------|-------------------------|--------------------------------------------------------------------------------------------------------------------------|
| `include`                  | `{}` (all rules)        | When set, only matching rules produce diagnostics. Empty means include everything.                                       |
| `exclude`                  | `{}` (nothing excluded) | Matching rules are suppressed. Applied after `include`.                                                                  |
| `severityLevel`            | `"INFO"`                | Minimum severity threshold. Diagnostics below this level are dropped. Values: `DEBUG`, `INFO`, `WARN`, `ERROR`, `FATAL`. |
| `parameterOverrides`       | `{}`                    | Override template parameter values during resolution. Keys are parameter logical IDs.                                    |
| `pseudoParameterOverrides` | all `undefined`         | Override CloudFormation pseudo-parameters (`AWS::AccountId`, `AWS::Region`, etc.).                                       |
| `strict`                   | `false`                 | When `true`, `WARN`-severity diagnostics are upgraded to `ERROR`.                                                        |
| `disableBuiltinRules`      | `false`                 | When `true`, all built-in rules (schema validation, Step Functions, engine rules) are skipped; only custom and Guard rules are evaluated. |

### RuleFilterConfig

Both `include` and `exclude` use this structure. All fields are additive — a rule matches if it hits any criterion.

```typescript
interface RuleFilterConfig {
    ids?: string[];                    // exact rule IDs, e.g. ["E3012", "W3010"]
    categories?: string[];             // category names, e.g. ["security", "best_practices"]
    idRanges?: IdRange[];              // numeric ranges, e.g. { prefix: "E", start: 3000, end: 3099 }
    idPatterns?: string[];             // regex patterns matched against rule IDs
    resourceIds?: ResourceIdFilter[];  // a rule (or every rule) on a logical resource ID
    logicalIds?: LogicalIdFilter[];    // a rule (or every rule) on a named template entity
    resourceTypes?: ResourceTypeFilter[]; // a rule (or every rule) on a resource type
    services?: ServiceFilter[];        // a rule (or every rule) on a service, e.g. "AWS::AutoScaling"
}

// resourceIds / logicalIds / resourceTypes / services each carry an optional ruleId:
// set it to scope the filter to one rule, or omit it for every rule on the target.
interface ResourceIdFilter   { ruleId?: string; resourceId: string; }
interface LogicalIdFilter    { ruleId?: string; logicalId: string; entityType?: EntityType; }
interface ResourceTypeFilter { ruleId?: string; resourceType: string; }
interface ServiceFilter      { ruleId?: string; service: string; }
```

The `service` is matched verbatim against the `service-provider::service-name` prefix of the resource type — its first
two `::`-delimited segments (e.g. `AWS::AutoScaling` in `AWS::AutoScaling::LaunchConfiguration`).

The `resourceIds` dimension matches only diagnostics attributed to a resource; `logicalIds` additionally matches
diagnostics on parameters, outputs, mappings, conditions, and template rules (for resource diagnostics the two carry
the same value). An optional `entityType` scopes a `LogicalIdFilter` to entities of one type, so `MyThing` as a
`"Parameter"` is matched without touching a same-named entity of another type.

### PseudoParameterOverrides

Override CloudFormation pseudo-parameters used during intrinsic function resolution. All fields optional — when
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

## TemplateFile

Wraps a filesystem path. Engines read the file bytes internally.

```typescript
const template = new TemplateFile("path/to/template.yaml");
```

## TemplateModel

Parses a template into the resolved `SemanticModel` for direct inspection — the same model the engines evaluate rules
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
| `formatVersion()`      | `string \ undefined`               | `AWSTemplateFormatVersion` value                                                                |
| `description()`        | `string \ undefined`               | Template description                                                                            |
| `toDiagnosticModel()`  | `DiagnosticModel`                  | Full diagnostic model including reference graph, condition implications, and resolution sources |
| `sourceLocation(path)` | `SourceSpan \ null`                | Source line/column span for a JSON path (e.g. `Resources/MyBucket/Properties/BucketName`)       |
| `free()`               | `void`                             | Releases WASM memory                                                                            |

## SchemaValidator

Runs schema validation independently from the rule engines. Checks each resource against compiled CloudFormation
provider schemas and produces `FATAL`-severity diagnostics for structural violations.

```typescript
const validator = new SchemaValidator();
const diagnostics = validator.validate(new TemplateFile("template.yaml"), "us-east-1");
validator.free();
```

| Method                        | Returns                | Description                                             |
|-------------------------------|------------------------|---------------------------------------------------------|
| `validate(template, region?)` | `StandardDiagnostic[]` | Schema diagnostics. `region` defaults to `"us-east-1"`. |
| `listRules()`                 | `RuleInfo[]`           | Schema rule metadata                                    |
| `schemaCount()`               | `number`               | Number of compiled provider schemas                     |
| `free()`                      | `void`                 | Releases WASM memory                                    |

## Report Types

### StandardReport / DetailedReport

```typescript
interface StandardReport {
    filePath: string;
    status: "OK" | "ERROR";           // ERROR when the template fails to parse
    version: string;
    metadata: ReportMetadata;
    performance: PerformanceMetrics;
    diagnostics: StandardDiagnostic[];
}
```

`DetailedReport` has the same structure but its diagnostics include additional fields: `documentationUrl`,
`ruleDescription`, `phase` (`PARSE` | `SCHEMA` | `LINT`), and `context` (`ViolationContext` with
`actualValue`, `expectedConstraint`, `resolutionSource`, etc.).

### StandardDiagnostic

```typescript
interface StandardDiagnostic {
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
