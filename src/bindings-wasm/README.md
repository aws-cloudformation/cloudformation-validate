# bindings-wasm

WASM bindings for the [CloudFormation Validation Engine](../../README.md). Compiles the full validation pipeline —
template parser, schema validator, Rego engine, and CEL engine — into a single `.wasm` module for Node.js.

All WASM objects must be explicitly freed via `.free()` to release memory.

## Engine

`RegoEngine` and `CelEngine` both implement the `Engine` interface. They are interchangeable — both produce identical
diagnostics for the same template and config.

```typescript
import {RegoEngine, CelEngine, TemplateFile} from "@aws/cloudformation-validate-wasm";

const engine = new RegoEngine();
const report = engine.validateStandard(new TemplateFile("template.yaml"));

for (const d of report.diagnostics) {
    console.log(`[${d.severity}] ${d.ruleId}: ${d.message}`);
}
engine.free();
```

### `Engine` interface

| Method                                | Returns          | Description                                                                                                      |
|---------------------------------------|------------------|------------------------------------------------------------------------------------------------------------------|
| `validateStandard(template, config?)` | `StandardReport` | Validates and returns diagnostics without extended context                                                       |
| `validateDetailed(template, config?)` | `DetailedReport` | Validates and returns diagnostics with documentation URLs, rule descriptions, phase tags, and `ViolationContext` |
| `listRules()`                         | `RuleInfo[]`     | Returns metadata for every built-in and loaded custom rule                                                       |
| `engineName()`                        | `string`         | `"rego"` or `"cel"`                                                                                              |
| `free()`                              | `void`           | Releases WASM memory                                                                                             |

### `EngineConfig`

Passed to the constructor. All fields optional, default to empty arrays.

```typescript
interface EngineConfig {
    customRules?: ExternalRuleSource[];  // engine-native rules (Rego for RegoEngine, CEL for CelEngine)
    guardRules?: ExternalRuleSource[];   // CloudFormation Guard DSL rules — translated internally by each engine
}

interface ExternalRuleSource {
    name: string;     // identifier shown in diagnostics (e.g. file path)
    content: string;  // full rule source text
}
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
    includeEngineRules?: boolean;
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
| `includeEngineRules`       | `true`                  | When `false`, diagnostics with `source: "ENGINE"` are suppressed.                                                        |

### RuleFilterConfig

Both `include` and `exclude` use this structure. All fields are additive — a rule matches if it hits any criterion.

```typescript
interface RuleFilterConfig {
    ids?: string[];                    // exact rule IDs, e.g. ["E3012", "W3010"]
    categories?: string[];             // category names, e.g. ["security", "best_practices"]
    idRanges?: IdRange[];              // numeric ranges, e.g. { prefix: "E", start: 3000, end: 3099 }
    idPatterns?: string[];             // regex patterns matched against rule IDs
    resourceIds?: ResourceIdFilter[];  // suppress rule for specific logical resource ID
    resourceTypes?: ResourceTypeFilter[]; // suppress rule for specific resource type
}
```

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
    engineVersion: string;
    metadata: ReportMetadata;
    performance: PerformanceMetrics;
    diagnostics: StandardDiagnostic[];
}
```

`DetailedReport` has the same structure but its diagnostics include additional fields: `documentationUrl`,
`ruleDescription`, `phase` (`PARSE` | `SCHEMA` | `LINT`), `section`, and `context` (`ViolationContext` with
`actualValue`, `expectedConstraint`, `resolutionSource`, etc.).

### StandardDiagnostic

```typescript
interface StandardDiagnostic {
    ruleId: string;                    // e.g. "E3012", "F1001", "W3010"
    severity: Severity;                // "FATAL" | "ERROR" | "WARN" | "INFO" | "DEBUG"
    message: string;
    source: RuleOrigin;                // "SCHEMA" | "CFN_LINT" | "ENGINE" | "CUSTOM" | "GUARD"
    resourceId?: string;               // logical resource ID
    resourceType?: string;             // e.g. "AWS::S3::Bucket"
    propertyPath?: string;             // e.g. "Properties/BucketName"
    suggestedFix?: string;
    category?: string;
    startLine?: number;
    startColumn?: number;
    endLine?: number;
    endColumn?: number;
    relatedResources?: RelatedResource[];
    conditionScenario?: Record<string, boolean>;  // condition truth assignment that triggers this diagnostic
}
```

### Severity levels

| Level   | Prefix | Meaning                                                               |
|---------|--------|-----------------------------------------------------------------------|
| `FATAL` | F      | Structural schema violation — CloudFormation will reject the template |
| `ERROR` | E      | Semantic error — likely deployment failure or incorrect behavior      |
| `WARN`  | W      | Security risk, deprecation, or risky pattern                          |
| `INFO`  | I      | Best practice suggestion                                              |
| `DEBUG` | D      | Internal diagnostic detail                                            |

## `version()`

Returns the engine version string.

```typescript
import {version} from "@aws/cloudformation-validate-wasm";

console.log(version()); // e.g. "0.1.0"
```
