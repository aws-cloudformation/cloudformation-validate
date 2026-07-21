# diagnostics

Shared type definitions for validation diagnostics, report structures, detail levels, filtering, and performance
metrics. Every crate in the workspace depends on `diagnostics` — it defines the common language for reporting validation
results.

## How It Works

All validation phases (parsing, schema validation, lint rules) produce `Diagnostic` values. Each diagnostic carries a
rule ID, severity, message, location, resource context, and optional metadata. The `ValidationReport` aggregates
diagnostics with summary counts and performance metrics. Reports are converted to `StandardReport` or `DetailedReport`
for serialization.

```
┌─────────────┐     ┌──────────────┐     ┌──────────────────┐
│  Diagnostic  │────▶│  FilterConfig │────▶│ ValidationReport │
│  (per-issue) │     │  (include/   │     │  (diagnostics +  │
│              │     │   exclude)   │     │   summary +      │
└─────────────┘     └──────────────┘     │   metadata)      │
                                          └──────────────────┘
                                                   │
                                          ┌────────┴────────┐
                                          ▼                 ▼
                                    StandardReport     DetailedReport
```

## Severity

| Level   | Ord | Meaning                                                          |
|---------|-----|------------------------------------------------------------------|
| `Fatal` | 4   | Structural schema violation — deployment will fail               |
| `Error` | 3   | Semantic error — likely deployment failure or incorrect behavior |
| `Warn`  | 2   | Security concern, deprecation, or risky pattern                  |
| `Info`  | 1   | Best practice suggestion                                         |
| `Debug` | 0   | Internal diagnostic detail                                       |

## Diagnostic

Each `Diagnostic` contains:

| Field                | Type                            | Purpose                                                       |
|----------------------|---------------------------------|---------------------------------------------------------------|
| `rule_id`            | `String`                        | Stable identifier (e.g., `E3012`, `F3003`)                    |
| `severity`           | `Severity`                      | Fatal / Error / Warn / Info / Debug                           |
| `message`            | `String`                        | Human-readable description                                    |
| `source`             | `RuleOrigin`                    | Where the rule originates (Schema, CfnLint, Engine, etc.)     |
| `resource`           | `Option<ResourceRef>`           | Logical resource ID and type                                  |
| `logical_id`         | `Option<String>`                | Logical ID of the named template entity the finding targets — a resource, parameter, output, mapping, condition, or rule |
| `property_path`      | `Option<String>`                | JSON path to offending property                               |
| `location`           | `Option<SourceSpan>`            | Start/end line and column in source file                      |
| `category`           | `Option<String>`                | Rule category (Schema, Structure, Intrinsic Function, etc.)   |
| `suggested_fix`      | `Option<String>`                | Actionable fix suggestion                                     |
| `documentation_url`  | `Option<String>`                | Link to rule documentation                                    |
| `rule_description`   | `Option<String>`                | Short description of the rule                                 |
| `phase`              | `Option<Phase>`                 | Validation phase (Parse, Schema, Lint)                        |
| `section`            | `Option<String>`                | CloudFormation template section (Resources, Parameters, etc.) |
| `related_resources`  | `Option<Vec<RelatedResource>>`  | Cross-resource references                                     |
| `condition_scenario` | `Option<HashMap<String, bool>>` | Condition truth values that trigger this diagnostic           |
| `context`            | `Option<ViolationContext>`      | Structured violation details (Detailed level only)            |

## StandardDiagnostic vs DetailedDiagnostic

`StandardDiagnostic` flattens `resource` into `resource_id`/`resource_type` and `location` into individual line/column
fields. Drops `documentation_url`, `rule_description`, `phase`, `section`, and `context`.

`DetailedDiagnostic` is the same flattened shape but includes those additional fields.

## ViolationContext

| Field                 | Type                                 | Purpose                             |
|-----------------------|--------------------------------------|-------------------------------------|
| `actual_value`        | `Option<JsonValue>`                  | The value that caused the violation |
| `expected_constraint` | `Option<String>`                     | What the schema or rule expected    |
| `property`            | `Option<String>`                     | Specific property name              |
| `lifecycle`           | `Option<String>`                     | Resource lifecycle context          |
| `resolution_source`   | `Option<String>`                     | How a value was resolved            |
| `extra`               | `Option<HashMap<String, JsonValue>>` | Additional structured data          |

## Report Types

All report types share: `file_path`, `status` (`Ok`/`Error`), `version`, `metadata`, `performance`,
`diagnostics`.

`ReportMetadata`: `rules_evaluated`, `resources_scanned`, `counts` (Summary by severity), `suppressed`, `strict`,
`severity_level`.

## Detail Level

| Variant    | Behavior                                                                | Use Case                             |
|------------|-------------------------------------------------------------------------|--------------------------------------|
| `Standard` | Flattens resource/location, drops context and enrichment fields         | IDE annotations, developer workflows |
| `Detailed` | Same flattening plus includes context, phase, section, rule_description | AI agents, deep debugging            |

`Detailed` is the default.

## Phase

| Variant  | Serde      |
|----------|------------|
| `Parse`  | `"PARSE"`  |
| `Schema` | `"SCHEMA"` |
| `Lint`   | `"LINT"`   |

## Filtering

`FilterConfig` supports include and exclude rules, evaluated in order:

1. If include filters are non-empty, a diagnostic must match at least one
2. Any diagnostic matching an exclude filter is removed

## Performance Metrics

`PerformanceMetrics` tracks `duration_ms` per pipeline phase: `schema_init`, `engine_init`, `model_build`,
`schema_validate`, `rule_evaluation`, `diagnostic_finalize`, `validate_total`.
