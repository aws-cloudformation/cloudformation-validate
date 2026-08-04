# CloudFormation Validate for Python

Validate AWS CloudFormation templates from Python and catch schema violations, security risks, and best-practice
findings before deployment — in your editor, build, or CI.

- **Offline** — all rules and resource schemas are bundled.
- **Fast** — sub-second validation per template.
- **Self-contained** — each platform wheel bundles its matching native library.

All types are importable from the top-level `cloudformation_validate` package.

## Installation

Available on [PyPI](https://pypi.org/project/cloudformation-validate/) as `cloudformation-validate`.

```bash
pip install cloudformation-validate
```

Requires Python 3.12+ and has no runtime dependencies. PyPI publishes a separate wheel for every supported native
target. Each wheel carries exactly one native library and an accurate platform tag, so pip downloads only the
artifact compatible with the installer host.

## Quick start

```python
from cloudformation_validate import RegoEngine

engine = RegoEngine()
report = engine.validate_standard("template.yaml")

for d in report.diagnostics:
    print(f"[{d.severity.name}] {d.rule_id}: {d.message}")
```

Each diagnostic identifies the rule, severity, affected resource and property, and source location — see
[StandardDiagnostic](#standarddiagnostic).

Engines are expensive to construct (rules compile once) and cheap to reuse — create one engine and validate many
templates. A template is passed either as a file path (`str` or `os.PathLike`, read from disk) or as raw `bytes`:

```python
report = engine.validate_standard(b"Resources: {}")
```

## Engine

`RegoEngine` and `CelEngine` both subclass `Engine` and are interchangeable — they produce identical diagnostics for
the same template and config.

| Method                                     | Returns          | Description                                                                                                      |
|--------------------------------------------|------------------|------------------------------------------------------------------------------------------------------------------|
| `validate_standard(template, config=None)` | `StandardReport` | Validates and returns diagnostics without extended context                                                       |
| `validate_detailed(template, config=None)` | `DetailedReport` | Validates and returns diagnostics with documentation URLs, rule descriptions, phase tags, and `ViolationContext` |
| `list_rules()`                             | `list[RuleInfo]` | Returns metadata for every built-in and loaded custom rule                                                       |
| `engine_name()`                            | `str`            | `"rego"` or `"cel"`                                                                                              |

`template` is a file path (`str` / `os.PathLike`) or raw `bytes`; `config` is an optional `ValidateConfig`.

### EngineConfig

Passed to the constructor. All fields default to empty lists.

```python
engine = RegoEngine()  # default config
engine = CelEngine(EngineConfig(guard_rules=[my_rule]))  # with Guard rules
```

| Field                | Default | Description                                                                                   |
|----------------------|---------|-----------------------------------------------------------------------------------------------|
| `custom_rules`       | `[]`    | Engine-native rules (Rego for `RegoEngine`, CEL for `CelEngine`)                              |
| `guard_rules`        | `[]`    | CloudFormation Guard DSL rules — translated internally by each engine                         |
| `schema_validator`   | `None`  | Optional `SchemaValidatorConfig`; configures the validator bundled by the engine              |

The optional `schema_validator` field accepts a `SchemaValidatorConfig` containing additional schemas. Each additional
schema is an `AdditionalSchemaSource`. Load one from a file with
`file_to_additional_schema_source(path, type_name="")`, or construct it from schema text. `type_name` may be empty
when the JSON contains its own `typeName`:

```python
from cloudformation_validate import EngineConfig, RegoEngine, SchemaValidatorConfig, file_to_additional_schema_source

engine = RegoEngine(
    EngineConfig(schema_validator=SchemaValidatorConfig(
        additional_schemas=[file_to_additional_schema_source("schemas/aws-lambda-function.json")]
    ))
)
```

Each rule is an `ExternalRuleSource`. Load one from a file with `file_to_external_rule_source(path)` — the same
pattern as passing a template path to `validate_standard` — or construct it from explicit values with
`ExternalRuleSource(name, content)`, where `name` identifies the rule in diagnostics and `content` is the full rule
source text. The two can be mixed freely:

```python
from cloudformation_validate import CelEngine, EngineConfig, ExternalRuleSource, file_to_external_rule_source

engine = CelEngine(
    EngineConfig(
        custom_rules=[file_to_external_rule_source("rules/s3_encryption.json")],
        guard_rules=[ExternalRuleSource(name="compliance.guard", content=open("rules/compliance.guard").read())],
    ),
)
```

## ValidateConfig

Controls filtering, severity, parameter overrides, and behavior. All fields have defaults — passing `ValidateConfig()`
uses them.

```python
config = ValidateConfig(
    exclude=RuleFilterConfig(ids=["I1002"]),
    severity_level=Severity.WARN,
)
report = engine.validate_standard("template.yaml", config)
```

| Field                        | Default                  | Description                                                                                                                               |
|------------------------------|--------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| `include`                    | empty (all rules)        | When set, only matching rules produce diagnostics. Empty means include everything.                                                        |
| `exclude`                    | empty (nothing excluded) | Matching rules are suppressed. Applied after `include`.                                                                                   |
| `severity_level`             | `Severity.INFO`          | Minimum severity threshold. Diagnostics below this level are dropped. Values: `DEBUG`, `INFO`, `WARN`, `ERROR`, `FATAL`.                  |
| `parameter_overrides`        | `{}`                     | Override template parameter values during resolution. Keys are parameter logical IDs.                                                     |
| `pseudo_parameter_overrides` | all `None`               | Override CloudFormation pseudo-parameters (`AWS::AccountId`, `AWS::Region`, etc.).                                                        |
| `strict`                     | `False`                  | When `True`, `WARN`-severity diagnostics are upgraded to `ERROR`.                                                                         |
| `disable_builtin_rules`      | `False`                  | When `True`, all built-in rules (schema validation, Step Functions, engine rules) are skipped; only custom and Guard rules are evaluated. |

### RuleFilterConfig

Both `include` and `exclude` use this structure. All fields are additive — a rule matches if it hits any criterion.

```python
class RuleFilterConfig:
    ids: list[str]  # exact rule IDs, e.g. ["E3012", "W3010"]
    categories: list[str]  # category names, e.g. ["security", "best_practices"]
    id_ranges: list[IdRange]  # numeric ranges, e.g. IdRange(prefix="E", start=3000, end=3099)
    id_patterns: list[str]  # regex patterns matched against rule IDs
    resource_ids: list[ResourceIdFilter]  # a rule (or every rule) on a logical resource ID
    logical_ids: list[LogicalIdFilter]  # a rule (or every rule) on a named template entity
    resource_types: list[ResourceTypeFilter]  # a rule (or every rule) on a resource type
    services: list[ServiceFilter]  # a rule (or every rule) on a service, e.g. "AWS::AutoScaling"


# All list fields above default to empty. Each filter below carries an optional
# rule_id: set it to scope the filter to one rule, or leave it None for every
# rule on the target.
class ResourceIdFilter:
    rule_id: str | None
    resource_id: str


class LogicalIdFilter:
    rule_id: str | None
    logical_id: str
    entity_type: EntityType | None


class ResourceTypeFilter:
    rule_id: str | None
    resource_type: str


class ServiceFilter:
    rule_id: str | None
    service: str
```

The `service` is matched verbatim against the `service-provider::service-name` prefix of the resource type — its first
two `::`-delimited segments (e.g. `AWS::AutoScaling` in `AWS::AutoScaling::LaunchConfiguration`).

The `resource_ids` dimension matches only diagnostics attributed to a resource; `logical_ids` additionally matches
diagnostics on parameters, outputs, mappings, conditions, and template rules (for resource diagnostics the two carry
the same value). A non-`None` `entity_type` scopes a `LogicalIdFilter` to entities of one type, so `MyThing` as a
`PARAMETER` is matched without touching a same-named entity of another type.

### PseudoParameterOverrides

Override CloudFormation pseudo-parameters used during intrinsic function resolution. All fields optional — when `None`,
the engine uses built-in defaults (e.g. region defaults to `us-east-1`).

```python
@dataclass
class PseudoParameterOverrides:
    account_id: str | None = None  # AWS::AccountId
    notification_arns: str | None = None  # AWS::NotificationARNs
    partition: str | None = None  # AWS::Partition
    region: str | None = None  # AWS::Region (default: "us-east-1")
    stack_id: str | None = None  # AWS::StackId
    stack_name: str | None = None  # AWS::StackName
    url_suffix: str | None = None  # AWS::URLSuffix
```

## TemplateModel

Parses a template into the resolved `SemanticModel` for direct inspection — the same model the engines evaluate rules
against.

```python
model = TemplateModel("template.yaml")  # accepts a path or bytes, like the engines
```

| Method                  | Returns                       | Description                                                                                     |
|-------------------------|-------------------------------|-------------------------------------------------------------------------------------------------|
| `resources()`           | `dict[str, ResolvedResource]` | All resources with resolved property values                                                     |
| `parameters()`          | `dict[str, ParameterInfo]`    | Parameter definitions with types, defaults, constraints                                         |
| `outputs()`             | `dict[str, ResolvedOutput]`   | Outputs with resolved values and export names                                                   |
| `conditions()`          | `list[str]`                   | Condition names defined in the template                                                         |
| `transforms()`          | `list[str]`                   | Transform declarations (e.g. `AWS::Serverless-2016-10-31`)                                      |
| `format_version()`      | `str \| None`                 | `AWSTemplateFormatVersion` value                                                                |
| `description()`         | `str \| None`                 | Template description                                                                            |
| `to_diagnostic_model()` | `DiagnosticModel`             | Full diagnostic model including reference graph, condition implications, and resolution sources |
| `source_location(path)` | `SourceSpan \| None`          | Source line/column span for a JSON path (e.g. `Resources/MyBucket/Properties/BucketName`)       |

## SchemaValidator

Runs schema validation independently from the rule engines. Checks each resource against compiled CloudFormation
provider schemas and produces `FATAL`-severity diagnostics for structural violations.

```python
validator = SchemaValidator()
diagnostics = validator.validate("template.yaml")
```

| Method                            | Returns                    | Description                                             |
|-----------------------------------|----------------------------|---------------------------------------------------------|
| `validate(template, region=None)` | `list[StandardDiagnostic]` | Schema diagnostics. `region` defaults to `"us-east-1"`. |
| `list_rules()`                    | `list[RuleInfo]`           | Schema rule metadata                                    |
| `schema_count()`                  | `int`                      | Number of compiled provider schemas                     |

## Report Types

All report and diagnostic types are dataclass-like records re-exported from `cloudformation_validate`.

### StandardReport / DetailedReport

```python
@dataclass
class StandardReport:
    file_path: str
    status: ReportStatus  # ReportStatus.OK or ReportStatus.ERROR (ERROR when the template fails to parse)
    version: str
    metadata: ReportMetadata
    performance: PerformanceMetrics
    diagnostics: list[StandardDiagnostic]
```

`DetailedReport` has the same structure but its diagnostics are `DetailedDiagnostic`, which add `documentation_url`,
`rule_description`, `phase` (`PARSE` | `SCHEMA` | `LINT`), and `context` (a `ViolationContext` with `actual_value`,
`expected_constraint`, `resolution_source`, etc.).

### StandardDiagnostic

```python
@dataclass
class StandardDiagnostic:
    rule_id: str  # e.g. "E3012", "F1001", "W3010"
    severity: Severity  # FATAL, ERROR, WARN, INFO, DEBUG
    message: str
    source: RuleOrigin  # SCHEMA, CFN_LINT, ENGINE, CUSTOM, GUARD
    entity: Entity | None  # the named template entity the finding targets, if any
    property_path: str | None  # e.g. "Properties.BucketName", or section-absolute like "Parameters/MyParam/Type"
    suggested_fix: str | None
    category: str | None
    start_line: int | None
    start_column: int | None
    end_line: int | None
    end_column: int | None
    related_resources: list[RelatedResource] | None
    condition_scenario: dict[str, bool] | None  # condition truth assignment that triggers this diagnostic


# The named template entity a diagnostic is attributed to. The entity type is the
# singular form of the top-level template section the entity is declared in.
@dataclass
class Entity:
    logical_id: str  # logical ID as declared in the template
    entity_type: EntityType
    resource_type: str | None = None  # CloudFormation type, when the entity is a resource whose type is known

# EntityType is an enum with members: RESOURCE, PARAMETER, OUTPUT, MAPPING,
# METADATA, RULE, CONDITION, TRANSFORM, FORMAT_VERSION, DESCRIPTION.
```

`Severity` and `RuleOrigin` are enums; use `.name` for the string form (e.g. `severity.name == "WARN"`). Every fallible
call raises `ValidationError` — internal panics are caught at the FFI boundary and surface as the same exception, never
a process abort.
