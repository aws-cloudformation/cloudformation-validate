# AWS CloudFormation Validate

Validate AWS CloudFormation templates from Python and catch schema violations, semantic errors, security risks, and
best-practice findings before deployment - in your editor, build, service, or CI.

- **Offline** - all rules and CloudFormation resource schemas are bundled; nothing is fetched at runtime and no AWS
  credentials are needed.
- **Fast** - engines and schemas compile once and are reused across validations; typical templates validate in under a
  second.
- **Self-contained** - each platform wheel bundles its matching native library.

All types are importable from the top-level `cloudformation_validate` package.

## Installation

Available on [PyPI](https://pypi.org/project/cloudformation-validate/) as `cloudformation-validate`.

```bash
pip install cloudformation-validate
```

Requires Python 3.9 or later. The package has no runtime dependencies. PyPI publishes a separate wheel for every
supported native target; each wheel carries exactly one native library and an accurate platform tag, so pip downloads
only the artifact compatible with the installing host.

## Quick start

```python
from cloudformation_validate import CompositeEngine

engine = CompositeEngine()
report = engine.validate_template("template.yaml")
for d in report.diagnostics:
    print(f"[{d.severity.name}] {d.rule_id}: {d.message}")
```

Each diagnostic identifies the rule, severity, affected entity and property, and source location - see
[Diagnostic](#diagnostic).

Engines are expensive to construct (rules compile once) and cheap to reuse - create one engine and validate many
templates. Every fallible call raises `ValidationError` on failure; internal panics are caught at the FFI boundary and
surface as the same exception, never a process abort. `version()` returns the version of the bundled validation core.

A template is passed as a `Template`: a file path (`str` or `os.PathLike`, read from disk; the path is used for
diagnostic source locations), raw `bytes`, or a `TemplateContent` carrying `str` text or `bytes` already in memory
together with an optional `name` that labels the report and its diagnostics exactly like a file path does. An
in-memory template with no name is labelled `"template"` (`DEFAULT_TEMPLATE_NAME`).

```python
Template = str | os.PathLike | bytes | TemplateContent

class TemplateContent:
    def __init__(self, content: str | bytes, name: str = DEFAULT_TEMPLATE_NAME): ...

report = engine.validate_template(b"Resources: {}")
report = engine.validate_template(TemplateContent("Resources: {}", "inline.yaml"))
```

`TemplateModel` and `SchemaValidator.validate` accept the same `Template` forms.

## Engine

`RegoEngine` and `CelEngine` both subclass `Engine` and are interchangeable - they produce identical diagnostics for
the same template and config. `CompositeEngine` also subclasses `Engine` and layers custom Rego, CEL, and Guard rules
on top of the built-in rules - see [CompositeEngine](#compositeengine).

### `Engine` base class

```python
class Engine:
    def validate_template(self, template: Template, config: ValidateConfig | None = None) -> ValidationReport: ...
    def validate_aws_cli_command(self, request: AwsCliCommand) -> AwsCliCommandValidation: ...
    def list_rules(self) -> list[RuleInfo]: ...
    def engine_name(self) -> str: ...
```

| Method                                     | Returns                   | Description                                                                                                                                                                                                                       |
|--------------------------------------------|---------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `validate_template(template, config=None)` | `ValidationReport`        | Validates the template and returns a report. `config.detail_level` (default `DETAILED`) selects how much per-diagnostic context is populated: `DETAILED` adds documentation URLs, rule descriptions, phase tags, and `ViolationContext`; `STANDARD` leaves those enrichment fields absent |
| `validate_aws_cli_command(request)`        | `AwsCliCommandValidation` | Models an AWS CLI command as CloudFormation resource state and validates it - see [AWS CLI command validation](#aws-cli-command-validation)                                                                                       |
| `list_rules()`                             | `list[RuleInfo]`          | Returns metadata for every built-in and loaded custom rule                                                                                                                                                                        |
| `engine_name()`                            | `str`                     | `"rego"`, `"cel"`, or `"composite"`                                                                                                                                                                                               |

### `EngineConfig`

Passed to the constructor. All fields are optional: the rule lists default to empty and a `None`
`schema_validator_config` uses only the bundled schemas.

```python
@dataclass
class EngineConfig:
    custom_rules: list[ExternalRuleSource] = []                 # engine-native rules (Rego for RegoEngine, CEL for CelEngine)
    guard_rules: list[ExternalRuleSource] = []                  # CloudFormation Guard DSL rules - evaluated by the Guard evaluator
    schema_validator_config: SchemaValidatorConfig | None = None  # additional resource provider schemas

@dataclass
class SchemaValidatorConfig:
    additional_schemas: list[AdditionalSchemaSource] = []  # resource provider schemas merged over the bundled schemas

@dataclass
class ExternalRuleSource:
    name: str     # identifier shown in diagnostics (e.g. file path)
    content: str  # full rule source text

@dataclass
class AdditionalSchemaSource:
    type_name: str | None = None  # None to use the typeName inside the schema JSON
    schema: str                   # complete resource provider schema JSON

def file_to_external_rule_source(path) -> ExternalRuleSource: ...                       # rule file read from disk; the path becomes the rule source name
def file_to_additional_schema_source(path, type_name=None) -> AdditionalSchemaSource: ...  # schema file; type_name defaults to the value inside the JSON
```

| Field                     | Default | Description                                                                                    |
|---------------------------|---------|------------------------------------------------------------------------------------------------|
| `custom_rules`            | `[]`    | Engine-native rules: Rego source for `RegoEngine`, CEL JSON for `CelEngine`                    |
| `guard_rules`             | `[]`    | CloudFormation Guard DSL rules, evaluated by the Guard evaluator identically in every engine                         |
| `schema_validator_config` | `None`  | Optional `SchemaValidatorConfig` whose `additional_schemas` are merged over the bundled schemas |

Each rule is an `ExternalRuleSource` - `name` identifies the rule in diagnostics and `content` is the full rule source
text. Use `file_to_external_rule_source(path)` to load one from disk (the same pattern as passing a template path to
`validate_template`), or construct an `ExternalRuleSource(name, content)` when you already have the rule text in memory.
Each additional schema is an `AdditionalSchemaSource` - a complete resource provider schema JSON plus an optional
`type_name` that may be omitted when the schema JSON contains its own `typeName`;
`file_to_additional_schema_source(path)` loads one from disk. Additional schemas extend the bundled schemas or register
resource types CloudFormation has not published yet; a malformed, contradictory, or unsupported schema fails engine
construction rather than silently weakening validation. Guard rules are evaluated by the CloudFormation Guard evaluator
itself against the template as written, so every engine reports exactly what `cfn-guard validate` reports; a Guard file
that does not parse also fails engine construction. The two forms can be mixed freely:

```python
from cloudformation_validate import (
    CelEngine, EngineConfig, SchemaValidatorConfig, file_to_additional_schema_source, file_to_external_rule_source,
)

engine = CelEngine(
    EngineConfig(
        custom_rules=[file_to_external_rule_source("rules/s3_encryption.json")],
        guard_rules=[file_to_external_rule_source("rules/compliance.guard")],
        schema_validator_config=SchemaValidatorConfig(
            additional_schemas=[file_to_additional_schema_source("schemas/aws-lambda-function.json")],
        ),
    ),
)
```

See [Custom Rules](../CUSTOM_RULES.md) for the Rego, CEL, and Guard rule formats and
[Additional Resource Provider Schemas](../validation-engine/API.md#additional-resource-provider-schemas) for the schema
merge model.

### `CompositeEngine`

`CompositeEngine` also subclasses `Engine` but takes a `CompositeEngineConfig`. It evaluates every built-in rule with a
fixed built-in CEL evaluator and layers the caller-supplied custom rules on top: custom CEL and Guard rules run
alongside that built-in engine, while custom Rego rules run in a separate external engine that is constructed only when
Rego rules are supplied. With no custom rules it produces the same built-in diagnostics as `RegoEngine` and `CelEngine`,
and `engine_name()` returns `"composite"`. Because the composite fixes which engine owns the built-ins, the config has
no `custom_rules` field - it carries only the custom rules layered on top:

```python
@dataclass
class CompositeEngineConfig:
    rego_rules: list[ExternalRuleSource] = []                     # custom Rego rules, run by the external engine
    cel_rules: list[ExternalRuleSource] = []                      # custom CEL rules, run by the built-in engine
    guard_rules: list[ExternalRuleSource] = []                    # CloudFormation Guard DSL rules, evaluated alongside the built-in engine
    schema_validator_config: SchemaValidatorConfig | None = None  # additional resource provider schemas, observed by both inner engines
```

| Field                     | Default | Description                                                                                      |
|---------------------------|---------|--------------------------------------------------------------------------------------------------|
| `rego_rules`              | `[]`    | Custom Rego rules layered on top of the built-in rules, run by the external engine               |
| `cel_rules`               | `[]`    | Custom CEL rules layered on top of the built-in rules, run by the built-in engine                |
| `guard_rules`             | `[]`    | CloudFormation Guard DSL rules layered on top of the built-in rules, evaluated alongside the built-in engine |
| `schema_validator_config` | `None`  | Optional `SchemaValidatorConfig`, observed by both inner engines                                 |

```python
from cloudformation_validate import CompositeEngine, CompositeEngineConfig, file_to_external_rule_source

engine = CompositeEngine(
    CompositeEngineConfig(
        rego_rules=[file_to_external_rule_source("rules/s3_naming.rego")],
        guard_rules=[file_to_external_rule_source("rules/compliance.guard")],
    ),
)
report = engine.validate_template("template.yaml")
```

## ValidateConfig

Controls filtering, detail, severity, parameter overrides, and behavior for one validation call. All fields have
defaults - omitting the config or passing `ValidateConfig()` uses them.

```python
from cloudformation_validate import RuleFilterConfig, Severity, ValidateConfig

report = engine.validate_template(
    "template.yaml",
    ValidateConfig(
        exclude=RuleFilterConfig(ids=["I1002"]),
        severity_level=Severity.WARN,
    ),
)
```

```python
@dataclass
class ValidateConfig:
    include: RuleFilterConfig = RuleFilterConfig()
    exclude: RuleFilterConfig = RuleFilterConfig()
    detail_level: DetailLevel | None = None       # None = DETAILED
    severity_level: Severity | None = None        # None = INFO
    parameter_overrides: dict[str, str] = {}
    pseudo_parameter_overrides: PseudoParameterOverrides = PseudoParameterOverrides()
    strict: bool | None = None                    # None = False
    disable_builtin_rules: bool | None = None     # None = False
```

| Field                        | Default                  | Description                                                                                                                                                              |
|------------------------------|--------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `include`                    | empty (all rules)        | When set, only matching rules produce diagnostics. Empty means include everything.                                                                                       |
| `exclude`                    | empty (nothing excluded) | Matching rules are suppressed. Applied after `include`.                                                                                                                  |
| `detail_level`               | `DETAILED`               | Per-diagnostic context. `DETAILED` populates documentation URLs, rule descriptions, phase tags, and `ViolationContext`; `STANDARD` leaves those enrichment fields absent. |
| `severity_level`             | `INFO`                   | Minimum severity threshold. Diagnostics below this level are dropped. Values: `DEBUG`, `INFO`, `WARN`, `ERROR`, `FATAL`.                                                 |
| `parameter_overrides`        | `{}`                     | Override template parameter values during resolution. Keys are parameter logical IDs.                                                                                    |
| `pseudo_parameter_overrides` | all `None`               | Override CloudFormation pseudo-parameters (`AWS::AccountId`, `AWS::Region`, etc.).                                                                                       |
| `strict`                     | `False`                  | When `True`, `WARN`-severity diagnostics are upgraded to `ERROR`.                                                                                                        |
| `disable_builtin_rules`      | `False`                  | When `True`, all built-in rules (schema validation, Step Functions, engine rules) are skipped; only custom and Guard rules are evaluated.                                |

### RuleFilterConfig

Both `include` and `exclude` use this structure. All fields are additive - a rule matches if it hits any criterion.

```python
@dataclass
class RuleFilterConfig:
    ids: list[str] = []                             # exact rule IDs, e.g. ["E3012", "W3010"]
    categories: list[str] = []                      # category names, e.g. ["security", "best_practices"]
    id_ranges: list[IdRange] = []                   # numeric ranges, e.g. IdRange(prefix="E", start=3000, end=3099)
    id_patterns: list[str] = []                     # regex patterns matched against rule IDs
    resource_ids: list[ResourceIdFilter] = []       # a rule (or every rule) on a logical resource ID
    logical_ids: list[LogicalIdFilter] = []         # a rule (or every rule) on a named template entity
    resource_types: list[ResourceTypeFilter] = []   # a rule (or every rule) on a resource type
    services: list[ServiceFilter] = []              # a rule (or every rule) on a service, e.g. "AWS::AutoScaling"

# resource_ids / logical_ids / resource_types / services each carry an optional rule_id:
# set it to scope the filter to one rule, or leave it None for every rule on the target.
@dataclass
class ResourceIdFilter:   rule_id: str | None = None; resource_id: str
@dataclass
class LogicalIdFilter:    rule_id: str | None = None; logical_id: str; entity_type: EntityType | None = None
@dataclass
class ResourceTypeFilter: rule_id: str | None = None; resource_type: str
@dataclass
class ServiceFilter:      rule_id: str | None = None; service: str
```

The `service` is matched verbatim against the `service-provider::service-name` prefix of the resource type - its first
two `::`-delimited segments (e.g. `AWS::AutoScaling` in `AWS::AutoScaling::LaunchConfiguration`).

The `resource_ids` dimension matches only diagnostics attributed to a resource; `logical_ids` additionally matches
diagnostics on parameters, outputs, mappings, conditions, and template rules (for resource diagnostics the two carry
the same value). A non-`None` `entity_type` scopes a `LogicalIdFilter` to entities of one type, so `MyThing` as a
`PARAMETER` is matched without touching a same-named entity of another type.

### PseudoParameterOverrides

Override CloudFormation pseudo-parameters used during intrinsic function resolution. All fields are optional - when
`None`, the engine uses built-in defaults (e.g. region defaults to `us-east-1`).

```python
@dataclass
class PseudoParameterOverrides:
    account_id: str | None = None         # AWS::AccountId
    notification_arns: str | None = None  # AWS::NotificationARNs
    partition: str | None = None          # AWS::Partition
    region: str | None = None             # AWS::Region (default: "us-east-1")
    stack_id: str | None = None           # AWS::StackId
    stack_name: str | None = None         # AWS::StackName
    url_suffix: str | None = None         # AWS::URLSuffix
```

## TemplateModel

Parses a template into the resolved `SemanticModel` for direct inspection - the same model the engines evaluate rules
against.

```python
model = TemplateModel("template.yaml")  # a path, bytes, or TemplateContent, like the engines
in_memory = TemplateModel(TemplateContent("Resources: {}"))
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

Runs schema validation independently from the rule engines. Checks each resource against the compiled CloudFormation
provider schemas and produces `FATAL`-severity diagnostics for structural violations. The optional constructor argument
is the same `SchemaValidatorConfig` accepted by `EngineConfig`; omitting it uses only the bundled schemas.

```python
validator = SchemaValidator()
diagnostics = validator.validate("template.yaml")
```

| Method                                | Returns            | Description                                                                                                     |
|---------------------------------------|--------------------|-----------------------------------------------------------------------------------------------------------------|
| `SchemaValidator(schema_config=None)` | `SchemaValidator`  | Constructs a validator; `None` uses only the bundled schemas                                                    |
| `validate(template, region=None)`     | `list[Diagnostic]` | Schema diagnostics at `STANDARD` detail - the enrichment fields are absent. `region` defaults to `"us-east-1"`. |
| `list_rules()`                        | `list[RuleInfo]`   | Schema rule metadata                                                                                            |
| `schema_count()`                      | `int`              | Number of compiled provider schemas                                                                             |

## AWS CLI command validation

`validate_aws_cli_command` models an AWS CLI (or SDK) API call as CloudFormation resource state and validates it
offline before it is sent. It classifies the operation, maps it to a CloudFormation resource type through a closed,
generated adapter catalog, synthesizes a template from the supplied parameters, and runs the normal template pipeline
on it. A `TemplateBody` parameter of a CloudFormation operation is validated as-is. Any request that cannot be modeled
exactly - an unregistered operation, a parameter without a lossless property mapping, or a value outside a
CloudFormation constraint the API itself does not enforce - is skipped with a reason, never guessed.

```python
from cloudformation_validate import AwsCliCommand, AwsCliCommandValidationStatus, CompositeEngine

engine = CompositeEngine()
request = AwsCliCommand("s3", "CreateBucket", {"Bucket": "example-bucket"})
validation = engine.validate_aws_cli_command(request)
if validation.status == AwsCliCommandValidationStatus.VALIDATED:
    for d in validation.report.diagnostics:
        print(f"[{d.severity.name}] {d.rule_id}: {d.message}")
else:
    print(f"skipped ({validation.operation_kind.name}): {validation.reason}")
```

```python
class AwsCliCommand:
    def __init__(
        self,
        service_name: str,                 # canonical botocore service name, e.g. "s3" or "cloudformation"
        operation_name: str,               # API operation name, e.g. "CreateBucket"
        parameters: Mapping[str, object],  # request parameters
        *,
        service_prefix: str | None = None, # signing prefix; context only
        http_method: str | None = None,    # classification hint ("GET"/"HEAD"/"DELETE") for unrecognized verbs
        is_read_only: bool | None = None,  # True classifies the operation as READ_ONLY
    ): ...
```

- `service_name` is matched case-insensitively. Signing names, endpoint aliases, and ARN prefixes are never resolved;
  translate an SDK's service identity first.
- `parameters` accepts nested mappings and sequences, `str`, `int`, `float`, `bool`, `None`, `bytes`, and
  `datetime.datetime` (serialized as ISO 8601) - the same values used by botocore request dictionaries. Any other value
  is carried as an explicit unsupported marker, and because synthesis is all-or-nothing the request is then skipped
  with a reason naming the offending parameter - no parameter is ever silently dropped.

The result is an `AwsCliCommandValidation`:

| Field             | Description                                                                                                                                                       |
|-------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `operation_kind`  | `AwsCliOperationKind`: `READ_ONLY`, `CLOUD_FORMATION_CREATE`, `CLOUD_FORMATION_UPDATE`, `CLOUD_FORMATION_DELETE`, `DATA_PLANE_MUTATION`, or `UNMAPPED_MUTATION`   |
| `status`          | `AwsCliCommandValidationStatus`: `VALIDATED` when the modeled template ran through the pipeline, `SKIPPED` otherwise                                               |
| `template_source` | `AwsCliTemplateSource \| None`: `TEMPLATE_BODY`, `CLOUD_CONTROL_DESIRED_STATE`, `SYNTHESIZED_CREATE`, or `SYNTHESIZED_UPDATE`; `None` when skipped                |
| `resource_types`  | `list[str]` - CloudFormation resource types the operation maps to                                                                                                 |
| `reason`          | `str` - why the request was validated or skipped                                                                                                                  |
| `report`          | `ValidationReport \| None` - present when `VALIDATED`. The configuration is fixed: `STANDARD` detail level and a `WARN` severity floor                             |
| `template`        | `bytes \| None` - the exact template bytes that were validated (the caller's `TemplateBody` unchanged, or the synthesized JSON); `None` when skipped               |

The full contract - the adapter catalog, all-or-nothing mapping, and which rules are dropped for synthesized state -
is documented in [validation-engine/API.md](../validation-engine/API.md#validating-an-aws-cli-command).

## Report Types

### ValidationReport

`validate_template` always returns a `ValidationReport` - a template syntax failure is returned as a report with
`ReportStatus.ERROR` and an `F1101` diagnostic; only infrastructure or engine failures raise:

```python
@dataclass
class ValidationReport:
    file_path: str
    status: ReportStatus  # OK, ANALYSIS_INCOMPLETE (findings may be omitted), or ERROR (pipeline failure)
    version: str
    metadata: ReportMetadata
    performance: PerformanceMetrics
    diagnostics: list[Diagnostic]
```

Every finding is a `Diagnostic` (see [Diagnostic](#diagnostic)). Its enrichment fields - `documentation_url`,
`rule_description`, `phase` (`PARSE` | `SCHEMA` | `LINT`), and `context` (`ViolationContext` with `actual_value`,
`expected_constraint`, `resolution_source`, etc.) - are populated only at `detail_level` `DETAILED` (the default);
validating at `STANDARD` leaves them `None`, keeping the base diagnostic fields.

`metadata` carries the summary counts, the number of suppressed diagnostics, the resources scanned and rules
evaluated, the strict flag and severity threshold used, and optional budget-exhaustion records. Each budget-exhaustion
record retains a stable machine-readable kind and also includes a human-readable description sentence, the numeric
limit, and whether that specific exhaustion makes analysis incomplete. `requiredPropertyCombinations` is context-only,
so its `analysis_incomplete` value is `False` and the report can remain `ReportStatus.OK`.

### Diagnostic

```python
@dataclass
class Diagnostic:
    rule_id: str                        # e.g. "E3012", "F1001", "W3010"
    severity: Severity                  # FATAL, ERROR, WARN, INFO, DEBUG
    message: str
    source: RuleOrigin                  # SCHEMA, CFN_LINT, ENGINE, CUSTOM, GUARD
    entity: Entity | None               # the named template entity the finding targets, if any
    property_path: str | None           # e.g. "Properties.BucketName", or section-absolute like "Parameters/MyParam/Type"
    suggested_fix: str | None
    category: str | None
    start_line: int | None
    start_column: int | None
    end_line: int | None
    end_column: int | None
    related_resources: list[RelatedResource] | None
    condition_scenario: dict[str, bool] | None  # condition truth assignment that triggers this diagnostic
    # Enrichment fields: populated at detail_level DETAILED (the default), None at STANDARD.
    documentation_url: str | None
    rule_description: str | None
    phase: Phase | None                 # PARSE | SCHEMA | LINT - pipeline stage that produced the finding
    context: ViolationContext | None    # actual_value, expected_constraint, resolution_source, etc.

# The named template entity a diagnostic is attributed to. The entity type is the
# singular form of the top-level template section the entity is declared in.
@dataclass
class Entity:
    logical_id: str                     # logical ID as declared in the template
    entity_type: EntityType
    resource_type: str | None = None    # CloudFormation type, when the entity is a resource whose type is known

class EntityType(enum.Enum):
    RESOURCE, PARAMETER, OUTPUT, MAPPING, METADATA, RULE, CONDITION, TRANSFORM, FORMAT_VERSION, DESCRIPTION
```

`Severity`, `RuleOrigin`, `DetailLevel`, and `ReportStatus` are `enum.Enum` classes; use `.name` for the string form
(`Severity.WARN.name == "WARN"`).
