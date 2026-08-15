"""AWS CloudFormation Validate - Python bindings.

Fast, offline validation for AWS CloudFormation templates. Wraps the
uniffi-generated modules with a convenience API mirroring the Node.js and JVM
bindings: construct an engine once, then validate many templates.

Example:
    from cloudformation_validate import RegoEngine

    engine = RegoEngine()
    report = engine.validate_standard("template.yaml")
    for d in report.diagnostics:
        print(f"[{d.severity.name}] {d.rule_id}: {d.message}")
"""

from __future__ import annotations

import datetime
import math
import os
import typing
from collections.abc import Mapping

from .bindings_python import (
    PyCelEngine as _PyCelEngine,
    PyRegoEngine as _PyRegoEngine,
    PySchemaValidator as _PySchemaValidator,
    PySemanticModel as _PySemanticModel,
    ValidateConfig,
    ValidationError,
    version,
)
from .diagnostics import (
    DetailedDiagnostic,
    DetailedReport,
    DetailLevel,
    Entity,
    PerformanceMetrics,
    PhaseMetric,
    RelatedResource,
    ReportMetadata,
    ReportStatus,
    ResourceRef,
    StandardDiagnostic,
    StandardReport,
    Summary,
    ViolationContext,
)
from .rules import (
    IdRange,
    LogicalIdFilter,
    ResourceIdFilter,
    ResourceTypeFilter,
    RuleFilterConfig,
    RuleInfo,
    RuleOrigin,
    ServiceFilter,
    Severity,
)
from .template_model import (
    ConditionalNull,
    ConditionalNullEntry,
    DiagnosticCondition,
    DiagnosticForEachExpansion,
    DiagnosticImplication,
    DiagnosticModel,
    DiagnosticMutexGroup,
    DiagnosticOutput,
    DiagnosticResource,
    DiagnosticRule,
    DiagnosticRuleAssertion,
    DiagnosticTemplate,
    EntityType,
    ForEachExpansion,
    GetAttRef,
    IncomingRef,
    JsonValue,
    MapEntry,
    OutgoingRef,
    ParameterInfo,
    PathTarget,
    PathValuePair,
    PathVariable,
    PseudoParameterOverrides,
    ReferenceEdge,
    RefKind,
    ResolutionSource,
    ResolvedOutput,
    ResolvedResource,
    ResolvedValue,
    ResourceDiagnostics,
    SourceSpan,
)
from .data_source import AdditionalSchemaSource
from .schema_validator import SchemaValidatorConfig
from .validation_engine import (
    AwsApiOperationKind,
    AwsApiRequestContext as _NativeAwsApiRequest,
    AwsApiRequestValidationStatus,
    AwsApiTemplateSource,
    AwsApiValue as _NativeAwsApiValue,
    DetailedAwsApiRequestValidation,
    EngineConfig,
    EngineType,
    ExternalRuleSource,
    StandardAwsApiRequestValidation,
)

__all__ = [
    "AdditionalSchemaSource",
    "AwsApiOperationKind",
    "AwsApiRequest",
    "AwsApiRequestValidationStatus",
    "AwsApiTemplateSource",
    "CelEngine",
    "ConditionalNull",
    "ConditionalNullEntry",
    "DetailLevel",
    "DetailedAwsApiRequestValidation",
    "DetailedDiagnostic",
    "DetailedReport",
    "DiagnosticCondition",
    "DiagnosticForEachExpansion",
    "DiagnosticImplication",
    "DiagnosticModel",
    "DiagnosticMutexGroup",
    "DiagnosticOutput",
    "DiagnosticResource",
    "DiagnosticRule",
    "DiagnosticRuleAssertion",
    "DiagnosticTemplate",
    "Engine",
    "EngineConfig",
    "EngineType",
    "Entity",
    "EntityType",
    "ExternalRuleSource",
    "ForEachExpansion",
    "GetAttRef",
    "IdRange",
    "IncomingRef",
    "JsonValue",
    "LogicalIdFilter",
    "MapEntry",
    "OutgoingRef",
    "ParameterInfo",
    "PathTarget",
    "PathValuePair",
    "PathVariable",
    "PerformanceMetrics",
    "PhaseMetric",
    "PseudoParameterOverrides",
    "RefKind",
    "ReferenceEdge",
    "RegoEngine",
    "RelatedResource",
    "ReportMetadata",
    "ReportStatus",
    "ResolutionSource",
    "ResolvedOutput",
    "ResolvedResource",
    "ResolvedValue",
    "ResourceDiagnostics",
    "ResourceIdFilter",
    "ResourceRef",
    "ResourceTypeFilter",
    "RuleFilterConfig",
    "RuleInfo",
    "RuleOrigin",
    "SchemaValidator",
    "SchemaValidatorConfig",
    "ServiceFilter",
    "Severity",
    "SourceSpan",
    "StandardAwsApiRequestValidation",
    "StandardDiagnostic",
    "StandardReport",
    "Summary",
    "TemplateModel",
    "ValidateConfig",
    "ValidationError",
    "ViolationContext",
    "file_to_additional_schema_source",
    "file_to_external_rule_source",
    "version",
]

Template = typing.Union[str, os.PathLike, bytes]
"""A template to validate: a file path (read from disk) or raw template bytes."""

_DEFAULT_FILE_PATH = "template"


def _template_bytes(template: Template) -> tuple[bytes, str]:
    """Resolves a template argument to its byte content and display path."""
    if isinstance(template, bytes):
        return template, _DEFAULT_FILE_PATH
    path = os.fspath(template)
    with open(path, "rb") as f:
        return f.read(), str(path)


def file_to_additional_schema_source(
    path: typing.Union[str, os.PathLike], type_name: typing.Optional[str] = None
) -> AdditionalSchemaSource:
    """Reads a resource provider schema file into an :class:`AdditionalSchemaSource`.

    ``type_name`` may be omitted when the schema contains its own ``typeName`` field.
    """
    resolved = os.fspath(path)
    with open(resolved, encoding="utf-8") as f:
        return AdditionalSchemaSource(type_name=type_name, schema=f.read())


def file_to_external_rule_source(path: typing.Union[str, os.PathLike]) -> ExternalRuleSource:
    """Reads a rule file into an :class:`ExternalRuleSource` for an engine's custom or Guard rules.

    The file path becomes the rule source name - the file-based counterpart to passing a
    template path to :meth:`Engine.validate_standard`.
    """
    resolved = os.fspath(path)
    with open(resolved, encoding="utf-8") as f:
        return ExternalRuleSource(name=str(resolved), content=f.read())


class AwsApiRequest:
    """Service, operation, and request values for CloudFormation validation.

    ``parameters`` accepts the same Python values used by botocore request
    dictionaries, including nested mappings/sequences, ``bytes``, and
    ``datetime.datetime``. Values that cannot be represented are carried as an
    explicit unsupported marker and are conservatively omitted during synthesis.
    """

    def __init__(
        self,
        service_name: str,
        operation_name: str,
        parameters: Mapping[str, object],
        *,
        service_prefix: typing.Optional[str] = None,
        http_method: typing.Optional[str] = None,
        is_read_only: typing.Optional[bool] = None,
    ):
        if not isinstance(parameters, Mapping):
            raise TypeError("parameters must be a mapping")
        if not all(isinstance(name, str) for name in parameters):
            raise TypeError("request parameter names must be strings")
        self.service_name = service_name
        self.operation_name = operation_name
        self.parameters = dict(parameters)
        self.service_prefix = service_prefix
        self.http_method = http_method
        self.is_read_only = is_read_only

    def _to_native(self) -> _NativeAwsApiRequest:
        return _NativeAwsApiRequest(
            service_name=self.service_name,
            operation_name=self.operation_name,
            parameters={name: _to_native_aws_api_value(value) for name, value in self.parameters.items()},
            service_prefix=self.service_prefix,
            http_method=self.http_method,
            is_read_only=self.is_read_only,
        )


def _to_native_aws_api_value(value: object) -> _NativeAwsApiValue:
    if value is None:
        return _NativeAwsApiValue.NULL()
    if isinstance(value, bool):
        return _NativeAwsApiValue.BOOLEAN(value=value)
    if isinstance(value, int):
        if -(2**63) <= value < 2**63:
            return _NativeAwsApiValue.INTEGER(value=value)
        if 0 <= value < 2**64:
            return _NativeAwsApiValue.UNSIGNED_INTEGER(value=value)
        return _NativeAwsApiValue.UNSUPPORTED(type_name="integer outside the 64-bit request range")
    if isinstance(value, float):
        if math.isfinite(value):
            return _NativeAwsApiValue.NUMBER(value=value)
        return _NativeAwsApiValue.UNSUPPORTED(type_name="non-finite floating-point number")
    if isinstance(value, str):
        return _NativeAwsApiValue.STRING(value=value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return _NativeAwsApiValue.BYTES(value=bytes(value))
    if isinstance(value, datetime.datetime):
        return _NativeAwsApiValue.STRING(value=value.isoformat())
    if isinstance(value, Mapping):
        if not all(isinstance(name, str) for name in value):
            return _NativeAwsApiValue.UNSUPPORTED(type_name="mapping with non-string keys")
        return _NativeAwsApiValue.OBJECT(
            entries={name: _to_native_aws_api_value(item) for name, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return _NativeAwsApiValue.ARRAY(items=[_to_native_aws_api_value(item) for item in value])
    value_type = type(value)
    return _NativeAwsApiValue.UNSUPPORTED(type_name=f"{value_type.__module__}.{value_type.__qualname__}")


class Engine:
    """Validates CloudFormation templates against the built-in rule set.

    Base class for :class:`RegoEngine` and :class:`CelEngine`. Construction is
    expensive (rules are compiled once); reuse one engine across templates.
    """

    _inner_cls: typing.ClassVar[typing.Optional[type]] = None

    def __init__(
        self,
        config: typing.Optional[EngineConfig] = None,
    ):
        if self._inner_cls is None:
            raise TypeError(f"{type(self).__name__} has no engine; construct RegoEngine or CelEngine instead")
        self._inner = self._inner_cls(
            config if config is not None else EngineConfig(),
        )

    def validate_standard(self, template: Template, config: typing.Optional[ValidateConfig] = None) -> StandardReport:
        """Validates a template and returns a standard-detail report."""
        content, path = _template_bytes(template)
        return self._inner.validate_standard(content, config if config is not None else ValidateConfig(), path)

    def validate_detailed(self, template: Template, config: typing.Optional[ValidateConfig] = None) -> DetailedReport:
        """Validates a template and returns a detailed report with violation context."""
        content, path = _template_bytes(template)
        return self._inner.validate_detailed(content, config if config is not None else ValidateConfig(), path)

    def validate_aws_api_request(
        self, request: AwsApiRequest, config: typing.Optional[ValidateConfig] = None
    ) -> DetailedAwsApiRequestValidation:
        """Classifies, models, and validates an AWS API request.

        This detailed variant is the primary integration entry point. A skipped
        request has ``report is None`` and an explicit status and reason.
        """
        return self.validate_aws_api_request_detailed(request, config)

    def validate_aws_api_request_standard(
        self, request: AwsApiRequest, config: typing.Optional[ValidateConfig] = None
    ) -> StandardAwsApiRequestValidation:
        """Validates an AWS API request and returns standard diagnostics."""
        if not isinstance(request, AwsApiRequest):
            raise TypeError("request must be an AwsApiRequest")
        return self._inner.validate_aws_api_request_standard(
            request._to_native(), config if config is not None else ValidateConfig()
        )

    def validate_aws_api_request_detailed(
        self, request: AwsApiRequest, config: typing.Optional[ValidateConfig] = None
    ) -> DetailedAwsApiRequestValidation:
        """Validates an AWS API request and returns detailed diagnostics."""
        if not isinstance(request, AwsApiRequest):
            raise TypeError("request must be an AwsApiRequest")
        return self._inner.validate_aws_api_request_detailed(
            request._to_native(), config if config is not None else ValidateConfig()
        )

    def list_rules(self) -> typing.List[RuleInfo]:
        """Lists every rule this engine evaluates, sorted by rule ID."""
        return self._inner.list_rules()

    def engine_name(self) -> str:
        """Returns the engine identifier ("rego" or "cel")."""
        return self._inner.engine_name()


class RegoEngine(Engine):
    """Rego-based validation engine."""

    _inner_cls = _PyRegoEngine


class CelEngine(Engine):
    """CEL-based validation engine."""

    _inner_cls = _PyCelEngine


class TemplateModel:
    """Parsed semantic model of a template: resources, parameters, outputs,
    conditions, reference graph, and source locations."""

    def __init__(self, template: Template):
        content, _ = _template_bytes(template)
        self._inner = _PySemanticModel.parse(content)

    def resources(self) -> typing.Dict[str, ResolvedResource]:
        return self._inner.resources()

    def parameters(self) -> typing.Dict[str, ParameterInfo]:
        return self._inner.parameters()

    def outputs(self) -> typing.Dict[str, ResolvedOutput]:
        return self._inner.outputs()

    def conditions(self) -> typing.List[str]:
        return self._inner.conditions()

    def transforms(self) -> typing.List[str]:
        return self._inner.transforms()

    def format_version(self) -> typing.Optional[str]:
        return self._inner.format_version()

    def description(self) -> typing.Optional[str]:
        return self._inner.description()

    def to_diagnostic_model(self) -> DiagnosticModel:
        return self._inner.to_diagnostic_model()

    def source_location(self, path: str) -> typing.Optional[SourceSpan]:
        return self._inner.source_location(path)


class SchemaValidator:
    """Validates resources against the compiled CloudFormation provider schemas."""

    def __init__(self, schema_config: typing.Optional[SchemaValidatorConfig] = None):
        self._inner = _PySchemaValidator(
            schema_config if schema_config is not None else SchemaValidatorConfig()
        )

    def list_rules(self) -> typing.List[RuleInfo]:
        return self._inner.list_rules()

    def schema_count(self) -> int:
        return self._inner.schema_count()

    def validate(self, template: Template, region: typing.Optional[str] = None) -> typing.List[StandardDiagnostic]:
        model = _PySemanticModel.parse(_template_bytes(template)[0])
        return self._inner.validate(model, region).diagnostics
