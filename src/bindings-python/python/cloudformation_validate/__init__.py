"""AWS CloudFormation Validate — Python bindings.

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

import os
import typing

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
from .validation_engine import EngineConfig, EngineType, ExternalRuleSource

__all__ = [
    "CelEngine",
    "ConditionalNull",
    "ConditionalNullEntry",
    "DetailLevel",
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
    "ServiceFilter",
    "Severity",
    "SourceSpan",
    "StandardDiagnostic",
    "StandardReport",
    "Summary",
    "TemplateModel",
    "ValidateConfig",
    "ValidationError",
    "ViolationContext",
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


def file_to_external_rule_source(path: typing.Union[str, os.PathLike]) -> ExternalRuleSource:
    """Reads a rule file into an :class:`ExternalRuleSource` for an engine's custom or Guard rules.

    The file path becomes the rule source name — the file-based counterpart to passing a
    template path to :meth:`Engine.validate_standard`.
    """
    resolved = os.fspath(path)
    with open(resolved, encoding="utf-8") as f:
        return ExternalRuleSource(name=str(resolved), content=f.read())


class Engine:
    """Validates CloudFormation templates against the built-in rule set.

    Base class for :class:`RegoEngine` and :class:`CelEngine`. Construction is
    expensive (rules are compiled once); reuse one engine across templates.
    """

    _inner_cls: typing.ClassVar[typing.Optional[type]] = None

    def __init__(self, config: typing.Optional[EngineConfig] = None):
        if self._inner_cls is None:
            raise TypeError(f"{type(self).__name__} has no engine; construct RegoEngine or CelEngine instead")
        self._inner = self._inner_cls(config if config is not None else EngineConfig())

    def validate_standard(self, template: Template, config: typing.Optional[ValidateConfig] = None) -> StandardReport:
        """Validates a template and returns a standard-detail report."""
        content, path = _template_bytes(template)
        return self._inner.validate_standard(content, config if config is not None else ValidateConfig(), path)

    def validate_detailed(self, template: Template, config: typing.Optional[ValidateConfig] = None) -> DetailedReport:
        """Validates a template and returns a detailed report with violation context."""
        content, path = _template_bytes(template)
        return self._inner.validate_detailed(content, config if config is not None else ValidateConfig(), path)

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

    def __init__(self):
        self._inner = _PySchemaValidator()

    def list_rules(self) -> typing.List[RuleInfo]:
        return self._inner.list_rules()

    def schema_count(self) -> int:
        return self._inner.schema_count()

    def validate(self, template: Template, region: typing.Optional[str] = None) -> typing.List[StandardDiagnostic]:
        model = _PySemanticModel.parse(_template_bytes(template)[0])
        return self._inner.validate(model, region).diagnostics
