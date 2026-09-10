package cfnvalidate

import "encoding/json"

// Severity of a diagnostic, from most to least severe: FATAL, ERROR, WARN,
// INFO, DEBUG.
type Severity string

const (
	SeverityFatal Severity = "FATAL"
	SeverityError Severity = "ERROR"
	SeverityWarn  Severity = "WARN"
	SeverityInfo  Severity = "INFO"
	SeverityDebug Severity = "DEBUG"
)

// DetailLevel controls how much per-diagnostic context a report carries.
// DETAILED, the level used when DetailLevel is unset, enriches each diagnostic
// with documentation URLs, rule descriptions, phase tags, and violation
// context; STANDARD leaves those fields absent.
type DetailLevel string

const (
	DetailLevelStandard DetailLevel = "STANDARD"
	DetailLevelDetailed DetailLevel = "DETAILED"
)

// ReportStatus is the outcome of a validation run. StatusOK means validation
// completed without correctness-affecting curtailment. StatusAnalysisIncomplete
// means a deterministic budget curtailed analysis and could omit findings.
// StatusError means the validation pipeline could not run, such as a parse failure.
type ReportStatus string

const (
	StatusOK                 ReportStatus = "OK"
	StatusAnalysisIncomplete ReportStatus = "ANALYSIS_INCOMPLETE"
	StatusError              ReportStatus = "ERROR"
)

type EntityType string

const (
	EntityTypeResource      EntityType = "Resource"
	EntityTypeParameter     EntityType = "Parameter"
	EntityTypeOutput        EntityType = "Output"
	EntityTypeMapping       EntityType = "Mapping"
	EntityTypeMetadata      EntityType = "Metadata"
	EntityTypeRule          EntityType = "Rule"
	EntityTypeCondition     EntityType = "Condition"
	EntityTypeTransform     EntityType = "Transform"
	EntityTypeFormatVersion EntityType = "FormatVersion"
	EntityTypeDescription   EntityType = "Description"
)

// Entity identifies the template construct a diagnostic points at.
type Entity struct {
	LogicalID    string     `json:"logicalId"`
	EntityType   EntityType `json:"entityType"`
	ResourceType *string    `json:"resourceType,omitempty"`
}

// SourceSpan is a location in the template source, 1-based.
type SourceSpan struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
	EndLine     int `json:"endLine"`
	EndColumn   int `json:"endColumn"`
}

// ResourceRef identifies a resource related to a diagnostic.
type ResourceRef struct {
	ID           *string `json:"id,omitempty"`
	ResourceType *string `json:"resourceType,omitempty"`
}

// RelatedResource links a diagnostic to another resource involved in the
// finding.
type RelatedResource struct {
	Resource *ResourceRef `json:"resource,omitempty"`
	Location *SourceSpan  `json:"location,omitempty"`
	Message  string       `json:"message"`
}

// ViolationContext carries the resolved values behind a diagnostic's enrichment
// context, populated only at the DETAILED detail level.
type ViolationContext struct {
	ActualValue        json.RawMessage            `json:"actualValue,omitempty"`
	ExpectedConstraint *string                    `json:"expectedConstraint,omitempty"`
	Property           *string                    `json:"property,omitempty"`
	Lifecycle          *string                    `json:"lifecycle,omitempty"`
	ResolutionSource   *string                    `json:"resolutionSource,omitempty"`
	Extra              map[string]json.RawMessage `json:"extra,omitempty"`
}

type RuleOrigin string

const (
	RuleOriginSchema  RuleOrigin = "SCHEMA"
	RuleOriginCfnLint RuleOrigin = "CFN_LINT"
	RuleOriginEngine  RuleOrigin = "ENGINE"
	RuleOriginCustom  RuleOrigin = "CUSTOM"
	RuleOriginGuard   RuleOrigin = "GUARD"
)

// Diagnostic is a single validation finding. The enrichment fields
// (DocumentationURL, RuleDescription, Phase, Context) are populated only when
// validation runs at the DETAILED detail level; a STANDARD run leaves them nil.
type Diagnostic struct {
	RuleID            string            `json:"ruleId"`
	Severity          Severity          `json:"severity"`
	Message           string            `json:"message"`
	Source            RuleOrigin        `json:"source"`
	Entity            *Entity           `json:"entity,omitempty"`
	PropertyPath      *string           `json:"propertyPath,omitempty"`
	SuggestedFix      *string           `json:"suggestedFix,omitempty"`
	Category          *string           `json:"category,omitempty"`
	StartLine         *int              `json:"startLine,omitempty"`
	StartColumn       *int              `json:"startColumn,omitempty"`
	EndLine           *int              `json:"endLine,omitempty"`
	EndColumn         *int              `json:"endColumn,omitempty"`
	RelatedResources  []RelatedResource `json:"relatedResources,omitempty"`
	ConditionScenario map[string]bool   `json:"conditionScenario,omitempty"`
	DocumentationURL  *string           `json:"documentationUrl,omitempty"`
	RuleDescription   *string           `json:"ruleDescription,omitempty"`
	Phase             *string           `json:"phase,omitempty"`
	Context           *ViolationContext `json:"context,omitempty"`
}

// Summary counts diagnostics by severity.
type Summary struct {
	Fatal         int `json:"fatal"`
	Errors        int `json:"errors"`
	Warnings      int `json:"warnings"`
	Informational int `json:"informational"`
	Debug         int `json:"debug"`
}

// BudgetExhaustionRecord is a single budget-exhaustion entry in report metadata.
type BudgetExhaustionRecord struct {
	Kind               string `json:"kind"`
	Description        string `json:"description"`
	Limit              uint64 `json:"limit"`
	AnalysisIncomplete bool   `json:"analysisIncomplete"`
}

// ReportMetadata describes the validation run.
type ReportMetadata struct {
	RulesEvaluated        int                      `json:"rulesEvaluated"`
	CfnLintVersion        string                   `json:"cfnLintVersion"`
	ResourceSchemaVersion string                   `json:"resourceSchemaVersion"`
	ResourcesScanned      int                      `json:"resourcesScanned"`
	Counts                Summary                  `json:"counts"`
	Suppressed            int                      `json:"suppressed"`
	Strict                bool                     `json:"strict"`
	SeverityLevel         Severity                 `json:"severityLevel"`
	BudgetExhaustions     []BudgetExhaustionRecord `json:"budgetExhaustions,omitempty"`
}

// PhaseMetric is the duration of one pipeline phase.
type PhaseMetric struct {
	DurationMs float64 `json:"durationMs"`
}

// PerformanceMetrics is the timing breakdown of the validation run.
type PerformanceMetrics struct {
	SchemaInit         PhaseMetric `json:"schemaInit"`
	EngineInit         PhaseMetric `json:"engineInit"`
	ModelBuild         PhaseMetric `json:"modelBuild"`
	SchemaValidate     PhaseMetric `json:"schemaValidate"`
	RuleEvaluation     PhaseMetric `json:"ruleEvaluation"`
	DiagnosticFinalize PhaseMetric `json:"diagnosticFinalize"`
	ValidateTotal      PhaseMetric `json:"validateTotal"`
}

// ValidationReport is the result of ValidateTemplate. Its diagnostics carry the
// enrichment fields only when validation ran at the DETAILED detail level; a
// STANDARD run leaves them nil.
type ValidationReport struct {
	FilePath    string             `json:"filePath"`
	Status      ReportStatus       `json:"status"`
	Version     string             `json:"version"`
	Metadata    ReportMetadata     `json:"metadata"`
	Performance PerformanceMetrics `json:"performance"`
	Diagnostics []Diagnostic       `json:"diagnostics"`
}

// RuleInfo describes one rule in the registry.
type RuleInfo struct {
	ID          string     `json:"id"`
	Severity    Severity   `json:"severity"`
	Category    *string    `json:"category,omitempty"`
	Description string     `json:"description"`
	Origin      RuleOrigin `json:"origin"`
}

// ExternalRuleSource is a custom rule file passed to an engine: Name labels
// diagnostics and errors, Content is the full rule source text.
type ExternalRuleSource struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

// AdditionalSchemaSource is a CloudFormation resource provider schema merged on
// top of the bundled schemas. TypeName is optional: leave it nil to take the
// resource type name from the Schema's own typeName field.
type AdditionalSchemaSource struct {
	TypeName *string `json:"typeName,omitempty"`
	Schema   string  `json:"schema"`
}

// EngineConfig holds engine construction options. The zero value uses only the
// built-in rules.
type EngineConfig struct {
	// CustomRules are engine-native rules (Rego or CEL depending on engine).
	CustomRules []ExternalRuleSource `json:"customRules,omitempty"`
	// GuardRules are Guard DSL rules, usable with either engine.
	GuardRules []ExternalRuleSource `json:"guardRules,omitempty"`
	// SchemaValidatorConfig optionally configures the validator bundled by the engine.
	// When set, the engine derives overlay-aware metadata from the configured
	// additional schemas.
	SchemaValidatorConfig *SchemaValidatorConfig `json:"schemaValidatorConfig,omitempty"`
}

// SchemaValidatorConfig holds schema validator construction options. The zero
// value builds a validator over only the bundled schemas.
type SchemaValidatorConfig struct {
	// AdditionalSchemas extend bundled resource provider schemas or register new
	// resource types before schema validation.
	AdditionalSchemas []AdditionalSchemaSource `json:"additionalSchemas,omitempty"`
}

// IdRange matches rule IDs with the given letter prefix and an inclusive
// numeric span.
type IdRange struct {
	Prefix string `json:"prefix"`
	Start  int    `json:"start"`
	End    int    `json:"end"`
}

// ResourceIdFilter scopes a rule to a logical resource ID. An empty RuleID
// scopes the filter to every rule on that resource.
type ResourceIdFilter struct {
	RuleID     *string `json:"ruleId,omitempty"`
	ResourceID string  `json:"resourceId"`
}

// LogicalIdFilter scopes a rule to a named template entity. Nil RuleID or
// EntityType values apply the filter to every rule or entity type respectively.
type LogicalIdFilter struct {
	RuleID     *string     `json:"ruleId,omitempty"`
	LogicalID  string      `json:"logicalId"`
	EntityType *EntityType `json:"entityType,omitempty"`
}

// ResourceTypeFilter scopes a rule to a resource type.
type ResourceTypeFilter struct {
	RuleID       *string `json:"ruleId,omitempty"`
	ResourceType string  `json:"resourceType"`
}

// ServiceFilter scopes a rule to an AWS service namespace.
type ServiceFilter struct {
	RuleID  *string `json:"ruleId,omitempty"`
	Service string  `json:"service"`
}

// RuleFilterConfig selects rules by ID, category, range, pattern, resource, or
// service.
type RuleFilterConfig struct {
	IDs           []string             `json:"ids,omitempty"`
	Categories    []string             `json:"categories,omitempty"`
	IDRanges      []IdRange            `json:"idRanges,omitempty"`
	IDPatterns    []string             `json:"idPatterns,omitempty"`
	ResourceIDs   []ResourceIdFilter   `json:"resourceIds,omitempty"`
	LogicalIDs    []LogicalIdFilter    `json:"logicalIds,omitempty"`
	ResourceTypes []ResourceTypeFilter `json:"resourceTypes,omitempty"`
	Services      []ServiceFilter      `json:"services,omitempty"`
}

// PseudoParameterOverrides supplies values for AWS pseudo parameters during
// resolution.
type PseudoParameterOverrides struct {
	AccountID        *string `json:"accountId,omitempty"`
	NotificationARNs *string `json:"notificationArns,omitempty"`
	Partition        *string `json:"partition,omitempty"`
	Region           *string `json:"region,omitempty"`
	StackID          *string `json:"stackId,omitempty"`
	StackName        *string `json:"stackName,omitempty"`
	URLSuffix        *string `json:"urlSuffix,omitempty"`
}

// ValidateConfig holds per-call validation options. A nil *ValidateConfig uses
// the defaults. DetailLevel defaults to DETAILED when left empty.
type ValidateConfig struct {
	Include                  *RuleFilterConfig         `json:"include,omitempty"`
	Exclude                  *RuleFilterConfig         `json:"exclude,omitempty"`
	DetailLevel              DetailLevel               `json:"detailLevel,omitempty"`
	SeverityLevel            Severity                  `json:"severityLevel,omitempty"`
	ParameterOverrides       map[string]string         `json:"parameterOverrides,omitempty"`
	PseudoParameterOverrides *PseudoParameterOverrides `json:"pseudoParameterOverrides,omitempty"`
	Strict                   *bool                     `json:"strict,omitempty"`
	DisableBuiltinRules      *bool                     `json:"disableBuiltinRules,omitempty"`
}

// AWSCLICommand holds an AWS CLI command for offline CloudFormation
// validation. ServiceName and OperationName identify the API; Parameters carry
// the request values (maps, strings, numbers, booleans, byte slices, etc.).
//
// ServiceName is the canonical botocore service name (for example "s3" or
// "cloudformation") and is the authoritative mapping identity, normalized only
// for ASCII case - never a signing name, ARN prefix, or endpoint alias. A
// future AWS SDK adapter, in any language, must translate its native service
// identity to the canonical botocore ServiceName before calling; the core does
// not guess aliases.
type AWSCLICommand struct {
	ServiceName   string         `json:"serviceName"`
	OperationName string         `json:"operationName"`
	Parameters    map[string]any `json:"parameters"`
	ServicePrefix string         `json:"servicePrefix,omitempty"`
	HTTPMethod    string         `json:"httpMethod,omitempty"`
	IsReadOnly    *bool          `json:"isReadOnly,omitempty"`
}

// AWSCLIOperationKind classifies an AWS CLI operation.
type AWSCLIOperationKind string

const (
	AWSCLIOperationKindReadOnly             AWSCLIOperationKind = "READ_ONLY"
	AWSCLIOperationKindCloudFormationCreate AWSCLIOperationKind = "CLOUD_FORMATION_CREATE"
	AWSCLIOperationKindCloudFormationUpdate AWSCLIOperationKind = "CLOUD_FORMATION_UPDATE"
	AWSCLIOperationKindCloudFormationDelete AWSCLIOperationKind = "CLOUD_FORMATION_DELETE"
	AWSCLIOperationKindDataPlaneMutation    AWSCLIOperationKind = "DATA_PLANE_MUTATION"
	AWSCLIOperationKindUnmappedMutation     AWSCLIOperationKind = "UNMAPPED_MUTATION"
)

// AWSCLICommandValidationStatus indicates whether validation ran or was skipped.
type AWSCLICommandValidationStatus string

const (
	AWSCLICommandValidationStatusValidated AWSCLICommandValidationStatus = "VALIDATED"
	AWSCLICommandValidationStatusSkipped   AWSCLICommandValidationStatus = "SKIPPED"
)

// AWSCLITemplateSource identifies the provenance of the template validated for
// an AWS CLI command.
type AWSCLITemplateSource string

const (
	AWSCLITemplateSourceTemplateBody             AWSCLITemplateSource = "TEMPLATE_BODY"
	AWSCLITemplateSourceCloudControlDesiredState AWSCLITemplateSource = "CLOUD_CONTROL_DESIRED_STATE"
	AWSCLITemplateSourceSynthesizedCreate        AWSCLITemplateSource = "SYNTHESIZED_CREATE"
	AWSCLITemplateSourceSynthesizedUpdate        AWSCLITemplateSource = "SYNTHESIZED_UPDATE"
)

// AWSCLICommandValidation is the canonical result of validating an AWS CLI
// command. Report is present only when Status is VALIDATED.
type AWSCLICommandValidation struct {
	OperationKind  AWSCLIOperationKind           `json:"operationKind"`
	Status         AWSCLICommandValidationStatus `json:"status"`
	TemplateSource *AWSCLITemplateSource         `json:"templateSource,omitempty"`
	ResourceTypes  []string                      `json:"resourceTypes"`
	Reason         string                        `json:"reason"`
	Report         *ValidationReport             `json:"report,omitempty"`
	// Template is the exact template bytes that were validated: the caller's
	// original TemplateBody without reserializing, or the synthesized JSON
	// template for adapter-mapped requests. It is nil when the request was
	// skipped. The core serializes these bytes as a JSON integer array, which
	// UnmarshalJSON decodes back into a byte slice.
	Template []byte `json:"template,omitempty"`
}
