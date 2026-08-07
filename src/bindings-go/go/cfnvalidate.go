// Package cfnvalidate validates AWS CloudFormation templates - fast, offline,
// and embeddable, backed by the same Rust core as the cfn-validate CLI and the
// Node.js, Python, and JVM bindings.
//
// Construct an engine once (rules compile at construction) and validate many
// templates:
//
//	engine, err := cfnvalidate.NewRegoEngine(nil)
//	if err != nil { ... }
//	defer engine.Destroy()
//
//	report, err := engine.ValidateStandardFile("template.yaml", nil)
//	for _, d := range report.Diagnostics {
//	    fmt.Printf("[%s] %s: %s\n", d.Severity, d.RuleID, d.Message)
//	}
//
// The native library is linked statically via cgo; run build.sh first to
// generate the internal bindings and stage the platform libraries.
package cfnvalidate

import (
	"encoding/json"
	"fmt"
	"os"

	bindings "github.com/aws-cloudformation/cloudformation-validate/src/bindings-go/go/internal/bindings_go"
)

const defaultFilePath = "template"

// Version returns the version of the underlying validation core.
func Version() string {
	return bindings.Version()
}

func marshalConfig(v any) (string, error) {
	if v == nil {
		return "{}", nil
	}
	data, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("cfnvalidate: encoding config: %w", err)
	}
	return string(data), nil
}

func engineConfigJSON(config *EngineConfig) (string, error) {
	if config == nil {
		return "{}", nil
	}
	return marshalConfig(config)
}

func schemaConfigJSON(config *SchemaValidatorConfig) (string, error) {
	if config == nil {
		return "{}", nil
	}
	return marshalConfig(config)
}

func validateConfigJSON(config *ValidateConfig) (string, error) {
	if config == nil {
		return "{}", nil
	}
	return marshalConfig(config)
}

func decodeInto[T any](data string, what string) (*T, error) {
	var out T
	if err := json.Unmarshal([]byte(data), &out); err != nil {
		return nil, fmt.Errorf("cfnvalidate: decoding %s: %w", what, err)
	}
	return &out, nil
}

// nativeEngine is the method set shared by the generated engine objects.
type nativeEngine interface {
	ValidateStandardJson(template []byte, optionsJson string, filePath string) (string, error)
	ValidateDetailedJson(template []byte, optionsJson string, filePath string) (string, error)
	ListRulesJson() (string, error)
	EngineName() string
	Destroy()
}

// Engine validates CloudFormation templates against the built-in rule set,
// optionally extended with custom rules. RegoEngine and CelEngine are
// interchangeable: both produce identical diagnostics.
type Engine struct {
	inner nativeEngine
}

// NewRegoEngine builds a Rego-based engine. A nil config uses only the
// built-in rules.
func NewRegoEngine(config *EngineConfig) (*Engine, error) {
	configJSON, err := engineConfigJSON(config)
	if err != nil {
		return nil, err
	}
	inner, err := bindings.NewGoRegoEngine(configJSON)
	if err != nil {
		return nil, err
	}
	return &Engine{inner: inner}, nil
}

// NewCelEngine builds a CEL-based engine. A nil config uses only the built-in
// rules.
func NewCelEngine(config *EngineConfig) (*Engine, error) {
	configJSON, err := engineConfigJSON(config)
	if err != nil {
		return nil, err
	}
	inner, err := bindings.NewGoCelEngine(configJSON)
	if err != nil {
		return nil, err
	}
	return &Engine{inner: inner}, nil
}

// ValidateStandard validates template bytes and returns a standard-detail
// report. filePath labels the report; pass "" for the default.
func (e *Engine) ValidateStandard(template []byte, config *ValidateConfig, filePath string) (*StandardReport, error) {
	optionsJSON, err := validateConfigJSON(config)
	if err != nil {
		return nil, err
	}
	if filePath == "" {
		filePath = defaultFilePath
	}
	data, err := e.inner.ValidateStandardJson(template, optionsJSON, filePath)
	if err != nil {
		return nil, err
	}
	return decodeInto[StandardReport](data, "standard report")
}

// ValidateStandardFile reads a template from disk and returns a
// standard-detail report.
func (e *Engine) ValidateStandardFile(path string, config *ValidateConfig) (*StandardReport, error) {
	template, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cfnvalidate: reading template: %w", err)
	}
	return e.ValidateStandard(template, config, path)
}

// ValidateDetailed validates template bytes and returns a detailed report with
// per-diagnostic context and enrichment. filePath labels the report; pass ""
// for the default.
func (e *Engine) ValidateDetailed(template []byte, config *ValidateConfig, filePath string) (*DetailedReport, error) {
	optionsJSON, err := validateConfigJSON(config)
	if err != nil {
		return nil, err
	}
	if filePath == "" {
		filePath = defaultFilePath
	}
	data, err := e.inner.ValidateDetailedJson(template, optionsJSON, filePath)
	if err != nil {
		return nil, err
	}
	return decodeInto[DetailedReport](data, "detailed report")
}

// ValidateDetailedFile reads a template from disk and returns a detailed
// report.
func (e *Engine) ValidateDetailedFile(path string, config *ValidateConfig) (*DetailedReport, error) {
	template, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cfnvalidate: reading template: %w", err)
	}
	return e.ValidateDetailed(template, config, path)
}

// ListRules lists every rule this engine evaluates, sorted by rule ID.
func (e *Engine) ListRules() ([]RuleInfo, error) {
	data, err := e.inner.ListRulesJson()
	if err != nil {
		return nil, err
	}
	rules, err := decodeInto[[]RuleInfo](data, "rule list")
	if err != nil {
		return nil, err
	}
	return *rules, nil
}

// EngineName returns the engine identifier ("rego" or "cel").
func (e *Engine) EngineName() string {
	return e.inner.EngineName()
}

// Destroy releases the native engine. The engine must not be used afterwards.
func (e *Engine) Destroy() {
	e.inner.Destroy()
}

// SchemaValidator validates resources against the compiled CloudFormation
// provider schemas.
type SchemaValidator struct {
	inner *bindings.GoSchemaValidator
}

// NewSchemaValidator builds a schema validator over the compiled provider
// schemas. A nil config uses only the bundled schemas.
func NewSchemaValidator(config *SchemaValidatorConfig) (*SchemaValidator, error) {
	schemaJSON, err := schemaConfigJSON(config)
	if err != nil {
		return nil, err
	}
	inner, err := bindings.NewGoSchemaValidator(schemaJSON)
	if err != nil {
		return nil, err
	}
	return &SchemaValidator{inner: inner}, nil
}

// ListRules lists the schema validator's rules.
func (v *SchemaValidator) ListRules() ([]RuleInfo, error) {
	data, err := v.inner.ListRulesJson()
	if err != nil {
		return nil, err
	}
	rules, err := decodeInto[[]RuleInfo](data, "rule list")
	if err != nil {
		return nil, err
	}
	return *rules, nil
}

// SchemaCount returns the number of compiled provider schemas.
func (v *SchemaValidator) SchemaCount() uint32 {
	return v.inner.SchemaCount()
}

// Validate checks template bytes against the provider schemas. region selects
// region-specific schemas; nil uses the default.
func (v *SchemaValidator) Validate(template []byte, region *string) ([]StandardDiagnostic, error) {
	model, err := bindings.GoSemanticModelParse(template)
	if err != nil {
		return nil, err
	}
	defer model.Destroy()
	data, err := v.inner.ValidateJson(model, region)
	if err != nil {
		return nil, err
	}
	diagnostics, err := decodeInto[[]StandardDiagnostic](data, "diagnostics")
	if err != nil {
		return nil, err
	}
	return *diagnostics, nil
}

// Destroy releases the native validator. It must not be used afterwards.
func (v *SchemaValidator) Destroy() {
	v.inner.Destroy()
}

// TemplateModel is the parsed semantic model of a template: resources,
// parameters, outputs, conditions, and source locations. Structured sections
// are returned as raw JSON for the caller to decode.
type TemplateModel struct {
	inner *bindings.GoSemanticModel
}

// ParseTemplate parses template bytes into a semantic model.
func ParseTemplate(template []byte) (*TemplateModel, error) {
	inner, err := bindings.GoSemanticModelParse(template)
	if err != nil {
		return nil, err
	}
	return &TemplateModel{inner: inner}, nil
}

// Resources returns the resolved resources as JSON keyed by logical ID.
func (m *TemplateModel) Resources() (json.RawMessage, error) {
	data, err := m.inner.ResourcesJson()
	return json.RawMessage(data), err
}

// Parameters returns the template parameters as JSON keyed by name.
func (m *TemplateModel) Parameters() (json.RawMessage, error) {
	data, err := m.inner.ParametersJson()
	return json.RawMessage(data), err
}

// Outputs returns the template outputs as JSON keyed by name.
func (m *TemplateModel) Outputs() (json.RawMessage, error) {
	data, err := m.inner.OutputsJson()
	return json.RawMessage(data), err
}

// Conditions returns the names of the template's conditions.
func (m *TemplateModel) Conditions() ([]string, error) {
	return m.inner.Conditions()
}

// Transforms returns the template's declared transforms.
func (m *TemplateModel) Transforms() ([]string, error) {
	return m.inner.Transforms()
}

// FormatVersion returns AWSTemplateFormatVersion when declared.
func (m *TemplateModel) FormatVersion() *string {
	return m.inner.FormatVersion()
}

// Description returns the template description when declared.
func (m *TemplateModel) Description() *string {
	return m.inner.Description()
}

// DiagnosticModel returns the full diagnostic model as JSON.
func (m *TemplateModel) DiagnosticModel() (json.RawMessage, error) {
	data, err := m.inner.ToDiagnosticModelJson()
	return json.RawMessage(data), err
}

// SourceLocation returns the source span for a template path (e.g.
// "Resources/MyBucket/Properties/BucketName"), or nil when the path has no
// recorded location.
func (m *TemplateModel) SourceLocation(path string) (*SourceSpan, error) {
	data, err := m.inner.SourceLocationJson(path)
	if err != nil || data == nil {
		return nil, err
	}
	return decodeInto[SourceSpan](*data, "source span")
}

// Destroy releases the native model. It must not be used afterwards.
func (m *TemplateModel) Destroy() {
	m.inner.Destroy()
}
