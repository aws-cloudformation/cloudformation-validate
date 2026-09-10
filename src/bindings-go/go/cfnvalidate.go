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
//	report, err := engine.ValidateTemplateFile("template.yaml", nil)
//	for _, d := range report.Diagnostics {
//	    fmt.Printf("[%s] %s: %s\n", d.Severity, d.RuleID, d.Message)
//	}
//
// The native library is linked statically via cgo; run build.sh first to
// generate the internal bindings and stage the platform libraries.
package cfnvalidate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

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

func compositeEngineConfigJSON(config *CompositeEngineConfig) (string, error) {
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
	ValidateTemplateJson(template []byte, optionsJson string, filePath string) (string, error)
	ValidateAwsCliCommandJson(requestJson string, optionsJson string) (string, error)
	ListRulesJson() (string, error)
	EngineName() string
	Destroy()
}

// Engine validates CloudFormation templates against the built-in rule set,
// optionally extended with custom rules. Engines from NewRegoEngine,
// NewCelEngine, and NewCompositeEngine all produce identical built-in
// diagnostics; the composite engine layers any external rule findings on top.
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

// NewCompositeEngine builds a composite engine that evaluates the built-in
// rules with one engine and the caller-supplied external Rego and Guard rules
// with another. It produces the same built-in diagnostics as NewRegoEngine and
// NewCelEngine, plus any external findings. A nil config uses only the built-in
// rules.
func NewCompositeEngine(config *CompositeEngineConfig) (*Engine, error) {
	configJSON, err := compositeEngineConfigJSON(config)
	if err != nil {
		return nil, err
	}
	inner, err := bindings.NewGoCompositeEngine(configJSON)
	if err != nil {
		return nil, err
	}
	return &Engine{inner: inner}, nil
}

// ValidateTemplate validates template bytes and returns a report. The report's
// detail follows config.DetailLevel: DETAILED (the default when unset) carries
// per-diagnostic documentation URLs, rule descriptions, phase tags, and
// violation context, while STANDARD leaves those fields nil. filePath labels
// the report; pass "" for the default.
func (e *Engine) ValidateTemplate(template []byte, config *ValidateConfig, filePath string) (*ValidationReport, error) {
	optionsJSON, err := validateConfigJSON(config)
	if err != nil {
		return nil, err
	}
	if filePath == "" {
		filePath = defaultFilePath
	}
	data, err := e.inner.ValidateTemplateJson(template, optionsJSON, filePath)
	if err != nil {
		return nil, err
	}
	return decodeInto[ValidationReport](data, "report")
}

// ValidateTemplateFile reads a template from disk and validates it. See
// ValidateTemplate for how config.DetailLevel controls the report detail.
func (e *Engine) ValidateTemplateFile(path string, config *ValidateConfig) (*ValidationReport, error) {
	template, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cfnvalidate: reading template: %w", err)
	}
	return e.ValidateTemplate(template, config, path)
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

// EngineName returns the engine identifier ("rego", "cel", or "composite").
func (e *Engine) EngineName() string {
	return e.inner.EngineName()
}

// Destroy releases the native engine. The engine must not be used afterwards.
func (e *Engine) Destroy() {
	e.inner.Destroy()
}

// ValidateAWSCLICommand classifies and validates an AWS CLI command against
// CloudFormation schemas and rules entirely offline. The result contains
// operation classification, resource type inference, and an optional
// ValidationReport when the request was validated (not skipped). The report
// carries only the shared diagnostic fields; enrichment fields are left nil.
func (e *Engine) ValidateAWSCLICommand(request AWSCLICommand, config *ValidateConfig) (*AWSCLICommandValidation, error) {
	optionsJSON, err := validateConfigJSON(config)
	if err != nil {
		return nil, err
	}
	requestJSON, err := marshalAWSCLICommand(request)
	if err != nil {
		return nil, err
	}
	data, err := e.inner.ValidateAwsCliCommandJson(requestJSON, optionsJSON)
	if err != nil {
		return nil, err
	}
	return decodeInto[AWSCLICommandValidation](data, "AWS CLI command validation")
}

// marshalAWSCLICommand encodes an AWSCLICommand into the wire JSON that the
// Rust side expects, converting Go parameter values into tagged AwsCliValue
// objects.
func marshalAWSCLICommand(request AWSCLICommand) (string, error) {
	wire := awsCliCommandWire{
		ServiceName:   request.ServiceName,
		OperationName: request.OperationName,
		Parameters:    make(map[string]awsCliValue, len(request.Parameters)),
		ServicePrefix: nilIfEmpty(request.ServicePrefix),
		HTTPMethod:    nilIfEmpty(request.HTTPMethod),
		IsReadOnly:    request.IsReadOnly,
	}
	for key, value := range request.Parameters {
		wire.Parameters[key] = encodeAwsCliValue(value, 0)
	}
	data, err := json.Marshal(wire)
	if err != nil {
		return "", fmt.Errorf("cfnvalidate: encoding AWS CLI command: %w", err)
	}
	return string(data), nil
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// awsCliCommandWire is the JSON structure consumed by the Rust wire parser.
type awsCliCommandWire struct {
	ServiceName   string                 `json:"serviceName"`
	OperationName string                 `json:"operationName"`
	Parameters    map[string]awsCliValue `json:"parameters"`
	ServicePrefix *string                `json:"servicePrefix,omitempty"`
	HTTPMethod    *string                `json:"httpMethod,omitempty"`
	IsReadOnly    *bool                  `json:"isReadOnly,omitempty"`
}

// awsCliValue is the tagged union wire format matching the core AwsCliValue
// serde representation (tag = "type", rename_all = "SCREAMING_SNAKE_CASE").
// Items and Entries use pointer fields so that empty slices/maps serialize as
// their JSON zero ([] / {}) while remaining absent for unrelated variants.
type awsCliValue struct {
	Type     string                  `json:"type"`
	Value    any                     `json:"value,omitempty"`
	Items    *[]awsCliValue          `json:"items,omitempty"`
	Entries  *map[string]awsCliValue `json:"entries,omitempty"`
	TypeName string                  `json:"type_name,omitempty"`
}

// maxEncodeDepth prevents stack overflow on cyclic or deeply nested structures.
const maxEncodeDepth = 64

// encodeAwsCliValue recursively converts a Go value into the tagged wire
// format. It is non-mutating: no pointer is followed through a write path.
// Unsupported types are represented as UNSUPPORTED rather than coerced.
//
// SDK-defined type aliases (e.g. types.InstanceType is a named string) are
// handled via reflect.Kind after concrete type checks, so any alias of a
// scalar kind is encoded correctly without enumerating every SDK type.
func encodeAwsCliValue(v any, depth int) awsCliValue {
	if depth > maxEncodeDepth {
		return awsCliValue{Type: "UNSUPPORTED", TypeName: "recursion depth exceeded"}
	}
	if v == nil {
		return awsCliValue{Type: "NULL"}
	}

	// Unwrap interface and pointer layers. Count indirections separately because
	// a pointer-to-interface cycle can otherwise loop before recursive
	// collection encoding reaches the depth guard.
	rv := reflect.ValueOf(v)
	indirections := 0
	for rv.Kind() == reflect.Ptr || rv.Kind() == reflect.Interface {
		if depth+indirections > maxEncodeDepth {
			return awsCliValue{Type: "UNSUPPORTED", TypeName: "recursion depth exceeded"}
		}
		if rv.IsNil() {
			return awsCliValue{Type: "NULL"}
		}
		rv = rv.Elem()
		indirections++
	}
	v = rv.Interface()

	// Concrete type checks for stdlib types that carry semantics beyond their
	// underlying kind (time.Time and json.Number).
	switch val := v.(type) {
	case time.Time:
		return awsCliValue{Type: "STRING", Value: val.UTC().Format(time.RFC3339Nano)}

	case json.Number:
		text := string(val)
		if i, err := val.Int64(); err == nil {
			return awsCliValue{Type: "INTEGER", Value: i}
		}
		if u, err := strconv.ParseUint(text, 10, 64); err == nil {
			return awsCliValue{Type: "UNSIGNED_INTEGER", Value: u}
		}
		if !strings.ContainsAny(text, ".eE") && json.Valid([]byte(text)) {
			return awsCliValue{Type: "UNSUPPORTED", TypeName: "integer outside 64-bit range"}
		}
		if f, err := val.Float64(); err == nil {
			if math.IsInf(f, 0) || math.IsNaN(f) {
				return awsCliValue{Type: "UNSUPPORTED", TypeName: "non-finite floating-point number"}
			}
			return awsCliValue{Type: "NUMBER", Value: f}
		}
		return awsCliValue{Type: "UNSUPPORTED", TypeName: "unparseable json.Number"}
	}

	// Kind-based handling covers both built-in types and SDK-defined aliases
	// (e.g. types.InstanceType is `type InstanceType string`).
	switch rv.Kind() {
	case reflect.Bool:
		return awsCliValue{Type: "BOOLEAN", Value: rv.Bool()}

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return awsCliValue{Type: "INTEGER", Value: rv.Int()}

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return awsCliValue{Type: "UNSIGNED_INTEGER", Value: rv.Uint()}

	case reflect.Float32, reflect.Float64:
		f := rv.Float()
		if math.IsInf(f, 0) || math.IsNaN(f) {
			return awsCliValue{Type: "UNSUPPORTED", TypeName: "non-finite floating-point number"}
		}
		return awsCliValue{Type: "NUMBER", Value: f}

	case reflect.String:
		return awsCliValue{Type: "STRING", Value: rv.String()}

	case reflect.Slice, reflect.Array:
		// []byte / [N]byte → BYTES, encoded as a JSON integer array so the
		// Rust side receives Vec<u8> from serde (encoding/json marshals
		// []byte as base64 which is incompatible with serde's Vec<u8>).
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			ints := make([]int, rv.Len())
			for i := range ints {
				ints[i] = int(rv.Index(i).Uint())
			}
			return awsCliValue{Type: "BYTES", Value: ints}
		}
		items := make([]awsCliValue, rv.Len())
		for i := range items {
			items[i] = encodeAwsCliValue(rv.Index(i).Interface(), depth+1)
		}
		return awsCliValue{Type: "ARRAY", Items: &items}

	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			return awsCliValue{Type: "UNSUPPORTED", TypeName: "mapping with non-string keys"}
		}
		entries := make(map[string]awsCliValue, rv.Len())
		iter := rv.MapRange()
		for iter.Next() {
			entries[iter.Key().String()] = encodeAwsCliValue(iter.Value().Interface(), depth+1)
		}
		return awsCliValue{Type: "OBJECT", Entries: &entries}

	case reflect.Struct:
		return awsCliValue{Type: "UNSUPPORTED", TypeName: rv.Type().String()}

	default:
		return awsCliValue{Type: "UNSUPPORTED", TypeName: rv.Type().String()}
	}
}

// UnmarshalJSON decodes an AWSCLICommandValidation, translating the core's
// integer-array encoding of the validated template into a byte slice.
//
// The core serializes the template as a JSON array of byte-valued integers
// (serde's representation of a byte vector), which encoding/json cannot decode
// into a []byte directly - it expects a base64 string. Every other field
// decodes with the standard rules. On any failure the receiver is left
// unchanged, so a decode error never leaves a partially populated result.
func (v *AWSCLICommandValidation) UnmarshalJSON(data []byte) error {
	type withoutTemplate AWSCLICommandValidation
	var wire struct {
		withoutTemplate
		Template json.RawMessage `json:"template"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	template, err := decodeTemplateBytes(wire.Template)
	if err != nil {
		return err
	}
	decoded := AWSCLICommandValidation(wire.withoutTemplate)
	decoded.Template = template
	*v = decoded
	return nil
}

// decodeTemplateBytes converts the core's JSON integer-array template encoding
// into a byte slice. A missing or null field yields nil; an empty array yields
// a non-nil empty slice; every element must be an integer in the range 0-255.
func decodeTemplateBytes(raw json.RawMessage) ([]byte, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.UseNumber()
	var elements []json.Number
	if err := decoder.Decode(&elements); err != nil {
		return nil, fmt.Errorf("cfnvalidate: template must be a JSON array of byte integers: %w", err)
	}
	template := make([]byte, len(elements))
	for i, element := range elements {
		value, err := element.Int64()
		if err != nil {
			return nil, fmt.Errorf("cfnvalidate: template byte at index %d is not an integer: %s", i, element)
		}
		if value < 0 || value > 255 {
			return nil, fmt.Errorf("cfnvalidate: template byte at index %d is out of range 0-255: %d", i, value)
		}
		template[i] = byte(value)
	}
	return template, nil
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
// region-specific schemas; nil uses the default. The returned diagnostics carry
// only the shared fields; enrichment fields are left nil.
func (v *SchemaValidator) Validate(template []byte, region *string) ([]Diagnostic, error) {
	model, err := bindings.GoSemanticModelParse(template)
	if err != nil {
		return nil, err
	}
	defer model.Destroy()
	data, err := v.inner.ValidateJson(model, region)
	if err != nil {
		return nil, err
	}
	diagnostics, err := decodeInto[[]Diagnostic](data, "diagnostics")
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
