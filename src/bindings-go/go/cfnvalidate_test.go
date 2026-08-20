package cfnvalidate

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMarshalAWSAPIRequestFormatsTimeAsRFC3339UTC(t *testing.T) {
	timestamp := time.Date(2025, time.January, 2, 3, 4, 5, 123456789, time.FixedZone("UTC+2", 2*60*60))

	encoded := encodedAWSAPIParameter(t, timestamp)

	if got := encoded["type"]; got != "STRING" {
		t.Fatalf("type = %v, want STRING", got)
	}
	if got := encoded["value"]; got != "2025-01-02T01:04:05.123456789Z" {
		t.Errorf("value = %v, want RFC3339 UTC timestamp", got)
	}
}

func TestMarshalAWSAPIRequestPreservesUnsignedJSONNumber(t *testing.T) {
	encoded := encodedAWSAPIParameter(t, json.Number("18446744073709551615"))

	if got := encoded["type"]; got != "UNSIGNED_INTEGER" {
		t.Fatalf("type = %v, want UNSIGNED_INTEGER", got)
	}
	value, ok := encoded["value"].(json.Number)
	if !ok {
		t.Fatalf("value type = %T, want json.Number", encoded["value"])
	}
	if got := value.String(); got != "18446744073709551615" {
		t.Errorf("value = %s, want exact uint64 maximum", got)
	}
}

func TestMarshalAWSAPIRequestMarksOutOfRangeIntegerUnsupported(t *testing.T) {
	encoded := encodedAWSAPIParameter(t, json.Number("18446744073709551616"))

	if got := encoded["type"]; got != "UNSUPPORTED" {
		t.Fatalf("type = %v, want UNSUPPORTED", got)
	}
	if got := encoded["type_name"]; got != "integer outside 64-bit range" {
		t.Errorf("type_name = %v, want integer outside 64-bit range", got)
	}
	if _, ok := encoded["value"]; ok {
		t.Error("UNSUPPORTED value must not contain a numeric value")
	}
}

func encodedAWSAPIParameter(t *testing.T, value any) map[string]any {
	t.Helper()
	requestJSON, err := marshalAWSAPIRequest(AWSAPIRequest{
		ServiceName:   "test",
		OperationName: "TestOperation",
		Parameters:    map[string]any{"Value": value},
	})
	if err != nil {
		t.Fatalf("marshalAWSAPIRequest failed: %v", err)
	}

	decoder := json.NewDecoder(strings.NewReader(requestJSON))
	decoder.UseNumber()
	var wire struct {
		Parameters map[string]map[string]any `json:"parameters"`
	}
	if err := decoder.Decode(&wire); err != nil {
		t.Fatalf("decoding request wire JSON failed: %v", err)
	}
	encoded, ok := wire.Parameters["Value"]
	if !ok {
		t.Fatal("encoded request is missing the Value parameter")
	}
	return encoded
}

// templateIntegerArray renders a string's bytes as the JSON integer array the
// core emits for the validated template field.
func templateIntegerArray(text string) string {
	elements := make([]string, len(text))
	for i := 0; i < len(text); i++ {
		elements[i] = strconv.Itoa(int(text[i]))
	}
	return "[" + strings.Join(elements, ",") + "]"
}

func unmarshalValidation(t *testing.T, blob string) AWSAPIRequestValidation {
	t.Helper()
	var validation AWSAPIRequestValidation
	if err := json.Unmarshal([]byte(blob), &validation); err != nil {
		t.Fatalf("unmarshalling AWSAPIRequestValidation failed: %v", err)
	}
	return validation
}

func TestUnmarshalValidationDecodesTemplateIntegerArrayToBytes(t *testing.T) {
	const template = `{"Resources":{"Resource":{"Type":"AWS::S3::Bucket"}}}`
	blob := `{"operationKind":"CLOUD_FORMATION_CREATE","status":"VALIDATED","resourceTypes":[],"reason":"synthesized","template":` +
		templateIntegerArray(template) + `}`

	validation := unmarshalValidation(t, blob)

	if got := string(validation.Template); got != template {
		t.Errorf("Template = %q, want %q", got, template)
	}
}

func TestUnmarshalValidationTreatsMissingTemplateAsNil(t *testing.T) {
	validation := unmarshalValidation(t, `{"operationKind":"READ_ONLY","status":"SKIPPED","resourceTypes":[],"reason":"read-only calls do not need validation"}`)

	if validation.Template != nil {
		t.Errorf("Template = %v, want nil for an absent field", validation.Template)
	}
}

func TestUnmarshalValidationTreatsNullTemplateAsNil(t *testing.T) {
	validation := unmarshalValidation(t, `{"operationKind":"READ_ONLY","status":"SKIPPED","resourceTypes":[],"reason":"skipped","template":null}`)

	if validation.Template != nil {
		t.Errorf("Template = %v, want nil for a JSON null", validation.Template)
	}
}

func TestUnmarshalValidationKeepsEmptyTemplateNonNil(t *testing.T) {
	validation := unmarshalValidation(t, `{"operationKind":"CLOUD_FORMATION_CREATE","status":"VALIDATED","resourceTypes":[],"reason":"synthesized","template":[]}`)

	if validation.Template == nil {
		t.Fatal("Template = nil, want a non-nil empty slice for an empty array")
	}
	if len(validation.Template) != 0 {
		t.Errorf("len(Template) = %d, want 0", len(validation.Template))
	}
}

func TestUnmarshalValidationRejectsMalformedTemplateBytes(t *testing.T) {
	cases := map[string]string{
		"non-integer fraction": `[123,2.5]`,
		"non-numeric element":  `[123,"x"]`,
		"negative byte":        `[-1]`,
		"byte above 255":       `[256]`,
		"not an array":         `"SGVsbG8="`,
	}
	for name, template := range cases {
		t.Run(name, func(t *testing.T) {
			blob := `{"operationKind":"CLOUD_FORMATION_CREATE","status":"VALIDATED","resourceTypes":[],"reason":"synthesized","template":` + template + `}`
			var validation AWSAPIRequestValidation
			if err := json.Unmarshal([]byte(blob), &validation); err == nil {
				t.Fatalf("expected an error for template %s, got Template = %v", template, validation.Template)
			}
		})
	}
}

func TestUnmarshalValidationReportsOffendingByteInError(t *testing.T) {
	blob := `{"operationKind":"CLOUD_FORMATION_CREATE","status":"VALIDATED","resourceTypes":[],"reason":"synthesized","template":[10,256]}`

	err := json.Unmarshal([]byte(blob), &AWSAPIRequestValidation{})
	if err == nil {
		t.Fatal("expected an out-of-range error")
	}
	if !strings.Contains(err.Error(), "index 1") || !strings.Contains(err.Error(), "256") {
		t.Errorf("error must name the offending index and value, got: %v", err)
	}
}

func TestUnmarshalValidationLeavesReceiverUnchangedOnError(t *testing.T) {
	existing := AWSAPIRequestValidation{
		OperationKind: AWSAPIOperationKindReadOnly,
		Status:        AWSAPIRequestValidationStatusSkipped,
		Reason:        "unchanged",
		Template:      []byte("original"),
	}
	validation := existing

	blob := `{"operationKind":"CLOUD_FORMATION_CREATE","status":"VALIDATED","resourceTypes":[],"reason":"synthesized","template":[999]}`
	if err := json.Unmarshal([]byte(blob), &validation); err == nil {
		t.Fatal("expected the out-of-range template to fail unmarshalling")
	}
	if validation.Status != existing.Status || validation.Reason != existing.Reason ||
		string(validation.Template) != string(existing.Template) {
		t.Errorf("receiver was mutated on failure: got %+v, want %+v", validation, existing)
	}
}

func TestUnmarshalValidationDecodesEveryFieldAlongsideTemplate(t *testing.T) {
	const template = `{"Resources":{"Resource":{"Type":"AWS::S3::Bucket","Properties":{"BucketName":"synthetic"}}}}`
	blob := `{
		"operationKind":"CLOUD_FORMATION_CREATE",
		"status":"VALIDATED",
		"templateSource":"SYNTHESIZED_CREATE",
		"resourceTypes":["AWS::S3::Bucket"],
		"reason":"synthesized one unambiguous CloudFormation resource",
		"report":{"filePath":"aws-api://s3/CreateBucket","status":"OK","version":"0.0.0","diagnostics":[]},
		"template":` + templateIntegerArray(template) + `
	}`

	validation := unmarshalValidation(t, blob)

	if validation.OperationKind != AWSAPIOperationKindCloudFormationCreate {
		t.Errorf("OperationKind = %q, want CLOUD_FORMATION_CREATE", validation.OperationKind)
	}
	if validation.Status != AWSAPIRequestValidationStatusValidated {
		t.Errorf("Status = %q, want VALIDATED", validation.Status)
	}
	if validation.TemplateSource == nil || *validation.TemplateSource != AWSAPITemplateSourceSynthesizedCreate {
		t.Errorf("TemplateSource = %v, want SYNTHESIZED_CREATE", validation.TemplateSource)
	}
	if len(validation.ResourceTypes) != 1 || validation.ResourceTypes[0] != "AWS::S3::Bucket" {
		t.Errorf("ResourceTypes = %v, want [AWS::S3::Bucket]", validation.ResourceTypes)
	}
	if validation.Reason != "synthesized one unambiguous CloudFormation resource" {
		t.Errorf("Reason = %q", validation.Reason)
	}
	if validation.Report == nil {
		t.Fatal("Report = nil, want the nested report to decode")
	}
	if validation.Report.FilePath != "aws-api://s3/CreateBucket" {
		t.Errorf("Report.FilePath = %q, want aws-api://s3/CreateBucket", validation.Report.FilePath)
	}
	if got := string(validation.Template); got != template {
		t.Errorf("Template = %q, want %q", got, template)
	}
}
