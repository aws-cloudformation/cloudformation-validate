package cfnvalidate

import (
	"encoding/json"
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
