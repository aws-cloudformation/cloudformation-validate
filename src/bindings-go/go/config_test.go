// Wire-contract tests for the config structs.
//
// The Go config structs and the option structs in ../src/lib.rs are two
// hand-maintained halves of one JSON contract. This file pins the Go half: a
// fully populated config must marshal to exactly the document the Rust half
// parses (FULL_VALIDATE_OPTIONS_JSON in ../src/lib.rs). A renamed or dropped
// json tag on either side fails one of the two tests instead of silently
// producing a config the engine ignores.
package cfnvalidate_test

import (
	"encoding/json"
	"reflect"
	"testing"

	cfnvalidate "github.com/aws-cloudformation/cloudformation-validate/src/bindings-go/go"
)

// Kept in sync with FULL_VALIDATE_OPTIONS_JSON in ../src/lib.rs.
const fullValidateConfigJSON = `{
    "include": {
        "ids": ["E3012"],
        "categories": ["Security"],
        "idRanges": [{"prefix": "E", "start": 3000, "end": 3099}],
        "idPatterns": ["^W30.*$"],
        "resourceIds": [{"ruleId": "W3010", "resourceId": "MyBucket"}],
        "logicalIds": [{"ruleId": "W2501", "logicalId": "MyPassword", "entityType": "Parameter"}],
        "resourceTypes": [{"ruleId": "I9040", "resourceType": "AWS::S3::Bucket"}],
        "services": [{"ruleId": "I3011", "service": "AWS::RDS"}]
    },
    "exclude": {
        "ids": ["I9003"],
        "categories": ["Best Practice"],
        "idRanges": [{"prefix": "I", "start": 9000, "end": 9099}],
        "idPatterns": ["^I90.*$"],
        "resourceIds": [{"resourceId": "MyQueue"}],
        "logicalIds": [{"logicalId": "MyOutput"}],
        "resourceTypes": [{"resourceType": "AWS::SQS::Queue"}],
        "services": [{"service": "AWS::SQS"}]
    },
    "severityLevel": "WARN",
    "parameterOverrides": {"Environment": "prod"},
    "pseudoParameterOverrides": {
        "accountId": "123456789012",
        "notificationArns": "arn:aws:sns:us-west-2:123456789012:topic",
        "partition": "aws",
        "region": "us-west-2",
        "stackId": "arn:aws:cloudformation:us-west-2:123456789012:stack/my-stack/id",
        "stackName": "my-stack",
        "urlSuffix": "amazonaws.com"
    },
    "strict": true,
    "disableBuiltinRules": false
}`

const fullEngineConfigJSON = `{
    "customRules": [{"name": "s3_encryption.json", "content": "{}"}],
    "guardRules": [{"name": "compliance.guard", "content": "let x = 1"}],
    "schemaValidator": {
        "additionalSchemas": [{
            "typeName": "",
            "schema": "{\"typeName\":\"AWS::Test::OverlayOnly\",\"properties\":{\"Name\":{\"type\":\"string\"}}}"
        }]
    }
}`

func stringPtr(value string) *string { return &value }

func boolPtr(value bool) *bool { return &value }

func fullValidateConfig() *cfnvalidate.ValidateConfig {
	parameterEntity := cfnvalidate.EntityTypeParameter
	return &cfnvalidate.ValidateConfig{
		Include: &cfnvalidate.RuleFilterConfig{
			IDs:         []string{"E3012"},
			Categories:  []string{"Security"},
			IDRanges:    []cfnvalidate.IdRange{{Prefix: "E", Start: 3000, End: 3099}},
			IDPatterns:  []string{"^W30.*$"},
			ResourceIDs: []cfnvalidate.ResourceIdFilter{{RuleID: stringPtr("W3010"), ResourceID: "MyBucket"}},
			LogicalIDs: []cfnvalidate.LogicalIdFilter{
				{RuleID: stringPtr("W2501"), LogicalID: "MyPassword", EntityType: &parameterEntity},
			},
			ResourceTypes: []cfnvalidate.ResourceTypeFilter{{RuleID: stringPtr("I9040"), ResourceType: "AWS::S3::Bucket"}},
			Services:      []cfnvalidate.ServiceFilter{{RuleID: stringPtr("I3011"), Service: "AWS::RDS"}},
		},
		Exclude: &cfnvalidate.RuleFilterConfig{
			IDs:           []string{"I9003"},
			Categories:    []string{"Best Practice"},
			IDRanges:      []cfnvalidate.IdRange{{Prefix: "I", Start: 9000, End: 9099}},
			IDPatterns:    []string{"^I90.*$"},
			ResourceIDs:   []cfnvalidate.ResourceIdFilter{{ResourceID: "MyQueue"}},
			LogicalIDs:    []cfnvalidate.LogicalIdFilter{{LogicalID: "MyOutput"}},
			ResourceTypes: []cfnvalidate.ResourceTypeFilter{{ResourceType: "AWS::SQS::Queue"}},
			Services:      []cfnvalidate.ServiceFilter{{Service: "AWS::SQS"}},
		},
		SeverityLevel:      cfnvalidate.SeverityWarn,
		ParameterOverrides: map[string]string{"Environment": "prod"},
		PseudoParameterOverrides: &cfnvalidate.PseudoParameterOverrides{
			AccountID:        stringPtr("123456789012"),
			NotificationARNs: stringPtr("arn:aws:sns:us-west-2:123456789012:topic"),
			Partition:        stringPtr("aws"),
			Region:           stringPtr("us-west-2"),
			StackID:          stringPtr("arn:aws:cloudformation:us-west-2:123456789012:stack/my-stack/id"),
			StackName:        stringPtr("my-stack"),
			URLSuffix:        stringPtr("amazonaws.com"),
		},
		Strict:              boolPtr(true),
		DisableBuiltinRules: boolPtr(false),
	}
}

func assertMarshalsTo(t *testing.T, value any, expected string) {
	t.Helper()
	actualJSON, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshaling config: %v", err)
	}
	var actual, want any
	if err := json.Unmarshal(actualJSON, &actual); err != nil {
		t.Fatalf("decoding marshaled config: %v", err)
	}
	if err := json.Unmarshal([]byte(expected), &want); err != nil {
		t.Fatalf("decoding expected config: %v", err)
	}
	if !reflect.DeepEqual(actual, want) {
		t.Errorf("config JSON does not match the contract\n--- actual ---\n%s\n--- expected ---\n%s", actualJSON, expected)
	}
}

func TestFullValidateConfigMarshalsToTheContractShape(t *testing.T) {
	assertMarshalsTo(t, fullValidateConfig(), fullValidateConfigJSON)
}

func TestFullEngineConfigMarshalsToTheContractShape(t *testing.T) {
	config := &cfnvalidate.EngineConfig{
		CustomRules: []cfnvalidate.ExternalRuleSource{{Name: "s3_encryption.json", Content: "{}"}},
		GuardRules:  []cfnvalidate.ExternalRuleSource{{Name: "compliance.guard", Content: "let x = 1"}},
		SchemaValidator: &cfnvalidate.SchemaValidatorConfig{
			AdditionalSchemas: []cfnvalidate.AdditionalSchemaSource{{
				Schema: `{"typeName":"AWS::Test::OverlayOnly","properties":{"Name":{"type":"string"}}}`,
			}},
		},
	}
	assertMarshalsTo(t, config, fullEngineConfigJSON)
}

func TestFullValidateConfigIsAcceptedByTheNativeLayer(t *testing.T) {
	engine := mustEngine(t, cfnvalidate.NewRegoEngine, nil)

	report, err := engine.ValidateStandard([]byte(unencryptedBucket), fullValidateConfig(), "contract.yaml")
	if err != nil {
		t.Fatalf("native layer rejected a fully populated config: %v", err)
	}
	if !report.Metadata.Strict {
		t.Error("metadata.strict must reflect the strict option carried across the boundary")
	}
	if report.Metadata.SeverityLevel != cfnvalidate.SeverityWarn {
		t.Errorf("metadata.severityLevel = %s, want WARN", report.Metadata.SeverityLevel)
	}
}

func TestFullSchemaValidatorConfigMarshalsToTheContractShape(t *testing.T) {
	config := &cfnvalidate.SchemaValidatorConfig{
		AdditionalSchemas: []cfnvalidate.AdditionalSchemaSource{{
			Schema: `{"typeName":"AWS::Test::OverlayOnly","properties":{"Name":{"type":"string"}}}`,
		}},
	}
	expected := `{"additionalSchemas":[{"typeName":"","schema":"{\"typeName\":\"AWS::Test::OverlayOnly\",\"properties\":{\"Name\":{\"type\":\"string\"}}}"}]}`
	assertMarshalsTo(t, config, expected)
}
