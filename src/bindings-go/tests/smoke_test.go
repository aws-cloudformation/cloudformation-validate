// Smoke tests for the Go bindings.
//
// Runs against the module assembled by ../build.sh (generated internal
// package + staged static library), exercising the public API end to end:
// engine construction, validation reports, engine parity, the template model,
// the schema validator, custom rules, and error handling.
package cfnvalidate_test

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	cfnvalidate "github.com/aws-cloudformation/cloudformation-validate/src/bindings-go/go"
)

const unencryptedBucket = `
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-test-bucket
`

const templateWithOverlayProperty = `
Resources:
  Function:
    Type: AWS::Lambda::Function
    Properties:
      Code:
        ZipFile: "exports.handler = async () => {};"
      Role: arn:aws:iam::123456789012:role/lambda-role
      Runtime: nodejs18.x
      Handler: index.handler
      TestForOverride: enabled
`

const lambdaOverlaySchema = `{
  "typeName": "AWS::Lambda::Function",
  "properties": {"TestForOverride": {"type": "string"}}
}`

var (
	workspaceDir = filepath.Join("..", "..")
	goodTemplate = filepath.Join(workspaceDir, "resources", "templates", "good", "aurora_dbinstance.yaml")
	rulesDir     = filepath.Join(workspaceDir, "resources", "rules")
)

func mustEngine(t *testing.T, build func(*cfnvalidate.EngineConfig) (*cfnvalidate.Engine, error), config *cfnvalidate.EngineConfig) *cfnvalidate.Engine {
	t.Helper()
	engine, err := build(config)
	if err != nil {
		t.Fatalf("engine construction failed: %v", err)
	}
	t.Cleanup(engine.Destroy)
	return engine
}

func bothEngines(t *testing.T) map[string]*cfnvalidate.Engine {
	t.Helper()
	return map[string]*cfnvalidate.Engine{
		"rego": mustEngine(t, cfnvalidate.NewRegoEngine, nil),
		"cel":  mustEngine(t, cfnvalidate.NewCelEngine, nil),
	}
}

func loadRule(t *testing.T, filename string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(rulesDir, filename))
	if err != nil {
		t.Fatalf("reading rule fixture %s: %v", filename, err)
	}
	return string(content)
}

func diagnosticKeys(report *cfnvalidate.StandardReport) []string {
	keys := make([]string, 0, len(report.Diagnostics))
	for _, d := range report.Diagnostics {
		line, column := -1, -1
		if d.StartLine != nil {
			line = *d.StartLine
		}
		if d.StartColumn != nil {
			column = *d.StartColumn
		}
		keys = append(keys, fmt.Sprintf("%s|%s|%d|%d", d.RuleID, d.Severity, line, column))
	}
	sort.Strings(keys)
	return keys
}

func TestVersionMatchesWorkspaceCargoToml(t *testing.T) {
	content, err := os.ReadFile(filepath.Join(workspaceDir, "Cargo.toml"))
	if err != nil {
		t.Fatalf("reading workspace Cargo.toml: %v", err)
	}
	match := regexp.MustCompile(`(?s)\[workspace\.package\].*?version = "([^"]+)"`).FindSubmatch(content)
	if match == nil {
		t.Fatal("missing version under [workspace.package] in workspace Cargo.toml")
	}
	if got, want := cfnvalidate.Version(), string(match[1]); got != want {
		t.Errorf("Version() = %q, want %q", got, want)
	}
}

func TestPackageVersionReportsLocalReplacementAsDevelopment(t *testing.T) {
	if got, want := cfnvalidate.PackageVersion(), "(devel)"; got != want {
		t.Errorf("PackageVersion() = %q, want %q", got, want)
	}
}

func TestEngineNames(t *testing.T) {
	for want, engine := range bothEngines(t) {
		if got := engine.EngineName(); got != want {
			t.Errorf("EngineName() = %q, want %q", got, want)
		}
	}
}

func TestListRulesSortedAndIdenticalAcrossEngines(t *testing.T) {
	engines := bothEngines(t)
	lists := map[string][]cfnvalidate.RuleInfo{}
	for name, engine := range engines {
		rules, err := engine.ListRules()
		if err != nil {
			t.Fatalf("%s: ListRules failed: %v", name, err)
		}
		if len(rules) == 0 {
			t.Fatalf("%s: rule list must not be empty", name)
		}
		if !sort.SliceIsSorted(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID }) {
			t.Errorf("%s: rules must be sorted by id", name)
		}
		lists[name] = rules
	}
	rego, cel := lists["rego"], lists["cel"]
	regoJSON, err := json.Marshal(rego)
	if err != nil {
		t.Fatalf("marshaling rego rules: %v", err)
	}
	celJSON, err := json.Marshal(cel)
	if err != nil {
		t.Fatalf("marshaling cel rules: %v", err)
	}
	if string(regoJSON) != string(celJSON) {
		t.Error("CEL and Rego must list identical rules")
	}
}

func TestSchemaValidator(t *testing.T) {
	validator, err := cfnvalidate.NewSchemaValidator(nil)
	if err != nil {
		t.Fatalf("schema validator construction failed: %v", err)
	}
	defer validator.Destroy()

	if count := validator.SchemaCount(); count == 0 {
		t.Error("schema count must be positive")
	}
	rules, err := validator.ListRules()
	if err != nil {
		t.Fatalf("ListRules failed: %v", err)
	}
	if len(rules) == 0 || rules[0].ID == "" {
		t.Error("schema validator must have rules with ids")
	}
	diagnostics, err := validator.Validate([]byte(unencryptedBucket), nil)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if diagnostics == nil {
		t.Error("Validate must return a diagnostics slice")
	}
}

func TestGoodTemplatePassesBothEngines(t *testing.T) {
	for name, engine := range bothEngines(t) {
		report, err := engine.ValidateStandardFile(goodTemplate, nil)
		if err != nil {
			t.Fatalf("%s: validation failed: %v", name, err)
		}
		if report.Status != cfnvalidate.StatusOK {
			t.Errorf("%s: status = %s, want OK", name, report.Status)
		}
		if report.FilePath != goodTemplate {
			t.Errorf("%s: filePath = %q, want %q", name, report.FilePath, goodTemplate)
		}
		for _, d := range report.Diagnostics {
			if d.Severity == cfnvalidate.SeverityError || d.Severity == cfnvalidate.SeverityFatal {
				t.Errorf("%s: good template must have no errors, got [%s] %s", name, d.RuleID, d.Message)
			}
		}
	}
}

func TestAdditionalSchemasApplyThroughTheTypedConfigOnBothEngines(t *testing.T) {
	schemaConfig := &cfnvalidate.SchemaValidatorConfig{
		AdditionalSchemas: []cfnvalidate.AdditionalSchemaSource{{Schema: lambdaOverlaySchema}},
	}
	builders := map[string]func(*cfnvalidate.EngineConfig) (*cfnvalidate.Engine, error){
		"rego": cfnvalidate.NewRegoEngine,
		"cel":  cfnvalidate.NewCelEngine,
	}
	for name, build := range builders {
		baseline := mustEngine(t, build, nil)
		baselineReport, err := baseline.ValidateStandard([]byte(templateWithOverlayProperty), nil, "overlay.yaml")
		if err != nil {
			t.Fatalf("%s baseline validation failed: %v", name, err)
		}
		baselineHasUnexpectedProperty := false
		for _, diagnostic := range baselineReport.Diagnostics {
			if diagnostic.RuleID == "F3002" {
				baselineHasUnexpectedProperty = true
			}
		}
		if !baselineHasUnexpectedProperty {
			t.Fatalf("%s baseline must report the unpublished property", name)
		}

		engine, err := build(&cfnvalidate.EngineConfig{SchemaValidatorConfig: schemaConfig})
		if err != nil {
			t.Fatalf("%s engine construction with overlay failed: %v", name, err)
		}
		defer engine.Destroy()
		report, err := engine.ValidateStandard([]byte(templateWithOverlayProperty), nil, "overlay.yaml")
		if err != nil {
			t.Fatalf("%s overlay validation failed: %v", name, err)
		}
		for _, diagnostic := range report.Diagnostics {
			if diagnostic.RuleID == "F3002" {
				t.Errorf("%s typed config did not apply the overlay: %s", name, diagnostic.Message)
			}
		}
	}
}

func TestDiagnosticsFireWithEntities(t *testing.T) {
	engine := mustEngine(t, cfnvalidate.NewRegoEngine, nil)
	report, err := engine.ValidateStandard([]byte(unencryptedBucket), nil, "")
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}
	if report.FilePath != "template" {
		t.Errorf("default filePath = %q, want %q", report.FilePath, "template")
	}
	if len(report.Diagnostics) == 0 {
		t.Fatal("unencrypted bucket template must produce diagnostics")
	}
	found := false
	for _, d := range report.Diagnostics {
		if d.Entity != nil && d.Entity.LogicalID == "MyBucket" {
			found = true
			if d.Entity.ResourceType == nil || *d.Entity.ResourceType != "AWS::S3::Bucket" {
				t.Errorf("entity resourceType = %v, want AWS::S3::Bucket", d.Entity.ResourceType)
			}
		}
	}
	if !found {
		t.Error("expected a diagnostic with entity MyBucket")
	}
}

func TestEnginesAgreeOnDiagnostics(t *testing.T) {
	engines := bothEngines(t)
	reports := map[string][]string{}
	for name, engine := range engines {
		report, err := engine.ValidateStandard([]byte(unencryptedBucket), nil, "")
		if err != nil {
			t.Fatalf("%s: validation failed: %v", name, err)
		}
		reports[name] = diagnosticKeys(report)
	}
	if got, want := reports["rego"], reports["cel"]; !equalStrings(got, want) {
		t.Errorf("engines disagree:\nrego: %v\ncel:  %v", got, want)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestSeverityLevelFiltersBelowThreshold(t *testing.T) {
	engine := mustEngine(t, cfnvalidate.NewRegoEngine, nil)
	config := &cfnvalidate.ValidateConfig{SeverityLevel: cfnvalidate.SeverityError}
	report, err := engine.ValidateStandard([]byte(unencryptedBucket), config, "")
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}
	for _, diagnostic := range report.Diagnostics {
		switch diagnostic.Severity {
		case cfnvalidate.SeverityWarn, cfnvalidate.SeverityInfo, cfnvalidate.SeverityDebug:
			t.Errorf("severityLevel=ERROR must exclude %s diagnostic %s", diagnostic.Severity, diagnostic.RuleID)
		}
	}
}

func TestLogicalIDFilterScopesByEntityType(t *testing.T) {
	engine := mustEngine(t, cfnvalidate.NewRegoEngine, nil)
	entityType := cfnvalidate.EntityTypeResource
	config := &cfnvalidate.ValidateConfig{
		Exclude: &cfnvalidate.RuleFilterConfig{
			LogicalIDs: []cfnvalidate.LogicalIdFilter{
				{LogicalID: "MyBucket", EntityType: &entityType},
			},
		},
	}
	report, err := engine.ValidateStandard([]byte(unencryptedBucket), config, "")
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}
	for _, diagnostic := range report.Diagnostics {
		if diagnostic.Entity != nil && diagnostic.Entity.LogicalID == "MyBucket" {
			t.Errorf("logical ID filter did not exclude diagnostic %s", diagnostic.RuleID)
		}
	}
}

func TestDetailedCountsMatchDiagnostics(t *testing.T) {
	engine := mustEngine(t, cfnvalidate.NewCelEngine, nil)
	report, err := engine.ValidateDetailed([]byte(unencryptedBucket), nil, "")
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}
	counts := report.Metadata.Counts
	total := counts.Fatal + counts.Errors + counts.Warnings + counts.Informational + counts.Debug
	if len(report.Diagnostics) != total {
		t.Errorf("diagnostics = %d, counts total = %d", len(report.Diagnostics), total)
	}
}

func TestCustomRulesFire(t *testing.T) {
	cases := map[string]struct {
		build  func(*cfnvalidate.EngineConfig) (*cfnvalidate.Engine, error)
		config *cfnvalidate.EngineConfig
	}{
		"cel custom": {
			cfnvalidate.NewCelEngine,
			&cfnvalidate.EngineConfig{CustomRules: []cfnvalidate.ExternalRuleSource{{Name: "cel_custom.json", Content: ""}}},
		},
		"rego custom": {
			cfnvalidate.NewRegoEngine,
			&cfnvalidate.EngineConfig{CustomRules: []cfnvalidate.ExternalRuleSource{{Name: "rego_custom.rego", Content: ""}}},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tc.config.CustomRules[0].Content = loadRule(t, tc.config.CustomRules[0].Name)
			engine := mustEngine(t, tc.build, tc.config)
			report, err := engine.ValidateStandard([]byte(unencryptedBucket), nil, "")
			if err != nil {
				t.Fatalf("validation failed: %v", err)
			}
			hits := 0
			for _, d := range report.Diagnostics {
				if d.RuleID == "CUSTOM001" {
					hits++
					if d.Message != "S3 bucket must have encryption configured" {
						t.Errorf("unexpected message: %q", d.Message)
					}
				}
			}
			if hits != 1 {
				t.Errorf("CUSTOM001 fired %d times, want 1", hits)
			}
		})
	}
}

func TestGuardRulesFireOnBothEngines(t *testing.T) {
	config := &cfnvalidate.EngineConfig{
		GuardRules: []cfnvalidate.ExternalRuleSource{
			{Name: "guard_encryption.guard", Content: loadRule(t, "guard_encryption.guard")},
		},
	}
	for name, build := range map[string]func(*cfnvalidate.EngineConfig) (*cfnvalidate.Engine, error){
		"rego": cfnvalidate.NewRegoEngine,
		"cel":  cfnvalidate.NewCelEngine,
	} {
		engine := mustEngine(t, build, config)
		report, err := engine.ValidateStandard([]byte(unencryptedBucket), nil, "")
		if err != nil {
			t.Fatalf("%s: validation failed: %v", name, err)
		}
		hits := 0
		for _, d := range report.Diagnostics {
			if strings.Contains(strings.ToLower(d.Message), "encryption") {
				hits++
			}
		}
		if hits == 0 {
			t.Errorf("%s: guard rule must fire", name)
		}
	}
}

func TestTemplateModel(t *testing.T) {
	model, err := cfnvalidate.ParseTemplate([]byte(unencryptedBucket))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	defer model.Destroy()

	resourcesJSON, err := model.Resources()
	if err != nil {
		t.Fatalf("Resources failed: %v", err)
	}
	var resources map[string]struct {
		ResourceType string `json:"resourceType"`
	}
	if err := json.Unmarshal(resourcesJSON, &resources); err != nil {
		t.Fatalf("decoding resources: %v", err)
	}
	if len(resources) != 1 || resources["MyBucket"].ResourceType != "AWS::S3::Bucket" {
		t.Errorf("resources = %v, want MyBucket of AWS::S3::Bucket", resources)
	}

	conditions, err := model.Conditions()
	if err != nil {
		t.Fatalf("Conditions failed: %v", err)
	}
	if len(conditions) != 0 {
		t.Errorf("conditions = %v, want none", conditions)
	}
	if v := model.FormatVersion(); v != nil {
		t.Errorf("formatVersion = %v, want nil", *v)
	}

	span, err := model.SourceLocation("Resources/MyBucket/Properties/BucketName")
	if err != nil {
		t.Fatalf("SourceLocation failed: %v", err)
	}
	if span == nil || span.StartLine <= 0 {
		t.Errorf("span = %+v, want a positive location", span)
	}
	missing, err := model.SourceLocation("Resources/DoesNotExist")
	if err != nil {
		t.Fatalf("SourceLocation for missing path failed: %v", err)
	}
	if missing != nil {
		t.Errorf("missing path span = %+v, want nil", missing)
	}
}

func TestUnparseableTemplateReportsErrorStatus(t *testing.T) {
	engine := mustEngine(t, cfnvalidate.NewRegoEngine, nil)
	report, err := engine.ValidateStandard([]byte("not: a: valid: yaml: ["), nil, "")
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}
	if report.Status != cfnvalidate.StatusError {
		t.Errorf("status = %s, want ERROR", report.Status)
	}
	if len(report.Diagnostics) == 0 {
		t.Error("parse failure must surface as a diagnostic")
	}
}

func TestErrorsSurfaceAsGoErrors(t *testing.T) {
	if _, err := cfnvalidate.ParseTemplate([]byte{0x00, 0x01}); err == nil {
		t.Error("parsing garbage must return an error")
	}

	config := &cfnvalidate.EngineConfig{
		CustomRules: []cfnvalidate.ExternalRuleSource{{Name: "broken.rego", Content: "not valid rego {{{"}},
	}
	if _, err := cfnvalidate.NewRegoEngine(config); err == nil {
		t.Error("invalid custom rule must fail engine construction")
	}
}

// --- AWS API Request Validation tests ---

func TestAWSAPIRequestS3CreateWithBothEnginesAndParity(t *testing.T) {
	request := cfnvalidate.AWSAPIRequest{
		ServiceName:   "s3",
		OperationName: "CreateBucket",
		Parameters:    map[string]any{"Bucket": "my-test-bucket"},
		HTTPMethod:    "PUT",
	}
	originalParams := map[string]any{"Bucket": "my-test-bucket"}

	results := map[string]*cfnvalidate.AWSAPIRequestValidation{}
	for name, engine := range bothEngines(t) {
		result, err := engine.ValidateAWSAPIRequest(request, nil)
		if err != nil {
			t.Fatalf("%s: ValidateAWSAPIRequest failed: %v", name, err)
		}
		results[name] = result

		if result.OperationKind != cfnvalidate.AWSAPIOperationKindCloudFormationCreate {
			t.Errorf("%s: operationKind = %s, want CLOUD_FORMATION_CREATE", name, result.OperationKind)
		}
		if result.Status != cfnvalidate.AWSAPIRequestValidationStatusValidated {
			t.Errorf("%s: status = %s, want VALIDATED", name, result.Status)
		}
		if len(result.ResourceTypes) == 0 || result.ResourceTypes[0] != "AWS::S3::Bucket" {
			t.Errorf("%s: resourceTypes = %v, want [AWS::S3::Bucket]", name, result.ResourceTypes)
		}
		if result.Report == nil {
			t.Fatalf("%s: report must be present for a validated request", name)
		}
		if result.Report.Status != cfnvalidate.StatusOK {
			t.Errorf("%s: report.Status = %s, want OK", name, result.Report.Status)
		}
	}

	// Verify engine parity.
	if results["rego"] != nil && results["cel"] != nil {
		regoKeys := diagnosticKeys(results["rego"].Report)
		celKeys := diagnosticKeys(results["cel"].Report)
		if !equalStrings(regoKeys, celKeys) {
			t.Errorf("engines disagree on AWS API diagnostics:\nrego: %v\ncel:  %v", regoKeys, celKeys)
		}
	}

	// Verify input non-mutation.
	if len(request.Parameters) != len(originalParams) {
		t.Errorf("request.Parameters mutated: len changed from %d to %d", len(originalParams), len(request.Parameters))
	}
	for key, want := range originalParams {
		if got, ok := request.Parameters[key]; !ok || got != want {
			t.Errorf("request.Parameters[%q] mutated: got %v, want %v", key, got, want)
		}
	}
}

func TestAWSAPIRequestCloudFormationTemplateBodyBytes(t *testing.T) {
	template := []byte(`{"AWSTemplateFormatVersion":"2010-09-09","Resources":{"Bucket":{"Type":"AWS::S3::Bucket","Properties":{"BucketName":"exact-body"}}}}`)
	request := cfnvalidate.AWSAPIRequest{
		ServiceName:   "cloudformation",
		OperationName: "CreateStack",
		Parameters:    map[string]any{"TemplateBody": template},
		HTTPMethod:    "POST",
	}

	engine := mustEngine(t, cfnvalidate.NewRegoEngine, nil)
	result, err := engine.ValidateAWSAPIRequest(request, nil)
	if err != nil {
		t.Fatalf("ValidateAWSAPIRequest failed: %v", err)
	}

	if result.Status != cfnvalidate.AWSAPIRequestValidationStatusValidated {
		t.Errorf("status = %s, want VALIDATED", result.Status)
	}
	if result.TemplateSource == nil || *result.TemplateSource != cfnvalidate.AWSAPITemplateSourceTemplateBody {
		t.Errorf("templateSource = %v, want TEMPLATE_BODY", result.TemplateSource)
	}
	if result.Report == nil {
		t.Fatal("report must be present for a validated template body")
	}
	if result.Report.Status != cfnvalidate.StatusOK {
		t.Errorf("report.Status = %s, want OK", result.Report.Status)
	}
}

func TestAWSAPIRequestReadOnlySkips(t *testing.T) {
	readOnly := true
	request := cfnvalidate.AWSAPIRequest{
		ServiceName:   "iam",
		OperationName: "GetRole",
		Parameters:    map[string]any{"RoleName": "test-role"},
		IsReadOnly:    &readOnly,
	}

	engine := mustEngine(t, cfnvalidate.NewCelEngine, nil)
	result, err := engine.ValidateAWSAPIRequest(request, nil)
	if err != nil {
		t.Fatalf("ValidateAWSAPIRequest failed: %v", err)
	}

	if result.OperationKind != cfnvalidate.AWSAPIOperationKindReadOnly {
		t.Errorf("operationKind = %s, want READ_ONLY", result.OperationKind)
	}
	if result.Status != cfnvalidate.AWSAPIRequestValidationStatusSkipped {
		t.Errorf("status = %s, want SKIPPED", result.Status)
	}
	if result.Report != nil {
		t.Errorf("report must be nil for a skipped request, got %+v", result.Report)
	}
}

func TestAWSAPIRequestUnregisteredOperationNoInferredTypes(t *testing.T) {
	request := cfnvalidate.AWSAPIRequest{
		ServiceName:   "customservice",
		OperationName: "DoSomethingUnknown",
		Parameters:    map[string]any{"Key": "value"},
		HTTPMethod:    "POST",
	}

	engine := mustEngine(t, cfnvalidate.NewRegoEngine, nil)
	result, err := engine.ValidateAWSAPIRequest(request, nil)
	if err != nil {
		t.Fatalf("ValidateAWSAPIRequest failed: %v", err)
	}

	if len(result.ResourceTypes) != 0 {
		t.Errorf("resourceTypes = %v, want empty for unregistered operation", result.ResourceTypes)
	}
	if result.Report != nil {
		t.Errorf("report must be nil for an unmapped operation that cannot synthesize, got non-nil")
	}
}

func TestAWSAPIRequestSDKServiceCasing(t *testing.T) {
	request := cfnvalidate.AWSAPIRequest{
		ServiceName:   "DynamoDb",
		OperationName: "CreateTable",
		Parameters: map[string]any{
			"TableName":            "PascalCased",
			"KeySchema":            []any{map[string]any{"AttributeName": "id", "KeyType": "HASH"}},
			"AttributeDefinitions": []any{map[string]any{"AttributeName": "id", "AttributeType": "S"}},
			"BillingMode":          "PAY_PER_REQUEST",
		},
		HTTPMethod: "POST",
	}

	engine := mustEngine(t, cfnvalidate.NewCelEngine, nil)
	result, err := engine.ValidateAWSAPIRequest(request, nil)
	if err != nil {
		t.Fatalf("ValidateAWSAPIRequest failed: %v", err)
	}

	if result.OperationKind != cfnvalidate.AWSAPIOperationKindCloudFormationCreate {
		t.Errorf("operationKind = %s, want CLOUD_FORMATION_CREATE", result.OperationKind)
	}
	if len(result.ResourceTypes) == 0 || result.ResourceTypes[0] != "AWS::DynamoDB::Table" {
		t.Errorf("resourceTypes = %v, want [AWS::DynamoDB::Table]", result.ResourceTypes)
	}
}

func TestAWSAPIRequestEC2MappedDiagnostic(t *testing.T) {
	// Use a defined string alias to exercise the scalar alias encoding path.
	// InstanceInitiatedShutdownBehavior has a real enum constraint in the
	// EC2 schema, so an invalid value triggers a diagnostic reliably.
	type ShutdownBehavior string
	request := cfnvalidate.AWSAPIRequest{
		ServiceName:   "ec2",
		OperationName: "RunInstances",
		Parameters: map[string]any{
			"ImageId":                           "ami-12345678",
			"InstanceInitiatedShutdownBehavior": ShutdownBehavior("invalid"),
		},
		HTTPMethod: "POST",
	}

	for name, engine := range bothEngines(t) {
		result, err := engine.ValidateAWSAPIRequest(request, nil)
		if err != nil {
			t.Fatalf("%s: ValidateAWSAPIRequest failed: %v", name, err)
		}
		if result.OperationKind != cfnvalidate.AWSAPIOperationKindCloudFormationCreate {
			t.Errorf("%s: operationKind = %s, want CLOUD_FORMATION_CREATE", name, result.OperationKind)
		}
		if len(result.ResourceTypes) == 0 || result.ResourceTypes[0] != "AWS::EC2::Instance" {
			t.Errorf("%s: resourceTypes = %v, want [AWS::EC2::Instance]", name, result.ResourceTypes)
		}
		if result.Status != cfnvalidate.AWSAPIRequestValidationStatusValidated {
			t.Errorf("%s: status = %s, want VALIDATED", name, result.Status)
		}
		if result.Report == nil {
			t.Fatalf("%s: report must be present", name)
		}
		hasDiagnostic := false
		for _, d := range result.Report.Diagnostics {
			if strings.Contains(d.Message, "InstanceInitiatedShutdownBehavior") || (d.PropertyPath != nil && strings.Contains(*d.PropertyPath, "InstanceInitiatedShutdownBehavior")) {
				hasDiagnostic = true
				break
			}
		}
		if !hasDiagnostic {
			t.Errorf("%s: expected at least one diagnostic about InstanceInitiatedShutdownBehavior, got %d total diagnostics", name, len(result.Report.Diagnostics))
		}
	}
}

func TestAWSAPIRequestEmptyArrayAndObjectParsed(t *testing.T) {
	// Empty ARRAY must serialize items:[] and empty OBJECT must serialize
	// entries:{} — the Rust parser rejects their absence.
	request := cfnvalidate.AWSAPIRequest{
		ServiceName:   "ec2",
		OperationName: "RunInstances",
		Parameters: map[string]any{
			"ImageId":           "ami-12345678",
			"TagSpecifications": []any{},
			"TagSet":            map[string]any{},
		},
		HTTPMethod: "POST",
	}

	engine := mustEngine(t, cfnvalidate.NewRegoEngine, nil)
	result, err := engine.ValidateAWSAPIRequest(request, nil)
	if err != nil {
		t.Fatalf("ValidateAWSAPIRequest failed with empty array/object parameters: %v", err)
	}
	// The request must not cause a JSON parse failure on the Rust side — it
	// should be accepted and processed (status VALIDATED, not an error).
	if result.Status != cfnvalidate.AWSAPIRequestValidationStatusValidated {
		t.Errorf("status = %s, want VALIDATED", result.Status)
	}
}

func TestAWSAPIRequestUnsupportedValueDoesNotCauseParseFailure(t *testing.T) {
	// Non-finite floating-point values, non-string-key maps, and cyclic
	// indirection are conservatively represented as UNSUPPORTED rather than
	// causing a JSON parse failure or looping in the Go encoder.
	var cyclic any
	cyclic = &cyclic
	request := cfnvalidate.AWSAPIRequest{
		ServiceName:   "ec2",
		OperationName: "RunInstances",
		Parameters: map[string]any{
			"ImageId":   "ami-12345678",
			"BadFloat":  math.Inf(1),
			"BadMapKey": map[int]string{1: "one"},
			"Cyclic":    cyclic,
		},
		HTTPMethod: "POST",
	}

	engine := mustEngine(t, cfnvalidate.NewCelEngine, nil)
	result, err := engine.ValidateAWSAPIRequest(request, nil)
	if err != nil {
		t.Fatalf("ValidateAWSAPIRequest must not fail for unsupported values: %v", err)
	}
	// The request crosses the FFI boundary without a JSON parse error —
	// unsupported values are encoded as {"type":"UNSUPPORTED","type_name":"..."}
	// which the Rust parser accepts.
	if result.Status != cfnvalidate.AWSAPIRequestValidationStatusValidated {
		t.Errorf("status = %s, want VALIDATED (unsupported values are carried, not rejected)", result.Status)
	}
}
