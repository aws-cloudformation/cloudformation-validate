// Smoke tests for the Go bindings.
//
// Runs against the module assembled by ../build.sh (generated internal
// package + staged static library), exercising the public API end to end:
// engine construction, validation reports, engine parity, the template model,
// the schema validator, custom rules, and error handling.
package cfnvalidate_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

func mustCompositeEngine(t *testing.T, config *cfnvalidate.CompositeEngineConfig) *cfnvalidate.Engine {
	t.Helper()
	engine, err := cfnvalidate.NewCompositeEngine(config)
	if err != nil {
		t.Fatalf("composite engine construction failed: %v", err)
	}
	t.Cleanup(engine.Destroy)
	return engine
}

func allEngines(t *testing.T) map[string]*cfnvalidate.Engine {
	t.Helper()
	return map[string]*cfnvalidate.Engine{
		"rego":      mustEngine(t, cfnvalidate.NewRegoEngine, nil),
		"cel":       mustEngine(t, cfnvalidate.NewCelEngine, nil),
		"composite": mustCompositeEngine(t, nil),
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

func diagnosticKeys(report *cfnvalidate.ValidationReport) []string {
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

func TestVersionMatchesExpectedVersionFixture(t *testing.T) {
	expectedVersionPath := filepath.Join(workspaceDir, "resources", "expected", "version.txt")
	content, err := os.ReadFile(expectedVersionPath)
	if err != nil {
		t.Fatalf("reading expected version fixture: %v", err)
	}
	expectedVersion := strings.TrimSpace(string(content))
	if expectedVersion == "" {
		t.Fatalf("%s must not be empty", expectedVersionPath)
	}
	if got, want := cfnvalidate.Version(), expectedVersion; got != want {
		t.Errorf("Version() = %q, want %q", got, want)
	}
}

func TestPackageVersionReportsLocalReplacementAsDevelopment(t *testing.T) {
	if got, want := cfnvalidate.PackageVersion(), "(devel)"; got != want {
		t.Errorf("PackageVersion() = %q, want %q", got, want)
	}
}

func TestEngineNames(t *testing.T) {
	for want, engine := range allEngines(t) {
		if got := engine.EngineName(); got != want {
			t.Errorf("EngineName() = %q, want %q", got, want)
		}
	}
}

func TestListRulesSortedAndIdenticalAcrossEngines(t *testing.T) {
	encoded := map[string]string{}
	for name, engine := range allEngines(t) {
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
		rulesJSON, err := json.Marshal(rules)
		if err != nil {
			t.Fatalf("%s: marshaling rules: %v", name, err)
		}
		encoded[name] = string(rulesJSON)
	}
	reference := encoded["rego"]
	for name, rulesJSON := range encoded {
		if rulesJSON != reference {
			t.Errorf("%s must list rules identical to rego", name)
		}
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

func TestGoodTemplatePassesAllEngines(t *testing.T) {
	for name, engine := range allEngines(t) {
		report, err := engine.ValidateTemplateFile(goodTemplate, nil)
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

func TestAdditionalSchemasApplyThroughTheTypedConfigOnAllEngines(t *testing.T) {
	schemaConfig := &cfnvalidate.SchemaValidatorConfig{
		AdditionalSchemas: []cfnvalidate.AdditionalSchemaSource{{Schema: lambdaOverlaySchema}},
	}
	// The composite engine takes a CompositeEngineConfig rather than an
	// EngineConfig, so each engine supplies its own baseline (no overlay) and
	// overlay (schema config applied) builders.
	builders := map[string]func() (baseline, overlay *cfnvalidate.Engine){
		"rego": func() (*cfnvalidate.Engine, *cfnvalidate.Engine) {
			return mustEngine(t, cfnvalidate.NewRegoEngine, nil),
				mustEngine(t, cfnvalidate.NewRegoEngine, &cfnvalidate.EngineConfig{SchemaValidatorConfig: schemaConfig})
		},
		"cel": func() (*cfnvalidate.Engine, *cfnvalidate.Engine) {
			return mustEngine(t, cfnvalidate.NewCelEngine, nil),
				mustEngine(t, cfnvalidate.NewCelEngine, &cfnvalidate.EngineConfig{SchemaValidatorConfig: schemaConfig})
		},
		"composite": func() (*cfnvalidate.Engine, *cfnvalidate.Engine) {
			return mustCompositeEngine(t, nil),
				mustCompositeEngine(t, &cfnvalidate.CompositeEngineConfig{SchemaValidatorConfig: schemaConfig})
		},
	}
	for name, build := range builders {
		baseline, overlay := build()
		baselineReport, err := baseline.ValidateTemplate([]byte(templateWithOverlayProperty), nil, "overlay.yaml")
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

		report, err := overlay.ValidateTemplate([]byte(templateWithOverlayProperty), nil, "overlay.yaml")
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
	report, err := engine.ValidateTemplate([]byte(unencryptedBucket), nil, "")
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
	// Every engine must produce the same built-in diagnostics for the same
	// template: rego and cel are the two independent built-in implementations,
	// and composite reuses the cel built-ins with no external rules layered on.
	engines := allEngines(t)
	reports := map[string][]string{}
	for name, engine := range engines {
		report, err := engine.ValidateTemplate([]byte(unencryptedBucket), nil, "")
		if err != nil {
			t.Fatalf("%s: validation failed: %v", name, err)
		}
		reports[name] = diagnosticKeys(report)
	}
	if len(reports["rego"]) == 0 {
		t.Fatal("the unencrypted bucket must produce built-in diagnostics")
	}
	for name, keys := range reports {
		if got, want := keys, reports["rego"]; !equalStrings(got, want) {
			t.Errorf("engines disagree:\nrego: %v\n%s: %v", want, name, got)
		}
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
	report, err := engine.ValidateTemplate([]byte(unencryptedBucket), config, "")
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
	report, err := engine.ValidateTemplate([]byte(unencryptedBucket), config, "")
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
	report, err := engine.ValidateTemplate([]byte(unencryptedBucket), nil, "")
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}
	counts := report.Metadata.Counts
	total := counts.Fatal + counts.Errors + counts.Warnings + counts.Informational + counts.Debug
	if len(report.Diagnostics) != total {
		t.Errorf("diagnostics = %d, counts total = %d", len(report.Diagnostics), total)
	}
}

// TestDefaultDetailLevelIsDetailed proves that leaving DetailLevel unset yields
// the DETAILED default: enrichment the native layer attaches only at DETAILED
// is present with a nil config and absent when STANDARD is requested.
func TestDefaultDetailLevelIsDetailed(t *testing.T) {
	engine := mustEngine(t, cfnvalidate.NewRegoEngine, nil)

	defaulted, err := engine.ValidateTemplate([]byte(unencryptedBucket), nil, "")
	if err != nil {
		t.Fatalf("default validation failed: %v", err)
	}
	standard, err := engine.ValidateTemplate(
		[]byte(unencryptedBucket),
		&cfnvalidate.ValidateConfig{DetailLevel: cfnvalidate.DetailLevelStandard},
		"",
	)
	if err != nil {
		t.Fatalf("standard validation failed: %v", err)
	}

	if !hasDetailedEnrichment(defaulted) {
		t.Error("an omitted DetailLevel must default to DETAILED enrichment")
	}
	if hasDetailedEnrichment(standard) {
		t.Error("STANDARD detail level must leave the enrichment fields nil")
	}
}

func hasDetailedEnrichment(report *cfnvalidate.ValidationReport) bool {
	for _, d := range report.Diagnostics {
		if d.RuleDescription != nil || d.DocumentationURL != nil || d.Phase != nil || d.Context != nil {
			return true
		}
	}
	return false
}

func TestCustomRulesFire(t *testing.T) {
	// Each case builds an engine whose only custom rule is CUSTOM001 in the
	// dialect that engine accepts. The composite accepts both dialects, so it is
	// exercised once per dialect.
	rule := func(name string) []cfnvalidate.ExternalRuleSource {
		return []cfnvalidate.ExternalRuleSource{{Name: name, Content: loadRule(t, name)}}
	}
	cases := map[string]func() *cfnvalidate.Engine{
		"cel custom": func() *cfnvalidate.Engine {
			return mustEngine(t, cfnvalidate.NewCelEngine, &cfnvalidate.EngineConfig{CustomRules: rule("cel_custom.json")})
		},
		"rego custom": func() *cfnvalidate.Engine {
			return mustEngine(t, cfnvalidate.NewRegoEngine, &cfnvalidate.EngineConfig{CustomRules: rule("rego_custom.rego")})
		},
		"composite cel custom": func() *cfnvalidate.Engine {
			return mustCompositeEngine(t, &cfnvalidate.CompositeEngineConfig{CelRules: rule("cel_custom.json")})
		},
		"composite rego custom": func() *cfnvalidate.Engine {
			return mustCompositeEngine(t, &cfnvalidate.CompositeEngineConfig{RegoRules: rule("rego_custom.rego")})
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			engine := build()
			report, err := engine.ValidateTemplate([]byte(unencryptedBucket), nil, "")
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

func TestGuardRulesFireOnAllEngines(t *testing.T) {
	guard := cfnvalidate.ExternalRuleSource{Name: "guard_encryption.guard", Content: loadRule(t, "guard_encryption.guard")}
	engines := map[string]*cfnvalidate.Engine{
		"rego":      mustEngine(t, cfnvalidate.NewRegoEngine, &cfnvalidate.EngineConfig{GuardRules: []cfnvalidate.ExternalRuleSource{guard}}),
		"cel":       mustEngine(t, cfnvalidate.NewCelEngine, &cfnvalidate.EngineConfig{GuardRules: []cfnvalidate.ExternalRuleSource{guard}}),
		"composite": mustCompositeEngine(t, &cfnvalidate.CompositeEngineConfig{GuardRules: []cfnvalidate.ExternalRuleSource{guard}}),
	}
	for name, engine := range engines {
		report, err := engine.ValidateTemplate([]byte(unencryptedBucket), nil, "")
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

func TestCompositeDefaultMatchesCelBuiltins(t *testing.T) {
	composite, err := cfnvalidate.NewCompositeEngine(nil)
	if err != nil {
		t.Fatalf("composite engine construction failed: %v", err)
	}
	t.Cleanup(composite.Destroy)

	if got, want := composite.EngineName(), "composite"; got != want {
		t.Errorf("EngineName() = %q, want %q", got, want)
	}

	compositeReport, err := composite.ValidateTemplate([]byte(unencryptedBucket), nil, "")
	if err != nil {
		t.Fatalf("composite validation failed: %v", err)
	}

	cel := mustEngine(t, cfnvalidate.NewCelEngine, nil)
	celReport, err := cel.ValidateTemplate([]byte(unencryptedBucket), nil, "")
	if err != nil {
		t.Fatalf("cel validation failed: %v", err)
	}
	if len(celReport.Diagnostics) == 0 {
		t.Fatal("the unencrypted bucket must produce built-in diagnostics")
	}

	if got, want := diagnosticKeys(compositeReport), diagnosticKeys(celReport); !equalStrings(got, want) {
		t.Errorf("composite default diagnostics must match the CEL engine's built-ins\ncomposite: %v\ncel:       %v", got, want)
	}
}

func TestCompositeWithCustomRegoAddsFindingToBuiltins(t *testing.T) {
	config := &cfnvalidate.CompositeEngineConfig{
		RegoRules: []cfnvalidate.ExternalRuleSource{
			{Name: "rego_custom.rego", Content: loadRule(t, "rego_custom.rego")},
		},
	}
	composite, err := cfnvalidate.NewCompositeEngine(config)
	if err != nil {
		t.Fatalf("composite engine construction with a custom Rego rule failed: %v", err)
	}
	t.Cleanup(composite.Destroy)

	report, err := composite.ValidateTemplate([]byte(unencryptedBucket), nil, "")
	if err != nil {
		t.Fatalf("composite validation failed: %v", err)
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

	// The custom finding layers on top of the built-ins: every built-in
	// diagnostic from a standalone CEL run must still be present.
	cel := mustEngine(t, cfnvalidate.NewCelEngine, nil)
	celReport, err := cel.ValidateTemplate([]byte(unencryptedBucket), nil, "")
	if err != nil {
		t.Fatalf("cel validation failed: %v", err)
	}
	compositeKeys := diagnosticKeys(report)
	for _, builtin := range diagnosticKeys(celReport) {
		if !containsString(compositeKeys, builtin) {
			t.Errorf("composite must retain built-in diagnostic %q", builtin)
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
	report, err := engine.ValidateTemplate([]byte("not: a: valid: yaml: ["), nil, "")
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

func synthesizedBucketName(t *testing.T, template []byte) string {
	t.Helper()
	if template == nil {
		t.Fatal("a validated request must carry the synthesized template bytes")
	}
	var document struct {
		Resources struct {
			Resource struct {
				Type       string `json:"Type"`
				Properties struct {
					BucketName string `json:"BucketName"`
				} `json:"Properties"`
			} `json:"Resource"`
		} `json:"Resources"`
	}
	if err := json.Unmarshal(template, &document); err != nil {
		t.Fatalf("decoding synthesized template JSON: %v", err)
	}
	if document.Resources.Resource.Type != "AWS::S3::Bucket" {
		t.Errorf("synthesized resource type = %q, want AWS::S3::Bucket", document.Resources.Resource.Type)
	}
	return document.Resources.Resource.Properties.BucketName
}

func TestValidateAWSCLICommandSynthesizesS3CreateBucketOnAllEngines(t *testing.T) {
	const bucketName = "synthetic-bucket"
	request := cfnvalidate.AWSCLICommand{
		ServiceName:   "s3",
		OperationName: "CreateBucket",
		Parameters:    map[string]any{"Bucket": bucketName},
	}

	perEngine := map[string]*cfnvalidate.AWSCLICommandValidation{}
	for name, engine := range allEngines(t) {
		validation, err := engine.ValidateAWSCLICommand(request, nil)
		if err != nil {
			t.Fatalf("%s: ValidateAWSCLICommand failed: %v", name, err)
		}
		if validation.Status != cfnvalidate.AWSCLICommandValidationStatusValidated {
			t.Errorf("%s: status = %s, want VALIDATED", name, validation.Status)
		}
		if validation.OperationKind != cfnvalidate.AWSCLIOperationKindCloudFormationCreate {
			t.Errorf("%s: operationKind = %s, want CLOUD_FORMATION_CREATE", name, validation.OperationKind)
		}
		if len(validation.ResourceTypes) != 1 || validation.ResourceTypes[0] != "AWS::S3::Bucket" {
			t.Errorf("%s: resourceTypes = %v, want [AWS::S3::Bucket]", name, validation.ResourceTypes)
		}
		if validation.TemplateSource == nil || *validation.TemplateSource != cfnvalidate.AWSCLITemplateSourceSynthesizedCreate {
			t.Errorf("%s: templateSource = %v, want SYNTHESIZED_CREATE", name, validation.TemplateSource)
		}
		if validation.Report == nil {
			t.Fatalf("%s: report must be present for a validated request", name)
		}
		if bucket := synthesizedBucketName(t, validation.Template); bucket != bucketName {
			t.Errorf("%s: synthesized BucketName = %q, want %q", name, bucket, bucketName)
		}
		perEngine[name] = validation
	}

	// Every engine must model the request identically; performance timings are
	// intentionally excluded from the comparison.
	rego := perEngine["rego"]
	for name, other := range perEngine {
		if name == "rego" {
			continue
		}
		if !bytes.Equal(rego.Template, other.Template) {
			t.Errorf("engines synthesized different templates:\nrego: %s\n%s: %s", rego.Template, name, other.Template)
		}
		if !equalStrings(diagnosticKeys(rego.Report), diagnosticKeys(other.Report)) {
			t.Errorf("engines disagree on diagnostics:\nrego: %v\n%s: %v", diagnosticKeys(rego.Report), name, diagnosticKeys(other.Report))
		}
	}
}

func TestValidateAWSCLICommandPreservesExactTemplateBodyBytes(t *testing.T) {
	// Distinctive whitespace and key order that a reserialization would not
	// reproduce, so an exact match proves the original bytes are returned.
	templateBody := []byte("{\n    \"Resources\": {\n        \"Bucket\": { \"Type\": \"AWS::S3::Bucket\" }\n    }\n}")
	request := cfnvalidate.AWSCLICommand{
		ServiceName:   "cloudformation",
		OperationName: "ValidateTemplate",
		Parameters:    map[string]any{"TemplateBody": templateBody},
	}

	for name, engine := range allEngines(t) {
		validation, err := engine.ValidateAWSCLICommand(request, nil)
		if err != nil {
			t.Fatalf("%s: ValidateAWSCLICommand failed: %v", name, err)
		}
		if validation.Status != cfnvalidate.AWSCLICommandValidationStatusValidated {
			t.Errorf("%s: status = %s, want VALIDATED", name, validation.Status)
		}
		if validation.TemplateSource == nil || *validation.TemplateSource != cfnvalidate.AWSCLITemplateSourceTemplateBody {
			t.Errorf("%s: templateSource = %v, want TEMPLATE_BODY", name, validation.TemplateSource)
		}
		if !bytes.Equal(validation.Template, templateBody) {
			t.Errorf("%s: returned template = %q, want exact request bytes %q", name, validation.Template, templateBody)
		}
	}
}

func TestValidateAWSCLICommandConservativelySkipsNestedDynamoDbFields(t *testing.T) {
	request := cfnvalidate.AWSCLICommand{
		ServiceName:   "dynamodb",
		OperationName: "CreateTable",
		Parameters: map[string]any{
			"TableName":            "Synthetic",
			"KeySchema":            []any{map[string]any{"AttributeName": "id", "KeyType": "HASH"}},
			"AttributeDefinitions": []any{map[string]any{"AttributeName": "id", "AttributeType": "S"}},
			"BillingMode":          "PAY_PER_REQUEST",
		},
	}

	for name, engine := range allEngines(t) {
		validation, err := engine.ValidateAWSCLICommand(request, nil)
		if err != nil {
			t.Fatalf("%s: ValidateAWSCLICommand failed: %v", name, err)
		}
		if validation.Status != cfnvalidate.AWSCLICommandValidationStatusSkipped {
			t.Errorf("%s: status = %s, want SKIPPED for unrepresentable nested fields", name, validation.Status)
		}
		if validation.Report != nil {
			t.Errorf("%s: a skipped request must have no report", name)
		}
		if validation.Template != nil {
			t.Errorf("%s: a skipped request must have a nil template, got %q", name, validation.Template)
		}
		if len(validation.ResourceTypes) != 1 || validation.ResourceTypes[0] != "AWS::DynamoDB::Table" {
			t.Errorf("%s: resourceTypes = %v, want the type still identified as [AWS::DynamoDB::Table]", name, validation.ResourceTypes)
		}
		if !strings.Contains(validation.Reason, "has no mapping") {
			t.Errorf("%s: reason must explain the unmapped nested parameter, got %q", name, validation.Reason)
		}
	}
}

func TestValidateAWSCLICommandDoesNotGuessNoncanonicalServiceAlias(t *testing.T) {
	// CloudWatch's canonical botocore service name is "cloudwatch"; "monitoring"
	// is its signing name. The core must resolve the operation under the
	// canonical name but never guess the signing alias.
	canonical := cfnvalidate.AWSCLICommand{
		ServiceName:   "cloudwatch",
		OperationName: "PutMetricAlarm",
		Parameters:    map[string]any{"AlarmName": "synthetic"},
	}
	alias := cfnvalidate.AWSCLICommand{
		ServiceName:   "monitoring",
		OperationName: "PutMetricAlarm",
		Parameters:    map[string]any{"AlarmName": "synthetic"},
	}

	for name, engine := range allEngines(t) {
		canonicalValidation, err := engine.ValidateAWSCLICommand(canonical, nil)
		if err != nil {
			t.Fatalf("%s: canonical ValidateAWSCLICommand failed: %v", name, err)
		}
		if !containsString(canonicalValidation.ResourceTypes, "AWS::CloudWatch::Alarm") {
			t.Errorf("%s: canonical cloudwatch:PutMetricAlarm must identify AWS::CloudWatch::Alarm, got %v",
				name, canonicalValidation.ResourceTypes)
		}

		aliasValidation, err := engine.ValidateAWSCLICommand(alias, nil)
		if err != nil {
			t.Fatalf("%s: alias ValidateAWSCLICommand failed: %v", name, err)
		}
		if aliasValidation.Status != cfnvalidate.AWSCLICommandValidationStatusSkipped {
			t.Errorf("%s: signing alias must not classify as a CloudFormation operation, status = %s", name, aliasValidation.Status)
		}
		if containsString(aliasValidation.ResourceTypes, "AWS::CloudWatch::Alarm") {
			t.Errorf("%s: signing alias 'monitoring' must not resolve to AWS::CloudWatch::Alarm, got %v",
				name, aliasValidation.ResourceTypes)
		}
		if aliasValidation.Template != nil {
			t.Errorf("%s: an unresolved alias must not synthesize a template", name)
		}
	}
}
