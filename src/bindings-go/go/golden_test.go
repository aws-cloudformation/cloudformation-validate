// Golden-file validation, mirroring the wasm and JVM suites: every template in
// the corpus is validated through both engines at both detail levels, and the
// result must match resources/expected/all_templates.json exactly (up to the
// fields the golden file intentionally excludes). Reports round-trip through
// the typed Go structs before comparison, so this also proves the Go type
// surface is faithful to the serialized report shape.
package cfnvalidate_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	cfnvalidate "github.com/aws-cloudformation/cloudformation-validate/src/bindings-go/go"
)

var goldenDirs = []string{"bad", "cdk", "good", "gh-issues", "integration", "issues", "lsp", "public", "quickstart"}

// Fields present only in detailed reports; stripped from the golden entry when
// comparing standard reports.
var detailedOnlyDiagnosticFields = []string{"documentationUrl", "context", "ruleDescription", "phase", "section"}

var templatesRoot = filepath.Join(workspaceDir, "resources", "templates")

func discoverGoldenTemplates(t *testing.T) []string {
	t.Helper()
	var templates []string
	for _, sub := range goldenDirs {
		root := filepath.Join(templatesRoot, sub)
		if _, err := os.Stat(root); err != nil {
			continue
		}
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			switch filepath.Ext(entry.Name()) {
			case ".yaml", ".yml", ".json":
				rel, relErr := filepath.Rel(templatesRoot, path)
				if relErr != nil {
					return relErr
				}
				templates = append(templates, filepath.ToSlash(rel))
			}
			return nil
		})
		if err != nil {
			t.Fatalf("discovering templates under %s: %v", root, err)
		}
	}
	sort.Strings(templates)
	return templates
}

func loadGolden(t *testing.T) map[string]map[string]any {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(workspaceDir, "resources", "expected", "all_templates.json"))
	if err != nil {
		t.Fatalf("reading golden file: %v", err)
	}
	var golden map[string]map[string]any
	if err := json.Unmarshal(content, &golden); err != nil {
		t.Fatalf("decoding golden file: %v", err)
	}
	return golden
}

// stripGoldenExcludedFields removes the report fields the golden file excludes
// (version, performance, and changing metadata provenance) and normalizes filePath.
func stripGoldenExcludedFields(report map[string]any, filePath string) map[string]any {
	if filePath != "" {
		report["filePath"] = filePath
	}
	delete(report, "version")
	delete(report, "performance")
	if metadata, ok := report["metadata"].(map[string]any); ok {
		delete(metadata, "rulesEvaluated")
		delete(metadata, "cfnLintVersion")
		delete(metadata, "resourceSchemaVersion")
	}
	return report
}

func stripDetailedOnlyFields(report map[string]any) map[string]any {
	diagnostics, ok := report["diagnostics"].([]any)
	if !ok {
		return report
	}
	for _, entry := range diagnostics {
		if d, ok := entry.(map[string]any); ok {
			for _, field := range detailedOnlyDiagnosticFields {
				delete(d, field)
			}
		}
	}
	return report
}

// toComparable round-trips a typed report through JSON into the same generic
// shape as the golden entries.
func toComparable(t *testing.T, report any) map[string]any {
	t.Helper()
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshaling report: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("re-decoding report: %v", err)
	}
	return out
}

func cloneGoldenEntry(t *testing.T, entry map[string]any) map[string]any {
	t.Helper()
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("cloning golden entry: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("cloning golden entry: %v", err)
	}
	return out
}

func diffJSON(t *testing.T, rel string, actual, expected map[string]any) {
	t.Helper()
	if reflect.DeepEqual(actual, expected) {
		return
	}
	actualJSON, _ := json.MarshalIndent(actual, "", " ")
	expectedJSON, _ := json.MarshalIndent(expected, "", " ")
	t.Errorf("%s: report does not match golden\n--- actual ---\n%s\n--- expected ---\n%s", rel, actualJSON, expectedJSON)
}

func TestGoldenFileValidation(t *testing.T) {
	templates := discoverGoldenTemplates(t)
	if len(templates) == 0 {
		t.Fatal("no templates discovered")
	}
	golden := loadGolden(t)
	debugLevel := &cfnvalidate.ValidateConfig{SeverityLevel: cfnvalidate.SeverityDebug}

	for engineName, engine := range bothEngines(t) {
		t.Run(engineName+" detailed matches golden", func(t *testing.T) {
			for _, rel := range templates {
				expected, ok := golden[rel]
				if !ok {
					t.Errorf("%s: missing golden entry", rel)
					continue
				}
				report, err := engine.ValidateDetailedFile(filepath.Join(templatesRoot, rel), debugLevel)
				if err != nil {
					t.Errorf("%s: validation failed: %v", rel, err)
					continue
				}
				actual := stripGoldenExcludedFields(toComparable(t, report), rel)
				want := stripGoldenExcludedFields(cloneGoldenEntry(t, expected), "")
				diffJSON(t, rel, actual, want)
			}
		})

		t.Run(engineName+" standard matches golden", func(t *testing.T) {
			for _, rel := range templates {
				expected, ok := golden[rel]
				if !ok {
					t.Errorf("%s: missing golden entry", rel)
					continue
				}
				report, err := engine.ValidateStandardFile(filepath.Join(templatesRoot, rel), debugLevel)
				if err != nil {
					t.Errorf("%s: validation failed: %v", rel, err)
					continue
				}
				actual := stripGoldenExcludedFields(toComparable(t, report), rel)
				want := stripDetailedOnlyFields(stripGoldenExcludedFields(cloneGoldenEntry(t, expected), ""))
				diffJSON(t, rel, actual, want)
			}
		})
	}
}

func TestPerformanceMetricsPresent(t *testing.T) {
	engine := mustEngine(t, cfnvalidate.NewRegoEngine, nil)
	report, err := engine.ValidateDetailedFile(filepath.Join(templatesRoot, "good", "generic.yaml"), nil)
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}
	phases := map[string]cfnvalidate.PhaseMetric{
		"schemaInit":         report.Performance.SchemaInit,
		"engineInit":         report.Performance.EngineInit,
		"modelBuild":         report.Performance.ModelBuild,
		"schemaValidate":     report.Performance.SchemaValidate,
		"ruleEvaluation":     report.Performance.RuleEvaluation,
		"diagnosticFinalize": report.Performance.DiagnosticFinalize,
		"validateTotal":      report.Performance.ValidateTotal,
	}
	for name, metric := range phases {
		if metric.DurationMs < 0 {
			t.Errorf("performance.%s.durationMs = %v, want >= 0", name, metric.DurationMs)
		}
	}
	if report.Performance.ValidateTotal.DurationMs == 0 {
		t.Error("validateTotal duration must be recorded")
	}
}

func TestEmptyTemplateReportsFatalParseRule(t *testing.T) {
	for name, engine := range bothEngines(t) {
		report, err := engine.ValidateStandardFile(filepath.Join(templatesRoot, "empty.yaml"), nil)
		if err != nil {
			t.Fatalf("%s: validation failed: %v", name, err)
		}
		if report.Status != cfnvalidate.StatusError {
			t.Errorf("%s: status = %s, want ERROR", name, report.Status)
		}
		if len(report.Diagnostics) == 0 || report.Diagnostics[0].RuleID != "F1101" ||
			report.Diagnostics[0].Severity != cfnvalidate.SeverityFatal {
			t.Errorf("%s: first diagnostic must be FATAL F1101, got %+v", name, report.Diagnostics)
		}
	}
}

func TestTemplateModelSections(t *testing.T) {
	minimal, err := os.ReadFile(filepath.Join(templatesRoot, "good", "minimal.yaml"))
	if err != nil {
		t.Fatalf("reading minimal.yaml: %v", err)
	}
	model, err := cfnvalidate.ParseTemplate(minimal)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	defer model.Destroy()
	if v := model.FormatVersion(); v == nil || *v != "2010-09-09" {
		t.Errorf("formatVersion = %v, want 2010-09-09", v)
	}
	resourcesJSON, err := model.Resources()
	if err != nil {
		t.Fatalf("Resources failed: %v", err)
	}
	var resources map[string]any
	if err := json.Unmarshal(resourcesJSON, &resources); err != nil {
		t.Fatalf("decoding resources: %v", err)
	}
	if _, ok := resources["IamPipeline"]; !ok {
		t.Error("minimal.yaml must contain IamPipeline resource")
	}
	if transforms, _ := model.Transforms(); len(transforms) != 0 {
		t.Errorf("transforms = %v, want none", transforms)
	}

	generic, err := os.ReadFile(filepath.Join(templatesRoot, "good", "generic.yaml"))
	if err != nil {
		t.Fatalf("reading generic.yaml: %v", err)
	}
	genericModel, err := cfnvalidate.ParseTemplate(generic)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	defer genericModel.Destroy()
	if d := genericModel.Description(); d == nil || *d != "A sample template" {
		t.Errorf("description = %v, want 'A sample template'", d)
	}
	conditions, err := genericModel.Conditions()
	if err != nil {
		t.Fatalf("Conditions failed: %v", err)
	}
	if !containsString(conditions, "ProdVolumeSize") {
		t.Errorf("conditions = %v, want ProdVolumeSize", conditions)
	}
	outputsJSON, err := genericModel.Outputs()
	if err != nil {
		t.Fatalf("Outputs failed: %v", err)
	}
	var outputs map[string]any
	if err := json.Unmarshal(outputsJSON, &outputs); err != nil {
		t.Fatalf("decoding outputs: %v", err)
	}
	if _, ok := outputs["ElasticIP"]; !ok {
		t.Error("generic.yaml outputs must contain ElasticIP")
	}
	diagnosticJSON, err := genericModel.DiagnosticModel()
	if err != nil {
		t.Fatalf("DiagnosticModel failed: %v", err)
	}
	var diagnostic map[string]any
	if err := json.Unmarshal(diagnosticJSON, &diagnostic); err != nil {
		t.Fatalf("decoding diagnostic model: %v", err)
	}
	for _, section := range []string{"template", "resources"} {
		if _, ok := diagnostic[section]; !ok {
			t.Errorf("diagnostic model must contain %q section", section)
		}
	}

	malformed, err := os.ReadFile(filepath.Join(templatesRoot, "malformed.yaml"))
	if err != nil {
		t.Fatalf("reading malformed.yaml: %v", err)
	}
	if _, err := cfnvalidate.ParseTemplate(malformed); err == nil {
		t.Error("malformed YAML must fail to parse")
	}
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func TestCombinedCustomAndGuardRuleListings(t *testing.T) {
	celConfig := &cfnvalidate.EngineConfig{
		CustomRules: []cfnvalidate.ExternalRuleSource{{Name: "cel_multi_custom.json", Content: loadRule(t, "cel_multi_custom.json")}},
		GuardRules: []cfnvalidate.ExternalRuleSource{
			{Name: "guard_encryption.guard", Content: loadRule(t, "guard_encryption.guard")},
			{Name: "guard_multi.guard", Content: loadRule(t, "guard_multi.guard")},
		},
	}
	regoConfig := &cfnvalidate.EngineConfig{
		CustomRules: []cfnvalidate.ExternalRuleSource{{Name: "rego_multi_custom.rego", Content: loadRule(t, "rego_multi_custom.rego")}},
		GuardRules: []cfnvalidate.ExternalRuleSource{
			{Name: "guard_encryption.guard", Content: loadRule(t, "guard_encryption.guard")},
			{Name: "guard_multi.guard", Content: loadRule(t, "guard_multi.guard")},
		},
	}
	cel := mustEngine(t, cfnvalidate.NewCelEngine, celConfig)
	rego := mustEngine(t, cfnvalidate.NewRegoEngine, regoConfig)

	// Rego discovers custom rule metadata during evaluation.
	if _, err := rego.ValidateStandardFile(filepath.Join(templatesRoot, "bad", "invalid_deletion_policy.yaml"), nil); err != nil {
		t.Fatalf("rego warm-up validation failed: %v", err)
	}

	type expectedRule struct {
		severity    cfnvalidate.Severity
		origin      cfnvalidate.RuleOrigin
		description string
	}
	expected := map[string]expectedRule{
		"CUSTOM010":               {cfnvalidate.SeverityError, cfnvalidate.RuleOriginCustom, "S3 bucket must have versioning enabled"},
		"CUSTOM011":               {cfnvalidate.SeverityWarn, cfnvalidate.RuleOriginCustom, "S3 bucket should have lifecycle rules configured"},
		"check_bucket_encryption": {"", cfnvalidate.RuleOriginGuard, "S3 bucket must have encryption configured"},
		"check_bucket_versioning": {"", cfnvalidate.RuleOriginGuard, "S3 bucket must have versioning enabled"},
		"check_bucket_lifecycle":  {"", cfnvalidate.RuleOriginGuard, "S3 bucket should have lifecycle rules configured"},
	}

	lists := map[string][]cfnvalidate.RuleInfo{}
	for name, engine := range map[string]*cfnvalidate.Engine{"cel": cel, "rego": rego} {
		rules, err := engine.ListRules()
		if err != nil {
			t.Fatalf("%s: ListRules failed: %v", name, err)
		}
		if !sort.SliceIsSorted(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID }) {
			t.Errorf("%s: rules must be sorted by id", name)
		}
		byID := map[string]cfnvalidate.RuleInfo{}
		for _, r := range rules {
			byID[r.ID] = r
		}
		for id, want := range expected {
			rule, ok := byID[id]
			if !ok {
				t.Errorf("%s: rule %s must be listed", name, id)
				continue
			}
			if rule.Origin != want.origin {
				t.Errorf("%s: %s origin = %s, want %s", name, id, rule.Origin, want.origin)
			}
			if rule.Description != want.description {
				t.Errorf("%s: %s description = %q, want %q", name, id, rule.Description, want.description)
			}
			if want.severity != "" && rule.Severity != want.severity {
				t.Errorf("%s: %s severity = %s, want %s", name, id, rule.Severity, want.severity)
			}
		}
		lists[name] = rules
	}

	celJSON, _ := json.Marshal(lists["cel"])
	regoJSON, _ := json.Marshal(lists["rego"])
	if !strings.EqualFold(string(celJSON), string(regoJSON)) {
		t.Error("CEL and Rego must list identical rules with custom + guard sources")
	}
}
