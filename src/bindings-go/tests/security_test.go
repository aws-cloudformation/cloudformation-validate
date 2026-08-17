package cfnvalidate_test

import (
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	cfnvalidate "github.com/aws-cloudformation/cloudformation-validate/src/bindings-go/go"
)

func discoverSecurityTemplates(t *testing.T) []string {
	t.Helper()
	securityRoot := filepath.Join(workspaceDir, "resources", "security")
	templates := []string{}
	err := filepath.WalkDir(securityRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(entry.Name())) {
		case ".json", ".yaml", ".yml":
			templates = append(templates, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("discovering security templates: %v", err)
	}
	sort.Strings(templates)
	if len(templates) == 0 {
		t.Fatalf("no security templates found under %s", securityRoot)
	}
	return templates
}

func TestEverySecurityTemplateWithBothEngines(t *testing.T) {
	templates := discoverSecurityTemplates(t)
	debugConfig := &cfnvalidate.ValidateConfig{SeverityLevel: cfnvalidate.SeverityDebug}
	const securityTimeout = 60 * time.Second

	for _, engineName := range []string{"rego", "cel"} {
		for _, templatePath := range templates {
			relativePath := filepath.Base(templatePath)
			t.Run(engineName+"/"+relativePath, func(t *testing.T) {
				type outcome struct {
					report *cfnvalidate.DetailedReport
					err    error
				}
				completed := make(chan outcome, 1)
				go func() {
					var engine *cfnvalidate.Engine
					var buildErr error
					if engineName == "rego" {
						engine, buildErr = cfnvalidate.NewRegoEngine(nil)
					} else {
						engine, buildErr = cfnvalidate.NewCelEngine(nil)
					}
					if buildErr != nil {
						completed <- outcome{err: buildErr}
						return
					}
					defer engine.Destroy()
					report, validationErr := engine.ValidateDetailedFile(templatePath, debugConfig)
					completed <- outcome{report: report, err: validationErr}
				}()

				select {
				case validation := <-completed:
					if validation.err != nil {
						if relativePath == "deep_nesting.json" {
							if validation.err.Error() == "" {
								t.Fatal("deep nesting must return a structured error")
							}
							return
						}
						t.Fatalf("detailed validation failed: %v", validation.err)
					}
					if validation.report == nil {
						t.Fatal("detailed validation returned no report")
					}
					if relativePath == "scenario_assignment_budget.yaml" {
						if validation.report.Status != cfnvalidate.StatusAnalysisIncomplete {
							t.Errorf("status = %s, want ANALYSIS_INCOMPLETE", validation.report.Status)
						}
						if len(validation.report.Metadata.BudgetExhaustions) == 0 {
							t.Error("exhausted budget metadata is absent")
						} else if !strings.HasSuffix(validation.report.Metadata.BudgetExhaustions[0].Description, ".") {
							t.Error("budget description is not a sentence")
						}
					}
					if relativePath == "condition_fusion.yaml" && validation.report.Metadata.BudgetExhaustions != nil {
						t.Error("non-exhausted budget metadata must be nil")
					}
				case <-time.After(securityTimeout):
					t.Fatalf("exceeded the hard %s limit", securityTimeout)
				}
			})
		}
	}
}
