// Command bench runs a benchmark of the Go bindings against a corpus of
// CloudFormation templates, producing aggregate and per-template JSON reports
// that match the contract of the native, WASM, JVM, Python, and Go harnesses.
//
// Usage:
//
//	go run . [TEMPLATE|DIR] --engine rego|cel --iterations N
//
// The default corpus is src/resources/templates (relative to the workspace
// root). Reports are written to src/bindings-go/reports/{engine}/.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	cfnvalidate "github.com/aws-cloudformation/cloudformation-validate/src/bindings-go/go"
)

const (
	bindingName     = "go"
	detailLevelName = "DETAILED"

	// The Go engine constructor embeds its own schema validator, so consumer init scope is the engine alone.
	consumerInitScopeEngine = "engine"

	defaultStartupTemplate = "good/minimal.yaml"

	goBindingModulePath = "github.com/aws-cloudformation/cloudformation-validate/src/bindings-go/go"

	cargoVersionEnv = "BENCHMARK_CARGO_VERSION"
	rustcVersionEnv = "BENCHMARK_RUSTC_VERSION"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		if isUsageError(err) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}

func run() error {
	args := os.Args[1:]
	if hasFlag(args, "-h") || hasFlag(args, "--help") {
		fmt.Fprintln(os.Stderr, "Usage: bench [TEMPLATE|DIR] --engine rego|cel --iterations N [--startup-probe]")
		return usageError("help requested")
	}

	if err := validateFlags(args); err != nil {
		return err
	}

	engineFlag, err := requiredFlagValue(args, "--engine", "rego")
	if err != nil {
		return err
	}
	if engineFlag != "rego" && engineFlag != "cel" {
		return usageError(fmt.Sprintf("--engine must be 'rego' or 'cel', got %q", engineFlag))
	}

	iterations, err := parseIterations(args)
	if err != nil {
		return err
	}

	validateConfig := &cfnvalidate.ValidateConfig{
		SeverityLevel: cfnvalidate.SeverityDebug,
	}

	if hasFlag(args, "--startup-probe") {
		return runStartupProbe(engineFlag, validateConfig)
	}

	return runBenchmark(engineFlag, iterations, validateConfig, positionalArg(args))
}

func runStartupProbe(engineFlag string, validateConfig *cfnvalidate.ValidateConfig) error {
	defaultCorpus, err := resolveDefaultCorpus()
	if err != nil {
		return fmt.Errorf("resolving default corpus: %w", err)
	}
	startupPath := filepath.Join(defaultCorpus, defaultStartupTemplate)

	startupBytes, err := os.ReadFile(startupPath)
	if err != nil {
		return fmt.Errorf("reading startup template %q: %w", startupPath, err)
	}
	startupLabel := filepath.Base(startupPath)

	engine, startup, err := measureStartup(engineFlag, startupBytes, startupLabel, validateConfig)
	if err != nil {
		return err
	}
	defer engine.Destroy()

	probe := startupProbeJSON(startup, engine.EngineName())
	serialized, err := json.Marshal(probe)
	if err != nil {
		return fmt.Errorf("serializing startup probe: %w", err)
	}
	fmt.Println(string(serialized))
	return nil
}

func runBenchmark(engineFlag string, iterations int, validateConfig *cfnvalidate.ValidateConfig, positional string) error {
	defaultTemplateDir, err := resolveDefaultCorpus()
	if err != nil {
		return fmt.Errorf("resolving default corpus: %w", err)
	}
	templateDir := positional
	if templateDir == "" {
		templateDir = defaultTemplateDir
	}

	templates, err := collectFiles(templateDir)
	if err != nil {
		return fmt.Errorf("collecting templates: %w", err)
	}
	if len(templates) == 0 {
		return fmt.Errorf("no templates found in %s", templateDir)
	}
	fmt.Fprintf(os.Stderr, "Benchmarking %d templates, %d iterations, engine=%s, format=DETAILED\n",
		len(templates), iterations, engineFlag)

	// Go is statically linked - there is no dynamic module load.
	const moduleLoadMs = 0.0

	startupLabel := filepath.ToSlash(relativePath(templateDir, templates[0]))
	startupBytes, err := os.ReadFile(templates[0])
	if err != nil {
		return fmt.Errorf("reading startup template %q: %w", templates[0], err)
	}
	engine, startup, err := measureStartup(engineFlag, startupBytes, startupLabel, validateConfig)
	if err != nil {
		return err
	}
	defer engine.Destroy()

	engineInitSamples := []float64{startup.EngineInitMs}
	initSamples := []float64{startup.EngineInitMs}
	coldInitMs := moduleLoadMs + initSamples[0]
	subsequentInitSamples := []float64{}
	schemaInitSamples := []float64{}

	reportDir, err := resolveReportDir(engineFlag)
	if err != nil {
		return fmt.Errorf("resolving report dir: %w", err)
	}
	jsonDir := filepath.Join(reportDir, "json_detailed")
	if err := os.RemoveAll(jsonDir); err != nil {
		return fmt.Errorf("failed to remove %s: %w", jsonDir, err)
	}
	if err := os.MkdirAll(jsonDir, 0o755); err != nil {
		return fmt.Errorf("failed to create %s: %w", jsonDir, err)
	}

	var results []templateResult

	benchStart := time.Now()

	for _, tplPath := range templates {
		rel := filepath.ToSlash(relativePath(templateDir, tplPath))
		fmt.Fprintf(os.Stderr, "  %s", rel)

		bytes, readErr := os.ReadFile(tplPath)
		if readErr != nil {
			results = append(results, errorResult(rel, "read_error", readErr.Error()))
			fmt.Fprintln(os.Stderr)
			continue
		}
		sizeBytes := len(bytes)
		jsonPath := filepath.Join(jsonDir, toJSONStem(rel)+".json")

		iterModelBuild := make([]float64, 0, iterations)
		iterSchemaValidate := make([]float64, 0, iterations)
		iterRuleEval := make([]float64, 0, iterations)
		iterFinalize := make([]float64, 0, iterations)
		iterHostModel := make([]float64, 0, iterations)
		iterEngineInternal := make([]float64, 0, iterations)
		iterHostValidate := make([]float64, 0, iterations)
		var lastReport *cfnvalidate.DetailedReport
		failed := false

		for i := 0; i < iterations; i++ {
			tm0 := time.Now()
			parsed, parseErr := cfnvalidate.ParseTemplate(bytes)
			hostModelMs := elapsed(tm0)
			if parseErr != nil {
				parseFailureReport, reportErr := engine.ValidateDetailed(bytes, validateConfig, rel)
				if reportErr != nil {
					return fmt.Errorf("creating parse-failure report for %s: %w", rel, reportErr)
				}
				normalizeParseFailureReport(parseFailureReport)
				payload, marshalErr := buildPerTemplatePayload(parseFailureReport, rel, engineFlag, zeroBenchmarkMetrics())
				if marshalErr != nil {
					return fmt.Errorf("marshaling parse-failure payload for %s: %w", rel, marshalErr)
				}
				if writeErr := writePerTemplateReport(jsonPath, payload); writeErr != nil {
					return writeErr
				}
				results = append(results, errorResult(rel, "parse_error", parseErr.Error()))
				failed = true
				break
			}
			parsed.Destroy()
			iterHostModel = append(iterHostModel, hostModelMs)

			t0 := time.Now()
			report, valErr := engine.ValidateDetailed(bytes, validateConfig, rel)
			hostValidateMs := elapsed(t0)
			if valErr != nil {
				results = append(results, errorResult(rel, "error", valErr.Error()))
				failed = true
				break
			}
			perf := report.Performance
			iterModelBuild = append(iterModelBuild, perf.ModelBuild.DurationMs)
			iterSchemaValidate = append(iterSchemaValidate, perf.SchemaValidate.DurationMs)
			iterRuleEval = append(iterRuleEval, perf.RuleEvaluation.DurationMs)
			iterFinalize = append(iterFinalize, perf.DiagnosticFinalize.DurationMs)
			iterEngineInternal = append(iterEngineInternal, perf.ValidateTotal.DurationMs)
			iterHostValidate = append(iterHostValidate, hostValidateMs)

			if i == iterations-1 {
				lastReport = report
			}
		}
		if failed {
			fmt.Fprintln(os.Stderr)
			continue
		}
		if lastReport == nil {
			return fmt.Errorf("no validation report produced for %s after %d iterations", rel, iterations)
		}
		report := lastReport

		// Binding overhead: median of per-call (wall - engine) differences.
		perCallDiffs := make([]float64, len(iterHostValidate))
		for i := range iterHostValidate {
			perCallDiffs[i] = iterHostValidate[i] - iterEngineInternal[i]
		}
		bindingOverheadMs := round4(medianOf(perCallDiffs))

		benchmarkMetrics := perTemplateMetricsJSON(iterations, iterHostModel, iterModelBuild,
			iterSchemaValidate, iterRuleEval, iterFinalize, iterEngineInternal, iterHostValidate, bindingOverheadMs)

		payload, marshalErr := buildPerTemplatePayload(report, rel, engineFlag, benchmarkMetrics)
		if marshalErr != nil {
			return fmt.Errorf("marshaling per-template payload for %s: %w", rel, marshalErr)
		}
		if writeErr := writePerTemplateReport(jsonPath, payload); writeErr != nil {
			return writeErr
		}

		tr := templateResult{
			File:                          rel,
			Status:                        "ok",
			SizeBytes:                     sizeBytes,
			Resources:                     report.Metadata.ResourcesScanned,
			Fatal:                         report.Metadata.Counts.Fatal,
			Errors:                        report.Metadata.Counts.Errors,
			Warnings:                      report.Metadata.Counts.Warnings,
			Informational:                 report.Metadata.Counts.Informational,
			DiagCount:                     len(report.Diagnostics),
			HostModelMs:                   medianOf(iterHostModel),
			FirstMeasuredHostModelMs:      iterHostModel[0],
			SubsequentHostModelMs:         subsequentMedianPtr(iterHostModel),
			ModelBuildMs:                  medianOf(iterModelBuild),
			SchemaValidateMs:              medianOf(iterSchemaValidate),
			RuleEvalMs:                    medianOf(iterRuleEval),
			DiagnosticFinalizeMs:          medianOf(iterFinalize),
			EngineInternalMs:              medianOf(iterEngineInternal),
			FirstMeasuredEngineInternalMs: iterEngineInternal[0],
			SubsequentEngineInternalMs:    subsequentMedianPtr(iterEngineInternal),
			WallClockMs:                   medianOf(iterHostValidate),
			FirstMeasuredWallClockMs:      iterHostValidate[0],
			SubsequentWallClockMs:         subsequentMedianPtr(iterHostValidate),
			BindingOverheadMs:             bindingOverheadMs,
			HostValidateTotal:             sum(iterHostValidate),
		}
		fmt.Fprintf(os.Stderr, "  model=%.4fms  engine=%.4fms  wall=%.4fms  %dE %dW %dI\n",
			tr.HostModelMs, tr.EngineInternalMs, tr.WallClockMs,
			tr.Errors, tr.Warnings, tr.Informational)
		results = append(results, tr)
	}

	totalWallMs := elapsed(benchStart)

	var ok []templateResult
	var failures []templateResult
	for _, r := range results {
		if r.Status == "ok" {
			ok = append(ok, r)
		} else {
			failures = append(failures, r)
		}
	}

	var measuredValidationWallMs float64
	for _, r := range ok {
		measuredValidationWallMs += r.HostValidateTotal
	}
	throughputPerSec := 0.0
	if measuredValidationWallMs > 0 {
		throughputPerSec = float64(len(ok)*iterations) / (measuredValidationWallMs / 1000.0)
	}

	corpusFingerprint, corpusFileCount, fpErr := computeCorpusFingerprint(templateDir)
	if fpErr != nil {
		return fmt.Errorf("computing corpus fingerprint: %w", fpErr)
	}
	runFingerprint := computeRunFingerprint(corpusFingerprint, engineFlag, detailLevelName, iterations)

	provenance := provenanceJSON()

	performance := buildPerformanceBlock(performanceInput{
		ok:                       ok,
		startup:                  startup,
		moduleLoadMs:             moduleLoadMs,
		initSamples:              initSamples,
		coldInitMs:               coldInitMs,
		subsequentInitSamples:    subsequentInitSamples,
		schemaInitSamples:        schemaInitSamples,
		engineInitSamples:        engineInitSamples,
		totalWallMs:              totalWallMs,
		throughputPerSec:         throughputPerSec,
		measuredValidationWallMs: measuredValidationWallMs,
	})

	aggregate := map[string]interface{}{
		"timestamp":               isoNow(),
		"engine":                  engineFlag,
		"binding":                 bindingName,
		"detail_level":            detailLevelName,
		"template_dir":            templateDir,
		"provenance":              provenance,
		"templates_total":         len(results),
		"templates_ok":            len(ok),
		"templates_failed":        len(failures),
		"iterations_per_template": iterations,
		"corpus_fingerprint":      corpusFingerprint,
		"corpus_file_count":       corpusFileCount,
		"run_fingerprint":         runFingerprint,
		"performance":             performance,
		"diagnostics":             buildDiagnosticsBlock(ok),
		"failures":                buildFailuresBlock(failures),
	}

	aggregatePath := filepath.Join(reportDir, "aggregate_detailed.json")
	aggregateData, marshalErr := json.MarshalIndent(aggregate, "", "  ")
	if marshalErr != nil {
		return fmt.Errorf("marshaling aggregate report: %w", marshalErr)
	}
	if writeErr := os.WriteFile(aggregatePath, aggregateData, 0o644); writeErr != nil {
		return fmt.Errorf("writing aggregate report %s: %w", aggregatePath, writeErr)
	}

	fmt.Fprintf(os.Stderr, "\nBenchmark complete: %d ok, %d failed (%d iterations/template)\n",
		len(ok), len(failures), iterations)
	fmt.Fprintf(os.Stderr, "Throughput: %.2f validations/sec\n", throughputPerSec)
	fmt.Fprintf(os.Stderr, "Corpus fingerprint: %s (%d files)\n", corpusFingerprint, corpusFileCount)
	fmt.Fprintf(os.Stderr, "Reports written to %s\n", reportDir)
	return nil
}

type firstValidation struct {
	HostMs               float64
	InternalMs           float64
	ModelBuildMs         float64
	SchemaValidateMs     float64
	RuleEvaluationMs     float64
	DiagnosticFinalizeMs float64
}

type startupMeasurement struct {
	StartupTemplate             string
	ModuleLoadMs                float64
	ConsumerInitScope           string
	ConsumerInitMs              float64
	SchemaInitMs                *float64
	EngineInitMs                float64
	First                       firstValidation
	InternalTimeToFirstResultMs float64
}

func measureStartup(engineFlag string, startupBytes []byte, startupLabel string, validateConfig *cfnvalidate.ValidateConfig) (*cfnvalidate.Engine, startupMeasurement, error) {
	const moduleLoadMs = 0.0

	engineStart := time.Now()
	engine, err := newEngine(engineFlag)
	if err != nil {
		return nil, startupMeasurement{}, fmt.Errorf("engine init failed: %w", err)
	}
	engineInitMs := elapsed(engineStart)
	consumerInitMs := engineInitMs

	validateStart := time.Now()
	report, err := engine.ValidateDetailed(startupBytes, validateConfig, startupLabel)
	if err != nil {
		engine.Destroy()
		return nil, startupMeasurement{}, fmt.Errorf("startup first validation failed on %q: %w", startupLabel, err)
	}
	hostMs := elapsed(validateStart)

	perf := report.Performance
	startup := startupMeasurement{
		StartupTemplate:   startupLabel,
		ModuleLoadMs:      moduleLoadMs,
		ConsumerInitScope: consumerInitScopeEngine,
		ConsumerInitMs:    consumerInitMs,
		SchemaInitMs:      nil,
		EngineInitMs:      engineInitMs,
		First: firstValidation{
			HostMs:               hostMs,
			InternalMs:           perf.ValidateTotal.DurationMs,
			ModelBuildMs:         perf.ModelBuild.DurationMs,
			SchemaValidateMs:     perf.SchemaValidate.DurationMs,
			RuleEvaluationMs:     perf.RuleEvaluation.DurationMs,
			DiagnosticFinalizeMs: perf.DiagnosticFinalize.DurationMs,
		},
		InternalTimeToFirstResultMs: moduleLoadMs + consumerInitMs + hostMs,
	}
	return engine, startup, nil
}

func startupProbeJSON(startup startupMeasurement, engineName string) map[string]interface{} {
	probe := startupSectionJSON(startup)
	probe["binding"] = bindingName
	probe["engine"] = engineName
	probe["versions"] = provenanceJSON()
	return probe
}

func startupSectionJSON(startup startupMeasurement) map[string]interface{} {
	var schemaInitMs interface{}
	if startup.SchemaInitMs != nil {
		schemaInitMs = round4(*startup.SchemaInitMs)
	}
	return map[string]interface{}{
		"startup_template": startup.StartupTemplate,
		"module_load_ms":   round4(startup.ModuleLoadMs),
		"consumer_init": map[string]interface{}{
			"scope":       startup.ConsumerInitScope,
			"duration_ms": round4(startup.ConsumerInitMs),
		},
		"schema_init_ms":                   schemaInitMs,
		"engine_init_ms":                   round4(startup.EngineInitMs),
		"first_validation":                 firstValidationJSON(startup.First),
		"internal_time_to_first_result_ms": round4(startup.InternalTimeToFirstResultMs),
	}
}

func firstValidationJSON(first firstValidation) map[string]interface{} {
	return map[string]interface{}{
		"host_ms":                round4(first.HostMs),
		"internal_ms":            round4(first.InternalMs),
		"model_build_ms":         round4(first.ModelBuildMs),
		"schema_validate_ms":     round4(first.SchemaValidateMs),
		"rule_evaluation_ms":     round4(first.RuleEvaluationMs),
		"diagnostic_finalize_ms": round4(first.DiagnosticFinalizeMs),
	}
}

func provenanceJSON() map[string]interface{} {
	return map[string]interface{}{
		"cloudformation_validate": cfnvalidate.Version(),
		"binding_artifact": map[string]interface{}{
			"kind":    bindingName,
			"version": cfnvalidate.PackageVersion(),
			"source":  goBindingModulePath,
		},
		"cargo":   envOrQuery(cargoVersionEnv, "cargo"),
		"rustc":   envOrQuery(rustcVersionEnv, "rustc"),
		"runtime": goRuntimeLabel(),
	}
}

func goRuntimeLabel() string {
	return fmt.Sprintf("%s %s-%s", runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

func envOrQuery(envVar, tool string) string {
	if value := strings.TrimSpace(os.Getenv(envVar)); value != "" {
		return value
	}
	return queryToolVersion(tool)
}

func queryToolVersion(tool string) string {
	output, err := exec.Command(tool, "--version").Output()
	if err != nil {
		return "unknown"
	}
	firstLine := strings.SplitN(strings.TrimSpace(string(output)), "\n", 2)[0]
	return strings.TrimSpace(firstLine)
}

var knownFlags = map[string]bool{
	"-h": true, "--help": true,
	"--engine": true, "--iterations": true, "--startup-probe": true,
}

var flagsWithValues = map[string]bool{
	"--engine": true, "--iterations": true,
}

func validateFlags(args []string) error {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			continue
		}
		if !knownFlags[a] {
			return usageError(fmt.Sprintf("unknown flag %q", a))
		}
		if flagsWithValues[a] {
			if i+1 >= len(args) {
				return usageError(fmt.Sprintf("flag %s requires a value", a))
			}
			i++
		}
	}
	return nil
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func requiredFlagValue(args []string, flag, defaultVal string) (string, error) {
	for i, a := range args {
		if a == flag {
			if i+1 >= len(args) {
				return "", usageError(fmt.Sprintf("flag %s requires a value", flag))
			}
			return args[i+1], nil
		}
	}
	return defaultVal, nil
}

func positionalArg(args []string) string {
	for i := 0; i < len(args); i++ {
		if flagsWithValues[args[i]] {
			i++
			continue
		}
		if !strings.HasPrefix(args[i], "-") {
			return args[i]
		}
	}
	return ""
}

func parseIterations(args []string) (int, error) {
	iterStr, err := requiredFlagValue(args, "--iterations", "")
	if err != nil {
		return 0, err
	}
	if iterStr == "" {
		return 20, nil
	}
	n := 0
	for _, c := range iterStr {
		if c < '0' || c > '9' {
			return 0, usageError(fmt.Sprintf("--iterations must be a positive integer, got %q", iterStr))
		}
		n = n*10 + int(c-'0')
	}
	if n < 1 {
		return 0, usageError(fmt.Sprintf("--iterations must be a positive integer, got %q", iterStr))
	}
	return n, nil
}

type usageErr struct {
	msg string
}

func (e *usageErr) Error() string { return e.msg }

func usageError(msg string) error { return &usageErr{msg: msg} }

func isUsageError(err error) bool {
	_, ok := err.(*usageErr)
	return ok
}

func newEngine(name string) (*cfnvalidate.Engine, error) {
	switch name {
	case "cel":
		return cfnvalidate.NewCelEngine(nil)
	default:
		return cfnvalidate.NewRegoEngine(nil)
	}
}

var templateExtensions = map[string]bool{
	".yaml": true,
	".yml":  true,
	".json": true,
}

func collectFiles(root string) ([]string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("stat %q: %w", root, err)
	}
	if !info.IsDir() {
		return []string{root}, nil
	}
	var files []string
	walkErr := filepath.Walk(root, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("walking %q: %w", path, err)
		}
		if fi.IsDir() {
			return nil
		}
		ext := filepath.Ext(fi.Name())
		if templateExtensions[ext] {
			files = append(files, path)
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	sort.Slice(files, func(i, j int) bool {
		ri := filepath.ToSlash(relOrBase(root, files[i]))
		rj := filepath.ToSlash(relOrBase(root, files[j]))
		return ri < rj
	})
	return files, nil
}

func relOrBase(base, path string) string {
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return filepath.Base(path)
	}
	return rel
}

func relativePath(base, full string) string {
	rel, err := filepath.Rel(base, full)
	if err != nil || rel == "" || rel == "." {
		return filepath.Base(full)
	}
	return rel
}

// sourceFileDir returns the directory of this Go source file at compile time
// via runtime.Caller. This is deterministic regardless of the working directory
// at execution time.
func sourceFileDir() (string, error) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("runtime.Caller failed to resolve source file location")
	}
	return filepath.Dir(filename), nil
}

func resolveDefaultCorpus() (string, error) {
	dir, err := sourceFileDir()
	if err != nil {
		return "", err
	}
	corpus := filepath.Join(dir, "..", "..", "resources", "templates")
	abs, err := filepath.Abs(corpus)
	if err != nil {
		return "", fmt.Errorf("resolving absolute path for corpus: %w", err)
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("default corpus %q not found: %w", abs, err)
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("default corpus %q is not a directory", abs)
	}
	return abs, nil
}

func resolveReportDir(engine string) (string, error) {
	dir, err := sourceFileDir()
	if err != nil {
		return "", err
	}
	reportDir := filepath.Join(dir, "..", "reports", engine)
	abs, err := filepath.Abs(reportDir)
	if err != nil {
		return "", fmt.Errorf("resolving absolute path for report dir: %w", err)
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return "", fmt.Errorf("creating report dir %q: %w", abs, err)
	}
	return abs, nil
}

func isoNow() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05Z")
}

func toJSONStem(rel string) string {
	s := strings.ReplaceAll(rel, "/", "_")
	for _, extension := range []string{".yaml", ".yml", ".json"} {
		if strings.HasSuffix(s, extension) {
			return strings.TrimSuffix(s, extension) + "_" + strings.TrimPrefix(extension, ".")
		}
	}
	return s
}

func iterationMetricsJSON(hostModel, modelBuild, schemaValidate, ruleEval, finalize, engineInternal, wallClock float64) map[string]interface{} {
	return map[string]interface{}{
		"hostModelMs":          round4(hostModel),
		"modelBuildMs":         round4(modelBuild),
		"schemaValidateMs":     round4(schemaValidate),
		"ruleEvaluationMs":     round4(ruleEval),
		"diagnosticFinalizeMs": round4(finalize),
		"engineInternalMs":     round4(engineInternal),
		"wallClockMs":          round4(wallClock),
	}
}

func subsequentMetric(vals []float64) interface{} {
	if len(vals) > 1 {
		return round4(medianOf(vals[1:]))
	}
	return nil
}

func steadyOrFirst(vals []float64) float64 {
	if len(vals) > 1 {
		return medianOf(vals[1:])
	}
	return vals[0]
}

func perTemplateMetricsJSON(iterations int, hostModel, modelBuild, schemaValidate, ruleEval, finalize, engineInternal, wallClock []float64, bindingOverheadMs float64) map[string]interface{} {
	firstMeasured := iterationMetricsJSON(
		hostModel[0], modelBuild[0], schemaValidate[0], ruleEval[0], finalize[0], engineInternal[0], wallClock[0])

	sampleCount := len(wallClock) - 1
	if sampleCount < 0 {
		sampleCount = 0
	}
	subsequent := map[string]interface{}{
		"sampleCount":          sampleCount,
		"hostModelMs":          subsequentMetric(hostModel),
		"modelBuildMs":         subsequentMetric(modelBuild),
		"schemaValidateMs":     subsequentMetric(schemaValidate),
		"ruleEvaluationMs":     subsequentMetric(ruleEval),
		"diagnosticFinalizeMs": subsequentMetric(finalize),
		"engineInternalMs":     subsequentMetric(engineInternal),
		"wallClockMs":          subsequentMetric(wallClock),
	}

	steadyState := iterationMetricsJSON(
		steadyOrFirst(hostModel), steadyOrFirst(modelBuild), steadyOrFirst(schemaValidate),
		steadyOrFirst(ruleEval), steadyOrFirst(finalize), steadyOrFirst(engineInternal), steadyOrFirst(wallClock))

	return map[string]interface{}{
		"iterations":        iterations,
		"firstMeasured":     firstMeasured,
		"subsequent":        subsequent,
		"firstIteration":    firstMeasured,
		"steadyState":       steadyState,
		"bindingOverheadMs": bindingOverheadMs,
	}
}

func zeroBenchmarkMetrics() map[string]interface{} {
	zeroIteration := func() map[string]interface{} {
		return map[string]interface{}{
			"hostModelMs":          0.0,
			"modelBuildMs":         0.0,
			"schemaValidateMs":     0.0,
			"ruleEvaluationMs":     0.0,
			"diagnosticFinalizeMs": 0.0,
			"engineInternalMs":     0.0,
			"wallClockMs":          0.0,
		}
	}
	return map[string]interface{}{
		"iterations":    0,
		"firstMeasured": zeroIteration(),
		"subsequent": map[string]interface{}{
			"sampleCount":          0,
			"hostModelMs":          nil,
			"modelBuildMs":         nil,
			"schemaValidateMs":     nil,
			"ruleEvaluationMs":     nil,
			"diagnosticFinalizeMs": nil,
			"engineInternalMs":     nil,
			"wallClockMs":          nil,
		},
		"firstIteration":    zeroIteration(),
		"steadyState":       zeroIteration(),
		"bindingOverheadMs": 0.0,
	}
}

func normalizeParseFailureReport(report *cfnvalidate.DetailedReport) {
	report.Metadata.Counts = cfnvalidate.Summary{}
	report.Performance = cfnvalidate.PerformanceMetrics{}
	report.Diagnostics = []cfnvalidate.DetailedDiagnostic{}
}

func buildPerTemplatePayload(report *cfnvalidate.DetailedReport, rel, engine string, benchmarkMetrics map[string]interface{}) (map[string]interface{}, error) {
	data, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("marshaling report: %w", err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("unmarshaling report to map: %w", err)
	}
	payload["engine"] = engine
	payload["binding"] = bindingName
	payload["detailLevel"] = detailLevelName
	payload["filePath"] = rel
	payload["benchmarkMetrics"] = benchmarkMetrics
	return payload, nil
}

func writePerTemplateReport(path string, payload map[string]interface{}) error {
	data, marshalErr := json.MarshalIndent(payload, "", "  ")
	if marshalErr != nil {
		return fmt.Errorf("marshaling JSON for %s: %w", path, marshalErr)
	}
	if writeErr := os.WriteFile(path, data, 0o644); writeErr != nil {
		return fmt.Errorf("writing per-template report %s: %w", path, writeErr)
	}
	return nil
}

type performanceInput struct {
	ok                       []templateResult
	startup                  startupMeasurement
	moduleLoadMs             float64
	initSamples              []float64
	coldInitMs               float64
	subsequentInitSamples    []float64
	schemaInitSamples        []float64
	engineInitSamples        []float64
	totalWallMs              float64
	throughputPerSec         float64
	measuredValidationWallMs float64
}

func buildPerformanceBlock(input performanceInput) map[string]interface{} {
	ok := input.ok
	modelBuildVec := extractField(ok, func(r templateResult) float64 { return r.ModelBuildMs })
	schemaValidateVec := extractField(ok, func(r templateResult) float64 { return r.SchemaValidateMs })
	ruleEvalVec := extractField(ok, func(r templateResult) float64 { return r.RuleEvalMs })
	finalizeVec := extractField(ok, func(r templateResult) float64 { return r.DiagnosticFinalizeMs })

	engineInternalVec := extractField(ok, func(r templateResult) float64 { return r.EngineInternalMs })
	firstEngineInternalVec := extractField(ok, func(r templateResult) float64 { return r.FirstMeasuredEngineInternalMs })
	subsequentEngineInternalVec := extractOptionalField(ok, func(r templateResult) *float64 { return r.SubsequentEngineInternalMs })

	wallClockVec := extractField(ok, func(r templateResult) float64 { return r.WallClockMs })
	firstWallClockVec := extractField(ok, func(r templateResult) float64 { return r.FirstMeasuredWallClockMs })
	subsequentWallClockVec := extractOptionalField(ok, func(r templateResult) *float64 { return r.SubsequentWallClockMs })

	hostModelVec := extractField(ok, func(r templateResult) float64 { return r.HostModelMs })
	firstHostModelVec := extractField(ok, func(r templateResult) float64 { return r.FirstMeasuredHostModelMs })
	subsequentHostModelVec := extractOptionalField(ok, func(r templateResult) *float64 { return r.SubsequentHostModelMs })

	overheadVec := extractField(ok, func(r templateResult) float64 { return r.BindingOverheadMs })

	return map[string]interface{}{
		"module_load_ms":              input.moduleLoadMs,
		"startup":                     startupSectionJSON(input.startup),
		"init_ms":                     statsJSON(input.initSamples),
		"cold_init_ms":                round4(input.coldInitMs),
		"warm_init_ms":                statsJSON(input.subsequentInitSamples),
		"subsequent_init_ms":          statsJSON(input.subsequentInitSamples),
		"schema_init_ms":              statsJSON(input.schemaInitSamples),
		"engine_init_ms":              statsJSON(input.engineInitSamples),
		"total_wall_ms":               round4(input.totalWallMs),
		"measured_validation_wall_ms": round4(input.measuredValidationWallMs),
		"throughput_per_sec":          round4(input.throughputPerSec),
		"model_build_ms":              statsJSON(modelBuildVec),
		"schema_validate_ms":          statsJSON(schemaValidateVec),
		"rule_evaluation_ms":          statsJSON(ruleEvalVec),
		"diagnostic_finalize_ms":      statsJSON(finalizeVec),
		"engine_internal_ms":          statsJSON(engineInternalVec),
		// cold/warm alias first_measured/subsequent for older report consumers.
		"first_measured_engine_internal_ms": statsJSON(firstEngineInternalVec),
		"subsequent_engine_internal_ms":     statsJSON(subsequentEngineInternalVec),
		"cold_engine_internal_ms":           statsJSON(firstEngineInternalVec),
		"warm_engine_internal_ms":           statsJSON(subsequentEngineInternalVec),
		"wall_clock_ms":                     statsJSON(wallClockVec),
		"first_measured_wall_clock_ms":      statsJSON(firstWallClockVec),
		"subsequent_wall_clock_ms":          statsJSON(subsequentWallClockVec),
		"cold_wall_clock_ms":                statsJSON(firstWallClockVec),
		"warm_wall_clock_ms":                statsJSON(subsequentWallClockVec),
		"host_model_ms":                     statsJSON(hostModelVec),
		"first_measured_host_model_ms":      statsJSON(firstHostModelVec),
		"subsequent_host_model_ms":          statsJSON(subsequentHostModelVec),
		"cold_host_model_ms":                statsJSON(firstHostModelVec),
		"warm_host_model_ms":                statsJSON(subsequentHostModelVec),
		"binding_overhead_ms":               statsJSON(overheadVec),
	}
}

func buildDiagnosticsBlock(ok []templateResult) map[string]interface{} {
	var totalFatal, totalErrors, totalWarnings, totalInfo int
	for _, r := range ok {
		totalFatal += r.Fatal
		totalErrors += r.Errors
		totalWarnings += r.Warnings
		totalInfo += r.Informational
	}
	return map[string]interface{}{
		"total_fatal":         totalFatal,
		"total_errors":        totalErrors,
		"total_warnings":      totalWarnings,
		"total_informational": totalInfo,
	}
}

func buildFailuresBlock(failures []templateResult) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(failures))
	for _, r := range failures {
		out = append(out, map[string]interface{}{
			"file":   r.File,
			"status": r.Status,
			"error":  r.ErrorMsg,
		})
	}
	return out
}

func computeCorpusFingerprint(root string) (string, int, error) {
	files, err := collectFiles(root)
	if err != nil {
		return "", 0, fmt.Errorf("collecting files for fingerprint: %w", err)
	}
	outer := sha256.New()
	for _, f := range files {
		content, readErr := os.ReadFile(f)
		if readErr != nil {
			return "", 0, fmt.Errorf("reading %q for fingerprint: %w", f, readErr)
		}
		inner := sha256.Sum256(content)
		fileHash := hex.EncodeToString(inner[:])
		rel := relativePath(root, f)
		rel = filepath.ToSlash(rel)
		outer.Write([]byte(rel + "\t" + fileHash + "\n"))
	}
	return hex.EncodeToString(outer.Sum(nil)), len(files), nil
}

func computeRunFingerprint(corpusFP, engine, format string, iterations int) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%d", corpusFP, engine, format, iterations)))
	return hex.EncodeToString(h[:])
}

func statsJSON(vals []float64) map[string]interface{} {
	return map[string]interface{}{
		"count":  len(vals),
		"min":    round4(minOf(vals)),
		"avg":    round4(avgOf(vals)),
		"stddev": round4(stddevOf(vals)),
		"median": round4(medianOf(vals)),
		"p90":    round4(percentileOf(vals, 90)),
		"p95":    round4(percentileOf(vals, 95)),
		"p99":    round4(percentileOf(vals, 99)),
		"max":    round4(maxOf(vals)),
		"total":  round4(sum(vals)),
	}
}

func minOf(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	m := vals[0]
	for _, v := range vals[1:] {
		if v < m {
			m = v
		}
	}
	return m
}

func maxOf(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	m := vals[0]
	for _, v := range vals[1:] {
		if v > m {
			m = v
		}
	}
	return m
}

func avgOf(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	return sum(vals) / float64(len(vals))
}

func sum(vals []float64) float64 {
	var s float64
	for _, v := range vals {
		s += v
	}
	return s
}

func medianOf(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sorted := make([]float64, len(vals))
	copy(sorted, vals)
	sort.Float64s(sorted)
	n := len(sorted)
	if n%2 == 0 {
		return (sorted[n/2-1] + sorted[n/2]) / 2.0
	}
	return sorted[n/2]
}

func percentileOf(vals []float64, pct float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sorted := make([]float64, len(vals))
	copy(sorted, vals)
	sort.Float64s(sorted)
	rank := (pct / 100.0) * float64(len(sorted)-1)
	lo := int(math.Floor(rank))
	hi := lo + 1
	if hi >= len(sorted) {
		hi = len(sorted) - 1
	}
	frac := rank - float64(lo)
	return sorted[lo] + frac*(sorted[hi]-sorted[lo])
}

func stddevOf(vals []float64) float64 {
	if len(vals) < 2 {
		return 0
	}
	mean := avgOf(vals)
	var variance float64
	for _, v := range vals {
		d := v - mean
		variance += d * d
	}
	variance /= float64(len(vals) - 1)
	return math.Sqrt(variance)
}

func round4(v float64) float64 {
	return math.Round(v*10000) / 10000
}

func subsequentMedianPtr(vals []float64) *float64 {
	if len(vals) > 1 {
		m := medianOf(vals[1:])
		return &m
	}
	return nil
}

func elapsed(start time.Time) float64 {
	return float64(time.Since(start).Nanoseconds()) / 1_000_000.0
}

func extractField(results []templateResult, fn func(templateResult) float64) []float64 {
	out := make([]float64, len(results))
	for i, r := range results {
		out[i] = fn(r)
	}
	return out
}

func extractOptionalField(results []templateResult, fn func(templateResult) *float64) []float64 {
	out := make([]float64, 0, len(results))
	for _, r := range results {
		if v := fn(r); v != nil {
			out = append(out, *v)
		}
	}
	return out
}

type templateResult struct {
	File                          string
	Status                        string
	SizeBytes                     int
	Resources                     int
	Fatal                         int
	Errors                        int
	Warnings                      int
	Informational                 int
	DiagCount                     int
	HostModelMs                   float64
	FirstMeasuredHostModelMs      float64
	SubsequentHostModelMs         *float64
	ModelBuildMs                  float64
	SchemaValidateMs              float64
	RuleEvalMs                    float64
	DiagnosticFinalizeMs          float64
	EngineInternalMs              float64
	FirstMeasuredEngineInternalMs float64
	SubsequentEngineInternalMs    *float64
	WallClockMs                   float64
	FirstMeasuredWallClockMs      float64
	SubsequentWallClockMs         *float64
	BindingOverheadMs             float64
	HostValidateTotal             float64
	ErrorMsg                      string
}

func errorResult(file, status, msg string) templateResult {
	return templateResult{
		File:     file,
		Status:   status,
		ErrorMsg: msg,
	}
}
