// Command bench runs a benchmark of the Go bindings against a corpus of
// CloudFormation templates, producing aggregate and per-template JSON reports
// that match the contract of the native, WASM, JVM, Python, and Go harnesses.
//
// Usage:
//
//	go run ./bench [TEMPLATE|DIR] --engine rego|cel --iterations N
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
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	cfnvalidate "github.com/aws-cloudformation/cloudformation-validate/src/bindings-go/go"
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
		fmt.Fprintln(os.Stderr, "Usage: bench [TEMPLATE|DIR] --engine rego|cel --iterations N")
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

	defaultTemplateDir, err := resolveDefaultCorpus()
	if err != nil {
		return fmt.Errorf("resolving default corpus: %w", err)
	}
	templateDir := positionalArg(args)
	if templateDir == "" {
		templateDir = defaultTemplateDir
	}

	info, err := os.Stat(templateDir)
	if err != nil {
		return fmt.Errorf("cannot stat template path %q: %w", templateDir, err)
	}
	if !info.IsDir() {
		ext := strings.ToLower(filepath.Ext(templateDir))
		if !templateExtensions[ext] {
			return usageError(fmt.Sprintf("unsupported template extension %q; expected .yaml, .yml, or .json", ext))
		}
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

	// Go is statically linked — there is no dynamic module load.
	const moduleLoadMs = 0.0

	// Measure standalone init costs. The engine constructor already embeds a
	// SchemaValidator internally, so standalone schema init timing is purely
	// informational — it is NOT additive to engine init. A consumer only calls
	// the engine constructor; the schema validator is created inside it. We
	// time standalone schema init separately to show its isolated cost, but
	// initSamples reflects actual consumer setup: one engine constructor call.
	schemaInitSamples := make([]float64, 0, iterations)
	engineInitSamples := make([]float64, 0, iterations)
	for i := 0; i < iterations; i++ {
		t0 := time.Now()
		schemaValidator, schemaError := cfnvalidate.NewSchemaValidator(nil)
		if schemaError != nil {
			return fmt.Errorf("schema validator init failed on iteration %d: %w", i, schemaError)
		}
		schemaInitSamples = append(schemaInitSamples, elapsed(t0))
		schemaValidator.Destroy()

		t1 := time.Now()
		eng, err := newEngine(engineFlag)
		if err != nil {
			return fmt.Errorf("engine init failed on iteration %d: %w", i, err)
		}
		engineInitSamples = append(engineInitSamples, elapsed(t1))
		eng.Destroy()
	}

	// initSamples equals engineInitSamples (the actual consumer setup cost).
	// Cold init is the first engine constructor call (module load is 0 for Go).
	initSamples := make([]float64, len(engineInitSamples))
	copy(initSamples, engineInitSamples)
	coldInitMs := moduleLoadMs + initSamples[0]
	warmInitSamples := initSamples
	if len(initSamples) > 1 {
		warmInitSamples = initSamples[1:]
	}

	engine, err := newEngine(engineFlag)
	if err != nil {
		return fmt.Errorf("engine init failed: %w", err)
	}
	defer engine.Destroy()

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

	validateConfig := &cfnvalidate.ValidateConfig{
		SeverityLevel: cfnvalidate.SeverityDebug,
	}

	// Warm up to amortize first-call costs.
	if len(templates) > 0 {
		if warmupBytes, err := os.ReadFile(templates[0]); err == nil {
			if m, err := cfnvalidate.ParseTemplate(warmupBytes); err == nil {
				m.Destroy()
			}
			_, _ = engine.ValidateDetailed(warmupBytes, validateConfig, templates[0])
		}
	}

	type deferredWrite struct {
		path    string
		payload map[string]interface{}
	}
	var pendingWrites []deferredWrite
	var results []templateResult

	benchStart := time.Now()

	for _, tplPath := range templates {
		rel := relativePath(templateDir, tplPath)
		rel = filepath.ToSlash(rel)
		fmt.Fprintf(os.Stderr, "  %s", rel)

		bytes, readErr := os.ReadFile(tplPath)
		if readErr != nil {
			results = append(results, errorResult(rel, "read_error", readErr.Error()))
			fmt.Fprintln(os.Stderr)
			continue
		}
		sizeBytes := len(bytes)

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

		report := lastReport
		coldEngineInternalMs := iterEngineInternal[0]
		warmEngineInternalMs := coldEngineInternalMs
		if iterations > 1 {
			warmEngineInternalMs = medianOf(iterEngineInternal[1:])
		}
		medianEngineInternal := medianOf(iterEngineInternal)
		coldWallClockMs := iterHostValidate[0]
		warmWallClockMs := coldWallClockMs
		if iterations > 1 {
			warmWallClockMs = medianOf(iterHostValidate[1:])
		}
		medianWallClock := medianOf(iterHostValidate)
		coldHostModelMs := iterHostModel[0]
		warmHostModelMs := coldHostModelMs
		if iterations > 1 {
			warmHostModelMs = medianOf(iterHostModel[1:])
		}
		medianHostModel := medianOf(iterHostModel)

		// Binding overhead: median of per-call (wall - engine) differences.
		perCallDiffs := make([]float64, len(iterHostValidate))
		for i := range iterHostValidate {
			perCallDiffs[i] = iterHostValidate[i] - iterEngineInternal[i]
		}
		bindingOverheadMs := round4(medianOf(perCallDiffs))

		jsonStem := toJSONStem(rel)
		benchmarkMetrics := map[string]interface{}{
			"iterations": iterations,
			"firstIteration": map[string]interface{}{
				"hostModelMs":          round4(iterHostModel[0]),
				"modelBuildMs":         round4(iterModelBuild[0]),
				"schemaValidateMs":     round4(iterSchemaValidate[0]),
				"ruleEvaluationMs":     round4(iterRuleEval[0]),
				"diagnosticFinalizeMs": round4(iterFinalize[0]),
				"engineInternalMs":     round4(coldEngineInternalMs),
				"wallClockMs":          round4(coldWallClockMs),
			},
			"steadyState": map[string]interface{}{
				"hostModelMs":          round4(warmHostModelMs),
				"modelBuildMs":         round4(warmMedian(iterModelBuild, iterations)),
				"schemaValidateMs":     round4(warmMedian(iterSchemaValidate, iterations)),
				"ruleEvaluationMs":     round4(warmMedian(iterRuleEval, iterations)),
				"diagnosticFinalizeMs": round4(warmMedian(iterFinalize, iterations)),
				"engineInternalMs":     round4(warmEngineInternalMs),
				"wallClockMs":          round4(warmWallClockMs),
			},
			"bindingOverheadMs": bindingOverheadMs,
		}

		payload, marshalErr := buildPerTemplatePayload(report, rel, engineFlag, benchmarkMetrics)
		if marshalErr != nil {
			return fmt.Errorf("marshaling per-template payload for %s: %w", rel, marshalErr)
		}
		pendingWrites = append(pendingWrites, deferredWrite{
			path:    filepath.Join(jsonDir, jsonStem+".json"),
			payload: payload,
		})

		tr := templateResult{
			File:                 rel,
			Status:               "ok",
			SizeBytes:            sizeBytes,
			Resources:            report.Metadata.ResourcesScanned,
			Fatal:                report.Metadata.Counts.Fatal,
			Errors:               report.Metadata.Counts.Errors,
			Warnings:             report.Metadata.Counts.Warnings,
			Informational:        report.Metadata.Counts.Informational,
			DiagCount:            len(report.Diagnostics),
			HostModelMs:          medianHostModel,
			ColdHostModelMs:      coldHostModelMs,
			WarmHostModelMs:      warmHostModelMs,
			ModelBuildMs:         medianOf(iterModelBuild),
			SchemaValidateMs:     medianOf(iterSchemaValidate),
			RuleEvalMs:           medianOf(iterRuleEval),
			DiagnosticFinalizeMs: medianOf(iterFinalize),
			EngineInternalMs:     medianEngineInternal,
			ColdEngineInternalMs: coldEngineInternalMs,
			WarmEngineInternalMs: warmEngineInternalMs,
			WallClockMs:          medianWallClock,
			ColdWallClockMs:      coldWallClockMs,
			WarmWallClockMs:      warmWallClockMs,
			BindingOverheadMs:    bindingOverheadMs,
			HostValidateTotal:    sum(iterHostValidate),
		}
		fmt.Fprintf(os.Stderr, "  model=%.4fms  engine=%.4fms  wall=%.4fms  %dE %dW %dI\n",
			tr.HostModelMs, tr.EngineInternalMs, tr.WallClockMs,
			tr.Errors, tr.Warnings, tr.Informational)
		results = append(results, tr)
	}

	totalWallMs := elapsed(benchStart)

	for _, pw := range pendingWrites {
		data, marshalErr := json.MarshalIndent(pw.payload, "", "  ")
		if marshalErr != nil {
			return fmt.Errorf("marshaling JSON for %s: %w", pw.path, marshalErr)
		}
		if writeErr := os.WriteFile(pw.path, data, 0o644); writeErr != nil {
			return fmt.Errorf("writing per-template report %s: %w", pw.path, writeErr)
		}
	}

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
	runFingerprint := computeRunFingerprint(corpusFingerprint, engineFlag, "DETAILED", iterations)

	aggregate := map[string]interface{}{
		"timestamp":               isoNow(),
		"engine":                  engineFlag,
		"binding":                 "go",
		"detail_level":            "DETAILED",
		"template_dir":            templateDir,
		"templates_total":         len(results),
		"templates_ok":            len(ok),
		"templates_failed":        len(failures),
		"iterations_per_template": iterations,
		"corpus_fingerprint":      corpusFingerprint,
		"corpus_file_count":       corpusFileCount,
		"run_fingerprint":         runFingerprint,
		"performance":             buildPerformanceBlock(ok, moduleLoadMs, initSamples, coldInitMs, warmInitSamples, schemaInitSamples, engineInitSamples, totalWallMs, throughputPerSec, measuredValidationWallMs),
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

var knownFlags = map[string]bool{
	"-h": true, "--help": true,
	"--engine": true, "--iterations": true,
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
		ext := strings.ToLower(filepath.Ext(fi.Name()))
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
	corpus := filepath.Join(dir, "..", "..", "..", "resources", "templates")
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
	reportDir := filepath.Join(dir, "..", "..", "reports", engine)
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
	// Replace path separators, then swap the file extension suffix for an
	// underscore-delimited form: "foo/bar.yaml" -> "foo_bar_yaml".
	s := strings.ReplaceAll(rel, "/", "_")
	ext := filepath.Ext(s)
	if ext != "" {
		s = strings.TrimSuffix(s, ext) + "_" + strings.TrimPrefix(ext, ".")
	}
	return s
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
	payload["binding"] = "go"
	payload["detailLevel"] = "DETAILED"
	payload["filePath"] = rel
	payload["benchmarkMetrics"] = benchmarkMetrics
	return payload, nil
}

func buildPerformanceBlock(ok []templateResult, moduleLoadMs float64, initSamples []float64, coldInitMs float64, warmInitSamples, schemaInitSamples, engineInitSamples []float64, totalWallMs, throughputPerSec, measuredValidationWallMs float64) map[string]interface{} {
	modelBuildVec := extractField(ok, func(r templateResult) float64 { return r.ModelBuildMs })
	schemaValidateVec := extractField(ok, func(r templateResult) float64 { return r.SchemaValidateMs })
	ruleEvalVec := extractField(ok, func(r templateResult) float64 { return r.RuleEvalMs })
	finalizeVec := extractField(ok, func(r templateResult) float64 { return r.DiagnosticFinalizeMs })
	engineInternalVec := extractField(ok, func(r templateResult) float64 { return r.EngineInternalMs })
	coldEngineInternalVec := extractField(ok, func(r templateResult) float64 { return r.ColdEngineInternalMs })
	warmEngineInternalVec := extractField(ok, func(r templateResult) float64 { return r.WarmEngineInternalMs })
	wallClockVec := extractField(ok, func(r templateResult) float64 { return r.WallClockMs })
	coldWallClockVec := extractField(ok, func(r templateResult) float64 { return r.ColdWallClockMs })
	warmWallClockVec := extractField(ok, func(r templateResult) float64 { return r.WarmWallClockMs })
	hostModelVec := extractField(ok, func(r templateResult) float64 { return r.HostModelMs })
	coldHostModelVec := extractField(ok, func(r templateResult) float64 { return r.ColdHostModelMs })
	warmHostModelVec := extractField(ok, func(r templateResult) float64 { return r.WarmHostModelMs })
	overheadVec := extractField(ok, func(r templateResult) float64 { return r.BindingOverheadMs })

	return map[string]interface{}{
		"module_load_ms":              moduleLoadMs,
		"init_ms":                     statsJSON(initSamples),
		"cold_init_ms":                round4(coldInitMs),
		"warm_init_ms":                statsJSON(warmInitSamples),
		"schema_init_ms":              statsJSON(schemaInitSamples),
		"engine_init_ms":              statsJSON(engineInitSamples),
		"total_wall_ms":               round4(totalWallMs),
		"measured_validation_wall_ms": round4(measuredValidationWallMs),
		"throughput_per_sec":          round4(throughputPerSec),
		"model_build_ms":              statsJSON(modelBuildVec),
		"schema_validate_ms":          statsJSON(schemaValidateVec),
		"rule_evaluation_ms":          statsJSON(ruleEvalVec),
		"diagnostic_finalize_ms":      statsJSON(finalizeVec),
		"engine_internal_ms":          statsJSON(engineInternalVec),
		"cold_engine_internal_ms":     statsJSON(coldEngineInternalVec),
		"warm_engine_internal_ms":     statsJSON(warmEngineInternalVec),
		"wall_clock_ms":               statsJSON(wallClockVec),
		"cold_wall_clock_ms":          statsJSON(coldWallClockVec),
		"warm_wall_clock_ms":          statsJSON(warmWallClockVec),
		"host_model_ms":               statsJSON(hostModelVec),
		"cold_host_model_ms":          statsJSON(coldHostModelVec),
		"warm_host_model_ms":          statsJSON(warmHostModelVec),
		"binding_overhead_ms":         statsJSON(overheadVec),
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

func warmMedian(vals []float64, iterations int) float64 {
	if iterations > 1 && len(vals) > 1 {
		return medianOf(vals[1:])
	}
	if len(vals) > 0 {
		return vals[0]
	}
	return 0
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

type templateResult struct {
	File                 string
	Status               string
	SizeBytes            int
	Resources            int
	Fatal                int
	Errors               int
	Warnings             int
	Informational        int
	DiagCount            int
	HostModelMs          float64
	ColdHostModelMs      float64
	WarmHostModelMs      float64
	ModelBuildMs         float64
	SchemaValidateMs     float64
	RuleEvalMs           float64
	DiagnosticFinalizeMs float64
	EngineInternalMs     float64
	ColdEngineInternalMs float64
	WarmEngineInternalMs float64
	WallClockMs          float64
	ColdWallClockMs      float64
	WarmWallClockMs      float64
	BindingOverheadMs    float64
	HostValidateTotal    float64
	ErrorMsg             string
}

func errorResult(file, status, msg string) templateResult {
	return templateResult{
		File:     file,
		Status:   status,
		ErrorMsg: msg,
	}
}
