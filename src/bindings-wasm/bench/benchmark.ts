#!/usr/bin/env npx ts-node
import { execFileSync } from 'child_process';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { performance } from 'perf_hooks';

// Measure WASM module instantiation (V8 compiles + runs wasm_bindgen #[start]).
const moduleLoadStart = performance.now();
require('@aws/cloudformation-validate');
const moduleLoadMs = performance.now() - moduleLoadStart;

import type { DetailedReport, EngineConfig, ValidateConfig } from '@aws/cloudformation-validate';
import type {
    WasmCelEngine as WasmCelEngineType,
    WasmRegoEngine as WasmRegoEngineType,
} from '@aws/cloudformation-validate/bindings_wasm';
type WasmEngine = WasmRegoEngineType | WasmCelEngineType;

// Raw WASM bindings - accept Uint8Array directly, no file I/O.
// The public package re-exports wrapper classes that read from File/TemplateFile;
// the benchmark needs the inner classes to pass pre-read bytes.
const wasmRaw = require('@aws/cloudformation-validate/bindings_wasm');
const WasmSemanticModel: { parse(bytes: Uint8Array): { free(): void } } = wasmRaw.WasmSemanticModel;

const args = process.argv.slice(2);
if (args.includes('-h') || args.includes('--help')) {
    console.error(
        'Usage: npx ts-node benchmark.ts [TEMPLATE|DIR] [--engine rego|cel] [--iterations N]\n' +
            '       npx ts-node benchmark.ts --startup-probe [--engine rego|cel]',
    );
    process.exit(2);
}

function argValue(flag: string): string | undefined {
    const idx = args.indexOf(flag);
    return idx >= 0 ? args[idx + 1] : undefined;
}

// __dirname is <benchDir> under ts-node but <benchDir>/build when running the compiled JS, so
// resolve the bench root by stepping out of the compiled output directory when present.
const benchDir = path.basename(__dirname) === 'build' ? path.dirname(__dirname) : __dirname;
const DEFAULT_STARTUP_TEMPLATE = path.join('good', 'minimal.yaml');
const DEFAULT_TEMPLATE_DIR = path.resolve(benchDir, '../../resources/templates');
const FLAGS_WITH_VALUES = new Set(['--engine', '--iterations']);
const startupProbe = args.includes('--startup-probe');
const positionalArg = (() => {
    for (let i = 0; i < args.length; i++) {
        if (FLAGS_WITH_VALUES.has(args[i])) {
            i++;
            continue;
        }
        if (!args[i].startsWith('-')) return args[i];
    }
    return undefined;
})();
const templateDir = positionalArg ?? DEFAULT_TEMPLATE_DIR;

const engineFlag: string = (() => {
    if (!args.includes('--engine')) return 'rego';
    const val = argValue('--engine');
    if (val === undefined || val.startsWith('-')) {
        console.error('Error: --engine requires a value');
        process.exit(2);
    }
    return val;
})();
if (engineFlag !== 'rego' && engineFlag !== 'cel') {
    console.error(`Error: --engine must be 'rego' or 'cel', got '${engineFlag}'`);
    process.exit(2);
}
const formatFlag = 'DETAILED';
const formatDir = 'detailed';
const iterationsRaw = argValue('--iterations');
const iterations: number = (() => {
    if (iterationsRaw === undefined) {
        if (args.includes('--iterations')) {
            console.error('Error: --iterations requires a value');
            process.exit(2);
        }
        return 20;
    }
    const parsed = Number(iterationsRaw);
    if (!Number.isInteger(parsed) || parsed <= 0) {
        console.error(`Error: --iterations must be a positive integer, got '${iterationsRaw}'`);
        process.exit(2);
    }
    return parsed;
})();

function round4(v: number): number {
    return Math.round(v * 10000) / 10000;
}

function fmtBytes(n: number): string {
    if (n >= 1_048_576) return `${(n / 1_048_576).toFixed(1)} MB`;
    if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${n} B`;
}

class Stats {
    private readonly sorted: number[];
    readonly total: number;

    constructor(values: number[]) {
        this.sorted = [...values].sort((a, b) => a - b);
        this.total = values.reduce((a, b) => a + b, 0);
    }

    get count(): number {
        return this.sorted.length;
    }
    get min(): number {
        return this.sorted.length === 0 ? 0 : this.sorted[0];
    }
    get max(): number {
        return this.sorted.length === 0 ? 0 : this.sorted[this.sorted.length - 1];
    }
    get avg(): number {
        return this.sorted.length === 0 ? 0 : this.total / this.sorted.length;
    }

    get median(): number {
        return this.percentile(50);
    }
    get stddev(): number {
        if (this.sorted.length < 2) return 0;
        const mean = this.avg;
        const variance = this.sorted.reduce((s, v) => s + (v - mean) ** 2, 0) / (this.sorted.length - 1);
        return Math.sqrt(variance);
    }
    get p90(): number {
        return this.percentile(90);
    }
    get p95(): number {
        return this.percentile(95);
    }
    get p99(): number {
        return this.percentile(99);
    }

    percentile(pct: number): number {
        if (this.sorted.length === 0) return 0;
        const rank = (pct / 100) * (this.sorted.length - 1);
        const lo = Math.floor(rank);
        const hi = Math.min(Math.ceil(rank), this.sorted.length - 1);
        return this.sorted[lo] + (rank - lo) * (this.sorted[hi] - this.sorted[lo]);
    }

    toJson(): Record<string, number> {
        return {
            count: this.count,
            min: round4(this.min),
            avg: round4(this.avg),
            stddev: round4(this.stddev),
            median: round4(this.median),
            p90: round4(this.p90),
            p95: round4(this.p95),
            p99: round4(this.p99),
            max: round4(this.max),
            total: round4(this.total),
        };
    }
}

const TEMPLATE_EXTENSIONS = new Set(['.yaml', '.yml', '.json']);

function collectFiles(dirOrFile: string): string[] {
    const stat = fs.statSync(dirOrFile);
    if (stat.isFile()) return [dirOrFile];
    const results: string[] = [];
    const walk = (dir: string) => {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const full = path.join(dir, entry.name);
            if (entry.isDirectory()) walk(full);
            else if (entry.isFile() && TEMPLATE_EXTENSIONS.has(path.extname(entry.name))) results.push(full);
        }
    };
    walk(dirOrFile);
    return results.sort();
}

interface TemplateResult {
    readonly file: string;
    readonly status: string;
    readonly sizeBytes: number;
    readonly resources: number;
    readonly fatal: number;
    readonly errors: number;
    readonly warnings: number;
    readonly informational: number;
    readonly diagCount: number;
    readonly hostModelMs: number;
    readonly firstMeasuredHostModelMs: number;
    readonly subsequentHostModelMs: number | null;
    readonly modelBuildMs: number;
    readonly schemaValidateMs: number;
    readonly ruleEvalMs: number;
    readonly diagnosticFinalizeMs: number;
    readonly engineInternalMs: number;
    readonly firstMeasuredEngineInternalMs: number;
    readonly subsequentEngineInternalMs: number | null;
    readonly wallClockMs: number;
    readonly firstMeasuredWallClockMs: number;
    readonly subsequentWallClockMs: number | null;
    readonly wallClockTotalMs: number;
    readonly bindingOverheadMs: number;
    readonly errorMsg?: string;
}

function errorResult(file: string, status: string, msg: string): TemplateResult {
    return {
        file,
        status,
        sizeBytes: 0,
        resources: 0,
        fatal: 0,
        errors: 0,
        warnings: 0,
        informational: 0,
        diagCount: 0,
        hostModelMs: 0,
        firstMeasuredHostModelMs: 0,
        subsequentHostModelMs: null,
        modelBuildMs: 0,
        schemaValidateMs: 0,
        ruleEvalMs: 0,
        diagnosticFinalizeMs: 0,
        engineInternalMs: 0,
        firstMeasuredEngineInternalMs: 0,
        subsequentEngineInternalMs: null,
        wallClockMs: 0,
        firstMeasuredWallClockMs: 0,
        subsequentWallClockMs: null,
        wallClockTotalMs: 0,
        bindingOverheadMs: 0,
        errorMsg: msg,
    };
}

function subsequentMedianOrNull(values: number[]): number | null {
    return values.length > 1 ? new Stats(values.slice(1)).median : null;
}

function iterationMetricsJson(
    hostModel: number,
    modelBuild: number,
    schemaValidate: number,
    ruleEval: number,
    finalize: number,
    engineInternal: number,
    wallClock: number,
): Record<string, number> {
    return {
        hostModelMs: round4(hostModel),
        modelBuildMs: round4(modelBuild),
        schemaValidateMs: round4(schemaValidate),
        ruleEvaluationMs: round4(ruleEval),
        diagnosticFinalizeMs: round4(finalize),
        engineInternalMs: round4(engineInternal),
        wallClockMs: round4(wallClock),
    };
}

function subsequentMetricJson(values: number[]): number | null {
    const median = subsequentMedianOrNull(values);
    return median === null ? null : round4(median);
}

function perTemplateMetricsJson(
    iterationCount: number,
    hostModel: number[],
    modelBuild: number[],
    schemaValidate: number[],
    ruleEval: number[],
    finalize: number[],
    engineInternal: number[],
    wallClock: number[],
    bindingOverheadMs: number,
): Record<string, unknown> {
    const firstMeasured = iterationMetricsJson(
        hostModel[0],
        modelBuild[0],
        schemaValidate[0],
        ruleEval[0],
        finalize[0],
        engineInternal[0],
        wallClock[0],
    );
    const subsequent = {
        sampleCount: Math.max(wallClock.length - 1, 0),
        hostModelMs: subsequentMetricJson(hostModel),
        modelBuildMs: subsequentMetricJson(modelBuild),
        schemaValidateMs: subsequentMetricJson(schemaValidate),
        ruleEvaluationMs: subsequentMetricJson(ruleEval),
        diagnosticFinalizeMs: subsequentMetricJson(finalize),
        engineInternalMs: subsequentMetricJson(engineInternal),
        wallClockMs: subsequentMetricJson(wallClock),
    };
    const steadyOrFirst = (values: number[]): number =>
        values.length > 1 ? new Stats(values.slice(1)).median : values[0];
    const steadyState = iterationMetricsJson(
        steadyOrFirst(hostModel),
        steadyOrFirst(modelBuild),
        steadyOrFirst(schemaValidate),
        steadyOrFirst(ruleEval),
        steadyOrFirst(finalize),
        steadyOrFirst(engineInternal),
        steadyOrFirst(wallClock),
    );
    return {
        iterations: iterationCount,
        firstMeasured,
        subsequent,
        firstIteration: firstMeasured,
        steadyState,
        bindingOverheadMs,
    };
}

function zeroBenchmarkMetrics(): Record<string, unknown> {
    const zeroIteration = () => ({
        hostModelMs: 0,
        modelBuildMs: 0,
        schemaValidateMs: 0,
        ruleEvaluationMs: 0,
        diagnosticFinalizeMs: 0,
        engineInternalMs: 0,
        wallClockMs: 0,
    });
    return {
        iterations: 0,
        firstMeasured: zeroIteration(),
        subsequent: {
            sampleCount: 0,
            hostModelMs: null,
            modelBuildMs: null,
            schemaValidateMs: null,
            ruleEvaluationMs: null,
            diagnosticFinalizeMs: null,
            engineInternalMs: null,
            wallClockMs: null,
        },
        firstIteration: zeroIteration(),
        steadyState: zeroIteration(),
        bindingOverheadMs: 0,
    };
}

function normalizeParseFailureReport(report: DetailedReport): DetailedReport {
    const zeroPhase = () => ({ durationMs: 0 });
    return {
        ...report,
        metadata: {
            ...report.metadata,
            counts: {
                fatal: 0,
                errors: 0,
                warnings: 0,
                informational: 0,
                debug: 0,
            },
        },
        performance: {
            schemaInit: zeroPhase(),
            engineInit: zeroPhase(),
            modelBuild: zeroPhase(),
            schemaValidate: zeroPhase(),
            ruleEvaluation: zeroPhase(),
            diagnosticFinalize: zeroPhase(),
            validateTotal: zeroPhase(),
        },
        diagnostics: [],
    };
}

function reportPath(jsonDir: string, relativePath: string): string {
    let stem = relativePath.replace(/\//g, '_');
    for (const [extension, replacement] of [
        ['.yaml', '_yaml'],
        ['.yml', '_yml'],
        ['.json', '_json'],
    ]) {
        if (stem.endsWith(extension)) {
            stem = `${stem.slice(0, -extension.length)}${replacement}`;
            break;
        }
    }
    return path.join(jsonDir, `${stem}.json`);
}

const engineConfig: EngineConfig = {
    customRules: [],
    guardRules: [],
};
function newEngine(): WasmEngine {
    return engineFlag === 'cel' ? new wasmRaw.WasmCelEngine(engineConfig) : new wasmRaw.WasmRegoEngine(engineConfig);
}

const validateConfig: ValidateConfig = {
    severityLevel: 'DEBUG',
    strict: false,
};

interface Provenance {
    cloudformation_validate: string;
    binding_artifact: { kind: string; version: string; source: string };
    cargo: string;
    rustc: string;
    runtime: string;
}

function queryToolVersion(tool: string): string {
    try {
        const out = execFileSync(tool, ['--version'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
        const firstLine = out.split('\n')[0]?.trim() ?? '';
        return firstLine === '' ? 'unknown' : firstLine;
    } catch {
        return 'unknown';
    }
}

function envOrQuery(varName: string, tool: string): string {
    const value = process.env[varName];
    if (value !== undefined && value.trim() !== '') return value.trim();
    return queryToolVersion(tool);
}

function npmArtifactVersion(): string {
    try {
        const pkg = require('@aws/cloudformation-validate/package.json') as { version?: unknown };
        return typeof pkg.version === 'string' && pkg.version.trim() !== '' ? pkg.version.trim() : 'unknown';
    } catch {
        return 'unknown';
    }
}

function bridgeVersion(): string {
    try {
        const v = wasmRaw.version();
        return typeof v === 'string' && v.trim() !== '' ? v.trim() : 'unknown';
    } catch {
        return 'unknown';
    }
}

function provenanceJson(): Provenance {
    return {
        cloudformation_validate: bridgeVersion(),
        binding_artifact: {
            kind: 'npm',
            version: npmArtifactVersion(),
            source: '@aws/cloudformation-validate',
        },
        cargo: envOrQuery('BENCHMARK_CARGO_VERSION', 'cargo'),
        rustc: envOrQuery('BENCHMARK_RUSTC_VERSION', 'rustc'),
        runtime: `node ${process.version} ${process.platform}-${process.arch}`,
    };
}

interface FirstValidation {
    hostMs: number;
    internalMs: number;
    modelBuildMs: number;
    schemaValidateMs: number;
    ruleEvaluationMs: number;
    diagnosticFinalizeMs: number;
}

interface StartupMeasurement {
    startupTemplate: string;
    moduleLoadMs: number;
    consumerInitScope: string;
    consumerInitMs: number;
    schemaInitMs: number | null;
    engineInitMs: number;
    first: FirstValidation;
    internalTimeToFirstResultMs: number;
}

function measureStartup(
    startupBytes: Uint8Array,
    startupLabel: string,
): {
    engine: WasmEngine;
    startup: StartupMeasurement;
} {
    const engineStart = performance.now();
    const engine = newEngine();
    const engineInitMs = performance.now() - engineStart;
    // The FFI engine constructor already embeds a SchemaValidator, so a consumer's
    // setup cost is the engine construction alone - there is no standalone schema step.
    const consumerInitMs = engineInitMs;

    const validateStart = performance.now();
    const report: DetailedReport = engine.validateDetailed(startupBytes, validateConfig, startupLabel);
    const hostMs = performance.now() - validateStart;

    const perf = report.performance;
    const first: FirstValidation = {
        hostMs,
        internalMs: perf.validateTotal.durationMs,
        modelBuildMs: perf.modelBuild.durationMs,
        schemaValidateMs: perf.schemaValidate.durationMs,
        ruleEvaluationMs: perf.ruleEvaluation.durationMs,
        diagnosticFinalizeMs: perf.diagnosticFinalize.durationMs,
    };
    const startup: StartupMeasurement = {
        startupTemplate: startupLabel,
        moduleLoadMs,
        consumerInitScope: 'engine',
        consumerInitMs,
        schemaInitMs: null,
        engineInitMs,
        first,
        internalTimeToFirstResultMs: moduleLoadMs + consumerInitMs + hostMs,
    };
    return { engine, startup };
}

function firstValidationJson(first: FirstValidation): Record<string, number> {
    return {
        host_ms: round4(first.hostMs),
        internal_ms: round4(first.internalMs),
        model_build_ms: round4(first.modelBuildMs),
        schema_validate_ms: round4(first.schemaValidateMs),
        rule_evaluation_ms: round4(first.ruleEvaluationMs),
        diagnostic_finalize_ms: round4(first.diagnosticFinalizeMs),
    };
}

function startupSectionJson(startup: StartupMeasurement): Record<string, unknown> {
    return {
        startup_template: startup.startupTemplate,
        module_load_ms: round4(startup.moduleLoadMs),
        consumer_init: {
            scope: startup.consumerInitScope,
            duration_ms: round4(startup.consumerInitMs),
        },
        schema_init_ms: startup.schemaInitMs === null ? null : round4(startup.schemaInitMs),
        engine_init_ms: round4(startup.engineInitMs),
        first_validation: firstValidationJson(startup.first),
        internal_time_to_first_result_ms: round4(startup.internalTimeToFirstResultMs),
    };
}

function runStartupProbe(): void {
    const startupPath = path.join(DEFAULT_TEMPLATE_DIR, DEFAULT_STARTUP_TEMPLATE);
    let startupBytes: Uint8Array;
    try {
        startupBytes = fs.readFileSync(startupPath);
    } catch (e: any) {
        console.error(`Error: failed to read startup template '${startupPath}': ${e?.message ?? e}`);
        process.exit(1);
    }
    const startupLabel = path.basename(startupPath);
    const { engine, startup } = measureStartup(startupBytes, startupLabel);
    const engineName = engine.engineName();
    try {
        engine.free();
    } catch {}
    const probe = {
        ...startupSectionJson(startup),
        binding: 'wasm',
        engine: engineName,
        versions: provenanceJson(),
    };
    process.stdout.write(`${JSON.stringify(probe)}\n`);
}

if (startupProbe) {
    runStartupProbe();
    process.exit(0);
}

const templates = collectFiles(templateDir);
if (templates.length === 0) {
    console.error(`No templates found in ${templateDir}`);
    process.exit(1);
}
console.error(
    `Benchmarking ${templates.length} templates, ${iterations} iterations, engine=${engineFlag}, format=${formatFlag}`,
);

const startupTemplate = templates[0];
const startupLabel = (path.relative(templateDir, startupTemplate).replace(/\\/g, '/').replace(/^\//, '') ||
    path.basename(startupTemplate)) as string;
let startupBytes: Uint8Array;
try {
    startupBytes = fs.readFileSync(startupTemplate);
} catch (e: any) {
    console.error(`Error: failed to read startup template '${startupTemplate}': ${e?.message ?? e}`);
    process.exit(1);
}
const { engine, startup } = measureStartup(startupBytes, startupLabel);

const schemaInitSamples: number[] = [];
const engineInitSamples: number[] = [startup.engineInitMs];
const initSamples = engineInitSamples.slice();
const coldInitMs = moduleLoadMs + initSamples[0];
const subsequentInitSamples: number[] = [];

const reportDir = path.resolve(benchDir, `../reports/${engineFlag}`);
const jsonDir = path.join(reportDir, `json_${formatDir}`);
// Clean previous output so stale reports from dropped/renamed templates are not left behind.
if (fs.existsSync(jsonDir)) {
    fs.rmSync(jsonDir, { recursive: true, force: true });
}
fs.mkdirSync(jsonDir, { recursive: true });

const results: TemplateResult[] = [];
const benchStart = performance.now();

for (const tpl of templates) {
    const rel = path.relative(templateDir, tpl).replace(/\\/g, '/').replace(/^\//, '') || path.basename(tpl);
    process.stderr.write(`  ${rel}`);

    let sizeBytes: number;
    let bytes: Uint8Array;
    try {
        bytes = fs.readFileSync(tpl);
        sizeBytes = bytes.length;
    } catch (e: any) {
        results.push(errorResult(rel, 'read_error', e.message));
        continue;
    }
    const jsonPath = reportPath(jsonDir, rel);

    const iterModelBuild: number[] = [];
    const iterSchemaValidate: number[] = [];
    const iterRuleEval: number[] = [];
    const iterFinalize: number[] = [];
    const iterHostModel: number[] = [];
    const iterEngineInternal: number[] = [];
    const iterWallClock: number[] = [];
    let lastReport: DetailedReport | null = null;
    let failed = false;

    for (let i = 0; i < iterations; i++) {
        let parsedModel: { free(): void } | null = null;
        try {
            const tm0 = performance.now();
            parsedModel = WasmSemanticModel.parse(bytes);
            iterHostModel.push(performance.now() - tm0);
        } catch (e: any) {
            const parseFailureReport = normalizeParseFailureReport(engine.validateDetailed(bytes, validateConfig, rel));
            fs.writeFileSync(
                jsonPath,
                JSON.stringify(
                    {
                        ...parseFailureReport,
                        filePath: rel,
                        engine: engineFlag,
                        binding: 'wasm',
                        detailLevel: formatFlag,
                        benchmarkMetrics: zeroBenchmarkMetrics(),
                    },
                    null,
                    2,
                ),
            );
            results.push(errorResult(rel, 'parse_error', e.message ?? String(e)));
            failed = true;
            break;
        } finally {
            try {
                parsedModel?.free();
            } catch {}
        }

        try {
            const t0 = performance.now();
            const report: DetailedReport = engine.validateDetailed(bytes, validateConfig, rel);
            const wallMs = performance.now() - t0;
            const perf = report.performance;
            iterModelBuild.push(perf.modelBuild.durationMs);
            iterSchemaValidate.push(perf.schemaValidate.durationMs);
            iterRuleEval.push(perf.ruleEvaluation.durationMs);
            iterFinalize.push(perf.diagnosticFinalize.durationMs);
            iterEngineInternal.push(perf.validateTotal.durationMs);
            iterWallClock.push(wallMs);
            if (i === iterations - 1) lastReport = report;
        } catch (e: any) {
            results.push(errorResult(rel, 'error', e.message ?? String(e)));
            failed = true;
            break;
        }
    }
    if (failed) continue;

    const report = lastReport!;
    const firstMeasuredEngineInternalMs = iterEngineInternal[0];
    const subsequentEngineInternalMs = subsequentMedianOrNull(iterEngineInternal);
    const medianEngineInternal = new Stats(iterEngineInternal).median;
    const firstMeasuredWallClockMs = iterWallClock[0];
    const subsequentWallClockMs = subsequentMedianOrNull(iterWallClock);
    const medianWallClock = new Stats(iterWallClock).median;
    const firstMeasuredHostModelMs = iterHostModel[0];
    const subsequentHostModelMs = subsequentMedianOrNull(iterHostModel);
    const medianHostModel = new Stats(iterHostModel).median;
    const perIterOverhead = iterWallClock.map((w, idx) => w - iterEngineInternal[idx]);
    const bindingOverheadMs = round4(new Stats(perIterOverhead).median);

    fs.writeFileSync(
        jsonPath,
        JSON.stringify(
            {
                ...report,
                filePath: rel,
                engine: engineFlag,
                binding: 'wasm',
                detailLevel: formatFlag,
                benchmarkMetrics: perTemplateMetricsJson(
                    iterations,
                    iterHostModel,
                    iterModelBuild,
                    iterSchemaValidate,
                    iterRuleEval,
                    iterFinalize,
                    iterEngineInternal,
                    iterWallClock,
                    bindingOverheadMs,
                ),
            },
            null,
            2,
        ),
    );

    const tr: TemplateResult = {
        file: rel,
        status: 'ok',
        sizeBytes,
        resources: report.metadata.resourcesScanned,
        fatal: report.metadata.counts.fatal,
        errors: report.metadata.counts.errors,
        warnings: report.metadata.counts.warnings,
        informational: report.metadata.counts.informational,
        diagCount: report.diagnostics.length,
        hostModelMs: medianHostModel,
        firstMeasuredHostModelMs,
        subsequentHostModelMs,
        modelBuildMs: new Stats(iterModelBuild).median,
        schemaValidateMs: new Stats(iterSchemaValidate).median,
        ruleEvalMs: new Stats(iterRuleEval).median,
        diagnosticFinalizeMs: new Stats(iterFinalize).median,
        engineInternalMs: medianEngineInternal,
        firstMeasuredEngineInternalMs,
        subsequentEngineInternalMs,
        wallClockMs: medianWallClock,
        firstMeasuredWallClockMs,
        subsequentWallClockMs,
        wallClockTotalMs: new Stats(iterWallClock).total,
        bindingOverheadMs,
    };
    process.stderr.write(
        `  model=${tr.hostModelMs.toFixed(4)}ms  engine=${tr.engineInternalMs.toFixed(4)}ms  wall=${tr.wallClockMs.toFixed(4)}ms  ${tr.errors}E ${tr.warnings}W ${tr.informational}I\n`,
    );
    results.push(tr);
}

const totalWallMs = performance.now() - benchStart;
try {
    engine.free();
} catch {}

const ok = results.filter((r) => r.status === 'ok');
const failures = results.filter((r) => r.status !== 'ok');

const isNumber = (v: number | null): v is number => v !== null;

const schemaInitStats = new Stats(schemaInitSamples);
const engineInitStats = new Stats(engineInitSamples);
const initStats = new Stats(initSamples);
const subsequentInitStats = new Stats(subsequentInitSamples);

const modelBuildStats = new Stats(ok.map((r) => r.modelBuildMs));
const schemaValidateStats = new Stats(ok.map((r) => r.schemaValidateMs));
const ruleEvalStats = new Stats(ok.map((r) => r.ruleEvalMs));
const finalizeStats = new Stats(ok.map((r) => r.diagnosticFinalizeMs));
const engineInternalStats = new Stats(ok.map((r) => r.engineInternalMs));
const firstMeasuredEngineInternalStats = new Stats(ok.map((r) => r.firstMeasuredEngineInternalMs));
const subsequentEngineInternalStats = new Stats(ok.map((r) => r.subsequentEngineInternalMs).filter(isNumber));
const wallClockStats = new Stats(ok.map((r) => r.wallClockMs));
const firstMeasuredWallClockStats = new Stats(ok.map((r) => r.firstMeasuredWallClockMs));
const subsequentWallClockStats = new Stats(ok.map((r) => r.subsequentWallClockMs).filter(isNumber));
const hostModelStats = new Stats(ok.map((r) => r.hostModelMs));
const firstMeasuredHostModelStats = new Stats(ok.map((r) => r.firstMeasuredHostModelMs));
const subsequentHostModelStats = new Stats(ok.map((r) => r.subsequentHostModelMs).filter(isNumber));
const overheadStats = new Stats(ok.map((r) => r.bindingOverheadMs));

// Throughput denominator: sum of host-timed validate calls for successful templates only.
// This excludes file I/O, standalone model benchmarks, logging overhead, and failures.
const measuredValidationWallMs = ok.reduce((s, r) => s + r.wallClockTotalMs, 0);
const throughputPerSec =
    measuredValidationWallMs > 0 ? (ok.length * iterations) / (measuredValidationWallMs / 1000) : 0;

const { fingerprint: corpusFingerprint, fileCount: corpusFileCount } = computeCorpusFingerprint(templateDir);
const runFingerprint = crypto
    .createHash('sha256')
    .update(`${corpusFingerprint}|${engineFlag}|${formatFlag}|${iterations}`)
    .digest('hex');

// Provenance is queried only after every timed measurement above so the
// cargo/rustc --version subprocess spawns cannot contaminate the numbers.
const provenance = provenanceJson();

const aggregate = {
    timestamp: new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
    engine: engineFlag,
    binding: 'wasm',
    detail_level: formatFlag,
    template_dir: templateDir,
    provenance,
    templates_total: results.length,
    templates_ok: ok.length,
    templates_failed: failures.length,
    iterations_per_template: iterations,
    corpus_fingerprint: corpusFingerprint,
    corpus_file_count: corpusFileCount,
    run_fingerprint: runFingerprint,
    performance: {
        module_load_ms: round4(moduleLoadMs),
        startup: startupSectionJson(startup),
        init_ms: initStats.toJson(),
        cold_init_ms: round4(coldInitMs),
        warm_init_ms: subsequentInitStats.toJson(),
        subsequent_init_ms: subsequentInitStats.toJson(),
        schema_init_ms: schemaInitStats.toJson(),
        engine_init_ms: engineInitStats.toJson(),
        total_wall_ms: round4(totalWallMs),
        measured_validation_wall_ms: round4(measuredValidationWallMs),
        throughput_per_sec: round4(throughputPerSec),
        model_build_ms: modelBuildStats.toJson(),
        schema_validate_ms: schemaValidateStats.toJson(),
        rule_evaluation_ms: ruleEvalStats.toJson(),
        diagnostic_finalize_ms: finalizeStats.toJson(),
        engine_internal_ms: engineInternalStats.toJson(),
        first_measured_engine_internal_ms: firstMeasuredEngineInternalStats.toJson(),
        subsequent_engine_internal_ms: subsequentEngineInternalStats.toJson(),
        // Legacy aliases: cold == first measured, warm == subsequent.
        cold_engine_internal_ms: firstMeasuredEngineInternalStats.toJson(),
        warm_engine_internal_ms: subsequentEngineInternalStats.toJson(),
        wall_clock_ms: wallClockStats.toJson(),
        first_measured_wall_clock_ms: firstMeasuredWallClockStats.toJson(),
        subsequent_wall_clock_ms: subsequentWallClockStats.toJson(),
        cold_wall_clock_ms: firstMeasuredWallClockStats.toJson(),
        warm_wall_clock_ms: subsequentWallClockStats.toJson(),
        host_model_ms: hostModelStats.toJson(),
        first_measured_host_model_ms: firstMeasuredHostModelStats.toJson(),
        subsequent_host_model_ms: subsequentHostModelStats.toJson(),
        cold_host_model_ms: firstMeasuredHostModelStats.toJson(),
        warm_host_model_ms: subsequentHostModelStats.toJson(),
        binding_overhead_ms: overheadStats.toJson(),
    },
    diagnostics: {
        total_fatal: ok.reduce((s, r) => s + r.fatal, 0),
        total_errors: ok.reduce((s, r) => s + r.errors, 0),
        total_warnings: ok.reduce((s, r) => s + r.warnings, 0),
        total_informational: ok.reduce((s, r) => s + r.informational, 0),
    },
    failures: failures.map((r) => ({ file: r.file, status: r.status, error: r.errorMsg })),
};

fs.writeFileSync(path.join(reportDir, `aggregate_${formatDir}.json`), JSON.stringify(aggregate, null, 2));
fs.writeFileSync(path.join(reportDir, `report_${formatDir}.md`), generateMarkdown(results, ok, failures));

console.error(`\nBenchmark complete: ${ok.length} ok, ${failures.length} failed (${iterations} iterations/template)`);
console.error(
    `startup: module_load=${round4(startup.moduleLoadMs)}ms  engine_init=${round4(startup.engineInitMs)}ms  first_validate=${round4(startup.first.hostMs)}ms`,
);
console.error(
    `schema_init (median): ${schemaInitStats.median.toFixed(4)}ms  engine_init (median): ${engineInitStats.median.toFixed(4)}ms`,
);
console.error(
    `engine_internal (median): median=${engineInternalStats.median.toFixed(4)}ms p99=${engineInternalStats.p99.toFixed(4)}ms max=${engineInternalStats.max.toFixed(4)}ms`,
);
console.error(
    `wall_clock     (median): median=${wallClockStats.median.toFixed(4)}ms p99=${wallClockStats.p99.toFixed(4)}ms max=${wallClockStats.max.toFixed(4)}ms`,
);
console.error(`Throughput: ${throughputPerSec.toFixed(2)} validations/sec`);
console.error(`Corpus fingerprint: ${corpusFingerprint} (${corpusFileCount} files)`);
console.error(`Reports written to ${reportDir}`);

function computeCorpusFingerprint(root: string): { fingerprint: string; fileCount: number } {
    const files = collectFiles(root);
    const outer = crypto.createHash('sha256');
    for (const f of files) {
        const content = fs.readFileSync(f);
        const fileHash = crypto.createHash('sha256').update(content).digest('hex');
        const rel = (path.relative(root, f) || path.basename(f)).replace(/\\/g, '/');
        outer.update(`${rel}\t${fileHash}\n`);
    }
    return { fingerprint: outer.digest('hex'), fileCount: files.length };
}

function generateMarkdown(
    allResults: TemplateResult[],
    okResults: TemplateResult[],
    failedResults: TemplateResult[],
): string {
    const lines: string[] = [];
    const push = (s: string) => lines.push(s);

    push(`# WASM Benchmark Report - ${engineFlag} engine (${formatFlag})\n`);
    push(`Generated: ${new Date().toISOString().replace(/\.\d+Z$/, 'Z')}\n`);
    push(`Corpus fingerprint: \`${corpusFingerprint}\` (${corpusFileCount} files)\n`);

    push('## Provenance\n');
    push('| Field | Value |\n|---|---|');
    push(`| cloudformation-validate (bridge) | ${provenance.cloudformation_validate} |`);
    push(`| Binding artifact (npm) | ${provenance.binding_artifact.version} |`);
    push(`| Cargo | ${provenance.cargo} |`);
    push(`| rustc | ${provenance.rustc} |`);
    push(`| Runtime | ${provenance.runtime} |`);

    push('\n## Summary\n');
    push('| Metric | Value |\n|---|---|');
    push(`| Templates | ${okResults.length} ok, ${failedResults.length} failed, ${allResults.length} total |`);
    push(`| Iterations per template | ${iterations} |`);
    push(`| Total resources | ${okResults.reduce((s, r) => s + r.resources, 0)} |`);
    push(`| Total wall time | ${totalWallMs.toFixed(4)} ms |`);
    push(`| Throughput | ${throughputPerSec.toFixed(2)} validations/sec |`);
    push(`| Detail level | ${formatFlag} |`);

    push('\n## Process Startup (single cold sequence)\n');
    push(
        'The consumer engine constructed once, then the first validate call on that same engine - the process-cold path a consumer pays before any warmup. The engine is reused for the corpus below.\n',
    );
    push('| Metric | Value (ms) |\n|---|---|');
    push(`| Startup template | ${startup.startupTemplate} |`);
    push(`| Module load | ${round4(startup.moduleLoadMs).toFixed(4)} |`);
    push(`| Consumer init (${startup.consumerInitScope}) | ${round4(startup.consumerInitMs).toFixed(4)} |`);
    push(`| First validation (host) | ${round4(startup.first.hostMs).toFixed(4)} |`);
    push(`| First validation (internal) | ${round4(startup.first.internalMs).toFixed(4)} |`);
    push(`| Internal time-to-first-result | ${round4(startup.internalTimeToFirstResultMs).toFixed(4)} |`);

    push('\n## Initialization (ms)\n');
    push('Schema init is timed standalone for comparison but is **not additive** for FFI consumers:');
    push(
        'the engine constructor already embeds a SchemaValidator. `init_ms` = engine construction only (actual consumer setup cost).\n',
    );
    push('| Stat | Schema Init (standalone) | Engine Init | Init (engine only) |\n|---|---|---|---|');
    push(
        `| Median | ${schemaInitStats.median.toFixed(4)} | ${engineInitStats.median.toFixed(4)} | ${initStats.median.toFixed(4)} |`,
    );
    push(
        `| P99 | ${schemaInitStats.p99.toFixed(4)} | ${engineInitStats.p99.toFixed(4)} | ${initStats.p99.toFixed(4)} |`,
    );
    push(
        `| Max | ${schemaInitStats.max.toFixed(4)} | ${engineInitStats.max.toFixed(4)} | ${initStats.max.toFixed(4)} |`,
    );

    push('\n## Validation Latency (ms, median / p99 / max per template)\n');
    push('host_model = JS-side timer around WasmSemanticModel.parse (includes WASM dispatch).');
    push('wall_clock = JS-side timer around validateDetailed() (includes WASM dispatch + marshalling).');
    push('engine_internal = Rust-internal `report.performance.validateTotal` (engine work only).');
    push('binding_overhead = median of per-iteration (wall_clock − engine_internal) differences.');
    push(
        'First measured = iteration 1 per template (warm at process level). Subsequent = median of iterations 2..N (empty when N=1).\n',
    );
    push('| Metric | Median | P99 | Max |\n|---|---|---|---|');
    const row = (label: string, s: Stats) =>
        `| ${label} | ${s.median.toFixed(4)} | ${s.p99.toFixed(4)} | ${s.max.toFixed(4)} |`;
    push(row('host_model - first measured', firstMeasuredHostModelStats));
    push(row('host_model - subsequent', subsequentHostModelStats));
    push(row('engine_internal - first measured', firstMeasuredEngineInternalStats));
    push(row('engine_internal - subsequent', subsequentEngineInternalStats));
    push(row('wall_clock - first measured', firstMeasuredWallClockStats));
    push(row('wall_clock - subsequent', subsequentWallClockStats));
    push(row('host_model (per-template median)', hostModelStats));
    push(row('engine_internal (per-template median)', engineInternalStats));
    push(row('wall_clock (per-template median)', wallClockStats));
    push(row('Model build (rust-internal)', modelBuildStats));
    push(row('Schema validate (rust-internal)', schemaValidateStats));
    push(row('Rule evaluation (rust-internal)', ruleEvalStats));
    push(row('Diagnostic finalize (rust-internal)', finalizeStats));
    push(row('Binding overhead (wall − internal)', overheadStats));

    push('\n## Diagnostics\n');
    push('| Level | Count |\n|---|---|');
    push(`| Fatal | ${okResults.reduce((s, r) => s + r.fatal, 0)} |`);
    push(`| Errors | ${okResults.reduce((s, r) => s + r.errors, 0)} |`);
    push(`| Warnings | ${okResults.reduce((s, r) => s + r.warnings, 0)} |`);
    push(`| Informational | ${okResults.reduce((s, r) => s + r.informational, 0)} |`);

    push('\n## All Results\n');
    const sorted = [...allResults].sort((a, b) => b.wallClockMs - a.wallClockMs);
    push(
        '| # | Template | Status | Size | Resources | Model (ms) | Schema (ms) | Rules (ms) | Finalize (ms) | Engine (ms) | Wall (ms) | Overhead (ms) | F | E | W | I | Diags |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|',
    );
    sorted.forEach((r, i) => {
        if (r.status === 'ok') {
            push(
                `| ${i + 1} | ${r.file} | ✅ | ${fmtBytes(r.sizeBytes)} | ${r.resources} | ${r.modelBuildMs.toFixed(4)} | ${r.schemaValidateMs.toFixed(4)} | ${r.ruleEvalMs.toFixed(4)} | ${r.diagnosticFinalizeMs.toFixed(4)} | ${r.engineInternalMs.toFixed(4)} | ${r.wallClockMs.toFixed(4)} | ${r.bindingOverheadMs.toFixed(4)} | ${r.fatal} | ${r.errors} | ${r.warnings} | ${r.informational} | ${r.diagCount} |`,
            );
        } else {
            push(
                `| ${i + 1} | ${r.file} | ❌ ${r.status} | - | - | - | - | - | - | - | - | - | - | 0 | 0 | 0 | 0 | 0 |`,
            );
        }
    });

    if (failedResults.length > 0) {
        push('\n## Failures\n');
        for (const r of failedResults) {
            push(`- **${r.file}**: ${r.status} - ${r.errorMsg ?? 'unknown'}`);
        }
    }

    return lines.join('\n') + '\n';
}
