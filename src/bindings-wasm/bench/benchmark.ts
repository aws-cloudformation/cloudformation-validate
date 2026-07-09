#!/usr/bin/env npx ts-node
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { performance } from 'perf_hooks';

// Measure WASM module instantiation (V8 compiles + runs wasm_bindgen #[start]).
const moduleLoadStart = performance.now();
const wasmBindings = require('@aws/cloudformation-validate');
const moduleLoadMs = performance.now() - moduleLoadStart;

import type { DetailedReport, EngineConfig, ValidateConfig } from '@aws/cloudformation-validate';
import type {
    WasmCelEngine as WasmCelEngineType,
    WasmRegoEngine as WasmRegoEngineType,
} from '@aws/cloudformation-validate/bindings_wasm';
type WasmEngine = WasmRegoEngineType | WasmCelEngineType;

const { SchemaValidator } = wasmBindings;

// Raw WASM bindings — accept Uint8Array directly, no file I/O.
// The public package re-exports wrapper classes that read from File/TemplateFile;
// the benchmark needs the inner classes to pass pre-read bytes.
const wasmRaw = require('@aws/cloudformation-validate/bindings_wasm');
const WasmSemanticModel: { parse(bytes: Uint8Array): { free(): void } } = wasmRaw.WasmSemanticModel;

const args = process.argv.slice(2);
if (args.includes('-h') || args.includes('--help')) {
    console.error('Usage: npx ts-node benchmark.ts [TEMPLATE|DIR] [--engine rego|cel] [--iterations N]');
    process.exit(2);
}

function argValue(flag: string): string | undefined {
    const idx = args.indexOf(flag);
    return idx >= 0 ? args[idx + 1] : undefined;
}

const DEFAULT_TEMPLATE_DIR = path.resolve(__dirname, '../../resources/templates');
const FLAGS_WITH_VALUES = new Set(['--engine', '--iterations']);
const templateDirArg = (() => {
    for (let i = 0; i < args.length; i++) {
        if (FLAGS_WITH_VALUES.has(args[i])) {
            i++;
            continue;
        }
        if (!args[i].startsWith('-')) return args[i];
    }
    return undefined;
})();
const templateDir = templateDirArg ?? DEFAULT_TEMPLATE_DIR;

const engineFlag = argValue('--engine') ?? 'rego';
const formatFlag = 'DETAILED';
const formatDir = 'detailed';
const iterations = Math.max(1, parseInt(argValue('--iterations') ?? '20', 10));

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
            else if (entry.isFile() && TEMPLATE_EXTENSIONS.has(path.extname(entry.name).toLowerCase()))
                results.push(full);
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
    readonly coldHostModelMs: number;
    readonly warmHostModelMs: number;
    readonly modelBuildMs: number;
    readonly schemaValidateMs: number;
    readonly ruleEvalMs: number;
    readonly diagnosticFinalizeMs: number;
    readonly engineInternalMs: number;
    readonly coldEngineInternalMs: number;
    readonly warmEngineInternalMs: number;
    readonly wallClockMs: number;
    readonly coldWallClockMs: number;
    readonly warmWallClockMs: number;
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
        coldHostModelMs: 0,
        warmHostModelMs: 0,
        modelBuildMs: 0,
        schemaValidateMs: 0,
        ruleEvalMs: 0,
        diagnosticFinalizeMs: 0,
        engineInternalMs: 0,
        coldEngineInternalMs: 0,
        warmEngineInternalMs: 0,
        wallClockMs: 0,
        coldWallClockMs: 0,
        warmWallClockMs: 0,
        bindingOverheadMs: 0,
        errorMsg: msg,
    };
}

const engineConfig: EngineConfig = {
    customRules: [],
    guardRules: [],
};
function newEngine(): WasmEngine {
    return engineFlag === 'cel' ? new wasmRaw.WasmCelEngine(engineConfig) : new wasmRaw.WasmRegoEngine(engineConfig);
}

const templates = collectFiles(templateDir);
if (templates.length === 0) {
    console.error(`No templates found in ${templateDir}`);
    process.exit(1);
}
console.error(
    `Benchmarking ${templates.length} templates, ${iterations} iterations, engine=${engineFlag}, format=${formatFlag}`,
);

const schemaInitSamples: number[] = [];
const engineInitSamples: number[] = [];
for (let i = 0; i < iterations; i++) {
    const t0 = performance.now();
    const sv = new SchemaValidator();
    schemaInitSamples.push(performance.now() - t0);
    sv.free();

    const t1 = performance.now();
    const eng = newEngine();
    engineInitSamples.push(performance.now() - t1);
    eng.free();
}
const initSamples = schemaInitSamples.map((s, i) => s + engineInitSamples[i]);
// cold_init_ms includes WASM module instantiation + first schema init + first engine init.
const coldInitMs = moduleLoadMs + initSamples[0];
const warmInitSamples = initSamples.length > 1 ? initSamples.slice(1) : initSamples.slice();

const engine = newEngine();

const reportDir = path.resolve(__dirname, `../reports/${engineFlag}`);
const jsonDir = path.join(reportDir, `json_${formatDir}`);
fs.mkdirSync(jsonDir, { recursive: true });

const validateConfig: ValidateConfig = {
    severityLevel: 'DEBUG',
    strict: false,
};

if (templates.length > 0) {
    const warmupBytes = fs.readFileSync(templates[0]);
    try {
        WasmSemanticModel.parse(warmupBytes);
    } catch {}
    try {
        engine.validateDetailed(warmupBytes, validateConfig, templates[0]);
    } catch {}
}

const pendingWrites: Array<[string, Record<string, unknown>]> = [];
const results: TemplateResult[] = [];
const benchStart = performance.now();

for (const tpl of templates) {
    const rel = path.relative(templateDir, tpl).replace(/^\//, '') || path.basename(tpl);
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
        try {
            const tm0 = performance.now();
            const parsed = WasmSemanticModel.parse(bytes);
            iterHostModel.push(performance.now() - tm0);
            try {
                parsed.free();
            } catch {}

            const t0 = performance.now();
            const report = engine.validateDetailed(bytes, validateConfig, rel);
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
    const coldEngineInternalMs = iterEngineInternal[0];
    const warmEngineInternalMs = iterations > 1 ? new Stats(iterEngineInternal.slice(1)).median : coldEngineInternalMs;
    const medianEngineInternal = new Stats(iterEngineInternal).median;
    const coldWallClockMs = iterWallClock[0];
    const warmWallClockMs = iterations > 1 ? new Stats(iterWallClock.slice(1)).median : coldWallClockMs;
    const medianWallClock = new Stats(iterWallClock).median;
    const coldHostModelMs = iterHostModel[0];
    const warmHostModelMs = iterations > 1 ? new Stats(iterHostModel.slice(1)).median : coldHostModelMs;
    const medianHostModel = new Stats(iterHostModel).median;
    const bindingOverheadMs = round4(medianWallClock - medianEngineInternal);

    const jsonStem = rel.replace(/\//g, '_').replace(/\.(yaml|json|yml)$/g, '');
    pendingWrites.push([
        path.join(jsonDir, `${jsonStem}.json`),
        {
            ...report,
            filePath: rel,
            engine: engineFlag,
            binding: 'wasm',
            detailLevel: formatFlag,
            benchmarkMetrics: {
                iterations,
                firstIteration: {
                    hostModelMs: round4(iterHostModel[0]),
                    modelBuildMs: round4(iterModelBuild[0]),
                    schemaValidateMs: round4(iterSchemaValidate[0]),
                    ruleEvaluationMs: round4(iterRuleEval[0]),
                    diagnosticFinalizeMs: round4(iterFinalize[0]),
                    engineInternalMs: round4(coldEngineInternalMs),
                    wallClockMs: round4(coldWallClockMs),
                },
                steadyState: {
                    hostModelMs: round4(warmHostModelMs),
                    modelBuildMs: round4(
                        iterations > 1 ? new Stats(iterModelBuild.slice(1)).median : iterModelBuild[0],
                    ),
                    schemaValidateMs: round4(
                        iterations > 1 ? new Stats(iterSchemaValidate.slice(1)).median : iterSchemaValidate[0],
                    ),
                    ruleEvaluationMs: round4(
                        iterations > 1 ? new Stats(iterRuleEval.slice(1)).median : iterRuleEval[0],
                    ),
                    diagnosticFinalizeMs: round4(
                        iterations > 1 ? new Stats(iterFinalize.slice(1)).median : iterFinalize[0],
                    ),
                    engineInternalMs: round4(warmEngineInternalMs),
                    wallClockMs: round4(warmWallClockMs),
                },
                bindingOverheadMs,
            },
        },
    ]);

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
        coldHostModelMs,
        warmHostModelMs,
        modelBuildMs: new Stats(iterModelBuild).median,
        schemaValidateMs: new Stats(iterSchemaValidate).median,
        ruleEvalMs: new Stats(iterRuleEval).median,
        diagnosticFinalizeMs: new Stats(iterFinalize).median,
        engineInternalMs: medianEngineInternal,
        coldEngineInternalMs,
        warmEngineInternalMs,
        wallClockMs: medianWallClock,
        coldWallClockMs,
        warmWallClockMs,
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

for (const [dest, payload] of pendingWrites) {
    fs.writeFileSync(dest, JSON.stringify(payload, null, 2));
}

const ok = results.filter((r) => r.status === 'ok');
const failures = results.filter((r) => r.status !== 'ok');

const schemaInitStats = new Stats(schemaInitSamples);
const engineInitStats = new Stats(engineInitSamples);
const initStats = new Stats(initSamples);
const warmInitStats = new Stats(warmInitSamples);

const modelBuildStats = new Stats(ok.map((r) => r.modelBuildMs));
const schemaValidateStats = new Stats(ok.map((r) => r.schemaValidateMs));
const ruleEvalStats = new Stats(ok.map((r) => r.ruleEvalMs));
const finalizeStats = new Stats(ok.map((r) => r.diagnosticFinalizeMs));
const engineInternalStats = new Stats(ok.map((r) => r.engineInternalMs));
const coldEngineInternalStats = new Stats(ok.map((r) => r.coldEngineInternalMs));
const warmEngineInternalStats = new Stats(ok.map((r) => r.warmEngineInternalMs));
const wallClockStats = new Stats(ok.map((r) => r.wallClockMs));
const coldWallClockStats = new Stats(ok.map((r) => r.coldWallClockMs));
const warmWallClockStats = new Stats(ok.map((r) => r.warmWallClockMs));
const hostModelStats = new Stats(ok.map((r) => r.hostModelMs));
const coldHostModelStats = new Stats(ok.map((r) => r.coldHostModelMs));
const warmHostModelStats = new Stats(ok.map((r) => r.warmHostModelMs));
const overheadStats = new Stats(ok.map((r) => r.bindingOverheadMs));

const throughputPerSec = totalWallMs > 0 ? (ok.length * iterations) / (totalWallMs / 1000) : 0;

const { fingerprint: corpusFingerprint, fileCount: corpusFileCount } = computeCorpusFingerprint(templateDir);
const runFingerprint = crypto
    .createHash('sha256')
    .update(`${corpusFingerprint}|${engineFlag}|${formatFlag}|${iterations}`)
    .digest('hex');

const aggregate = {
    timestamp: new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
    engine: engineFlag,
    binding: 'wasm',
    detail_level: formatFlag,
    template_dir: templateDir,
    templates_total: results.length,
    templates_ok: ok.length,
    templates_failed: failures.length,
    iterations_per_template: iterations,
    corpus_fingerprint: corpusFingerprint,
    corpus_file_count: corpusFileCount,
    run_fingerprint: runFingerprint,
    performance: {
        module_load_ms: round4(moduleLoadMs),
        init_ms: initStats.toJson(),
        cold_init_ms: round4(coldInitMs),
        warm_init_ms: warmInitStats.toJson(),
        schema_init_ms: schemaInitStats.toJson(),
        engine_init_ms: engineInitStats.toJson(),
        total_wall_ms: round4(totalWallMs),
        throughput_per_sec: round4(throughputPerSec),
        model_build_ms: modelBuildStats.toJson(),
        schema_validate_ms: schemaValidateStats.toJson(),
        rule_evaluation_ms: ruleEvalStats.toJson(),
        diagnostic_finalize_ms: finalizeStats.toJson(),
        engine_internal_ms: engineInternalStats.toJson(),
        cold_engine_internal_ms: coldEngineInternalStats.toJson(),
        warm_engine_internal_ms: warmEngineInternalStats.toJson(),
        wall_clock_ms: wallClockStats.toJson(),
        cold_wall_clock_ms: coldWallClockStats.toJson(),
        warm_wall_clock_ms: warmWallClockStats.toJson(),
        host_model_ms: hostModelStats.toJson(),
        cold_host_model_ms: coldHostModelStats.toJson(),
        warm_host_model_ms: warmHostModelStats.toJson(),
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
        const rel = path.relative(root, f) || path.basename(f);
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

    push(`# WASM Benchmark Report — ${engineFlag} engine (${formatFlag})\n`);
    push(`Generated: ${new Date().toISOString().replace(/\.\d+Z$/, 'Z')}\n`);
    push(`Corpus fingerprint: \`${corpusFingerprint}\` (${corpusFileCount} files)\n`);

    push('## Summary\n');
    push('| Metric | Value |\n|---|---|');
    push(`| Templates | ${okResults.length} ok, ${failedResults.length} failed, ${allResults.length} total |`);
    push(`| Iterations per template | ${iterations} |`);
    push(`| Total resources | ${okResults.reduce((s, r) => s + r.resources, 0)} |`);
    push(`| Total wall time | ${totalWallMs.toFixed(4)} ms |`);
    push(`| Throughput | ${throughputPerSec.toFixed(2)} validations/sec |`);
    push(`| Detail level | ${formatFlag} |`);

    push('\n## Initialization (ms)\n');
    push('| Stat | Schema Init | Engine Init | Combined |\n|---|---|---|---|');
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
    push('| Metric | Median | P99 | Max |\n|---|---|---|---|');
    const row = (label: string, s: Stats) =>
        `| ${label} | ${s.median.toFixed(4)} | ${s.p99.toFixed(4)} | ${s.max.toFixed(4)} |`;
    push(row('Cold host_model (first iter)', coldHostModelStats));
    push(row('Warm host_model (steady)', warmHostModelStats));
    push(row('Cold engine_internal (first iter)', coldEngineInternalStats));
    push(row('Warm engine_internal (steady)', warmEngineInternalStats));
    push(row('Cold wall_clock (first iter)', coldWallClockStats));
    push(row('Warm wall_clock (steady)', warmWallClockStats));
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
            push(`- **${r.file}**: ${r.status} — ${r.errorMsg ?? 'unknown'}`);
        }
    }

    return lines.join('\n') + '\n';
}
