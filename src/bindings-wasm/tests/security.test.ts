import { describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { Worker } from 'node:worker_threads';

const SECURITY_ROOT = path.resolve(__dirname, '../../resources/security');
const WASM_PACKAGE = path.resolve(__dirname, '../dist');
const SECURITY_TIMEOUT_MS = 60_000;

function discoverSecurityTemplates(directory: string): string[] {
    const templates: string[] = [];
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
        const fullPath = path.join(directory, entry.name);
        if (entry.isDirectory()) {
            templates.push(...discoverSecurityTemplates(fullPath));
        } else if (/\.(json|yaml|yml)$/.test(entry.name)) {
            templates.push(fullPath);
        }
    }
    return templates.sort();
}

interface WorkerResult {
    ok: boolean;
    structuredError?: string;
    reportStatus?: string;
    budgetExhaustionCount?: number;
    budgetDescription?: string;
    diagnosticCount?: number;
}

function validateInWorker(engineName: string, templatePath: string): Promise<WorkerResult> {
    const source = `
        const { parentPort, workerData } = require('node:worker_threads');
        const { CelEngine, RegoEngine, CompositeEngine, TemplateFile } = require(workerData.packagePath);
        const engines = { rego: RegoEngine, cel: CelEngine, composite: CompositeEngine };
        const Engine = engines[workerData.engineName];
        const engine = new Engine();
        try {
            const report = engine.validateTemplate(
                new TemplateFile(workerData.templatePath),
                { severityLevel: 'DEBUG', detailLevel: 'DETAILED' },
            );
            parentPort.postMessage({
                ok: true,
                reportStatus: report.status,
                budgetExhaustionCount: report.metadata.budgetExhaustions?.length,
                budgetDescription: report.metadata.budgetExhaustions?.[0]?.description,
                diagnosticCount: report.diagnostics.length,
            });
        } catch (error) {
            parentPort.postMessage({
                ok: false,
                structuredError: error instanceof Error ? error.message : String(error),
            });
        } finally {
            engine.free();
        }
    `;
    return new Promise((resolve, reject) => {
        const worker = new Worker(source, {
            eval: true,
            workerData: { engineName, packagePath: WASM_PACKAGE, templatePath },
        });
        const timeout = setTimeout(() => {
            void worker.terminate();
            reject(new Error(`${engineName}/${path.basename(templatePath)} exceeded ${SECURITY_TIMEOUT_MS}ms`));
        }, SECURITY_TIMEOUT_MS);
        worker.once('message', (message: WorkerResult) => {
            clearTimeout(timeout);
            void worker.terminate();
            resolve(message);
        });
        worker.once('error', (error) => {
            clearTimeout(timeout);
            reject(error);
        });
        worker.once('exit', (code) => {
            if (code !== 0) {
                clearTimeout(timeout);
                reject(new Error(`${engineName}/${path.basename(templatePath)} worker exited with status ${code}`));
            }
        });
    });
}

const securityTemplates = discoverSecurityTemplates(SECURITY_ROOT);

describe('security templates', () => {
    it('discovers templates only from resources/security', () => {
        expect(securityTemplates.length).toBeGreaterThan(0);
        expect(securityTemplates.every((template) => template.startsWith(`${SECURITY_ROOT}${path.sep}`))).toBe(true);
    });

    for (const engineName of ['rego', 'cel', 'composite']) {
        for (const templatePath of securityTemplates) {
            const templateName = path.relative(SECURITY_ROOT, templatePath).replace(/\\/g, '/');
            it(
                `${engineName}/${templateName}`,
                async () => {
                    const outcome = await validateInWorker(engineName, templatePath);
                    if (templateName === 'deep_nesting.json' && !outcome.ok) {
                        expect(outcome.structuredError).toBeTruthy();
                        return;
                    }
                    expect(outcome.ok, outcome.structuredError).toBe(true);
                    expect(outcome.reportStatus).toBeDefined();
                    if (templateName === 'scenario_assignment_budget.yaml') {
                        expect(outcome.reportStatus).toBe('ANALYSIS_INCOMPLETE');
                        expect(outcome.budgetExhaustionCount).toBeGreaterThan(0);
                        expect(outcome.budgetDescription).toMatch(/\.$/);
                    }
                    if (templateName === 'condition_fusion.yaml') {
                        expect(outcome.budgetExhaustionCount).toBeUndefined();
                    }
                    expect(outcome.diagnosticCount).toBeGreaterThanOrEqual(0);
                },
                SECURITY_TIMEOUT_MS + 5_000,
            );
        }
    }
});

const PANICKING_REGO_RULE = [
    'package panic_test',
    'import rego.v1',
    'violation contains finding if {',
    '    value := rand.intn("panic-test", 10)',
    '    finding := {"rule_id": "PANIC_TEST", "severity": "ERROR", "message": sprintf("value: %v", [value])}',
    '}',
].join('\n');

const TERMINATED_INSTANCE_MESSAGE = 'terminated by an earlier failure';

const WORKER_PRELUDE = `
    const { parentPort, workerData } = require('node:worker_threads');
    console.error = () => {};
    const outcomeOf = (operation) => {
        try {
            return { ok: true, value: operation() };
        } catch (error) {
            return {
                ok: false,
                name: error?.constructor?.name,
                message: error?.message,
                isRuntimeError: error instanceof WebAssembly.RuntimeError,
                causeName: error?.cause?.constructor?.name,
                causeMessage: error?.cause?.message,
            };
        }
    };
`;

function runLifecycleWorker(body: string): Promise<any> {
    return new Promise((resolve, reject) => {
        const worker = new Worker(WORKER_PRELUDE + body, {
            eval: true,
            workerData: { packagePath: WASM_PACKAGE, panickingRule: PANICKING_REGO_RULE },
        });
        worker.once('message', resolve);
        worker.once('error', reject);
        worker.once('exit', (code) => {
            if (code !== 0) {
                reject(new Error(`lifecycle worker exited with status ${code}`));
            }
        });
    });
}

describe('WASM instance containment', () => {
    it('isolates a preloaded bridge, retires every object after panic, and recovers with a fresh instance', async () => {
        const outcome = await runLifecycleWorker(`
            Object.defineProperty(globalThis, 'crypto', { value: undefined, configurable: true });
            const bridgePath = require.resolve(workerData.packagePath + '/bindings_wasm.js');
            const preloadedBridge = require(bridgePath);
            const validator = require(workerData.packagePath);
            const packageEntryPath = require.resolve(workerData.packagePath);
            const wrapperBridgeIsIsolated = require.cache[bridgePath].exports !== preloadedBridge;
            const sibling = new validator.TemplateModel(new validator.TemplateContent('Resources: {}'));
            const engine = new validator.RegoEngine({
                customRules: [{ name: 'panic.rego', content: workerData.panickingRule }],
            });
            const trap = outcomeOf(() => engine.validateTemplate(new validator.TemplateContent('Resources: {}')));
            const sameEngine = outcomeOf(() => engine.listRules());
            const siblingAfterTrap = outcomeOf(() => sibling.resources());
            const freeAfterTrap = outcomeOf(() => {
                engine.free();
                sibling.free();
            });
            const replacement = new validator.CelEngine();
            const replacementStatus = replacement.validateTemplate(new validator.TemplateContent('Resources: {}')).status;
            replacement.free();
            const retainedBridgeCount = require.cache[packageEntryPath].children.filter(
                (child) => child.filename === bridgePath,
            ).length;
            parentPort.postMessage({
                trap,
                sameEngine,
                siblingAfterTrap,
                freeAfterTrap,
                replacementStatus,
                retainedBridgeCount,
                wrapperBridgeIsIsolated,
            });
        `);

        expect(outcome.trap.isRuntimeError).toBe(true);
        expect(outcome.trap.message).toContain('could not initialize ThreadRng: Web Crypto API is unavailable');
        expect(outcome.trap.causeName).toBe('RuntimeError');
        expect(outcome.trap.causeMessage).toBe('unreachable');
        expect(outcome.sameEngine.message).toContain(TERMINATED_INSTANCE_MESSAGE);
        expect(outcome.siblingAfterTrap.message, 'poisoning must be instance-wide').toContain(
            TERMINATED_INSTANCE_MESSAGE,
        );
        expect(outcome.freeAfterTrap.ok, 'free() must not re-enter a terminated instance').toBe(true);
        expect(outcome.replacementStatus).toBe('OK');
        expect(outcome.wrapperBridgeIsIsolated, 'the wrapper must replace a preloaded raw bridge').toBe(true);
        expect(outcome.retainedBridgeCount, 'the terminated bridge must not remain a CommonJS child').toBe(1);
    });

    it('surfaces a host exception that escapes an export unchanged and retires the interrupted instance', async () => {
        const outcome = await runLifecycleWorker(`
            const validator = require(workerData.packagePath);
            const sibling = new validator.TemplateModel(new validator.TemplateContent('Resources: {}'));
            const engine = new validator.CelEngine();
            const originalEntries = Object.entries;
            let failNextEntries = false;
            Object.entries = (value) => {
                if (failNextEntries) {
                    failNextEntries = false;
                    throw new TypeError('host reflection failed');
                }
                return originalEntries(value);
            };
            failNextEntries = true;
            const escaped = outcomeOf(() =>
                engine.validateTemplate(new validator.TemplateContent('Resources: {}'), {
                    parameterOverrides: { Stage: 'prod' },
                }),
            );
            Object.entries = originalEntries;
            const sameEngine = outcomeOf(() => engine.listRules());
            const siblingAfterEscape = outcomeOf(() => sibling.resources());
            const replacement = new validator.CelEngine();
            const replacementStatus = replacement.validateTemplate(new validator.TemplateContent('Resources: {}')).status;
            replacement.free();
            parentPort.postMessage({ escaped, sameEngine, siblingAfterEscape, replacementStatus });
        `);

        expect(outcome.escaped.name).toBe('TypeError');
        expect(outcome.escaped.message).toBe('host reflection failed');
        expect(outcome.sameEngine.message).toContain(TERMINATED_INSTANCE_MESSAGE);
        expect(outcome.siblingAfterEscape.message).toContain(TERMINATED_INSTANCE_MESSAGE);
        expect(outcome.replacementStatus).toBe('OK');
    });

    it('fails closed when the module loader returns the terminated bridge after eviction', async () => {
        const outcome = await runLifecycleWorker(`
            Object.defineProperty(globalThis, 'crypto', { value: undefined, configurable: true });
            const Module = require('node:module');
            const validator = require(workerData.packagePath);
            const bridgePath = require.resolve(workerData.packagePath + '/bindings_wasm.js');
            const terminatedBridge = require.cache[bridgePath].exports;
            const engine = new validator.RegoEngine({
                customRules: [{ name: 'panic.rego', content: workerData.panickingRule }],
            });
            const trap = outcomeOf(() => engine.validateTemplate(new validator.TemplateContent('Resources: {}')));
            const originalLoad = Module._load;
            Module._load = (request, parent, isMain) => {
                const resolved = Module._resolveFilename(request, parent, isMain);
                return resolved === bridgePath ? terminatedBridge : originalLoad(request, parent, isMain);
            };
            const blockedRecovery = outcomeOf(() => new validator.CelEngine());
            Module._load = originalLoad;
            const replacement = new validator.CelEngine();
            const replacementStatus = replacement.validateTemplate(new validator.TemplateContent('Resources: {}')).status;
            replacement.free();
            parentPort.postMessage({ trap, blockedRecovery, replacementStatus });
        `);

        expect(outcome.trap.isRuntimeError).toBe(true);
        expect(outcome.blockedRecovery.isRuntimeError).toBe(true);
        expect(outcome.blockedRecovery.message).toContain('cannot create a fresh one');
        expect(outcome.replacementStatus).toBe('OK');
    });
});
