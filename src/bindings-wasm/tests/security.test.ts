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
        const { CelEngine, RegoEngine, TemplateFile } = require(workerData.packagePath);
        const Engine = workerData.engineName === 'rego' ? RegoEngine : CelEngine;
        const engine = new Engine();
        try {
            const report = engine.validateDetailed(
                new TemplateFile(workerData.templatePath),
                { severityLevel: 'DEBUG' },
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

    for (const engineName of ['rego', 'cel']) {
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
