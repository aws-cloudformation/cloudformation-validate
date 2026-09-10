import { describe, expect, it } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const {
    RegoEngine,
    CelEngine,
    CompositeEngine,
    SchemaValidator,
    SchemaFile,
    TemplateModel,
    TemplateFile,
    version,
} = require('@aws/cloudformation-validate');

const TEMPLATES_ROOT = path.resolve(__dirname, '../../resources/templates');
const RULES_DIR = path.resolve(__dirname, '../../resources/rules');
const EXPECTED_DIR = path.resolve(__dirname, '../../resources/expected');

function loadTemplate(rel: string): InstanceType<typeof TemplateFile> {
    return new TemplateFile(path.join(TEMPLATES_ROOT, rel));
}

function loadRule(filename: string): string {
    return fs.readFileSync(path.join(RULES_DIR, filename), 'utf-8');
}

const CHUNK_PREFIX = 'validation_reports';
const CHUNK_EXTENSION = '.json';

/**
 * Discover all numbered snapshot chunk files (validation_reportsN.json) in numeric
 * order and strictly merge them into a single map. Fails on no chunks, non-object
 * JSON, or duplicate template keys.
 */
function loadCombinedSnapshots(): Record<string, unknown> {
    const entries = fs.readdirSync(EXPECTED_DIR);
    const chunks: { index: number; path: string }[] = [];
    const pattern = new RegExp(`^${CHUNK_PREFIX}([1-9][0-9]*)${CHUNK_EXTENSION.replace('.', '\\.')}$`);
    for (const entry of entries) {
        const match = pattern.exec(entry);
        if (match) {
            const index = parseInt(match[1], 10);
            chunks.push({ index, path: path.join(EXPECTED_DIR, entry) });
        }
    }
    if (chunks.length === 0) {
        throw new Error(`no snapshot chunk files (${CHUNK_PREFIX}N${CHUNK_EXTENSION}) found in ${EXPECTED_DIR}`);
    }
    chunks.sort((a, b) => a.index - b.index);

    for (let i = 0; i < chunks.length; i++) {
        if (chunks[i].index !== i + 1) {
            throw new Error(
                `non-contiguous snapshot chunk sequence: expected index ${i + 1} but found ${chunks[i].index}`,
            );
        }
    }

    const merged: Record<string, unknown> = {};
    for (const chunk of chunks) {
        const data = JSON.parse(fs.readFileSync(chunk.path, 'utf-8'));
        if (typeof data !== 'object' || data === null || Array.isArray(data)) {
            throw new Error(`snapshot chunk ${path.basename(chunk.path)} is not a JSON object`);
        }
        for (const [key, value] of Object.entries(data)) {
            if (key in merged) {
                throw new Error(`duplicate template key "${key}" in chunk ${path.basename(chunk.path)}`);
            }
            merged[key] = value;
        }
    }
    return merged;
}

const COMBINED_SNAPSHOTS: Record<string, unknown> = loadCombinedSnapshots();

/**
 * Recursively discover all template files (.yaml/.yml/.json) under the templates
 * root, excluding security fixtures. Returns sorted forward-slash relative paths.
 */
function discoverAllTemplates(): string[] {
    if (!fs.existsSync(TEMPLATES_ROOT)) {
        throw new Error(`templates directory does not exist: ${TEMPLATES_ROOT}`);
    }
    const templates: string[] = [];
    function walk(dir: string) {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const full = path.join(dir, entry.name);
            if (entry.isDirectory()) walk(full);
            else if (/\.(yaml|yml|json)$/.test(entry.name)) {
                templates.push(path.relative(TEMPLATES_ROOT, full).replace(/\\/g, '/'));
            }
        }
    }
    walk(TEMPLATES_ROOT);
    if (templates.length === 0) {
        throw new Error(`no templates discovered in ${TEMPLATES_ROOT}`);
    }
    return templates.sort();
}

const EXPECTED_TEMPLATES = discoverAllTemplates();

const ENRICHMENT_DIAGNOSTIC_FIELDS = ['documentationUrl', 'context', 'ruleDescription', 'phase', 'section'];

const CEL = new CelEngine();
const REGO = new RegoEngine();
const COMPOSITE = new CompositeEngine();

const TEMPLATE_WITH_OVERLAY_PROPERTY = `
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
`;

const LAMBDA_OVERLAY_SCHEMA = `{
  "typeName": "AWS::Lambda::Function",
  "properties": {"TestForOverride": {"type": "string"}}
}`;

function loadSnapshot(rel: string): unknown {
    return COMBINED_SNAPSHOTS[rel];
}

function stripSnapshotExcludedFields(report: any, filePath?: string): unknown {
    const clone = JSON.parse(JSON.stringify(report));
    if (filePath !== undefined) {
        clone.filePath = filePath;
    }
    delete clone.version;
    delete clone.performance;
    if (clone.metadata && typeof clone.metadata === 'object') {
        delete clone.metadata.rulesEvaluated;
        delete clone.metadata.cfnLintVersion;
        delete clone.metadata.resourceSchemaVersion;
        delete clone.metadata.suppressed;
    }
    return clone;
}

// ── version ──────────────────────────────────────────────────────────────────

function readExpectedVersion(): string {
    const expectedVersionPath = path.join(EXPECTED_DIR, 'version.txt');
    const expectedVersion = fs.readFileSync(expectedVersionPath, 'utf-8').trim();
    if (expectedVersion.length === 0) {
        throw new Error(`${expectedVersionPath} must not be empty`);
    }
    return expectedVersion;
}

describe('version', () => {
    it('returns the expected version fixture', () => {
        expect(version()).toBe(readExpectedVersion());
    });
});

// ── Engine construction ──────────────────────────────────────────────────────

describe('engine construction', () => {
    it("CelEngine reports name 'cel'", () => {
        const engine = new CelEngine();
        expect(engine.engineName()).toBe('cel');
        engine.free();
    });

    it("RegoEngine reports name 'rego'", () => {
        const engine = new RegoEngine();
        expect(engine.engineName()).toBe('rego');
        engine.free();
    });

    it("CompositeEngine reports name 'composite'", () => {
        const engine = new CompositeEngine();
        expect(engine.engineName()).toBe('composite');
        engine.free();
    });
});

// ── CompositeEngine ──────────────────────────────────────────────────────────

describe('CompositeEngine', () => {
    const BUCKET_TEMPLATE = 'bad/invalid_deletion_policy.yaml';

    it('with no external rules matches the built-in engine diagnostics and rules', () => {
        const engine = new CompositeEngine();
        const template = loadTemplate(BUCKET_TEMPLATE);
        const baseline = REGO.validateTemplate(template).diagnostics;
        expect(baseline.length, 'the parity template must produce built-in diagnostics').toBeGreaterThan(0);
        expect(engine.validateTemplate(template).diagnostics).toEqual(baseline);
        expect(engine.listRules()).toEqual(REGO.listRules());
        engine.free();
    });

    it('evaluates a custom Rego rule layered on top of the built-ins', () => {
        const builtinRuleCount = CEL.listRules().length;
        const engine = new CompositeEngine({
            regoRules: [{ name: 'rego_custom.rego', content: loadRule('rego_custom.rego') }],
        });

        const report = engine.validateTemplate(loadTemplate(BUCKET_TEMPLATE));
        const custom = report.diagnostics.find((d: any) => d.ruleId === 'CUSTOM001');
        expect(custom, 'CUSTOM001 diagnostic must fire').toBeDefined();
        expect(custom.severity).toBe('ERROR');
        expect(custom.source).toBe('CUSTOM');
        expect(custom.entity?.logicalId).toBe('Bucket');
        expect(custom.entity?.resourceType).toBe('AWS::S3::Bucket');

        const rules = engine.listRules();
        const registered = rules.find((r: any) => r.id === 'CUSTOM001');
        expect(registered, 'CUSTOM001 must be listed').toBeDefined();
        expect(registered.origin).toBe('CUSTOM');
        expect(rules.filter((r: any) => r.origin !== 'CUSTOM').length).toBe(builtinRuleCount);
        engine.free();
    });

    it('evaluates a Guard rule layered on top of the built-ins', () => {
        const engine = new CompositeEngine({
            guardRules: [{ name: 'guard_encryption.guard', content: loadRule('guard_encryption.guard') }],
        });

        const report = engine.validateTemplate(loadTemplate(BUCKET_TEMPLATE));
        const guard = report.diagnostics.find((d: any) => d.ruleId === 'check_bucket_encryption');
        expect(guard, 'check_bucket_encryption diagnostic must fire').toBeDefined();
        expect(guard.severity).toBe('ERROR');
        expect(guard.source).toBe('GUARD');
        expect(guard.entity?.logicalId).toBe('Bucket');

        const listed = engine.listRules().find((r: any) => r.id === 'check_bucket_encryption');
        expect(listed, 'check_bucket_encryption must be listed').toBeDefined();
        expect(listed.origin).toBe('GUARD');
        engine.free();
    });

    it('disableBuiltinRules leaves only the external Guard finding', () => {
        const engine = new CompositeEngine({
            guardRules: [{ name: 'guard_encryption.guard', content: loadRule('guard_encryption.guard') }],
        });

        const report = engine.validateTemplate(loadTemplate(BUCKET_TEMPLATE), { disableBuiltinRules: true });
        const ruleIds = report.diagnostics.map((d: any) => d.ruleId);
        expect(ruleIds).toContain('check_bucket_encryption');
        expect(ruleIds.every((id: string) => id === 'check_bucket_encryption')).toBe(true);
        engine.free();
    });
});

// ── SchemaValidator ──────────────────────────────────────────────────────────

describe('SchemaValidator', () => {
    it('exposes schemas and rules', () => {
        const sv = new SchemaValidator();
        expect(sv.schemaCount()).toBeGreaterThan(0);
        const rules = sv.listRules();
        expect(rules.length).toBeGreaterThan(0);
        expect(rules[0].id).toBeDefined();
        sv.free();
    });
});

// ── listRules ────────────────────────────────────────────────────────────────

describe('listRules', () => {
    it('CelEngine rules are sorted by id', () => {
        const ids = CEL.listRules().map((r: any) => r.id);
        expect(ids.length).toBeGreaterThan(0);
        expect(ids).toEqual([...ids].sort());
    });

    it('RegoEngine rules are sorted by id', () => {
        const ids = REGO.listRules().map((r: any) => r.id);
        expect(ids.length).toBeGreaterThan(0);
        expect(ids).toEqual([...ids].sort());
    });

    it('CompositeEngine rules are sorted by id', () => {
        const ids = COMPOSITE.listRules().map((r: any) => r.id);
        expect(ids.length).toBeGreaterThan(0);
        expect(ids).toEqual([...ids].sort());
    });

    it('CelEngine, RegoEngine, and CompositeEngine list identical rules', () => {
        const celRules = CEL.listRules();
        const regoRules = REGO.listRules();
        expect(celRules).toEqual(regoRules);
        expect(COMPOSITE.listRules()).toEqual(regoRules);
    });
});

// ── TemplateModel (SemanticModel) ────────────────────────────────────────────

describe('TemplateModel', () => {
    it('parses format version and resources from minimal template', () => {
        const model = new TemplateModel(loadTemplate('good/minimal.yaml'));
        expect(model.formatVersion()).toBe('2010-09-09');
        const resources = model.resources();
        expect(Object.keys(resources)).toContain('IamPipeline');
        model.free();
    });

    it('parses description, conditions, and outputs from generic template', () => {
        const model = new TemplateModel(loadTemplate('good/generic.yaml'));
        expect(model.description()).toBe('A sample template');
        expect(model.conditions()).toContain('ProdVolumeSize');
        expect(model.outputs()).toHaveProperty('ElasticIP');
        model.free();
    });

    it('toDiagnosticModel returns template and resources sections', () => {
        const model = new TemplateModel(loadTemplate('good/generic.yaml'));
        const json = model.toDiagnosticModel();
        expect(json).toHaveProperty('template');
        expect(json).toHaveProperty('resources');
        model.free();
    });

    it('rejects malformed YAML', () => {
        expect(() => new TemplateModel(loadTemplate('malformed.yaml'))).toThrow();
    });

    it('minimal template has no conditions or transforms', () => {
        const model = new TemplateModel(loadTemplate('good/minimal.yaml'));
        expect(model.transforms()).toHaveLength(0);
        expect(model.conditions()).toHaveLength(0);
        model.free();
    });
});

// ── Invalid input ────────────────────────────────────────────────────────────

describe('invalid input', () => {
    it('CelEngine returns F1101 for empty template', () => {
        const report = CEL.validateTemplate(loadTemplate('empty.yaml'));
        expect(report.status).toBe('ERROR');
        expect(report.diagnostics[0].ruleId).toBe('F1101');
        expect(report.diagnostics[0].severity).toBe('FATAL');
    });

    it('RegoEngine returns F1101 for empty template', () => {
        const report = REGO.validateTemplate(loadTemplate('empty.yaml'));
        expect(report.status).toBe('ERROR');
        expect(report.diagnostics[0].ruleId).toBe('F1101');
        expect(report.diagnostics[0].severity).toBe('FATAL');
    });

    it('CompositeEngine returns F1101 for empty template', () => {
        const report = COMPOSITE.validateTemplate(loadTemplate('empty.yaml'));
        expect(report.status).toBe('ERROR');
        expect(report.diagnostics[0].ruleId).toBe('F1101');
        expect(report.diagnostics[0].severity).toBe('FATAL');
    });
});

// ── Valid input ──────────────────────────────────────────────────────────────

describe('valid template', () => {
    const GOOD_TEMPLATE = 'good/generic.yaml';

    it('all engines agree on an OK report for a good template', () => {
        const rego = REGO.validateTemplate(loadTemplate(GOOD_TEMPLATE));
        expect(rego.status).toBe('OK');
        expect(CEL.validateTemplate(loadTemplate(GOOD_TEMPLATE)).diagnostics).toEqual(rego.diagnostics);
        expect(COMPOSITE.validateTemplate(loadTemplate(GOOD_TEMPLATE)).diagnostics).toEqual(rego.diagnostics);
    });
});

// ── Additional schema overlays ──────────────────────────────────────────────

describe('additional schemas', () => {
    it('SchemaFile applies through the public config on all engines', () => {
        const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'cloudformation-validate-overlay-'));
        try {
            const templatePath = path.join(directory, 'template.yaml');
            const schemaPath = path.join(directory, 'schema.json');
            fs.writeFileSync(templatePath, TEMPLATE_WITH_OVERLAY_PROPERTY);
            fs.writeFileSync(schemaPath, LAMBDA_OVERLAY_SCHEMA);
            const template = new TemplateFile(templatePath);

            for (const [name, baseline, EngineType] of [
                ['rego', REGO, RegoEngine],
                ['cel', CEL, CelEngine],
                ['composite', COMPOSITE, CompositeEngine],
            ] as const) {
                expect(
                    baseline
                        .validateTemplate(template)
                        .diagnostics.some((diagnostic: any) => diagnostic.ruleId === 'F3002'),
                    `${name} baseline must report the unpublished property`,
                ).toBe(true);

                const engine = new EngineType({
                    schemaValidatorConfig: { additionalSchemas: [new SchemaFile(schemaPath)] },
                });
                const report = engine.validateTemplate(template);
                expect(
                    report.diagnostics.some((diagnostic: any) => diagnostic.ruleId === 'F3002'),
                    `${name} public config must apply the overlay`,
                ).toBe(false);
                engine.free();
            }
        } finally {
            fs.rmSync(directory, { recursive: true, force: true });
        }
    });
});

// ── Custom rules: 1 file, 1 rule ────────────────────────────────────────────

describe('custom rule', () => {
    it('listRules and validate match between engines with explicit values', () => {
        const cel = new CelEngine({
            customRules: [{ name: 'cel_custom.json', content: loadRule('cel_custom.json') }],
        });
        const rego = new RegoEngine({
            customRules: [{ name: 'rego_custom.rego', content: loadRule('rego_custom.rego') }],
        });

        for (const [name, engine] of [
            ['cel', cel],
            ['rego', rego],
        ] as const) {
            const report = (engine as any).validateTemplate(loadTemplate('bad/invalid_deletion_policy.yaml'));
            const d = report.diagnostics.find((d: any) => d.ruleId === 'CUSTOM001');
            expect(d, `${name}: CUSTOM001 diagnostic must fire`).toBeDefined();
            expect(d.severity).toBe('ERROR');
            expect(d.entity?.logicalId).toBe('Bucket');
            expect(d.entity?.resourceType).toBe('AWS::S3::Bucket');
        }

        const baselineCount = CEL.listRules().length;
        for (const [name, engine] of [
            ['cel', cel],
            ['rego', rego],
        ] as const) {
            const rules = (engine as any).listRules();
            const c = rules.find((r: any) => r.id === 'CUSTOM001');
            expect(c, `${name}: CUSTOM001 must exist`).toBeDefined();
            expect(c.severity).toBe('ERROR');
            expect(c.origin).toBe('CUSTOM');
            expect(c.description).toBe('S3 bucket must have encryption configured');
            expect(rules.filter((r: any) => r.origin !== 'CUSTOM').length).toBe(baselineCount);
        }

        expect(cel.listRules()).toEqual(rego.listRules());
        cel.free();
        rego.free();
    });
});

// ── Guard rules: 1 file, 1 rule ─────────────────────────────────────────────

describe('guard rule', () => {
    it('listRules and validate match between engines with explicit values', () => {
        const cel = new CelEngine({
            guardRules: [{ name: 'guard_encryption.guard', content: loadRule('guard_encryption.guard') }],
        });
        const rego = new RegoEngine({
            guardRules: [{ name: 'guard_encryption.guard', content: loadRule('guard_encryption.guard') }],
        });
        const composite = new CompositeEngine({
            guardRules: [{ name: 'guard_encryption.guard', content: loadRule('guard_encryption.guard') }],
        });

        const baselineCount = CEL.listRules().length;
        for (const [name, engine] of [
            ['cel', cel],
            ['rego', rego],
            ['composite', composite],
        ] as const) {
            const rules = (engine as any).listRules();
            const g = rules.find((r: any) => r.id === 'check_bucket_encryption');
            expect(g, `${name}: check_bucket_encryption must exist`).toBeDefined();
            expect(g.severity).toBe('ERROR');
            expect(g.origin).toBe('GUARD');
            expect(g.description).toBe('S3 bucket must have encryption configured');
            expect(rules.filter((r: any) => r.origin !== 'GUARD').length).toBe(baselineCount);

            const report = (engine as any).validateTemplate(loadTemplate('bad/invalid_deletion_policy.yaml'));
            const d = report.diagnostics.find((d: any) => d.ruleId === 'check_bucket_encryption');
            expect(d, `${name}: check_bucket_encryption diagnostic must fire`).toBeDefined();
            expect(d.severity).toBe('ERROR');
            expect(d.source).toBe('GUARD');
            expect(d.entity?.logicalId).toBe('Bucket');
        }

        expect(cel.listRules()).toEqual(rego.listRules());
        expect(composite.listRules()).toEqual(rego.listRules());
        cel.free();
        rego.free();
        composite.free();
    });
});

// ── Combined: 1 custom file + 1 guard file ──────────────────────────────────

describe('single combined custom + guard', () => {
    it('listRules and validate match between engines with explicit values', () => {
        const cel = new CelEngine({
            customRules: [{ name: 'cel_custom.json', content: loadRule('cel_custom.json') }],
            guardRules: [{ name: 'guard_encryption.guard', content: loadRule('guard_encryption.guard') }],
        });
        const rego = new RegoEngine({
            customRules: [{ name: 'rego_custom.rego', content: loadRule('rego_custom.rego') }],
            guardRules: [{ name: 'guard_encryption.guard', content: loadRule('guard_encryption.guard') }],
        });

        // Rego discovers custom rule metadata during evaluation.
        rego.validateTemplate(loadTemplate('bad/invalid_deletion_policy.yaml'));

        for (const [name, engine] of [
            ['cel', cel],
            ['rego', rego],
        ] as const) {
            const rules = (engine as any).listRules();
            expect(rules.find((r: any) => r.id === 'CUSTOM001')?.origin).toBe('CUSTOM');
            expect(rules.find((r: any) => r.id === 'check_bucket_encryption')?.origin).toBe('GUARD');
            const ids = rules.map((r: any) => r.id);
            expect(ids).toEqual([...ids].sort());
        }

        expect(cel.listRules()).toEqual(rego.listRules());
        cel.free();
        rego.free();
    });
});

// ── Multi: 2 custom rules + 2 guard files (1 rule + 2 rules) ────────────────

describe('multi combined custom + guard', () => {
    it('listRules match between engines with explicit values for all rules', () => {
        const cel = new CelEngine({
            customRules: [{ name: 'cel_multi_custom.json', content: loadRule('cel_multi_custom.json') }],
            guardRules: [
                { name: 'guard_encryption.guard', content: loadRule('guard_encryption.guard') },
                { name: 'guard_multi.guard', content: loadRule('guard_multi.guard') },
            ],
        });
        const rego = new RegoEngine({
            customRules: [{ name: 'rego_multi_custom.rego', content: loadRule('rego_multi_custom.rego') }],
            guardRules: [
                { name: 'guard_encryption.guard', content: loadRule('guard_encryption.guard') },
                { name: 'guard_multi.guard', content: loadRule('guard_multi.guard') },
            ],
        });

        // Rego discovers custom rule metadata during evaluation.
        rego.validateTemplate(loadTemplate('bad/invalid_deletion_policy.yaml'));

        for (const [name, engine] of [
            ['cel', cel],
            ['rego', rego],
        ] as const) {
            const rules = (engine as any).listRules();

            const c1 = rules.find((r: any) => r.id === 'CUSTOM010');
            expect(c1, `${name}: CUSTOM010`).toBeDefined();
            expect(c1.severity).toBe('ERROR');
            expect(c1.origin).toBe('CUSTOM');
            expect(c1.description).toBe('S3 bucket must have versioning enabled');

            const c2 = rules.find((r: any) => r.id === 'CUSTOM011');
            expect(c2, `${name}: CUSTOM011`).toBeDefined();
            expect(c2.severity).toBe('WARN');
            expect(c2.origin).toBe('CUSTOM');
            expect(c2.description).toBe('S3 bucket should have lifecycle rules configured');

            const enc = rules.find((r: any) => r.id === 'check_bucket_encryption');
            expect(enc, `${name}: check_bucket_encryption`).toBeDefined();
            expect(enc.origin).toBe('GUARD');
            expect(enc.description).toBe('S3 bucket must have encryption configured');

            const ver = rules.find((r: any) => r.id === 'check_bucket_versioning');
            expect(ver, `${name}: check_bucket_versioning`).toBeDefined();
            expect(ver.origin).toBe('GUARD');
            expect(ver.description).toBe('S3 bucket must have versioning enabled');

            const lc = rules.find((r: any) => r.id === 'check_bucket_lifecycle');
            expect(lc, `${name}: check_bucket_lifecycle`).toBeDefined();
            expect(lc.origin).toBe('GUARD');
            expect(lc.description).toBe('S3 bucket should have lifecycle rules configured');

            const ids = rules.map((r: any) => r.id);
            expect(ids).toEqual([...ids].sort());
        }

        expect(cel.listRules()).toEqual(rego.listRules());
        cel.free();
        rego.free();
    });
});

function stripEnrichmentFields(report: any): unknown {
    const clone = JSON.parse(JSON.stringify(report));
    if (clone.diagnostics) {
        for (const d of clone.diagnostics) {
            for (const field of ENRICHMENT_DIAGNOSTIC_FIELDS) {
                delete d[field];
            }
        }
    }
    return clone;
}

describe('snapshot validation', () => {
    function detailedTests(engineName: string, engine: any) {
        describe(`${engineName} detailed matches snapshot`, () => {
            for (const rel of EXPECTED_TEMPLATES) {
                it(rel, () => {
                    const actual = engine.validateTemplate(loadTemplate(rel), {
                        severityLevel: 'DEBUG',
                        detailLevel: 'DETAILED',
                    });
                    expect(stripSnapshotExcludedFields(actual, rel)).toEqual(
                        stripSnapshotExcludedFields(loadSnapshot(rel)),
                    );
                });
            }
        });
    }

    function standardTests(engineName: string, engine: any) {
        describe(`${engineName} standard matches snapshot`, () => {
            for (const rel of EXPECTED_TEMPLATES) {
                it(rel, () => {
                    const actual = engine.validateTemplate(loadTemplate(rel), {
                        severityLevel: 'DEBUG',
                        detailLevel: 'STANDARD',
                    });
                    expect(stripSnapshotExcludedFields(stripEnrichmentFields(actual), rel)).toEqual(
                        stripSnapshotExcludedFields(stripEnrichmentFields(loadSnapshot(rel))),
                    );
                });
            }
        });
    }

    detailedTests('rego', REGO);
    standardTests('rego', REGO);
    detailedTests('cel', CEL);
    standardTests('cel', CEL);
    detailedTests('composite', COMPOSITE);
    standardTests('composite', COMPOSITE);
});

describe('report fields excluded from snapshot', () => {
    const REPORT_TEMPLATE = 'good/generic.yaml';

    it('performance is present with a timing metric per phase', () => {
        const report = REGO.validateTemplate(loadTemplate(REPORT_TEMPLATE), {
            severityLevel: 'DEBUG',
            detailLevel: 'DETAILED',
        });
        const phases = [
            'schemaInit',
            'engineInit',
            'modelBuild',
            'schemaValidate',
            'ruleEvaluation',
            'diagnosticFinalize',
            'validateTotal',
        ];
        expect(report.performance).toBeDefined();
        for (const phase of phases) {
            expect(typeof report.performance[phase].durationMs, `performance.${phase}.durationMs`).toBe('number');
        }
    });
});

describe('validateTemplate detail level', () => {
    const DETAIL_LEVEL_TEMPLATE = 'good/generic.yaml';

    for (const [engineName, engine] of [
        ['rego', REGO],
        ['cel', CEL],
    ] as const) {
        it(`${engineName} defaults to DETAILED when detailLevel is omitted`, () => {
            const withDefault = engine.validateTemplate(loadTemplate(DETAIL_LEVEL_TEMPLATE), {
                severityLevel: 'DEBUG',
            });
            const explicitDetailed = engine.validateTemplate(loadTemplate(DETAIL_LEVEL_TEMPLATE), {
                severityLevel: 'DEBUG',
                detailLevel: 'DETAILED',
            });
            expect(withDefault.diagnostics.some((d: any) => d.ruleDescription !== undefined)).toBe(true);
            expect(stripSnapshotExcludedFields(withDefault)).toEqual(stripSnapshotExcludedFields(explicitDetailed));
        });

        it(`${engineName} STANDARD omits the enrichment fields that DETAILED includes`, () => {
            const detailed = engine.validateTemplate(loadTemplate(DETAIL_LEVEL_TEMPLATE), {
                severityLevel: 'DEBUG',
                detailLevel: 'DETAILED',
            });
            const standard = engine.validateTemplate(loadTemplate(DETAIL_LEVEL_TEMPLATE), {
                severityLevel: 'DEBUG',
                detailLevel: 'STANDARD',
            });
            expect(detailed.diagnostics.some((d: any) => d.ruleDescription !== undefined)).toBe(true);
            expect(standard.diagnostics.every((d: any) => d.ruleDescription === undefined)).toBe(true);
        });

        it(`${engineName} STANDARD omits the parse-phase field a DETAILED parse error carries`, () => {
            const detailed = engine.validateTemplate(loadTemplate('empty.yaml'), {
                severityLevel: 'DEBUG',
                detailLevel: 'DETAILED',
            });
            const standard = engine.validateTemplate(loadTemplate('empty.yaml'), {
                severityLevel: 'DEBUG',
                detailLevel: 'STANDARD',
            });
            expect(detailed.diagnostics[0].ruleId).toBe('F1101');
            expect(detailed.diagnostics[0].phase).toBe('PARSE');
            expect(standard.diagnostics[0].ruleId).toBe('F1101');
            expect(standard.diagnostics[0].phase).toBeUndefined();
        });
    }
});
