import { describe, expect, it } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const {
    RegoEngine,
    CelEngine,
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
            throw new Error(`non-contiguous snapshot chunk sequence: expected index ${i + 1} but found ${chunks[i].index}`);
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

const FULL_ONLY_DIAGNOSTIC_FIELDS = ['documentationUrl', 'context', 'ruleDescription', 'phase', 'section'];

const CEL = new CelEngine();
const REGO = new RegoEngine();

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
    }
    return clone;
}

// ── version ──────────────────────────────────────────────────────────────────

function readWorkspaceVersion(): string {
    const cargoTomlPath = path.resolve(__dirname, '../../Cargo.toml');
    const lines = fs.readFileSync(cargoTomlPath, 'utf-8').split('\n');
    let inWorkspacePackage = false;
    for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed === '[workspace.package]') {
            inWorkspacePackage = true;
            continue;
        }
        if (inWorkspacePackage && trimmed.startsWith('[')) {
            break;
        }
        if (inWorkspacePackage && trimmed.startsWith('version = ')) {
            const value = trimmed.slice('version = '.length).trim();
            if (!value.startsWith('"') || !value.endsWith('"')) {
                throw new Error(`malformed version line in ${cargoTomlPath}: ${line}`);
            }
            return value.slice(1, -1);
        }
    }
    throw new Error(`missing 'version = ' under [workspace.package] in ${cargoTomlPath}`);
}

describe('version', () => {
    it('returns the crate version from workspace Cargo.toml', () => {
        expect(version()).toBe(readWorkspaceVersion());
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

    it('CelEngine and RegoEngine list identical rules', () => {
        const celRules = CEL.listRules();
        const regoRules = REGO.listRules();
        expect(celRules).toEqual(regoRules);
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
        const report = CEL.validateStandard(loadTemplate('empty.yaml'));
        expect(report.status).toBe('ERROR');
        expect(report.diagnostics[0].ruleId).toBe('F1101');
        expect(report.diagnostics[0].severity).toBe('FATAL');
    });

    it('RegoEngine returns F1101 for empty template', () => {
        const report = REGO.validateStandard(loadTemplate('empty.yaml'));
        expect(report.status).toBe('ERROR');
        expect(report.diagnostics[0].ruleId).toBe('F1101');
        expect(report.diagnostics[0].severity).toBe('FATAL');
    });
});

// ── Additional schema overlays ──────────────────────────────────────────────

describe('additional schemas', () => {
    it('SchemaFile applies through the public config on both engines', () => {
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
            ] as const) {
                expect(
                    baseline
                        .validateStandard(template)
                        .diagnostics.some((diagnostic: any) => diagnostic.ruleId === 'F3002'),
                    `${name} baseline must report the unpublished property`,
                ).toBe(true);

                const engine = new EngineType({ schemaValidatorConfig: { additionalSchemas: [new SchemaFile(schemaPath)] } });
                const report = engine.validateStandard(template);
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
            const report = (engine as any).validateStandard(loadTemplate('bad/invalid_deletion_policy.yaml'));
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

        const baselineCount = CEL.listRules().length;
        for (const [name, engine] of [
            ['cel', cel],
            ['rego', rego],
        ] as const) {
            const rules = (engine as any).listRules();
            const g = rules.find((r: any) => r.id === 'check_bucket_encryption');
            expect(g, `${name}: check_bucket_encryption must exist`).toBeDefined();
            expect(g.severity).toBe('ERROR');
            expect(g.origin).toBe('GUARD');
            expect(g.description).toBe('S3 bucket must have encryption configured');
            expect(rules.filter((r: any) => r.origin !== 'GUARD').length).toBe(baselineCount);

            const report = (engine as any).validateStandard(loadTemplate('bad/invalid_deletion_policy.yaml'));
            const d = report.diagnostics.find((d: any) => d.ruleId === 'check_bucket_encryption');
            expect(d, `${name}: check_bucket_encryption diagnostic must fire`).toBeDefined();
            expect(d.severity).toBe('ERROR');
            expect(d.source).toBe('GUARD');
            expect(d.entity?.logicalId).toBe('Bucket');
        }

        expect(cel.listRules()).toEqual(rego.listRules());
        cel.free();
        rego.free();
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
        rego.validateStandard(loadTemplate('bad/invalid_deletion_policy.yaml'));

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
        rego.validateStandard(loadTemplate('bad/invalid_deletion_policy.yaml'));

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

function stripDetailedOnlyFields(report: any): unknown {
    const clone = JSON.parse(JSON.stringify(report));
    if (clone.diagnostics) {
        for (const d of clone.diagnostics) {
            for (const field of FULL_ONLY_DIAGNOSTIC_FIELDS) {
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
                    const actual = engine.validateDetailed(loadTemplate(rel), { severityLevel: 'DEBUG' });
                    expect(stripSnapshotExcludedFields(actual, rel)).toEqual(stripSnapshotExcludedFields(loadSnapshot(rel)));
                });
            }
        });
    }

    function standardTests(engineName: string, engine: any) {
        describe(`${engineName} standard matches snapshot`, () => {
            for (const rel of EXPECTED_TEMPLATES) {
                it(rel, () => {
                    const actual = engine.validateStandard(loadTemplate(rel), { severityLevel: 'DEBUG' });
                    expect(stripSnapshotExcludedFields(actual, rel)).toEqual(
                        stripSnapshotExcludedFields(stripDetailedOnlyFields(loadSnapshot(rel))),
                    );
                });
            }
        });
    }

    detailedTests('rego', REGO);
    standardTests('rego', REGO);
    detailedTests('cel', CEL);
    standardTests('cel', CEL);
});

describe('report fields excluded from snapshot', () => {
    const REPORT_TEMPLATE = 'good/generic.yaml';

    it('performance is present with a timing metric per phase', () => {
        const report = REGO.validateDetailed(loadTemplate(REPORT_TEMPLATE), { severityLevel: 'DEBUG' });
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
