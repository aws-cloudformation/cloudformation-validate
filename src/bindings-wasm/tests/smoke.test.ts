import { describe, expect, it } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const {
    RegoEngine,
    CelEngine,
    AwsApiRequest,
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

// ── AWS API request validation ──────────────────────────────────────────────

describe('AWS API request validation', () => {
    const engines = [
        ['rego', REGO],
        ['cel', CEL],
    ] as const;

    function diagnosticKeys(report: any): string[] {
        return (report?.diagnostics ?? []).map(
            (diagnostic: any) =>
                `${diagnostic.ruleId}|${diagnostic.entity?.logicalId ?? ''}|${diagnostic.propertyPath ?? ''}`,
        );
    }

    it('synthesizes canonical S3 CreateBucket state on both engines', () => {
        const request = new AwsApiRequest('s3', 'CreateBucket', { Bucket: 'synthetic-bucket' });
        const validations: Record<string, any> = {};

        for (const [name, engine] of engines) {
            const validation = engine.validateAwsApiRequest(request);
            expect(validation.status, name).toBe('VALIDATED');
            expect(validation.operationKind, name).toBe('CLOUD_FORMATION_CREATE');
            expect(validation.resourceTypes, name).toEqual(['AWS::S3::Bucket']);
            expect(validation.templateSource, name).toBe('SYNTHESIZED_CREATE');
            expect(validation.report, name).not.toBeNull();
            expect(validation.template, name).toBeInstanceOf(Uint8Array);
            const document = JSON.parse(Buffer.from(validation.template).toString('utf8'));
            expect(document.Resources.Resource.Type, name).toBe('AWS::S3::Bucket');
            expect(document.Resources.Resource.Properties.BucketName, name).toBe('synthetic-bucket');
            validations[name] = validation;
        }

        expect(Array.from(validations.rego.template)).toEqual(Array.from(validations.cel.template));
        expect(diagnosticKeys(validations.rego.report)).toEqual(diagnosticKeys(validations.cel.report));
    });

    it('preserves CloudFormation TemplateBody bytes exactly on both engines', () => {
        const templateBody = Buffer.from(
            '{\n    "Resources": {\n        "Bucket": { "Type": "AWS::S3::Bucket" }\n    }\n}',
        );
        const request = new AwsApiRequest('cloudformation', 'ValidateTemplate', {
            TemplateBody: templateBody,
        });

        for (const [name, engine] of engines) {
            const validation = engine.validateAwsApiRequest(request);
            expect(validation.status, name).toBe('VALIDATED');
            expect(validation.templateSource, name).toBe('TEMPLATE_BODY');
            expect(validation.template, name).toBeInstanceOf(Uint8Array);
            expect(Buffer.from(validation.template), name).toEqual(templateBody);
        }
    });

    it('conservatively skips unmapped nested DynamoDB state on both engines', () => {
        const request = new AwsApiRequest('dynamodb', 'CreateTable', {
            TableName: 'Synthetic',
            KeySchema: [{ AttributeName: 'id', KeyType: 'HASH' }],
            AttributeDefinitions: [{ AttributeName: 'id', AttributeType: 'S' }],
            BillingMode: 'PAY_PER_REQUEST',
        });

        for (const [name, engine] of engines) {
            const validation = engine.validateAwsApiRequest(request);
            expect(validation.status, name).toBe('SKIPPED');
            expect(validation.report, name).toBeNull();
            expect(validation.template, name).toBeNull();
            expect(validation.resourceTypes, name).toEqual(['AWS::DynamoDB::Table']);
            expect(validation.reason, name).toContain('has no mapping');
        }
    });

    it('never guesses the noncanonical CloudWatch signing alias', () => {
        const canonical = new AwsApiRequest('cloudwatch', 'PutMetricAlarm', {
            AlarmName: 'synthetic',
        });
        const alias = new AwsApiRequest('monitoring', 'PutMetricAlarm', {
            AlarmName: 'synthetic',
        });

        for (const [name, engine] of engines) {
            const canonicalValidation = engine.validateAwsApiRequest(canonical);
            expect(canonicalValidation.resourceTypes, name).toContain('AWS::CloudWatch::Alarm');
            const aliasValidation = engine.validateAwsApiRequest(alias);
            expect(aliasValidation.status, name).toBe('SKIPPED');
            expect(aliasValidation.resourceTypes, name).not.toContain('AWS::CloudWatch::Alarm');
            expect(aliasValidation.template, name).toBeNull();
        }
    });

    it('preserves signed and unsigned 64-bit bigint values across the WASM boundary', () => {
        const request = new AwsApiRequest('lambda', 'CreateFunction', {
            MemorySize: 18446744073709551615n,
            Timeout: -9223372036854775808n,
        });

        for (const [name, engine] of engines) {
            const validation = engine.validateAwsApiRequest(request);
            expect(validation.status, name).toBe('VALIDATED');
            expect(validation.template, name).toBeInstanceOf(Uint8Array);
            const template = Buffer.from(validation.template).toString('utf8');
            expect(template, name).toContain('"MemorySize":18446744073709551615');
            expect(template, name).toContain('"Timeout":-9223372036854775808');
        }
    });

    it('marks unsupported request values conservatively instead of coercing them', () => {
        const request = new AwsApiRequest('s3', 'CreateBucket', {
            Bucket: Symbol('not-a-bucket-name'),
        });

        for (const [name, engine] of engines) {
            const validation = engine.validateAwsApiRequest(request);
            expect(validation.status, name).toBe('SKIPPED');
            expect(validation.report, name).toBeNull();
            expect(validation.template, name).toBeNull();
        }
    });

    it('does not invoke object accessors', () => {
        let accessorInvoked = false;
        const state: Record<string, unknown> = Object.create(null);
        Object.defineProperty(state, 'accessor', {
            enumerable: true,
            get() {
                accessorInvoked = true;
                throw new Error('request accessors must not run');
            },
        });
        const request = new AwsApiRequest('s3', 'CreateBucket', { Bucket: state });

        for (const [name, engine] of engines) {
            const validation = engine.validateAwsApiRequest(request);
            expect(validation.status, name).toBe('SKIPPED');
            expect(validation.template, name).toBeNull();
        }
        expect(accessorInvoked).toBe(false);
    });

    it('does not invoke indexed array accessors', () => {
        let accessorInvoked = false;
        const state: unknown[] = [];
        Object.defineProperty(state, '0', {
            enumerable: true,
            get() {
                accessorInvoked = true;
                throw new Error('request accessors must not run');
            },
        });
        const request = new AwsApiRequest('s3', 'CreateBucket', { Bucket: state });

        for (const [name, engine] of engines) {
            const validation = engine.validateAwsApiRequest(request);
            expect(validation.status, name).toBe('SKIPPED');
            expect(validation.template, name).toBeNull();
        }
        expect(accessorInvoked).toBe(false);
    });

    it('skips cyclic request state conservatively', () => {
        const state: Record<string, unknown> = Object.create(null);
        state.cycle = state;
        const request = new AwsApiRequest('s3', 'CreateBucket', { Bucket: state });

        for (const [name, engine] of engines) {
            const validation = engine.validateAwsApiRequest(request);
            expect(validation.status, name).toBe('SKIPPED');
            expect(validation.template, name).toBeNull();
        }
    });

    it('bypasses caller-overridden Date and Uint8Array methods', () => {
        let overrideInvoked = false;
        const date = new Date('2024-01-02T03:04:05.000Z');
        Object.defineProperty(date, 'getTime', {
            get() {
                overrideInvoked = true;
                throw new Error('request overrides must not run');
            },
        });
        Object.defineProperty(date, 'toISOString', {
            get() {
                overrideInvoked = true;
                throw new Error('request overrides must not run');
            },
        });

        const expectedTemplateBody = Buffer.from('{"Resources":{"Bucket":{"Type":"AWS::S3::Bucket"}}}');
        const templateBody = new Uint8Array(expectedTemplateBody);
        Object.defineProperty(templateBody, Symbol.iterator, {
            get() {
                overrideInvoked = true;
                throw new Error('request overrides must not run');
            },
        });
        Object.defineProperty(templateBody, 'forEach', {
            get() {
                overrideInvoked = true;
                throw new Error('request overrides must not run');
            },
        });

        const dateRequest = new AwsApiRequest('s3', 'CreateBucket', { Bucket: date });
        const bytesRequest = new AwsApiRequest('cloudformation', 'ValidateTemplate', {
            TemplateBody: templateBody,
        });
        for (const [name, engine] of engines) {
            const dateValidation = engine.validateAwsApiRequest(dateRequest);
            expect(dateValidation.status, name).toBe('VALIDATED');
            expect(Buffer.from(dateValidation.template).toString('utf8'), name).toContain('2024-01-02T03:04:05.000Z');

            const bytesValidation = engine.validateAwsApiRequest(bytesRequest);
            expect(bytesValidation.status, name).toBe('VALIDATED');
            expect(Buffer.from(bytesValidation.template), name).toEqual(expectedTemplateBody);
        }
        expect(overrideInvoked).toBe(false);
    });

    it('rejects invalid top-level parameter dictionaries without dropping keys', () => {
        expect(() => new AwsApiRequest('s3', 'CreateBucket', [] as unknown as Record<string, unknown>)).toThrow(
            'parameters must be a plain object',
        );

        const symbolParameters: Record<PropertyKey, unknown> = Object.create(null);
        symbolParameters[Symbol('Bucket')] = 'synthetic-bucket';
        expect(() => new AwsApiRequest('s3', 'CreateBucket', symbolParameters as Record<string, unknown>)).toThrow(
            'request parameter names must be strings',
        );
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

                const engine = new EngineType({
                    schemaValidatorConfig: { additionalSchemas: [new SchemaFile(schemaPath)] },
                });
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
