import type {
    DetailedReport,
    DiagnosticModel,
    AdditionalSchemaSource,
    EngineConfig as WasmEngineConfig,
    SchemaValidatorConfig as WasmSchemaValidatorConfig,
    ExternalRuleSource,
    ParameterInfo,
    ResolvedOutput,
    ResolvedResource,
    RuleInfo,
    SourceSpan,
    StandardDiagnostic,
    StandardReport,
    ValidateConfig,
} from '../dist/bindings_wasm';
import { readFileSync } from 'fs';

export type {
    Severity,
    DetailLevel,
    RuleOrigin,
    IdRange,
    ResourceIdFilter,
    LogicalIdFilter,
    ResourceTypeFilter,
    ServiceFilter,
    RuleFilterConfig,
    RuleInfo,
    SourceSpan,
    Entity,
    EntityType,
    ResourceRef,
    RelatedResource,
    ViolationContext,
    StandardDiagnostic,
    DetailedDiagnostic,
    PhaseMetric,
    PerformanceMetrics,
    Summary,
    ReportMetadata,
    StandardReport,
    DetailedReport,
    PseudoParameterOverrides,
    ValidateConfig,
    ExternalRuleSource,
    AdditionalSchemaSource,
    ResolvedValue,
    RefKind,
    ParameterInfo,
    ResolvedResource,
    ResolvedOutput,
    ForEachExpansion,
    ResourceDiagnostics,
    MapEntry,
    PathValuePair,
    ConditionalNull,
    ConditionalNullEntry,
    DiagnosticModel,
    DiagnosticTemplate,
    DiagnosticCondition,
    DiagnosticImplication,
    DiagnosticMutexGroup,
    ReferenceEdge,
    OutgoingRef,
    IncomingRef,
    DiagnosticResource,
    PathVariable,
    DiagnosticForEachExpansion,
    PathTarget,
    GetAttRef,
    DiagnosticOutput,
    DiagnosticRule,
    DiagnosticRuleAssertion,
    ResolutionSource,
} from '../dist/bindings_wasm';

export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

export type AwsApiOperationKind =
    | 'READ_ONLY'
    | 'CLOUD_FORMATION_CREATE'
    | 'CLOUD_FORMATION_UPDATE'
    | 'CLOUD_FORMATION_DELETE'
    | 'DATA_PLANE_MUTATION'
    | 'UNMAPPED_MUTATION';
export type AwsApiRequestValidationStatus = 'VALIDATED' | 'SKIPPED';
export type AwsApiTemplateSource =
    'TEMPLATE_BODY' | 'CLOUD_CONTROL_DESIRED_STATE' | 'SYNTHESIZED_CREATE' | 'SYNTHESIZED_UPDATE';

export interface AwsApiRequestOptions {
    servicePrefix?: string;
    httpMethod?: string;
    isReadOnly?: boolean;
}

/**
 * Service, operation, and input values for one AWS API request.
 *
 * `serviceName` is the canonical botocore service name and is normalized only
 * for ASCII case. Callers adapting an SDK request must translate its native
 * service identity before constructing this request; endpoint and signing-name
 * aliases are never guessed by the validation core.
 */
export class AwsApiRequest {
    public readonly parameters: Record<string, unknown>;
    public readonly servicePrefix?: string;
    public readonly httpMethod?: string;
    public readonly isReadOnly?: boolean;

    constructor(
        public readonly serviceName: string,
        public readonly operationName: string,
        parameters: Record<string, unknown>,
        options: AwsApiRequestOptions = {},
    ) {
        if (!isPlainRecord(parameters)) {
            throw new TypeError('parameters must be a plain object with string keys');
        }
        const copiedParameters = Object.create(null) as Record<string, unknown>;
        for (const key of Reflect.ownKeys(parameters)) {
            if (typeof key !== 'string') {
                throw new TypeError('request parameter names must be strings');
            }
            const descriptor = Object.getOwnPropertyDescriptor(parameters, key);
            if (descriptor === undefined || !('value' in descriptor)) {
                throw new TypeError(`request parameter ${JSON.stringify(key)} must be a value property`);
            }
            copiedParameters[key] = descriptor.value;
        }
        this.parameters = copiedParameters;
        this.servicePrefix = options.servicePrefix;
        this.httpMethod = options.httpMethod;
        this.isReadOnly = options.isReadOnly;
    }
}

export interface AwsApiRequestValidation {
    operationKind: AwsApiOperationKind;
    status: AwsApiRequestValidationStatus;
    templateSource: AwsApiTemplateSource | null;
    resourceTypes: string[];
    reason: string;
    report: StandardReport | null;
    template: Uint8Array | null;
}

type WireAwsApiValue =
    | { type: 'NULL' }
    | { type: 'BOOLEAN'; value: boolean }
    | { type: 'INTEGER'; value: number | bigint }
    | { type: 'UNSIGNED_INTEGER'; value: bigint }
    | { type: 'NUMBER'; value: number }
    | { type: 'STRING'; value: string }
    | { type: 'BYTES'; value: number[] }
    | { type: 'ARRAY'; items: WireAwsApiValue[] }
    | { type: 'OBJECT'; entries: Record<string, WireAwsApiValue> }
    | { type: 'UNSUPPORTED'; type_name: string };

interface WireAwsApiRequest {
    serviceName: string;
    operationName: string;
    parameters: Record<string, WireAwsApiValue>;
    servicePrefix?: string;
    httpMethod?: string;
    isReadOnly?: boolean;
}

interface WireAwsApiRequestValidation extends Omit<AwsApiRequestValidation, 'template'> {
    template?: number[] | Uint8Array | null;
}

const MIN_SIGNED_64 = -(1n << 63n);
const MAX_SIGNED_64 = (1n << 63n) - 1n;
const MAX_UNSIGNED_64 = (1n << 64n) - 1n;
const MAX_REQUEST_VALUE_DEPTH = 64;
const DATE_GET_TIME = Date.prototype.getTime;
const DATE_TO_ISO_STRING = Date.prototype.toISOString;
const UINT8_ARRAY_FOR_EACH = Uint8Array.prototype.forEach;

function isPlainRecord(value: unknown): value is Record<string, unknown> {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
        return false;
    }
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}

function unsupportedValue(typeName: string): WireAwsApiValue {
    return { type: 'UNSUPPORTED', type_name: typeName };
}

function encodeAwsApiValue(value: unknown, depth = 0, ancestors = new Set<object>()): WireAwsApiValue {
    if (depth > MAX_REQUEST_VALUE_DEPTH) {
        return unsupportedValue('recursion depth exceeded');
    }
    if (value === null) {
        return { type: 'NULL' };
    }
    if (typeof value === 'boolean') {
        return { type: 'BOOLEAN', value };
    }
    if (typeof value === 'number') {
        if (!Number.isFinite(value)) {
            return unsupportedValue('non-finite floating-point number');
        }
        if (Number.isInteger(value)) {
            return Number.isSafeInteger(value)
                ? { type: 'INTEGER', value }
                : unsupportedValue('integer outside the JavaScript safe range');
        }
        return { type: 'NUMBER', value };
    }
    if (typeof value === 'bigint') {
        if (value >= MIN_SIGNED_64 && value <= MAX_SIGNED_64) {
            return { type: 'INTEGER', value };
        }
        if (value >= 0n && value <= MAX_UNSIGNED_64) {
            return { type: 'UNSIGNED_INTEGER', value };
        }
        return unsupportedValue('integer outside the 64-bit request range');
    }
    if (typeof value === 'string') {
        return { type: 'STRING', value };
    }
    if (value instanceof Uint8Array) {
        const bytes: number[] = [];
        try {
            UINT8_ARRAY_FOR_EACH.call(value, (byte: number) => {
                bytes.push(byte);
            });
        } catch {
            return unsupportedValue('invalid Uint8Array');
        }
        return { type: 'BYTES', value: bytes };
    }
    if (value instanceof Date) {
        try {
            const timestamp = DATE_GET_TIME.call(value);
            return Number.isFinite(timestamp)
                ? { type: 'STRING', value: DATE_TO_ISO_STRING.call(value) }
                : unsupportedValue('invalid Date');
        } catch {
            return unsupportedValue('invalid Date');
        }
    }
    if (Array.isArray(value)) {
        if (ancestors.has(value)) {
            return unsupportedValue('cyclic array');
        }
        ancestors.add(value);
        try {
            const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
            if (
                lengthDescriptor === undefined ||
                !('value' in lengthDescriptor) ||
                !Number.isSafeInteger(lengthDescriptor.value) ||
                lengthDescriptor.value < 0
            ) {
                return unsupportedValue('array with invalid length');
            }
            const items: WireAwsApiValue[] = [];
            for (let index = 0; index < lengthDescriptor.value; index += 1) {
                const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
                if (descriptor === undefined) {
                    return unsupportedValue('sparse array');
                }
                if (!('value' in descriptor)) {
                    return unsupportedValue('array with accessor elements');
                }
                items.push(encodeAwsApiValue(descriptor.value, depth + 1, ancestors));
            }
            return { type: 'ARRAY', items };
        } finally {
            ancestors.delete(value);
        }
    }
    if (isPlainRecord(value)) {
        if (ancestors.has(value)) {
            return unsupportedValue('cyclic object');
        }
        ancestors.add(value);
        try {
            const entries = Object.create(null) as Record<string, WireAwsApiValue>;
            for (const key of Reflect.ownKeys(value)) {
                if (typeof key !== 'string') {
                    return unsupportedValue('mapping with non-string keys');
                }
                const descriptor = Object.getOwnPropertyDescriptor(value, key);
                if (descriptor === undefined || !('value' in descriptor)) {
                    return unsupportedValue('mapping with accessor properties');
                }
                entries[key] = encodeAwsApiValue(descriptor.value, depth + 1, ancestors);
            }
            return { type: 'OBJECT', entries };
        } finally {
            ancestors.delete(value);
        }
    }
    return unsupportedValue(typeof value);
}

function toWireAwsApiRequest(request: AwsApiRequest): WireAwsApiRequest {
    const parameters = Object.create(null) as Record<string, WireAwsApiValue>;
    for (const [name, value] of Object.entries(request.parameters)) {
        try {
            parameters[name] = encodeAwsApiValue(value);
        } catch {
            parameters[name] = unsupportedValue('request value inspection failed');
        }
    }
    return {
        serviceName: request.serviceName,
        operationName: request.operationName,
        parameters,
        ...(request.servicePrefix === undefined ? {} : { servicePrefix: request.servicePrefix }),
        ...(request.httpMethod === undefined ? {} : { httpMethod: request.httpMethod }),
        ...(request.isReadOnly === undefined ? {} : { isReadOnly: request.isReadOnly }),
    };
}

function fromWireAwsApiRequestValidation(validation: WireAwsApiRequestValidation): AwsApiRequestValidation {
    const template = validation.template;
    return {
        ...validation,
        templateSource: validation.templateSource ?? null,
        report: validation.report ?? null,
        template: template == null ? null : Uint8Array.from(template),
    };
}

export interface Engine {
    validateStandard(template: TemplateFile, config?: ValidateConfig): StandardReport;
    validateDetailed(template: TemplateFile, config?: ValidateConfig): DetailedReport;
    validateAwsApiRequest(request: AwsApiRequest, config?: ValidateConfig): AwsApiRequestValidation;
    listRules(): RuleInfo[];
    engineName(): string;
    free(): void;
}

const bridge = require('../dist/bindings_wasm');

export class TemplateFile {
    constructor(public readonly path: string) {}

    readBytes(): Uint8Array {
        return readFileSync(this.path);
    }
}

export class RuleFile {
    constructor(public readonly path: string) {}

    readContent(): string {
        return readFileSync(this.path, 'utf8');
    }
}

export type RuleSource = ExternalRuleSource | RuleFile;

/**
 * A CloudFormation resource provider schema loaded from a file, for use as an
 * overlay. `typeName` may be omitted to use the `typeName` inside the file.
 */
export class SchemaFile {
    constructor(
        public readonly path: string,
        public readonly typeName?: string,
    ) {}

    readContent(): string {
        return readFileSync(this.path, 'utf8');
    }
}

export type SchemaSource = AdditionalSchemaSource | SchemaFile;

export interface EngineConfig {
    /** Engine-native rules (Rego for RegoEngine, CEL for CelEngine). */
    customRules?: RuleSource[];
    /** CloudFormation Guard DSL rules, usable with either engine. */
    guardRules?: RuleSource[];
    /**
     * Optional schema validator configuration. When present, the engine derives
     * overlay-aware metadata from the configured additional schemas.
     */
    schemaValidatorConfig?: SchemaValidatorConfig;
}

/**
 * Configuration for the schema validator. Additional schemas are merged on top
 * of the bundled CloudFormation provider schemas before schema validation.
 */
export interface SchemaValidatorConfig {
    /**
     * Additional CloudFormation resource provider schemas to merge on top of the
     * bundled schemas. Each overlay extends or overrides the bundled schema for
     * its resource type.
     */
    additionalSchemas?: SchemaSource[];
}

function toExternalRuleSources(sources?: RuleSource[]): ExternalRuleSource[] {
    return (sources ?? []).map((source) =>
        source instanceof RuleFile ? { name: source.path, content: source.readContent() } : source,
    );
}

function toAdditionalSchemas(sources?: SchemaSource[]): AdditionalSchemaSource[] {
    return (sources ?? []).map((source) =>
        source instanceof SchemaFile ? { typeName: source.typeName, schema: source.readContent() } : source,
    );
}

function toWasmEngineConfig(config?: EngineConfig): WasmEngineConfig {
    return {
        customRules: toExternalRuleSources(config?.customRules),
        guardRules: toExternalRuleSources(config?.guardRules),
        schemaValidatorConfig: config?.schemaValidatorConfig
            ? toWasmSchemaValidatorConfig(config.schemaValidatorConfig)
            : undefined,
    };
}

function toWasmSchemaValidatorConfig(config?: SchemaValidatorConfig): WasmSchemaValidatorConfig {
    return {
        additionalSchemas: toAdditionalSchemas(config?.additionalSchemas),
    };
}

export class TemplateModel {
    private readonly inner: InstanceType<typeof bridge.WasmSemanticModel>;

    constructor(template: TemplateFile) {
        this.inner = bridge.WasmSemanticModel.parse(template.readBytes());
    }

    resources(): Record<string, ResolvedResource> {
        return this.inner.resources();
    }
    parameters(): Record<string, ParameterInfo> {
        return this.inner.parameters();
    }
    outputs(): Record<string, ResolvedOutput> {
        return this.inner.outputs();
    }
    conditions(): string[] {
        return this.inner.conditions();
    }
    transforms(): string[] {
        return this.inner.transforms();
    }
    formatVersion(): string | undefined {
        return this.inner.formatVersion();
    }
    description(): string | undefined {
        return this.inner.description();
    }
    toDiagnosticModel(): DiagnosticModel {
        return this.inner.toDiagnosticModel();
    }
    sourceLocation(path: string): SourceSpan | null {
        return this.inner.sourceLocation(path);
    }

    free(): void {
        this.inner.free();
    }
}

export class SchemaValidator {
    private readonly inner: InstanceType<typeof bridge.WasmSchemaValidator>;

    constructor(config?: SchemaValidatorConfig) {
        this.inner = new bridge.WasmSchemaValidator(toWasmSchemaValidatorConfig(config));
    }

    listRules(): RuleInfo[] {
        return this.inner.listRules();
    }

    schemaCount(): number {
        return this.inner.schemaCount();
    }

    validate(template: TemplateFile, region?: string): StandardDiagnostic[] {
        const model = bridge.WasmSemanticModel.parse(template.readBytes());
        try {
            return this.inner.validate(model, region).diagnostics;
        } finally {
            model.free();
        }
    }

    free(): void {
        this.inner.free();
    }
}

interface WasmEngineInstance {
    validateStandard(template: Uint8Array, options: ValidateConfig, filePath: string): StandardReport;
    validateDetailed(template: Uint8Array, options: ValidateConfig, filePath: string): DetailedReport;
    validateAwsApiRequest(request: WireAwsApiRequest, options: ValidateConfig): WireAwsApiRequestValidation;
    listRules(): RuleInfo[];
    engineName(): string;
    free(): void;
}

function createEngineClass(
    WasmClass: new (config: WasmEngineConfig) => WasmEngineInstance,
): new (config?: EngineConfig) => Engine {
    return class implements Engine {
        private readonly inner: WasmEngineInstance;

        constructor(config?: EngineConfig) {
            this.inner = new WasmClass(toWasmEngineConfig(config));
        }

        validateStandard(template: TemplateFile, config?: ValidateConfig): StandardReport {
            return this.inner.validateStandard(template.readBytes(), config ?? {}, template.path);
        }

        validateDetailed(template: TemplateFile, config?: ValidateConfig): DetailedReport {
            return this.inner.validateDetailed(template.readBytes(), config ?? {}, template.path);
        }

        validateAwsApiRequest(request: AwsApiRequest, config?: ValidateConfig): AwsApiRequestValidation {
            if (!(request instanceof AwsApiRequest)) {
                throw new TypeError('request must be an AwsApiRequest');
            }
            return fromWireAwsApiRequestValidation(
                this.inner.validateAwsApiRequest(toWireAwsApiRequest(request), config ?? {}),
            );
        }

        listRules(): RuleInfo[] {
            return this.inner.listRules();
        }

        engineName(): string {
            return this.inner.engineName();
        }

        free(): void {
            this.inner.free();
        }
    } as new (config?: EngineConfig) => Engine;
}

export const RegoEngine: new (config?: EngineConfig) => Engine = createEngineClass(bridge.WasmRegoEngine);
export const CelEngine: new (config?: EngineConfig) => Engine = createEngineClass(bridge.WasmCelEngine);

export function version(): string {
    return bridge.version();
}
