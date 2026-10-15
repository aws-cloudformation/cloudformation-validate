import type {
    Diagnostic,
    ValidationReport,
    DiagnosticModel,
    AdditionalSchemaSource,
    EngineConfig as WasmEngineConfig,
    CompositeEngineConfig as WasmCompositeEngineConfig,
    SchemaValidatorConfig as WasmSchemaValidatorConfig,
    ExternalRuleSource,
    ParameterInfo,
    ResolvedOutput,
    ResolvedResource,
    RuleInfo,
    SourceSpan,
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
    Diagnostic,
    PhaseMetric,
    PerformanceMetrics,
    Summary,
    ReportMetadata,
    ValidationReport,
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

/** @deprecated Use {@link Diagnostic}; a `STANDARD` report leaves its enrichment fields undefined. */
export type StandardDiagnostic = Diagnostic;
/** @deprecated Use {@link Diagnostic}. */
export type DetailedDiagnostic = Diagnostic;
/** @deprecated Use {@link ValidationReport} with `detailLevel: 'STANDARD'`. */
export type StandardReport = ValidationReport;
/** @deprecated Use {@link ValidationReport}. */
export type DetailedReport = ValidationReport;

export type AwsCliOperationKind =
    | 'READ_ONLY'
    | 'CLOUD_FORMATION_CREATE'
    | 'CLOUD_FORMATION_UPDATE'
    | 'CLOUD_FORMATION_DELETE'
    | 'DATA_PLANE_MUTATION'
    | 'UNMAPPED_MUTATION';
export type AwsCliCommandValidationStatus = 'VALIDATED' | 'SKIPPED';
export type AwsCliTemplateSource =
    'TEMPLATE_BODY' | 'CLOUD_CONTROL_DESIRED_STATE' | 'SYNTHESIZED_CREATE' | 'SYNTHESIZED_UPDATE';

export interface AwsCliCommandOptions {
    servicePrefix?: string;
    httpMethod?: string;
    isReadOnly?: boolean;
}

/**
 * Service, operation, and input values for one AWS CLI command.
 *
 * `serviceName` is the canonical botocore service name and is normalized only
 * for ASCII case. Callers adapting an SDK request must translate its native
 * service identity before constructing this request; endpoint and signing-name
 * aliases are never guessed by the validation core.
 */
export class AwsCliCommand {
    public readonly parameters: Record<string, unknown>;
    public readonly servicePrefix?: string;
    public readonly httpMethod?: string;
    public readonly isReadOnly?: boolean;

    constructor(
        public readonly serviceName: string,
        public readonly operationName: string,
        parameters: Record<string, unknown>,
        options: AwsCliCommandOptions = {},
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

export interface AwsCliCommandValidation {
    operationKind: AwsCliOperationKind;
    status: AwsCliCommandValidationStatus;
    templateSource: AwsCliTemplateSource | null;
    resourceTypes: string[];
    reason: string;
    report: ValidationReport | null;
    template: Uint8Array | null;
}

type WireAwsCliValue =
    | { type: 'NULL' }
    | { type: 'BOOLEAN'; value: boolean }
    | { type: 'INTEGER'; value: number | bigint }
    | { type: 'UNSIGNED_INTEGER'; value: bigint }
    | { type: 'NUMBER'; value: number }
    | { type: 'STRING'; value: string }
    | { type: 'BYTES'; value: number[] }
    | { type: 'ARRAY'; items: WireAwsCliValue[] }
    | { type: 'OBJECT'; entries: Record<string, WireAwsCliValue> }
    | { type: 'UNSUPPORTED'; type_name: string };

interface WireAwsCliCommand {
    serviceName: string;
    operationName: string;
    parameters: Record<string, WireAwsCliValue>;
    servicePrefix?: string;
    httpMethod?: string;
    isReadOnly?: boolean;
}

interface WireAwsCliCommandValidation extends Omit<AwsCliCommandValidation, 'template'> {
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

function unsupportedValue(typeName: string): WireAwsCliValue {
    return { type: 'UNSUPPORTED', type_name: typeName };
}

function encodeAwsCliValue(value: unknown, depth = 0, ancestors = new Set<object>()): WireAwsCliValue {
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
            const items: WireAwsCliValue[] = [];
            for (let index = 0; index < lengthDescriptor.value; index += 1) {
                const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
                if (descriptor === undefined) {
                    return unsupportedValue('sparse array');
                }
                if (!('value' in descriptor)) {
                    return unsupportedValue('array with accessor elements');
                }
                items.push(encodeAwsCliValue(descriptor.value, depth + 1, ancestors));
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
            const entries = Object.create(null) as Record<string, WireAwsCliValue>;
            for (const key of Reflect.ownKeys(value)) {
                if (typeof key !== 'string') {
                    return unsupportedValue('mapping with non-string keys');
                }
                const descriptor = Object.getOwnPropertyDescriptor(value, key);
                if (descriptor === undefined || !('value' in descriptor)) {
                    return unsupportedValue('mapping with accessor properties');
                }
                entries[key] = encodeAwsCliValue(descriptor.value, depth + 1, ancestors);
            }
            return { type: 'OBJECT', entries };
        } finally {
            ancestors.delete(value);
        }
    }
    return unsupportedValue(typeof value);
}

function toWireAwsCliCommand(request: AwsCliCommand): WireAwsCliCommand {
    const parameters = Object.create(null) as Record<string, WireAwsCliValue>;
    for (const [name, value] of Object.entries(request.parameters)) {
        try {
            parameters[name] = encodeAwsCliValue(value);
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

function fromWireAwsCliCommandValidation(validation: WireAwsCliCommandValidation): AwsCliCommandValidation {
    const template = validation.template;
    return {
        ...validation,
        templateSource: validation.templateSource ?? null,
        report: validation.report ?? null,
        template: template == null ? null : Uint8Array.from(template),
    };
}

export interface Engine {
    validateTemplate(template: Template, config?: ValidateConfig): ValidationReport;
    /**
     * @deprecated Use {@link validateTemplate} with `detailLevel: 'STANDARD'`. Any `detailLevel`
     * in `config` is overridden by `'STANDARD'`.
     */
    validateStandard(template: Template, config?: ValidateConfig): StandardReport;
    /**
     * @deprecated Use {@link validateTemplate}; `DETAILED` is already its default. Any `detailLevel`
     * in `config` is overridden by `'DETAILED'`.
     */
    validateDetailed(template: Template, config?: ValidateConfig): DetailedReport;
    validateAwsCliCommand(request: AwsCliCommand): AwsCliCommandValidation;
    listRules(): RuleInfo[];
    engineName(): string;
    free(): void;
}

/** The error a WebAssembly trap raises; the configured TypeScript libraries do not declare it. */
const WasmRuntimeError = (globalThis as unknown as { WebAssembly: { RuntimeError: new (message?: string) => Error } })
    .WebAssembly.RuntimeError;

type Bridge = typeof import('../dist/bindings_wasm');

/** Generated-glue members the host relies on to own each object's lifetime. */
interface WasmObject {
    __wbg_ptr: number;
    __destroy_into_raw(): number;
    free(): void;
}

/** Errors the instance guard raised itself, rethrown unchanged by enclosing guards. */
const guardErrors = new WeakSet<object>();
const INTERNAL_ERROR_PREFIX = 'Internal validation error';

function guardError(message: string): Error {
    const error = new WasmRuntimeError(message);
    guardErrors.add(error);
    return error;
}

function isTrap(error: unknown): boolean {
    return error instanceof WasmRuntimeError || (error instanceof RangeError && /call stack/i.test(error.message));
}

/**
 * One evaluation of the generated glue and the WebAssembly instance it created.
 *
 * A Rust panic, an allocation failure, or a stack overflow traps the instance
 * mid-call without running Rust cleanup, so locks, borrows, and the shadow
 * stack can be left inconsistent. The first such failure terminates the
 * instance: every later call on an object it owns throws instead of running
 * on that state, and objects constructed afterwards use a fresh instance.
 */
class WasmInstance {
    readonly bridge: Bridge;
    private panicMessage: string | undefined;
    private terminationReason: string | undefined;

    constructor(bridge: Bridge) {
        this.bridge = bridge;
        bridge.setPanicListener((message: string) => {
            this.panicMessage = message;
        });
    }

    get terminated(): boolean {
        return this.terminationReason !== undefined;
    }

    /** Runs one call into the instance; terminates it if the call did not return through Rust. */
    call<T>(operation: (bridge: Bridge) => T): T {
        if (this.terminationReason !== undefined) {
            throw guardError(
                `${INTERNAL_ERROR_PREFIX}: the WebAssembly instance was terminated by an earlier failure ` +
                    `(${this.terminationReason}); construct a new object to continue`,
            );
        }
        this.panicMessage = undefined;
        try {
            return operation(this.bridge);
        } catch (error) {
            if (typeof error === 'object' && error !== null && guardErrors.has(error)) {
                throw error;
            }
            if (this.panicMessage === undefined && !isTrap(error) && !this.interrupted()) {
                throw error;
            }
            const reason = this.panicMessage ?? (error instanceof Error ? error.message : String(error));
            this.terminate(reason);
            if (this.panicMessage === undefined && !isTrap(error)) {
                // A host runtime hook interrupted generated deserialization: preserve
                // the original exception while preventing reuse of the abandoned frame.
                throw error;
            }
            const failure = guardError(`${INTERNAL_ERROR_PREFIX}: ${reason}`);
            Object.defineProperty(failure, 'cause', { value: error, configurable: true, writable: true });
            throw failure;
        } finally {
            this.panicMessage = undefined;
        }
    }

    private interrupted(): boolean {
        try {
            return this.bridge.activeCalls() !== 0;
        } catch {
            return true;
        }
    }

    private terminate(reason: string): void {
        this.terminationReason ??= reason;
        if (activeInstance === this) {
            activeInstance = undefined;
        }
    }
}

const loadedBridges = new WeakSet<object>();

function resolveBridgeCacheKey(): string | undefined {
    try {
        return require.resolve('../dist/bindings_wasm');
    } catch {
        return undefined;
    }
}

function evictBridgeModule(): unknown {
    const bridgeCacheKey = resolveBridgeCacheKey();
    if (bridgeCacheKey === undefined) {
        return undefined;
    }
    const staleBridge = require.cache?.[bridgeCacheKey];
    if (staleBridge === undefined) {
        return undefined;
    }
    delete require.cache[bridgeCacheKey];
    const childModules: NodeModule[] | undefined = module.children;
    if (Array.isArray(childModules)) {
        for (let index = childModules.length - 1; index >= 0; index -= 1) {
            if (childModules[index] === staleBridge) {
                childModules.splice(index, 1);
            }
        }
    }
    return staleBridge.exports;
}

function loadInstance(): WasmInstance {
    const evictedBridge = evictBridgeModule();
    const bridge: Bridge = require('../dist/bindings_wasm');
    if (bridge === evictedBridge || loadedBridges.has(bridge)) {
        throw new WasmRuntimeError(
            `${INTERNAL_ERROR_PREFIX}: the WebAssembly instance was terminated and this module loader ` +
                'cannot create a fresh one; restart the process or worker to continue',
        );
    }
    loadedBridges.add(bridge);
    return new WasmInstance(bridge);
}

let activeInstance: WasmInstance | undefined;

function currentInstance(): WasmInstance {
    activeInstance ??= loadInstance();
    return activeInstance;
}

interface Allocation {
    readonly instance: WasmInstance;
    readonly prototype: object;
    readonly pointer: number;
}

/**
 * Frees objects the caller dropped without calling `free()`. It replaces the
 * generated glue's own finalizer, which calls into the instance unconditionally:
 * after a trap that call can trap again inside a finalization callback, which
 * Node.js reports as an uncaught exception.
 */
const allocations = new FinalizationRegistry<Allocation>(({ instance, prototype, pointer }) => {
    if (instance.terminated) {
        return;
    }
    try {
        instance.call(() => {
            const shell = Object.create(prototype) as WasmObject;
            shell.__wbg_ptr = pointer;
            shell.free();
        });
    } catch {
        // The failure has already terminated the instance; a finalizer has no caller to report to.
    }
});

/** Exclusive owner of one generated-glue object and the instance that created it. */
class Owned<T extends object> {
    private inner: T | undefined;

    constructor(
        private readonly instance: WasmInstance,
        create: (bridge: Bridge) => T,
        private readonly label: string,
    ) {
        const inner = instance.call(create);
        const object = inner as unknown as WasmObject;
        const pointer = object.__destroy_into_raw();
        object.__wbg_ptr = pointer;
        allocations.register(inner, { instance, prototype: Object.getPrototypeOf(inner), pointer }, inner);
        this.inner = inner;
    }

    /** The live object, for passing as an argument to another call on the same instance. */
    raw(): T {
        if (this.inner === undefined) {
            throw new Error(`${this.label} has been freed`);
        }
        return this.inner;
    }

    use<R>(operation: (inner: T) => R): R {
        const inner = this.inner;
        if (inner === undefined) {
            throw new Error(`${this.label} has been freed`);
        }
        return this.instance.call(() => operation(inner));
    }

    free(): void {
        const inner = this.inner;
        if (inner === undefined) {
            return;
        }
        this.inner = undefined;
        allocations.unregister(inner);
        if (!this.instance.terminated) {
            this.instance.call(() => (inner as unknown as WasmObject).free());
        }
    }
}

activeInstance = loadInstance();

/** Name reported for an in-memory template when the caller does not supply one. */
export const DEFAULT_TEMPLATE_NAME = 'template';

/** A template read from disk; the path labels the report and its diagnostics. */
export class TemplateFile {
    constructor(public readonly path: string) {}

    readBytes(): Uint8Array {
        return readFileSync(this.path);
    }
}

/**
 * A template already held in memory as UTF-8 text or raw bytes, so nothing is
 * read from disk. `name` labels the report and its diagnostics exactly like a
 * {@link TemplateFile} path does and defaults to {@link DEFAULT_TEMPLATE_NAME}.
 */
export class TemplateContent {
    constructor(
        public readonly content: string | Uint8Array,
        public readonly name: string = DEFAULT_TEMPLATE_NAME,
    ) {
        if (typeof content !== 'string' && !(content instanceof Uint8Array)) {
            throw new TypeError('template content must be a string or a Uint8Array');
        }
    }

    readBytes(): Uint8Array {
        return typeof this.content === 'string' ? new TextEncoder().encode(this.content) : this.content;
    }
}

/** A template source accepted by every template-consuming API: on disk or in memory. */
export type Template = TemplateFile | TemplateContent;

function templateLabel(template: Template): string {
    const label = template instanceof TemplateContent ? template.name : template.path;
    if (typeof label !== 'string') {
        throw new TypeError('template name must be a string');
    }
    return label;
}

function templateBytes(template: Template): Uint8Array {
    const bytes = template.readBytes();
    if (!(bytes instanceof Uint8Array)) {
        throw new TypeError('template content must be a string or a Uint8Array');
    }
    return new Uint8Array(bytes);
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
 * Configuration for the {@link CompositeEngine}. The built-in rules are always
 * evaluated by the engine's fixed built-in evaluator, so these fields only layer
 * external rules on top - there is no engine-native custom-rule field.
 */
export interface CompositeEngineConfig {
    /** Custom Rego rules layered on top of the built-in rules. */
    regoRules?: RuleSource[];
    /** Custom CEL rules layered on top of the built-in rules. */
    celRules?: RuleSource[];
    /** CloudFormation Guard DSL rules layered on top of the built-in rules. */
    guardRules?: RuleSource[];
    /**
     * Optional schema validator configuration, observed by both the built-in and
     * external rule evaluation.
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

const MAX_WASM_INPUT_DEPTH = 64;
const MAP_FOR_EACH = Map.prototype.forEach;

function copyWasmInput(value: unknown, path: string, depth = 0, ancestors = new Set<object>()): unknown {
    if (value === null || (typeof value !== 'object' && typeof value !== 'function')) {
        return value;
    }
    if (depth > MAX_WASM_INPUT_DEPTH) {
        throw new TypeError(`${path} exceeds the supported nesting depth`);
    }
    if (ancestors.has(value)) {
        throw new TypeError(`${path} must not contain a cycle`);
    }
    ancestors.add(value);
    try {
        if (Array.isArray(value)) {
            const length = Object.getOwnPropertyDescriptor(value, 'length')?.value;
            if (!Number.isSafeInteger(length) || length < 0) {
                throw new TypeError(`${path} must have a valid array length`);
            }
            const copied: unknown[] = [];
            for (let index = 0; index < length; index += 1) {
                const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
                if (descriptor === undefined || !('value' in descriptor)) {
                    throw new TypeError(`${path}[${index}] must be a value property`);
                }
                copied.push(copyWasmInput(descriptor.value, `${path}[${index}]`, depth + 1, ancestors));
            }
            return copied;
        }
        if (value instanceof Map) {
            const copied = new Map<unknown, unknown>();
            MAP_FOR_EACH.call(value, (entryValue: unknown, entryKey: unknown) => {
                copied.set(
                    copyWasmInput(entryKey, `${path} key`, depth + 1, ancestors),
                    copyWasmInput(entryValue, `${path} value`, depth + 1, ancestors),
                );
            });
            return copied;
        }
        if (!isPlainRecord(value)) {
            throw new TypeError(`${path} must contain only plain objects, arrays, maps, and primitive values`);
        }
        const copied = Object.create(null) as Record<string, unknown>;
        for (const key of Reflect.ownKeys(value)) {
            if (typeof key !== 'string') {
                throw new TypeError(`${path} property names must be strings`);
            }
            const descriptor = Object.getOwnPropertyDescriptor(value, key);
            if (descriptor === undefined || !('value' in descriptor)) {
                throw new TypeError(`${path}.${key} must be a value property`);
            }
            copied[key] = copyWasmInput(descriptor.value, `${path}.${key}`, depth + 1, ancestors);
        }
        return copied;
    } finally {
        ancestors.delete(value);
    }
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

function toWasmCompositeEngineConfig(config?: CompositeEngineConfig): WasmCompositeEngineConfig {
    return {
        regoRules: toExternalRuleSources(config?.regoRules),
        celRules: toExternalRuleSources(config?.celRules),
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

type WasmSemanticModel = ReturnType<Bridge['WasmSemanticModel']['parse']>;

export class TemplateModel {
    private readonly owned: Owned<WasmSemanticModel>;

    constructor(template: Template) {
        const bytes = templateBytes(template);
        this.owned = new Owned(currentInstance(), (bridge) => bridge.WasmSemanticModel.parse(bytes), 'TemplateModel');
    }

    resources(): Record<string, ResolvedResource> {
        return this.owned.use((inner) => inner.resources());
    }
    parameters(): Record<string, ParameterInfo> {
        return this.owned.use((inner) => inner.parameters());
    }
    outputs(): Record<string, ResolvedOutput> {
        return this.owned.use((inner) => inner.outputs());
    }
    conditions(): string[] {
        return this.owned.use((inner) => inner.conditions());
    }
    transforms(): string[] {
        return this.owned.use((inner) => inner.transforms());
    }
    formatVersion(): string | undefined {
        return this.owned.use((inner) => inner.formatVersion());
    }
    description(): string | undefined {
        return this.owned.use((inner) => inner.description());
    }
    toDiagnosticModel(): DiagnosticModel {
        return this.owned.use((inner) => inner.toDiagnosticModel());
    }
    sourceLocation(path: string): SourceSpan | null {
        if (typeof path !== 'string') {
            throw new TypeError('path must be a string');
        }
        return this.owned.use((inner) => inner.sourceLocation(path));
    }

    free(): void {
        this.owned.free();
    }
}

export class SchemaValidator {
    private readonly instance: WasmInstance;
    private readonly owned: Owned<InstanceType<Bridge['WasmSchemaValidator']>>;

    constructor(config?: SchemaValidatorConfig) {
        const wasmConfig = copyWasmInput(
            toWasmSchemaValidatorConfig(config),
            'schema validator config',
        ) as WasmSchemaValidatorConfig;
        this.instance = currentInstance();
        this.owned = new Owned(
            this.instance,
            (bridge) => new bridge.WasmSchemaValidator(wasmConfig),
            'SchemaValidator',
        );
    }

    listRules(): RuleInfo[] {
        return this.owned.use((inner) => inner.listRules());
    }

    schemaCount(): number {
        return this.owned.use((inner) => inner.schemaCount());
    }

    validate(template: Template, region?: string): Diagnostic[] {
        if (region !== undefined && typeof region !== 'string') {
            throw new TypeError('region must be a string');
        }
        const bytes = templateBytes(template);
        const model = new Owned(this.instance, (bridge) => bridge.WasmSemanticModel.parse(bytes), 'TemplateModel');
        try {
            const parsed = model.raw();
            return this.owned.use((inner) => inner.validate(parsed, region).diagnostics);
        } finally {
            model.free();
        }
    }

    free(): void {
        this.owned.free();
    }
}

interface WasmEngineInstance {
    validateTemplate(template: Uint8Array, options: ValidateConfig, filePath: string): ValidationReport;
    validateAwsCliCommand(request: WireAwsCliCommand): WireAwsCliCommandValidation;
    listRules(): RuleInfo[];
    engineName(): string;
    free(): void;
}

function createEngineClass<TConfig, TWasmConfig>(
    label: string,
    wasmClass: (bridge: Bridge) => new (config: TWasmConfig) => WasmEngineInstance,
    toWasmConfig: (config?: TConfig) => TWasmConfig,
): new (config?: TConfig) => Engine {
    return class implements Engine {
        private readonly owned: Owned<WasmEngineInstance>;

        constructor(config?: TConfig) {
            const wasmConfig = copyWasmInput(toWasmConfig(config), `${label} config`) as TWasmConfig;
            this.owned = new Owned(currentInstance(), (bridge) => new (wasmClass(bridge))(wasmConfig), label);
        }

        validateTemplate(template: Template, config?: ValidateConfig): ValidationReport {
            const bytes = templateBytes(template);
            const label = templateLabel(template);
            const wasmConfig = copyWasmInput(config ?? {}, 'validation config') as ValidateConfig;
            return this.owned.use((inner) => inner.validateTemplate(bytes, wasmConfig, label));
        }

        validateStandard(template: Template, config?: ValidateConfig): StandardReport {
            return this.validateTemplate(template, { ...config, detailLevel: 'STANDARD' });
        }

        validateDetailed(template: Template, config?: ValidateConfig): DetailedReport {
            return this.validateTemplate(template, { ...config, detailLevel: 'DETAILED' });
        }

        validateAwsCliCommand(request: AwsCliCommand): AwsCliCommandValidation {
            if (!(request instanceof AwsCliCommand)) {
                throw new TypeError('request must be an AwsCliCommand');
            }
            const wire = toWireAwsCliCommand(request);
            return fromWireAwsCliCommandValidation(this.owned.use((inner) => inner.validateAwsCliCommand(wire)));
        }

        listRules(): RuleInfo[] {
            return this.owned.use((inner) => inner.listRules());
        }

        engineName(): string {
            return this.owned.use((inner) => inner.engineName());
        }

        free(): void {
            this.owned.free();
        }
    } as new (config?: TConfig) => Engine;
}

export const RegoEngine: new (config?: EngineConfig) => Engine = createEngineClass(
    'RegoEngine',
    (bridge) => bridge.WasmRegoEngine,
    toWasmEngineConfig,
);
export const CelEngine: new (config?: EngineConfig) => Engine = createEngineClass(
    'CelEngine',
    (bridge) => bridge.WasmCelEngine,
    toWasmEngineConfig,
);
export const CompositeEngine: new (config?: CompositeEngineConfig) => Engine = createEngineClass(
    'CompositeEngine',
    (bridge) => bridge.WasmCompositeEngine,
    toWasmCompositeEngineConfig,
);

export function version(): string {
    return currentInstance().call((bridge) => bridge.version());
}
