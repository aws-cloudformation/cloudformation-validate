'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.CompositeEngine =
    exports.CelEngine =
    exports.RegoEngine =
    exports.SchemaValidator =
    exports.TemplateModel =
    exports.SchemaFile =
    exports.RuleFile =
    exports.TemplateContent =
    exports.TemplateFile =
    exports.DEFAULT_TEMPLATE_NAME =
    exports.AwsCliCommand =
        void 0;
exports.version = version;
const fs_1 = require('fs');
/**
 * Service, operation, and input values for one AWS CLI command.
 *
 * `serviceName` is the canonical botocore service name and is normalized only
 * for ASCII case. Callers adapting an SDK request must translate its native
 * service identity before constructing this request; endpoint and signing-name
 * aliases are never guessed by the validation core.
 */
class AwsCliCommand {
    constructor(serviceName, operationName, parameters, options = {}) {
        this.serviceName = serviceName;
        this.operationName = operationName;
        if (!isPlainRecord(parameters)) {
            throw new TypeError('parameters must be a plain object with string keys');
        }
        const copiedParameters = Object.create(null);
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
exports.AwsCliCommand = AwsCliCommand;
const MIN_SIGNED_64 = -(1n << 63n);
const MAX_SIGNED_64 = (1n << 63n) - 1n;
const MAX_UNSIGNED_64 = (1n << 64n) - 1n;
const MAX_REQUEST_VALUE_DEPTH = 64;
const DATE_GET_TIME = Date.prototype.getTime;
const DATE_TO_ISO_STRING = Date.prototype.toISOString;
const UINT8_ARRAY_FOR_EACH = Uint8Array.prototype.forEach;
function isPlainRecord(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
        return false;
    }
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function unsupportedValue(typeName) {
    return { type: 'UNSUPPORTED', type_name: typeName };
}
function encodeAwsCliValue(value, depth = 0, ancestors = new Set()) {
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
        const bytes = [];
        try {
            UINT8_ARRAY_FOR_EACH.call(value, (byte) => {
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
            const items = [];
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
            const entries = Object.create(null);
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
function toWireAwsCliCommand(request) {
    const parameters = Object.create(null);
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
function fromWireAwsCliCommandValidation(validation) {
    const template = validation.template;
    return {
        ...validation,
        templateSource: validation.templateSource ?? null,
        report: validation.report ?? null,
        template: template == null ? null : Uint8Array.from(template),
    };
}
/** The error a WebAssembly trap raises; the configured TypeScript libraries do not declare it. */
const WasmRuntimeError = globalThis.WebAssembly.RuntimeError;
/** Errors the instance guard raised itself, rethrown unchanged by enclosing guards. */
const guardErrors = new WeakSet();
const INTERNAL_ERROR_PREFIX = 'Internal validation error';
function guardError(message) {
    const error = new WasmRuntimeError(message);
    guardErrors.add(error);
    return error;
}
function isTrap(error) {
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
    constructor(bridge) {
        this.bridge = bridge;
        bridge.setPanicListener((message) => {
            this.panicMessage = message;
        });
    }
    get terminated() {
        return this.terminationReason !== undefined;
    }
    /** Runs one call into the instance; terminates it if the call did not return through Rust. */
    call(operation) {
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
    interrupted() {
        try {
            return this.bridge.activeCalls() !== 0;
        } catch {
            return true;
        }
    }
    terminate(reason) {
        this.terminationReason ?? (this.terminationReason = reason);
        if (activeInstance === this) {
            activeInstance = undefined;
        }
    }
}
const loadedBridges = new WeakSet();
function resolveBridgeCacheKey() {
    try {
        return require.resolve('./bindings_wasm');
    } catch {
        return undefined;
    }
}
function evictBridgeModule() {
    const bridgeCacheKey = resolveBridgeCacheKey();
    if (bridgeCacheKey === undefined) {
        return undefined;
    }
    const staleBridge = require.cache?.[bridgeCacheKey];
    if (staleBridge === undefined) {
        return undefined;
    }
    delete require.cache[bridgeCacheKey];
    const childModules = module.children;
    if (Array.isArray(childModules)) {
        for (let index = childModules.length - 1; index >= 0; index -= 1) {
            if (childModules[index] === staleBridge) {
                childModules.splice(index, 1);
            }
        }
    }
    return staleBridge.exports;
}
function loadInstance() {
    const evictedBridge = evictBridgeModule();
    const bridge = require('./bindings_wasm');
    if (bridge === evictedBridge || loadedBridges.has(bridge)) {
        throw new WasmRuntimeError(
            `${INTERNAL_ERROR_PREFIX}: the WebAssembly instance was terminated and this module loader ` +
                'cannot create a fresh one; restart the process or worker to continue',
        );
    }
    loadedBridges.add(bridge);
    return new WasmInstance(bridge);
}
let activeInstance;
function currentInstance() {
    activeInstance ?? (activeInstance = loadInstance());
    return activeInstance;
}
/**
 * Frees objects the caller dropped without calling `free()`. It replaces the
 * generated glue's own finalizer, which calls into the instance unconditionally:
 * after a trap that call can trap again inside a finalization callback, which
 * Node.js reports as an uncaught exception.
 */
const allocations = new FinalizationRegistry(({ instance, prototype, pointer }) => {
    if (instance.terminated) {
        return;
    }
    try {
        instance.call(() => {
            const shell = Object.create(prototype);
            shell.__wbg_ptr = pointer;
            shell.free();
        });
    } catch {
        // The failure has already terminated the instance; a finalizer has no caller to report to.
    }
});
/** Exclusive owner of one generated-glue object and the instance that created it. */
class Owned {
    constructor(instance, create, label) {
        this.instance = instance;
        this.label = label;
        const inner = instance.call(create);
        const object = inner;
        const pointer = object.__destroy_into_raw();
        object.__wbg_ptr = pointer;
        allocations.register(inner, { instance, prototype: Object.getPrototypeOf(inner), pointer }, inner);
        this.inner = inner;
    }
    /** The live object, for passing as an argument to another call on the same instance. */
    raw() {
        if (this.inner === undefined) {
            throw new Error(`${this.label} has been freed`);
        }
        return this.inner;
    }
    use(operation) {
        const inner = this.inner;
        if (inner === undefined) {
            throw new Error(`${this.label} has been freed`);
        }
        return this.instance.call(() => operation(inner));
    }
    free() {
        const inner = this.inner;
        if (inner === undefined) {
            return;
        }
        this.inner = undefined;
        allocations.unregister(inner);
        if (!this.instance.terminated) {
            this.instance.call(() => inner.free());
        }
    }
}
activeInstance = loadInstance();
/** Name reported for an in-memory template when the caller does not supply one. */
exports.DEFAULT_TEMPLATE_NAME = 'template';
/** A template read from disk; the path labels the report and its diagnostics. */
class TemplateFile {
    constructor(path) {
        this.path = path;
    }
    readBytes() {
        return (0, fs_1.readFileSync)(this.path);
    }
}
exports.TemplateFile = TemplateFile;
/**
 * A template already held in memory as UTF-8 text or raw bytes, so nothing is
 * read from disk. `name` labels the report and its diagnostics exactly like a
 * {@link TemplateFile} path does and defaults to {@link DEFAULT_TEMPLATE_NAME}.
 */
class TemplateContent {
    constructor(content, name = exports.DEFAULT_TEMPLATE_NAME) {
        this.content = content;
        this.name = name;
        if (typeof content !== 'string' && !(content instanceof Uint8Array)) {
            throw new TypeError('template content must be a string or a Uint8Array');
        }
    }
    readBytes() {
        return typeof this.content === 'string' ? new TextEncoder().encode(this.content) : this.content;
    }
}
exports.TemplateContent = TemplateContent;
function templateLabel(template) {
    const label = template instanceof TemplateContent ? template.name : template.path;
    if (typeof label !== 'string') {
        throw new TypeError('template name must be a string');
    }
    return label;
}
function templateBytes(template) {
    const bytes = template.readBytes();
    if (!(bytes instanceof Uint8Array)) {
        throw new TypeError('template content must be a string or a Uint8Array');
    }
    return new Uint8Array(bytes);
}
class RuleFile {
    constructor(path) {
        this.path = path;
    }
    readContent() {
        return (0, fs_1.readFileSync)(this.path, 'utf8');
    }
}
exports.RuleFile = RuleFile;
/**
 * A CloudFormation resource provider schema loaded from a file, for use as an
 * overlay. `typeName` may be omitted to use the `typeName` inside the file.
 */
class SchemaFile {
    constructor(path, typeName) {
        this.path = path;
        this.typeName = typeName;
    }
    readContent() {
        return (0, fs_1.readFileSync)(this.path, 'utf8');
    }
}
exports.SchemaFile = SchemaFile;
const MAX_WASM_INPUT_DEPTH = 64;
const MAP_FOR_EACH = Map.prototype.forEach;
function copyWasmInput(value, path, depth = 0, ancestors = new Set()) {
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
            const copied = [];
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
            const copied = new Map();
            MAP_FOR_EACH.call(value, (entryValue, entryKey) => {
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
        const copied = Object.create(null);
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
function toExternalRuleSources(sources) {
    return (sources ?? []).map((source) =>
        source instanceof RuleFile ? { name: source.path, content: source.readContent() } : source,
    );
}
function toAdditionalSchemas(sources) {
    return (sources ?? []).map((source) =>
        source instanceof SchemaFile ? { typeName: source.typeName, schema: source.readContent() } : source,
    );
}
function toWasmEngineConfig(config) {
    return {
        customRules: toExternalRuleSources(config?.customRules),
        guardRules: toExternalRuleSources(config?.guardRules),
        schemaValidatorConfig: config?.schemaValidatorConfig
            ? toWasmSchemaValidatorConfig(config.schemaValidatorConfig)
            : undefined,
    };
}
function toWasmCompositeEngineConfig(config) {
    return {
        regoRules: toExternalRuleSources(config?.regoRules),
        celRules: toExternalRuleSources(config?.celRules),
        guardRules: toExternalRuleSources(config?.guardRules),
        schemaValidatorConfig: config?.schemaValidatorConfig
            ? toWasmSchemaValidatorConfig(config.schemaValidatorConfig)
            : undefined,
    };
}
function toWasmSchemaValidatorConfig(config) {
    return {
        additionalSchemas: toAdditionalSchemas(config?.additionalSchemas),
    };
}
class TemplateModel {
    constructor(template) {
        const bytes = templateBytes(template);
        this.owned = new Owned(currentInstance(), (bridge) => bridge.WasmSemanticModel.parse(bytes), 'TemplateModel');
    }
    resources() {
        return this.owned.use((inner) => inner.resources());
    }
    parameters() {
        return this.owned.use((inner) => inner.parameters());
    }
    outputs() {
        return this.owned.use((inner) => inner.outputs());
    }
    conditions() {
        return this.owned.use((inner) => inner.conditions());
    }
    transforms() {
        return this.owned.use((inner) => inner.transforms());
    }
    formatVersion() {
        return this.owned.use((inner) => inner.formatVersion());
    }
    description() {
        return this.owned.use((inner) => inner.description());
    }
    toDiagnosticModel() {
        return this.owned.use((inner) => inner.toDiagnosticModel());
    }
    sourceLocation(path) {
        if (typeof path !== 'string') {
            throw new TypeError('path must be a string');
        }
        return this.owned.use((inner) => inner.sourceLocation(path));
    }
    free() {
        this.owned.free();
    }
}
exports.TemplateModel = TemplateModel;
class SchemaValidator {
    constructor(config) {
        const wasmConfig = copyWasmInput(toWasmSchemaValidatorConfig(config), 'schema validator config');
        this.instance = currentInstance();
        this.owned = new Owned(
            this.instance,
            (bridge) => new bridge.WasmSchemaValidator(wasmConfig),
            'SchemaValidator',
        );
    }
    listRules() {
        return this.owned.use((inner) => inner.listRules());
    }
    schemaCount() {
        return this.owned.use((inner) => inner.schemaCount());
    }
    validate(template, region) {
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
    free() {
        this.owned.free();
    }
}
exports.SchemaValidator = SchemaValidator;
function createEngineClass(label, wasmClass, toWasmConfig) {
    return class {
        constructor(config) {
            const wasmConfig = copyWasmInput(toWasmConfig(config), `${label} config`);
            this.owned = new Owned(currentInstance(), (bridge) => new (wasmClass(bridge))(wasmConfig), label);
        }
        validateTemplate(template, config) {
            const bytes = templateBytes(template);
            const label = templateLabel(template);
            const wasmConfig = copyWasmInput(config ?? {}, 'validation config');
            return this.owned.use((inner) => inner.validateTemplate(bytes, wasmConfig, label));
        }
        validateStandard(template, config) {
            return this.validateTemplate(template, { ...config, detailLevel: 'STANDARD' });
        }
        validateDetailed(template, config) {
            return this.validateTemplate(template, { ...config, detailLevel: 'DETAILED' });
        }
        validateAwsCliCommand(request) {
            if (!(request instanceof AwsCliCommand)) {
                throw new TypeError('request must be an AwsCliCommand');
            }
            const wire = toWireAwsCliCommand(request);
            return fromWireAwsCliCommandValidation(this.owned.use((inner) => inner.validateAwsCliCommand(wire)));
        }
        listRules() {
            return this.owned.use((inner) => inner.listRules());
        }
        engineName() {
            return this.owned.use((inner) => inner.engineName());
        }
        free() {
            this.owned.free();
        }
    };
}
exports.RegoEngine = createEngineClass('RegoEngine', (bridge) => bridge.WasmRegoEngine, toWasmEngineConfig);
exports.CelEngine = createEngineClass('CelEngine', (bridge) => bridge.WasmCelEngine, toWasmEngineConfig);
exports.CompositeEngine = createEngineClass(
    'CompositeEngine',
    (bridge) => bridge.WasmCompositeEngine,
    toWasmCompositeEngineConfig,
);
function version() {
    return currentInstance().call((bridge) => bridge.version());
}
