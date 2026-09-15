'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.CompositeEngine =
    exports.CelEngine =
    exports.RegoEngine =
    exports.SchemaValidator =
    exports.TemplateModel =
    exports.SchemaFile =
    exports.RuleFile =
    exports.TemplateFile =
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
const bridge = require('./bindings_wasm');
class TemplateFile {
    constructor(path) {
        this.path = path;
    }
    readBytes() {
        return (0, fs_1.readFileSync)(this.path);
    }
}
exports.TemplateFile = TemplateFile;
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
        this.inner = bridge.WasmSemanticModel.parse(template.readBytes());
    }
    resources() {
        return this.inner.resources();
    }
    parameters() {
        return this.inner.parameters();
    }
    outputs() {
        return this.inner.outputs();
    }
    conditions() {
        return this.inner.conditions();
    }
    transforms() {
        return this.inner.transforms();
    }
    formatVersion() {
        return this.inner.formatVersion();
    }
    description() {
        return this.inner.description();
    }
    toDiagnosticModel() {
        return this.inner.toDiagnosticModel();
    }
    sourceLocation(path) {
        return this.inner.sourceLocation(path);
    }
    free() {
        this.inner.free();
    }
}
exports.TemplateModel = TemplateModel;
class SchemaValidator {
    constructor(config) {
        this.inner = new bridge.WasmSchemaValidator(toWasmSchemaValidatorConfig(config));
    }
    listRules() {
        return this.inner.listRules();
    }
    schemaCount() {
        return this.inner.schemaCount();
    }
    validate(template, region) {
        const model = bridge.WasmSemanticModel.parse(template.readBytes());
        try {
            return this.inner.validate(model, region).diagnostics;
        } finally {
            model.free();
        }
    }
    free() {
        this.inner.free();
    }
}
exports.SchemaValidator = SchemaValidator;
function createEngineClass(WasmClass, toWasmConfig) {
    return class {
        constructor(config) {
            this.inner = new WasmClass(toWasmConfig(config));
        }
        validateTemplate(template, config) {
            return this.inner.validateTemplate(template.readBytes(), config ?? {}, template.path);
        }
        validateAwsCliCommand(request) {
            if (!(request instanceof AwsCliCommand)) {
                throw new TypeError('request must be an AwsCliCommand');
            }
            return fromWireAwsCliCommandValidation(this.inner.validateAwsCliCommand(toWireAwsCliCommand(request)));
        }
        listRules() {
            return this.inner.listRules();
        }
        engineName() {
            return this.inner.engineName();
        }
        free() {
            this.inner.free();
        }
    };
}
exports.RegoEngine = createEngineClass(bridge.WasmRegoEngine, toWasmEngineConfig);
exports.CelEngine = createEngineClass(bridge.WasmCelEngine, toWasmEngineConfig);
exports.CompositeEngine = createEngineClass(bridge.WasmCompositeEngine, toWasmCompositeEngineConfig);
function version() {
    return bridge.version();
}
