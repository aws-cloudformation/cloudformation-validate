'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.CelEngine =
    exports.RegoEngine =
    exports.SchemaValidator =
    exports.TemplateModel =
    exports.SchemaFile =
    exports.RuleFile =
    exports.TemplateFile =
        void 0;
exports.version = version;
const fs_1 = require('fs');
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
function createEngineClass(WasmClass) {
    return class {
        constructor(config) {
            this.inner = new WasmClass(toWasmEngineConfig(config));
        }
        validateStandard(template, config) {
            return this.inner.validateStandard(template.readBytes(), config ?? {}, template.path);
        }
        validateDetailed(template, config) {
            return this.inner.validateDetailed(template.readBytes(), config ?? {}, template.path);
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
exports.RegoEngine = createEngineClass(bridge.WasmRegoEngine);
exports.CelEngine = createEngineClass(bridge.WasmCelEngine);
function version() {
    return bridge.version();
}
