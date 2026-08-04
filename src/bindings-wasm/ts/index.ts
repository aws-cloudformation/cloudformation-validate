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
export interface Engine {
    validateStandard(template: TemplateFile, config?: ValidateConfig): StandardReport;
    validateDetailed(template: TemplateFile, config?: ValidateConfig): DetailedReport;
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
 * overlay. `typeName` may be left empty to use the `typeName` inside the file.
 */
export class SchemaFile {
    constructor(
        public readonly path: string,
        public readonly typeName: string = '',
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
    schemaValidator?: SchemaValidatorConfig;
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
        schemaValidator: config?.schemaValidator
            ? toWasmSchemaValidatorConfig(config.schemaValidator)
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
