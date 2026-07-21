import type {
    DetailedReport,
    DiagnosticModel,
    EngineConfig,
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
    EngineConfig,
    ValidateConfig,
    ExternalRuleSource,
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
    private readonly inner: InstanceType<typeof bridge.WasmSchemaValidator> = new bridge.WasmSchemaValidator();

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
    WasmClass: new (config: EngineConfig) => WasmEngineInstance,
): new (config?: EngineConfig) => Engine {
    return class implements Engine {
        private readonly inner: WasmEngineInstance;

        constructor(config?: EngineConfig) {
            this.inner = new WasmClass(config ?? {});
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
