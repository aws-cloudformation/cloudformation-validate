import type {
    Diagnostic,
    ValidationReport,
    DiagnosticModel,
    AdditionalSchemaSource,
    ExternalRuleSource,
    ParameterInfo,
    ResolvedOutput,
    ResolvedResource,
    RuleInfo,
    SourceSpan,
    ValidateConfig,
} from './bindings_wasm';
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
} from './bindings_wasm';
export type JsonValue =
    | string
    | number
    | boolean
    | null
    | JsonValue[]
    | {
          [key: string]: JsonValue;
      };
export interface Engine {
    validateTemplate(template: TemplateFile, config?: ValidateConfig): ValidationReport;
    listRules(): RuleInfo[];
    engineName(): string;
    free(): void;
}
export declare class TemplateFile {
    readonly path: string;
    constructor(path: string);
    readBytes(): Uint8Array;
}
export declare class RuleFile {
    readonly path: string;
    constructor(path: string);
    readContent(): string;
}
export type RuleSource = ExternalRuleSource | RuleFile;
/**
 * A CloudFormation resource provider schema loaded from a file, for use as an
 * overlay. `typeName` may be omitted to use the `typeName` inside the file.
 */
export declare class SchemaFile {
    readonly path: string;
    readonly typeName?: string | undefined;
    constructor(path: string, typeName?: string | undefined);
    readContent(): string;
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
export declare class TemplateModel {
    private readonly inner;
    constructor(template: TemplateFile);
    resources(): Record<string, ResolvedResource>;
    parameters(): Record<string, ParameterInfo>;
    outputs(): Record<string, ResolvedOutput>;
    conditions(): string[];
    transforms(): string[];
    formatVersion(): string | undefined;
    description(): string | undefined;
    toDiagnosticModel(): DiagnosticModel;
    sourceLocation(path: string): SourceSpan | null;
    free(): void;
}
export declare class SchemaValidator {
    private readonly inner;
    constructor(config?: SchemaValidatorConfig);
    listRules(): RuleInfo[];
    schemaCount(): number;
    validate(template: TemplateFile, region?: string): Diagnostic[];
    free(): void;
}
export declare const RegoEngine: new (config?: EngineConfig) => Engine;
export declare const CelEngine: new (config?: EngineConfig) => Engine;
export declare const CompositeEngine: new (config?: CompositeEngineConfig) => Engine;
export declare function version(): string;
