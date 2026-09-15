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
export declare class AwsCliCommand {
    readonly serviceName: string;
    readonly operationName: string;
    readonly parameters: Record<string, unknown>;
    readonly servicePrefix?: string;
    readonly httpMethod?: string;
    readonly isReadOnly?: boolean;
    constructor(
        serviceName: string,
        operationName: string,
        parameters: Record<string, unknown>,
        options?: AwsCliCommandOptions,
    );
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
export interface Engine {
    validateTemplate(template: TemplateFile, config?: ValidateConfig): ValidationReport;
    validateAwsCliCommand(request: AwsCliCommand): AwsCliCommandValidation;
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
