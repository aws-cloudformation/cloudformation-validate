export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };
/* tslint:disable */
/* eslint-disable */
/**
 * A pre-read rule file provided by the caller (custom Rego/CEL or Guard DSL).
 *
 * `name` identifies the rule source in error messages and logging. For a
 * file-backed rule this is typically the filesystem path; otherwise it is
 * whatever label the caller provides.
 *
 * `content` is the full source text of the rule file.
 */
export interface ExternalRuleSource {
    name: string;
    content: string;
}

/**
 * Controls the level of detail in validation output.
 */
export type DetailLevel = 'STANDARD' | 'DETAILED';

/**
 * Filter criteria across seven dimensions: rule IDs, categories, ID ranges, regex
 * patterns, resource IDs, resource types, and services.
 */
export interface RuleFilterConfig {
    ids?: string[];
    categories?: string[];
    idRanges?: IdRange[];
    idPatterns?: string[];
    resourceIds?: ResourceIdFilter[];
    resourceTypes?: ResourceTypeFilter[];
    services?: ServiceFilter[];
}

/**
 * Numeric range filter for rule IDs sharing a common letter prefix, matching an
 * inclusive span of the trailing numbers.
 */
export interface IdRange {
    prefix: string;
    start: number;
    end: number;
}

/**
 * Outcome of a validation run. `Ok` means the engine completed; `Error` means
 * the pipeline could not run (e.g. parse failure).
 */
export type ReportStatus = 'OK' | 'ERROR';

/**
 * Selects which validation engine evaluates rules.
 */
export type EngineType = 'REGO' | 'CEL';

/**
 * Serializable, owned representation of a rule returned by public APIs.
 */
export interface RuleInfo {
    id: string;
    severity: Severity;
    category?: string;
    description: string;
    origin: RuleOrigin;
}

/**
 * Suppress a rule for a specific logical resource ID. An absent `rule_id`
 * scopes the filter to every rule on that resource.
 */
export interface ResourceIdFilter {
    ruleId?: string;
    resourceId: string;
}

/**
 * Suppress a rule for a specific resource type. An absent `rule_id` scopes the
 * filter to every rule on that type.
 */
export interface ResourceTypeFilter {
    ruleId?: string;
    resourceType: string;
}

/**
 * Suppress a rule for every resource belonging to a service — the
 * `service-provider::service-name` prefix of the resource type (its first two
 * `::`-delimited segments, for example `AWS::AutoScaling` in
 * `AWS::AutoScaling::LaunchConfiguration`, or `Alexa::ASK` in
 * `Alexa::ASK::Skill`). An absent `rule_id` scopes the filter to every rule on
 * that service.
 *
 * The service string is compared verbatim against that prefix.
 */
export interface ServiceFilter {
    ruleId?: string;
    service: string;
}

/**
 * Validation pipeline phase a diagnostic originates from.
 */
export type Phase = 'PARSE' | 'SCHEMA' | 'LINT';

/**
 * Where a rule\'s logic originates.
 */
export type RuleOrigin = 'SCHEMA' | 'CFN_LINT' | 'ENGINE' | 'CUSTOM' | 'GUARD';

export interface ConditionalNull {
    path: string;
    condition: string;
    nullInTrue: boolean;
}

export interface ConditionalNullEntry {
    path: string;
    condition: string;
    nullInTrueBranch: boolean;
}

export interface DetailedDiagnostic {
    ruleId: string;
    severity: Severity;
    message: string;
    source: RuleOrigin;
    resourceId?: string;
    resourceType?: string;
    propertyPath?: string;
    suggestedFix?: string;
    category?: string;
    startLine?: number;
    startColumn?: number;
    endLine?: number;
    endColumn?: number;
    relatedResources?: RelatedResource[];
    conditionScenario?: Record<string, boolean>;
    documentationUrl?: string;
    ruleDescription?: string;
    phase?: Phase;
    section?: string;
    context?: ViolationContext;
}

export interface DetailedReport {
    filePath: string;
    status: ReportStatus;
    engineVersion: string;
    metadata: ReportMetadata;
    performance: PerformanceMetrics;
    diagnostics: DetailedDiagnostic[];
}

export interface DiagnosticCondition {
    expression?: string;
    deps?: string[];
    mutexWith?: string[];
}

export interface DiagnosticForEachExpansion {
    path: string;
    identifier: string;
    collection: string;
}

export interface DiagnosticImplication {
    antecedent: string;
    consequent: string;
}

export interface DiagnosticModel {
    template: DiagnosticTemplate;
    parameters: Record<string, JsonValue>;
    conditions: Record<string, DiagnosticCondition>;
    conditionParamRefs: string[];
    conditionImplications: DiagnosticImplication[];
    conditionMutexGroups: DiagnosticMutexGroup[];
    conditionExclusions: string[][];
    resourceConditionMap: Record<string, string>;
    mappings: JsonValue;
    resources: Record<string, DiagnosticResource>;
    outputs: Record<string, DiagnosticOutput>;
    edges: ReferenceEdge[];
    cycles: string[][];
    outputEmptyJoins: string[];
    samImplicitResources: string[];
    globalsParamRefs: string[];
    isCdk: boolean;
    fnIfConditions: string[];
    findInMapNames: string[];
    paramsReferencedInDefinitions: string[];
    hasDynamicFindinmapName: boolean;
    hasParseErrors: boolean;
    parsedRules: DiagnosticRule[];
    resolutionSources: ResolutionSource[];
}

export interface DiagnosticMutexGroup {
    conditions: string[];
    parameter: string;
    values: string[];
}

export interface DiagnosticOutput {
    value: JsonValue;
    description?: string;
    condition?: string;
    exportName?: JsonValue;
    getattRefs: GetAttRef[];
    conditionRefs: string[];
}

export interface DiagnosticResource {
    resourceType: string;
    condition?: string;
    dependsOn: string[];
    deletionPolicy?: JsonValue;
    updateReplacePolicy?: JsonValue;
    creationPolicy?: JsonValue;
    updatePolicy?: JsonValue;
    properties: Record<string, JsonValue>;
    outgoingRefs: OutgoingRef[];
    incomingRefs: IncomingRef[];
    findInMapRefs: string[];
    simpleSubs: PathVariable[];
    redundantSubs: string[];
    emptyJoins: string[];
    hardcodedPartitionArns: string[];
    conditionallyNullProps: ConditionalNull[];
    conditionRefs: string[];
    forEachExpansions: DiagnosticForEachExpansion[];
    unsubstitutedVariables: PathVariable[];
    invalidRefs: PathTarget[];
}

export interface DiagnosticRule {
    name: string;
    condition?: JsonValue;
    assertions: DiagnosticRuleAssertion[];
}

export interface DiagnosticRuleAssertion {
    assertExpr: JsonValue;
    assertDescription?: string;
}

export interface DiagnosticTemplate {
    formatVersion?: string;
    description?: string;
    transforms: string[];
    rawTopLevelKeys: string[];
}

export interface EngineConfig {
    /**
     * Engine-native custom rules (Rego or CEL depending on engine).
     */
    customRules?: ExternalRuleSource[];
    /**
     * Guard DSL rules as raw source text — each engine parses and translates internally.
     */
    guardRules?: ExternalRuleSource[];
}

export interface ForEachExpansion {
    propertyPath: string;
    identifier: string;
    collectionSource: string;
}

export interface GetAttRef {
    resource: string;
    attribute: string;
}

export interface IncomingRef {
    source: string;
    sourcePath: string;
    kind: string;
    attr?: string;
}

export interface MapEntry {
    key: string;
    value: ResolvedValue;
}

export interface OutgoingRef {
    sourcePath: string;
    target: string;
    kind: string;
    attr?: string;
    conditionContext?: string;
}

export interface ParameterInfo {
    paramType: string;
    default?: string;
    allowedValues?: string[];
    allowedPattern?: string;
    minLength?: number;
    maxLength?: number;
    minValue?: number;
    maxValue?: number;
    description?: string;
    noEcho: boolean;
    allowedPatternValid?: boolean;
    defaultMatchesAllowedPattern?: boolean;
}

export interface PathTarget {
    path: string;
    target: string;
}

export interface PathValuePair {
    path: string;
    value: string;
}

export interface PathVariable {
    path: string;
    variable: string;
}

export interface PerformanceMetrics {
    schemaInit: PhaseMetric;
    engineInit: PhaseMetric;
    modelBuild: PhaseMetric;
    schemaValidate: PhaseMetric;
    ruleEvaluation: PhaseMetric;
    diagnosticFinalize: PhaseMetric;
    validateTotal: PhaseMetric;
}

export interface PhaseMetric {
    durationMs: number;
}

export interface PseudoParameterOverrides {
    accountId?: string;
    notificationArns?: string;
    partition?: string;
    region?: string;
    stackId?: string;
    stackName?: string;
    urlSuffix?: string;
}

export interface ReferenceEdge {
    source: string;
    sourcePath: string;
    target: string;
    kind: string;
    attr?: string;
    conditionContext?: string;
}

export interface RelatedResource {
    resource?: ResourceRef;
    location?: SourceSpan;
    message: string;
}

export interface ReportMetadata {
    rulesEvaluated?: number;
    resourcesScanned: number;
    counts: Summary;
    suppressed: number;
    strict: boolean;
    severityLevel: Severity;
}

export interface ResolutionSource {
    resourceId: string;
    propertyPath: string;
    source: string;
}

export interface ResolvedOutput {
    value: ResolvedValue;
    description?: string;
    condition?: string;
    exportName?: ResolvedValue;
}

export interface ResolvedResource {
    logicalId: string;
    resourceType: string;
    condition?: string;
    dependsOn: string[];
    deletionPolicy?: ResolvedValue;
    updateReplacePolicy?: ResolvedValue;
    updatePolicy?: JsonValue;
    creationPolicy?: JsonValue;
    metadata?: JsonValue;
    properties: Record<string, ResolvedValue>;
    /**
     * True when the entire `Properties` block is a non-map intrinsic (e.g.
     * `Properties: !Ref AWS::NoValue`) whose effective property set is decided at
     * deploy time. Distinguishes \"no properties given\" from \"properties are
     * dynamic\", so required-property checks can be skipped for the latter.
     */
    propertiesDynamic: boolean;
    diagnostics: ResourceDiagnostics;
}

export interface ResourceDiagnostics {
    findInMapRefs: string[];
    simpleSubs: PathValuePair[];
    redundantSubs: string[];
    emptyJoins: string[];
    conditionRefs: string[];
    hardcodedPartitionArns: string[];
    conditionallyNullProps: ConditionalNullEntry[];
    foreachExpansions: ForEachExpansion[];
    unsubstitutedVariables: PathValuePair[];
    invalidRefs: PathValuePair[];
}

export interface ResourceRef {
    id?: string;
    resourceType?: string;
}

export interface SourceSpan {
    startLine: number;
    startColumn: number;
    endLine: number;
    endColumn: number;
}

export interface StandardDiagnostic {
    ruleId: string;
    severity: Severity;
    message: string;
    source: RuleOrigin;
    resourceId?: string;
    resourceType?: string;
    propertyPath?: string;
    suggestedFix?: string;
    category?: string;
    startLine?: number;
    startColumn?: number;
    endLine?: number;
    endColumn?: number;
    relatedResources?: RelatedResource[];
    conditionScenario?: Record<string, boolean>;
}

export interface StandardReport {
    filePath: string;
    status: ReportStatus;
    engineVersion: string;
    metadata: ReportMetadata;
    performance: PerformanceMetrics;
    diagnostics: StandardDiagnostic[];
}

export interface Summary {
    fatal: number;
    errors: number;
    warnings: number;
    informational: number;
    debug: number;
}

export interface ValidateConfig {
    include?: RuleFilterConfig;
    exclude?: RuleFilterConfig;
    severityLevel?: Severity;
    parameterOverrides?: Record<string, string>;
    pseudoParameterOverrides?: PseudoParameterOverrides;
    strict?: boolean;
    disableBuiltinRules?: boolean;
}

export interface ViolationContext {
    actualValue?: JsonValue;
    expectedConstraint?: string;
    property?: string;
    lifecycle?: string;
    resolutionSource?: string;
    extra?: Record<string, JsonValue>;
}

export interface WasmSchemaValidationResult {
    diagnostics: StandardDiagnostic[];
    metric: PhaseMetric;
}

export type RefKind = 'REF' | { GET_ATT: { attr: string } } | { SUB: { var: string } } | 'DEPENDS_ON';

export type ResolvedValue =
    | { Concrete: { value: JsonValue } }
    | { List: { items: ResolvedValue[] } }
    | { Map: { entries: MapEntry[] } }
    | { Enum: { variants: ResolvedValue[] } }
    | { Conditional: { condition: string; if_true: ResolvedValue; if_false: ResolvedValue } }
    | { Reference: { target: string; kind: RefKind } }
    | { Dynamic: { reason: string } }
    | { TypedDynamic: { reason: string; param_type: string } };

export type Severity = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR' | 'FATAL';

export class WasmCelEngine {
    free(): void;
    [Symbol.dispose](): void;
    engineName(): string;
    listRules(): any;
    constructor(config: EngineConfig);
    validateDetailed(template: Uint8Array, options: ValidateConfig, file_path: string): any;
    validateStandard(template: Uint8Array, options: ValidateConfig, file_path: string): any;
}

export class WasmRegoEngine {
    free(): void;
    [Symbol.dispose](): void;
    engineName(): string;
    listRules(): any;
    constructor(config: EngineConfig);
    validateDetailed(template: Uint8Array, options: ValidateConfig, file_path: string): any;
    validateStandard(template: Uint8Array, options: ValidateConfig, file_path: string): any;
}

export class WasmSchemaValidator {
    free(): void;
    [Symbol.dispose](): void;
    listRules(): any;
    constructor();
    schemaCount(): number;
    validate(model: WasmSemanticModel, region: string): any;
}

export class WasmSemanticModel {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    conditions(): any;
    description(): string | undefined;
    formatVersion(): string | undefined;
    outputs(): any;
    parameters(): any;
    static parse(template: Uint8Array): WasmSemanticModel;
    resources(): any;
    sourceLocation(path: string): any;
    toDiagnosticModel(): any;
    transforms(): any;
}

export function init(): void;

export function version(): string;
