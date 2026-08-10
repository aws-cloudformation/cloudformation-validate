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
 * A property path paired with a variable name referenced there.
 */
export interface PathVariable {
    path: string;
    variable: string;
}

/**
 * A property path paired with the reference target found there.
 */
export interface PathTarget {
    path: string;
    target: string;
}

/**
 * A property that is dropped (resolves to AWS::NoValue) in one branch of an Fn::If condition.
 */
export interface ConditionalNullEntry {
    /**
     * Dot-separated property path that becomes absent in one branch.
     */
    path: string;
    /**
     * Name of the condition governing the Fn::If that drops this property.
     */
    condition: string;
    /**
     * True when the property is absent in the condition\'s true branch; false when absent in the false branch.
     */
    nullInTrueBranch: boolean;
}

/**
 * A property that resolves to null in one branch of a condition.
 */
export interface ConditionalNull {
    path: string;
    condition: string;
    /**
     * True if the property is null in the condition\'s true branch; false if null in the false branch.
     */
    nullInTrue: boolean;
}

/**
 * A property value after CloudFormation intrinsics (Ref, Fn::GetAtt, Fn::Sub, Fn::If, ...)
 * have been resolved as far as possible. Depending on how much can be known before
 * deployment, a value is fully concrete, a reference to another resource, one of several
 * possible values, conditional on a template condition, or opaque until deploy time.
 */
export type ResolvedValue =
    | { Concrete: { value: JsonValue } }
    | { List: { items: ResolvedValue[] } }
    | { Map: { entries: MapEntry[] } }
    | { Enum: { variants: ResolvedValue[] } }
    | { Conditional: { condition: string; if_true: ResolvedValue; if_false: ResolvedValue } }
    | { Reference: { target: string; kind: RefKind } }
    | { Dynamic: { reason: string } }
    | { TypedDynamic: { reason: string; param_type: string } };

/**
 * A range in the source template. Lines and columns are 1-based.
 */
export interface SourceSpan {
    startLine: number;
    startColumn: number;
    endLine: number;
    endColumn: number;
}

/**
 * A reference a resource makes to another resource or parameter.
 */
export interface OutgoingRef {
    /**
     * Property path within the resource where the reference occurs.
     */
    sourcePath: string;
    /**
     * Logical ID of the referenced resource or parameter.
     */
    target: string;
    /**
     * How the reference is made, such as Ref, GetAtt, Sub, or DependsOn.
     */
    kind: string;
    /**
     * For a GetAtt or Sub reference, the attribute or variable name being referenced.
     */
    attr?: string;
    /**
     * Name of the condition under which this reference is active, if it is inside a conditional branch.
     */
    conditionContext?: string;
}

/**
 * A reference made to this resource by another resource.
 */
export interface IncomingRef {
    /**
     * Logical ID of the resource that makes the reference.
     */
    source: string;
    /**
     * Property path within the source where the reference occurs.
     */
    sourcePath: string;
    /**
     * How the reference is made, such as Ref, GetAtt, Sub, or DependsOn.
     */
    kind: string;
    /**
     * For a GetAtt or Sub reference, the attribute or variable name being referenced.
     */
    attr?: string;
}

/**
 * A resource after intrinsic resolution, with its properties, references, and detected findings.
 */
export interface DiagnosticResource {
    resourceType: string;
    /**
     * Name of the condition gating whether this resource is created, if any.
     */
    condition?: string;
    dependsOn: string[];
    deletionPolicy?: JsonValue;
    updateReplacePolicy?: JsonValue;
    creationPolicy?: JsonValue;
    updatePolicy?: JsonValue;
    /**
     * The resource\'s properties with intrinsics resolved where possible.
     */
    properties: Record<string, JsonValue>;
    outgoingRefs: OutgoingRef[];
    incomingRefs: IncomingRef[];
    /**
     * Mapping names referenced by Fn::FindInMap within this resource.
     */
    findInMapRefs: string[];
    /**
     * Fn::Sub uses whose template is a single variable with no surrounding text, which could be written as a plain reference.
     */
    simpleSubs: PathVariable[];
    /**
     * Property paths where Fn::Sub has no variables to substitute.
     */
    redundantSubs: string[];
    /**
     * Property paths where Fn::Join uses an empty delimiter, concatenating its elements directly.
     */
    emptyJoins: string[];
    /**
     * Property paths where an ARN hardcodes the aws partition instead of using AWS::Partition.
     */
    hardcodedPartitionArns: string[];
    /**
     * Properties that resolve to null in one branch of a condition.
     */
    conditionallyNullProps: ConditionalNull[];
    /**
     * Names of conditions referenced within this resource\'s properties.
     */
    conditionRefs: string[];
    /**
     * Fn::ForEach loops in this resource, each with its iteration variable and collection source.
     */
    forEachExpansions: DiagnosticForEachExpansion[];
    /**
     * Property paths containing ${...} text that is not an Fn::Sub variable and is left as a literal.
     */
    unsubstitutedVariables: PathVariable[];
    /**
     * Fn::Sub map keys not referenced in the template string, each with its path and the unused key name.
     */
    unusedSubKeys: PathVariable[];
    /**
     * Property values that are a raw pseudo-parameter string instead of using Ref, each with its path and the pseudo-parameter name.
     */
    rawPseudoParams: PathVariable[];
    /**
     * Property paths containing a {{resolve:secretsmanager:...}} dynamic reference.
     */
    secretsmanagerRefPaths: string[];
    /**
     * References whose target does not resolve to any resource or parameter, each with its path and unresolved target.
     */
    invalidRefs: PathTarget[];
}

/**
 * A resource property path paired with a string value found at it, such as a substitution variable or literal.
 */
export interface PathValuePair {
    /**
     * Dot-separated property path within the resource (e.g. \'Properties.BucketName\').
     */
    path: string;
    value: string;
}

/**
 * A set of conditions that are mutually exclusive because they test the same parameter against different values.
 */
export interface DiagnosticMutexGroup {
    conditions: string[];
    /**
     * The parameter all conditions in the group test.
     */
    parameter: string;
    /**
     * The distinct parameter values the conditions compare against, one per condition.
     */
    values: string[];
}

/**
 * A set of rule-matching criteria; a rule matches when it satisfies any one of them.
 */
export interface RuleFilterConfig {
    ids?: string[];
    categories?: string[];
    idRanges?: IdRange[];
    /**
     * Regular expressions matched against the rule ID.
     */
    idPatterns?: string[];
    resourceIds?: ResourceIdFilter[];
    logicalIds?: LogicalIdFilter[];
    resourceTypes?: ResourceTypeFilter[];
    services?: ServiceFilter[];
}

/**
 * A single Conditions entry with its expression and relationships to other conditions.
 */
export interface DiagnosticCondition {
    /**
     * The condition expression rendered as a readable string.
     */
    expression?: string;
    /**
     * Names of other conditions this condition depends on.
     */
    deps?: string[];
    /**
     * Names of conditions that are mutually exclusive with this one.
     */
    mutexWith?: string[];
}

/**
 * A single additional CloudFormation resource provider schema to overlay on top
 * of the bundled schemas.
 *
 * `type_name` identifies the resource type (e.g., `\"AWS::Lambda::Function\"`).
 * When absent (`None`), the `typeName` field inside the schema JSON is used
 * instead. When both are present they must agree.
 *
 * `schema` is the complete resource provider schema as a JSON string, in the
 * standard CloudFormation registry format.
 */
export interface AdditionalSchemaSource {
    /**
     * The resource type name (e.g., `\"AWS::Lambda::Function\"`). When absent, the
     * `typeName` field of the schema JSON is used instead. When both are
     * present they must agree.
     */
    typeName?: string;
    /**
     * The complete resource provider schema as a JSON string, in the standard
     * CloudFormation registry format.
     */
    schema: string;
}

/**
 * A single assertion within a template rule.
 */
export interface DiagnosticRuleAssertion {
    /**
     * The assertion expression that must evaluate to true.
     */
    assertExpr: JsonValue;
    assertDescription?: string;
}

/**
 * A single edge in the template\'s reference graph, from a referencing resource to its target.
 */
export interface ReferenceEdge {
    /**
     * Logical ID of the resource that makes the reference.
     */
    source: string;
    /**
     * Property path within the source where the reference occurs.
     */
    sourcePath: string;
    /**
     * Logical ID of the referenced resource or parameter.
     */
    target: string;
    /**
     * How the reference is made, such as Ref, GetAtt, Sub, or DependsOn.
     */
    kind: string;
    /**
     * For a GetAtt or Sub reference, the attribute or variable name being referenced.
     */
    attr?: string;
    /**
     * Name of the condition under which this reference is active, if it is inside a conditional branch.
     */
    conditionContext?: string;
}

/**
 * A template Parameter\'s declaration: its type, constraints (allowed values/pattern,
 * length and value bounds), default, and description.
 */
export interface ParameterInfo {
    /**
     * The parameter\'s declared CloudFormation type (for example String, Number, or an AWS-specific type); defaults to String when the template omits Type.
     */
    paramType: string;
    default?: string;
    allowedValues?: string[];
    allowedPattern?: string;
    minLength?: number;
    maxLength?: number;
    minValue?: number;
    maxValue?: number;
    description?: string;
    /**
     * Whether the parameter is declared with NoEcho, meaning its value is masked in CloudFormation output.
     */
    noEcho: boolean;
    /**
     * Whether the AllowedPattern is a valid, supported regular expression; absent when no AllowedPattern is declared.
     */
    allowedPatternValid?: boolean;
    /**
     * Whether the Default value satisfies the AllowedPattern; absent unless both a Default and an AllowedPattern are declared.
     */
    defaultMatchesAllowedPattern?: boolean;
}

/**
 * A template output after intrinsic resolution, with its references.
 */
export interface DiagnosticOutput {
    /**
     * The output value with intrinsics resolved where possible.
     */
    value: JsonValue;
    description?: string;
    /**
     * Name of the condition gating whether this output is emitted, if any.
     */
    condition?: string;
    exportName?: JsonValue;
    /**
     * Fn::GetAtt references appearing in the output value.
     */
    getattRefs: GetAttRef[];
    /**
     * Names of conditions referenced within the output value.
     */
    conditionRefs: string[];
}

/**
 * A template output with its value and metadata after intrinsic functions have been resolved.
 */
export interface ResolvedOutput {
    value: ResolvedValue;
    description?: string;
    condition?: string;
    exportName?: ResolvedValue;
}

/**
 * A template resource with its metadata and properties after intrinsic functions have been resolved.
 */
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
     * `Properties: !Ref AWS::NoValue`) whose effective property set is only known
     * at deploy time, as distinct from a resource that simply declares no properties.
     */
    propertiesDynamic: boolean;
    diagnostics: ResourceDiagnostics;
}

/**
 * A top-level CloudFormation template section, as documented in the template
 * anatomy (<https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/template-anatomy.html>).
 *
 * This is the canonical, single definition of the section names — section
 * constants in other crates derive from it.
 */
export type TopLevelSection =
    | 'Resources'
    | 'Parameters'
    | 'Outputs'
    | 'Mappings'
    | 'Metadata'
    | 'Rules'
    | 'Conditions'
    | 'Transform'
    | 'FormatVersion'
    | 'Description';

/**
 * Advanced introspection view of a parsed CloudFormation template: its reference graph,
 * conditions, and resolved resources and outputs.
 */
export interface DiagnosticModel {
    template: DiagnosticTemplate;
    parameters: Record<string, JsonValue>;
    conditions: Record<string, DiagnosticCondition>;
    /**
     * Parameter logical IDs referenced by the template\'s condition expressions.
     */
    conditionParamRefs: string[];
    /**
     * Logical implications between conditions: if the antecedent condition holds, the consequent condition must also hold.
     */
    conditionImplications: DiagnosticImplication[];
    /**
     * Groups of conditions that are mutually exclusive because they test the same parameter against different values.
     */
    conditionMutexGroups: DiagnosticMutexGroup[];
    /**
     * Pairs of condition names that can never both be true at the same time.
     */
    conditionExclusions: string[][];
    /**
     * Maps each resource\'s logical ID to the name of the condition that gates whether it is created.
     */
    resourceConditionMap: Record<string, string>;
    mappings: JsonValue;
    resources: Record<string, DiagnosticResource>;
    outputs: Record<string, DiagnosticOutput>;
    edges: ReferenceEdge[];
    /**
     * Reference cycles in the template, each listed as the resource logical IDs forming the cycle.
     */
    cycles: string[][];
    /**
     * Output names whose value is an Fn::Join with an empty delimiter.
     */
    outputEmptyJoins: string[];
    /**
     * Logical IDs of resources the SAM transform generates implicitly (such as function execution roles and an implicit REST API).
     */
    samImplicitResources: string[];
    /**
     * Parameter logical IDs referenced from the SAM Globals section.
     */
    globalsParamRefs: string[];
    /**
     * True when the template appears to be generated by the AWS CDK.
     */
    isCdk: boolean;
    /**
     * Names of conditions referenced by Fn::If expressions in the template.
     */
    fnIfConditions: string[];
    /**
     * Mapping names referenced by Fn::FindInMap expressions.
     */
    findInMapNames: string[];
    /**
     * Parameter logical IDs referenced from within other parameters\' own definitions.
     */
    paramsReferencedInDefinitions: string[];
    /**
     * True when a Fn::FindInMap uses a computed mapping name rather than a literal string.
     */
    hasDynamicFindinmapName: boolean;
    /**
     * True when the template could not be fully parsed and the model is therefore incomplete.
     */
    hasParseErrors: boolean;
    /**
     * The template\'s Rules section, each with its optional condition and assertions.
     */
    parsedRules: DiagnosticRule[];
    /**
     * For resolved resource properties, records where each value came from (such as a parameter default, allowed values, an override, or an intrinsic).
     */
    resolutionSources: ResolutionSource[];
}

/**
 * An Fn::ForEach loop within a resource that expands a property over a collection.
 */
export interface ForEachExpansion {
    /**
     * Property path within the resource where the Fn::ForEach appears.
     */
    propertyPath: string;
    /**
     * Loop variable name bound to each element during expansion.
     */
    identifier: string;
    /**
     * Human-readable description of the collection being iterated over.
     */
    collectionSource: string;
}

/**
 * An Fn::ForEach loop within a resource.
 */
export interface DiagnosticForEachExpansion {
    /**
     * Property path where the Fn::ForEach occurs.
     */
    path: string;
    /**
     * The loop\'s iteration variable name.
     */
    identifier: string;
    /**
     * A description of the collection the loop iterates over, such as a reference to a parameter, an inline list, or a dynamic value.
     */
    collection: string;
}

/**
 * An Fn::GetAtt reference to a resource attribute.
 */
export interface GetAttRef {
    /**
     * Logical ID of the resource whose attribute is referenced.
     */
    resource: string;
    attribute: string;
}

/**
 * An entry from the template\'s Rules section.
 */
export interface DiagnosticRule {
    name: string;
    /**
     * The rule\'s RuleCondition expression, if present, that gates when the assertions apply.
     */
    condition?: JsonValue;
    assertions: DiagnosticRuleAssertion[];
}

/**
 * An implication between two conditions: whenever the antecedent holds, the consequent also holds.
 */
export interface DiagnosticImplication {
    antecedent: string;
    consequent: string;
}

/**
 * Another resource involved in the diagnostic, such as the target of a reference.
 */
export interface RelatedResource {
    resource?: ResourceRef;
    /**
     * Source location of the related resource.
     */
    location?: SourceSpan;
    message: string;
}

/**
 * Configuration for constructing a [`SchemaValidator`] with optional overlay
 * schemas. Bindings and the CLI use this to build the validator separately from
 * the rule engine.
 */
export interface SchemaValidatorConfig {
    /**
     * Additional CloudFormation resource provider schemas to merge on top of the
     * bundled schemas before schema validation.
     */
    additionalSchemas?: AdditionalSchemaSource[];
}

/**
 * Controls the level of detail in validation output.
 */
export type DetailLevel = 'STANDARD' | 'DETAILED';

/**
 * Detailed validation result: like the standard report but with per-diagnostic context and enrichment.
 */
export interface DetailedReport {
    filePath: string;
    status: ReportStatus;
    version: string;
    metadata: ReportMetadata;
    performance: PerformanceMetrics;
    diagnostics: DetailedDiagnostic[];
}

/**
 * Extra detail about a specific violation, present only in the detailed report.
 */
export interface ViolationContext {
    /**
     * The resolved property value that triggered the violation.
     */
    actualValue?: JsonValue;
    /**
     * The constraint the value was expected to satisfy (such as the required type or allowed pattern).
     */
    expectedConstraint?: string;
    /**
     * Name of the offending property.
     */
    property?: string;
    /**
     * Lifecycle marker for the flagged resource type or property, such as \'deprecated\', \'create-only\', or \'write-only\'.
     */
    lifecycle?: string;
    /**
     * How the offending value was derived, such as a Ref, Fn::GetAtt, Fn::If, or parameter.
     */
    resolutionSource?: string;
    /**
     * Additional finding-specific values keyed by name.
     */
    extra?: Record<string, JsonValue>;
}

/**
 * How one template item refers to another: a Ref, an Fn::GetAtt attribute lookup,
 * an Fn::Sub variable, or an explicit DependsOn.
 */
export type RefKind = 'REF' | { GET_ATT: { attr: string } } | { SUB: { var: string } } | 'DEPENDS_ON';

/**
 * Metadata describing a validation rule.
 */
export interface RuleInfo {
    id: string;
    severity: Severity;
    category?: string;
    description: string;
    origin: RuleOrigin;
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
 * Per-resource observations collected while resolving intrinsics, used to drive lint checks.
 */
export interface ResourceDiagnostics {
    /**
     * Mapping names referenced by Fn::FindInMap within this resource.
     */
    findInMapRefs: string[];
    /**
     * Fn::Sub uses whose template is a single variable that could be a plain Ref; each pairs the property path with the variable name.
     */
    simpleSubs: PathValuePair[];
    /**
     * Property paths where Fn::Sub wraps a constant string with no variables to substitute.
     */
    redundantSubs: string[];
    /**
     * Property paths where Fn::Join uses an empty delimiter, concatenating its elements directly.
     */
    emptyJoins: string[];
    /**
     * Names of conditions referenced by this resource\'s property values.
     */
    conditionRefs: string[];
    /**
     * Property paths building ARNs with a hardcoded \'aws\' partition instead of AWS::Partition.
     */
    hardcodedPartitionArns: string[];
    conditionallyNullProps: ConditionalNullEntry[];
    foreachExpansions: ForEachExpansion[];
    /**
     * Occurrences of ${...} placeholders outside an Fn::Sub that will not be substituted; each pairs the property path with the placeholder text.
     */
    unsubstitutedVariables: PathValuePair[];
    /**
     * Fn::Sub map keys not referenced in the template string; each pairs the property path with the unused key name.
     */
    unusedSubKeys: PathValuePair[];
    /**
     * Property values that are a raw pseudo-parameter string (e.g. \"AWS::Region\") instead of using Ref.
     */
    rawPseudoParams: PathValuePair[];
    /**
     * Property paths containing a {{resolve:secretsmanager:...}} dynamic reference.
     */
    secretsmanagerRefPaths: string[];
    /**
     * References whose target is not a defined resource, parameter, or pseudo parameter; each pairs the property path with the missing target name.
     */
    invalidRefs: PathValuePair[];
}

/**
 * Records where a resolved resource property value came from.
 */
export interface ResolutionSource {
    resourceId: string;
    propertyPath: string;
    /**
     * Origin of the resolved value, such as a parameter default, allowed values, an override, or an intrinsic.
     */
    source: string;
}

/**
 * Selects which validation engine evaluates rules.
 */
export type EngineType = 'REGO' | 'CEL';

/**
 * Standard validation result: the report plus flattened diagnostics.
 */
export interface StandardReport {
    filePath: string;
    status: ReportStatus;
    version: string;
    metadata: ReportMetadata;
    performance: PerformanceMetrics;
    diagnostics: StandardDiagnostic[];
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
 * Suppress a rule for a specific named template entity — a resource,
 * parameter, output, mapping, condition, or template rule — identified by its
 * logical ID. An absent `rule_id` scopes the filter to every rule on that
 * entity; an absent `entity_type` scopes it to entities of every type with
 * that logical ID.
 */
export interface LogicalIdFilter {
    ruleId?: string;
    logicalId: string;
    entityType?: EntityType;
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
 * The kind of template entity a diagnostic targets — the singular form of the
 * top-level section the entity is declared in. Every documented section has a
 * variant; the ones whose children are addressable by logical ID (resources,
 * parameters, outputs, mappings, conditions, rules, and metadata keys) are
 * the ones diagnostics attribute findings to today.
 */
export type EntityType =
    | 'Resource'
    | 'Parameter'
    | 'Output'
    | 'Mapping'
    | 'Metadata'
    | 'Rule'
    | 'Condition'
    | 'Transform'
    | 'FormatVersion'
    | 'Description';

/**
 * The named template entity a diagnostic is attributed to, when it targets
 * one. The entity type is the singular form of the top-level template
 * section the entity is declared in.
 */
export interface Entity {
    /**
     * Logical ID of the entity as declared in the template.
     */
    logicalId: string;
    entityType: EntityType;
    /**
     * CloudFormation resource type, when the entity is a resource whose type
     * is known.
     */
    resourceType?: string;
}

/**
 * The template resource a diagnostic is attributed to, when it targets one.
 */
export interface ResourceRef {
    /**
     * Logical ID of the resource as declared in the template.
     */
    id?: string;
    resourceType?: string;
}

/**
 * Timing breakdown of the validation run, per pipeline phase.
 */
export interface PerformanceMetrics {
    /**
     * Time to load the provider schemas.
     */
    schemaInit: PhaseMetric;
    /**
     * Time to initialize the rule evaluation engine.
     */
    engineInit: PhaseMetric;
    /**
     * Time to parse the template and build its model.
     */
    modelBuild: PhaseMetric;
    schemaValidate: PhaseMetric;
    ruleEvaluation: PhaseMetric;
    /**
     * Time spent enriching, filtering, sorting, and finalizing the diagnostics after rule evaluation.
     */
    diagnosticFinalize: PhaseMetric;
    validateTotal: PhaseMetric;
}

/**
 * Timing for a single phase of validation (parsing, schema validation, rule evaluation, etc.).
 */
export interface PhaseMetric {
    durationMs: number;
}

/**
 * Top-level template metadata.
 */
export interface DiagnosticTemplate {
    formatVersion?: string;
    description?: string;
    transforms: string[];
    /**
     * The top-level section names present in the template as written.
     */
    rawTopLevelKeys: string[];
}

/**
 * Validation pipeline phase a diagnostic originates from.
 */
export type Phase = 'PARSE' | 'SCHEMA' | 'LINT';

/**
 * Values used for AWS pseudo parameters (Ref AWS::Region, AWS::AccountId, ...) when
 * resolving the template; any field left unset falls back to a sensible default.
 */
export interface PseudoParameterOverrides {
    accountId?: string;
    notificationArns?: string;
    partition?: string;
    region?: string;
    stackId?: string;
    stackName?: string;
    urlSuffix?: string;
}

/**
 * Where a rule\'s logic originates.
 */
export type RuleOrigin = 'SCHEMA' | 'CFN_LINT' | 'ENGINE' | 'CUSTOM' | 'GUARD';

/**
 *r" A single validation finding with its source location flattened into individual fields.
 */
export interface StandardDiagnostic {
    /**
     * Identifier of the rule that produced this finding; its leading letter encodes the severity.
     */
    ruleId: string;
    severity: Severity;
    message: string;
    /**
     * Where the rule came from, such as a provider schema, the built-in engine, or a user-supplied rule.
     */
    source: RuleOrigin;
    /**
     * The named template entity this finding targets — a resource, parameter, output, mapping, condition, or template rule — if any.
     */
    entity?: Entity;
    /**
     * Path to the offending property within the resource, such as \'Properties.Name\'.
     */
    propertyPath?: string;
    suggestedFix?: string;
    category?: string;
    /**
     * Line in the source template where the finding begins (1-based).
     */
    startLine?: number;
    startColumn?: number;
    endLine?: number;
    endColumn?: number;
    relatedResources?: RelatedResource[];
    /**
     * Condition name to boolean assignment under which this finding applies, when it depends on template conditions.
     */
    conditionScenario?: Record<string, boolean>;
}

/**
 *r" A validation finding with additional context and enrichment beyond the standard finding.
 */
export interface DetailedDiagnostic {
    /**
     * Identifier of the rule that produced this finding; its leading letter encodes the severity.
     */
    ruleId: string;
    severity: Severity;
    message: string;
    /**
     * Where the rule came from, such as a provider schema, the built-in engine, or a user-supplied rule.
     */
    source: RuleOrigin;
    /**
     * The named template entity this finding targets — a resource, parameter, output, mapping, condition, or template rule — if any.
     */
    entity?: Entity;
    /**
     * Path to the offending property within the resource, such as \'Properties.Name\'.
     */
    propertyPath?: string;
    suggestedFix?: string;
    category?: string;
    /**
     * Line in the source template where the finding begins (1-based).
     */
    startLine?: number;
    startColumn?: number;
    endLine?: number;
    endColumn?: number;
    relatedResources?: RelatedResource[];
    /**
     * Condition name to boolean assignment under which this finding applies, when it depends on template conditions.
     */
    conditionScenario?: Record<string, boolean>;
    documentationUrl?: string;
    ruleDescription?: string;
    phase?: Phase;
    context?: ViolationContext;
}

export interface EngineConfig {
    /**
     * Engine-native custom rules (Rego or CEL depending on engine).
     */
    customRules?: ExternalRuleSource[];
    /**
     * Guard DSL rules as raw source text, usable regardless of the selected engine.
     */
    guardRules?: ExternalRuleSource[];
    /**
     * Optional schema validator configuration. A standalone engine derives its
     * schema-aware rule metadata from this config. Language APIs also use it to
     * construct the schema validator bundled with the engine, so both components
     * observe the same additional schemas.
     */
    schemaValidatorConfig?: SchemaValidatorConfig;
}

export interface MapEntry {
    key: string;
    value: ResolvedValue;
}

export interface ReportMetadata {
    /**
     * Number of rules that were active for this run after any category exclusions.
     */
    rulesEvaluated?: number;
    resourcesScanned: number;
    /**
     * Tally of reported diagnostics by severity.
     */
    counts: Summary;
    /**
     * Number of diagnostics removed by filters and the severity threshold.
     */
    suppressed: number;
    /**
     * Whether strict mode was enabled, promoting warnings to errors.
     */
    strict: boolean;
    /**
     * Minimum severity included in the report; lower-severity findings are omitted.
     */
    severityLevel: Severity;
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

export interface WasmSchemaValidationResult {
    diagnostics: StandardDiagnostic[];
    metric: PhaseMetric;
}

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
    constructor(config: SchemaValidatorConfig);
    schemaCount(): number;
    validate(model: WasmSemanticModel, region?: string | null): any;
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
