use crate::template_section::TopLevelSection;

pub const PSEUDO_PREFIX: &str = "AWS::";
pub const PSEUDO_NO_VALUE: &str = "AWS::NoValue";
pub const PSEUDO_ACCOUNT_ID: &str = "AWS::AccountId";
pub const PSEUDO_NOTIFICATION_ARNS: &str = "AWS::NotificationARNs";
pub const PSEUDO_PARTITION: &str = "AWS::Partition";
pub const PSEUDO_REGION: &str = "AWS::Region";
pub const PSEUDO_STACK_ID: &str = "AWS::StackId";
pub const PSEUDO_STACK_NAME: &str = "AWS::StackName";
pub const PSEUDO_URL_SUFFIX: &str = "AWS::URLSuffix";

pub const PSEUDO_PARAMETERS: &[&str] = &[
    PSEUDO_ACCOUNT_ID,
    PSEUDO_NOTIFICATION_ARNS,
    PSEUDO_NO_VALUE,
    PSEUDO_PARTITION,
    PSEUDO_REGION,
    PSEUDO_STACK_ID,
    PSEUDO_STACK_NAME,
    PSEUDO_URL_SUFFIX,
];

pub const DEFAULT_ACCOUNT_ID: &str = "123456789012";
pub const DEFAULT_STACK_NAME: &str = "teststack";

// Section keys derive from the shared `TopLevelSection` enum — the single
// definition of the documented template sections. `Globals` is SAM-only and
// not part of the documented template anatomy, so it stays a plain constant.
pub const SECTION_PARAMETERS: &str = TopLevelSection::Parameters.name();
pub const SECTION_MAPPINGS: &str = TopLevelSection::Mappings.name();
pub const SECTION_CONDITIONS: &str = TopLevelSection::Conditions.name();
pub const SECTION_RESOURCES: &str = TopLevelSection::Resources.name();
pub const SECTION_OUTPUTS: &str = TopLevelSection::Outputs.name();
pub const SECTION_RULES: &str = TopLevelSection::Rules.name();
pub const SECTION_METADATA: &str = TopLevelSection::Metadata.name();
pub const SECTION_GLOBALS: &str = "Globals";
pub const SECTION_FORMAT_VERSION: &str = TopLevelSection::FormatVersion.name();
pub const SECTION_DESCRIPTION: &str = TopLevelSection::Description.name();
pub const SECTION_TRANSFORM: &str = TopLevelSection::Transform.name();

pub const KEY_TYPE: &str = "Type";
pub const KEY_CONDITION: &str = "Condition";
pub const KEY_PROPERTIES: &str = "Properties";
pub const KEY_DEPENDS_ON: &str = "DependsOn";
pub const KEY_DELETION_POLICY: &str = "DeletionPolicy";
pub const KEY_UPDATE_REPLACE_POLICY: &str = "UpdateReplacePolicy";
pub const KEY_UPDATE_POLICY: &str = "UpdatePolicy";
pub const KEY_CREATION_POLICY: &str = "CreationPolicy";

pub const KEY_DEFAULT: &str = "Default";
pub const KEY_ALLOWED_VALUES: &str = "AllowedValues";
pub const KEY_ALLOWED_PATTERN: &str = "AllowedPattern";
pub const KEY_NO_ECHO: &str = "NoEcho";
pub const KEY_MIN_LENGTH: &str = "MinLength";
pub const KEY_MAX_LENGTH: &str = "MaxLength";
pub const KEY_MIN_VALUE: &str = "MinValue";
pub const KEY_MAX_VALUE: &str = "MaxValue";

pub const KEY_VALUE: &str = "Value";
pub const KEY_EXPORT: &str = "Export";
pub const KEY_NAME: &str = "Name";
pub const KEY_CONSTRAINT_DESCRIPTION: &str = "ConstraintDescription";

/// Optional fourth element of `Fn::FindInMap`: `{ "DefaultValue": ... }`.
pub const KEY_DEFAULT_VALUE: &str = "DefaultValue";

/// Argument keys of `Fn::GetStackOutput`: `StackName` and `OutputName` are
/// required; `Region` and `RoleArn` are optional. No other keys are permitted.
pub const KEY_STACK_NAME: &str = "StackName";
pub const KEY_OUTPUT_NAME: &str = "OutputName";
pub const KEY_REGION: &str = "Region";
pub const KEY_ROLE_ARN: &str = "RoleArn";

pub const SAM_SERVERLESS_TYPE_PREFIX: &str = "AWS::Serverless::";
pub const SAM_FUNCTION_TYPE: &str = "AWS::Serverless::Function";
pub const SAM_API_TYPE: &str = "AWS::Serverless::Api";
pub const SAM_HTTP_API_TYPE: &str = "AWS::Serverless::HttpApi";
pub const SAM_SIMPLE_TABLE_TYPE: &str = "AWS::Serverless::SimpleTable";
pub const SAM_LAYER_VERSION_TYPE: &str = "AWS::Serverless::LayerVersion";
pub const SAM_APPLICATION_TYPE: &str = "AWS::Serverless::Application";
pub const SAM_STATE_MACHINE_TYPE: &str = "AWS::Serverless::StateMachine";
pub const SAM_CONNECTOR_TYPE: &str = "AWS::Serverless::Connector";
pub const SAM_GRAPHQL_API_TYPE: &str = "AWS::Serverless::GraphQLApi";
pub const SAM_EVENT_TYPE_API: &str = "Api";
pub const SAM_EVENT_TYPE_HTTP_API: &str = "HttpApi";
pub const SAM_EVENT_TYPE_SCHEDULE: &str = "Schedule";
pub const SAM_IMPLICIT_REST_API: &str = "ServerlessRestApi";
pub const SAM_IMPLICIT_HTTP_API: &str = "ServerlessHttpApi";
/// The SAM transform gives the implicit REST API a stage named `Prod`, whose
/// logical id is `ServerlessRestApi` + `Prod` + `Stage`.
pub const SAM_IMPLICIT_REST_API_STAGE: &str = "ServerlessRestApiProdStage";
pub const SAM_AUTO_PUBLISH_ALIAS: &str = "AutoPublishAlias";
pub const SAM_LAYER_CONTENT_URI: &str = "ContentUri";
pub const SAM_APPLICATION_LOCATION: &str = "Location";
pub const SAM_FUNCTION_EVENTS: &str = "Events";
pub const SAM_FUNCTION_ROLE: &str = "Role";
pub const SAM_SCHEDULE_PROPERTY: &str = "Schedule";
pub const SAM_API_STAGE_NAME: &str = "StageName";
pub const SAM_DEFINITION: &str = "Definition";
pub const SAM_DEFINITION_URI: &str = "DefinitionUri";
pub const SAM_CONNECTOR_SOURCE: &str = "Source";
pub const SAM_CONNECTOR_DESTINATION: &str = "Destination";
pub const SAM_CONNECTOR_PERMISSIONS: &str = "Permissions";
pub const SAM_GRAPHQL_AUTH: &str = "Auth";
pub const SAM_SIMPLE_TABLE_PRIMARY_KEY: &str = "PrimaryKey";
pub const SAM_PRIMARY_KEY_TYPE: &str = "Type";
/// Valid DynamoDB attribute types for a `SimpleTable` PrimaryKey.
pub const SAM_PRIMARY_KEY_TYPES: &[&str] = &["String", "Number", "Binary"];

// Function properties involved in transform-error validation.
pub const SAM_FUNCTION_PACKAGE_TYPE: &str = "PackageType";
pub const SAM_FUNCTION_RUNTIME: &str = "Runtime";
pub const SAM_FUNCTION_HANDLER: &str = "Handler";
pub const SAM_FUNCTION_LAYERS: &str = "Layers";
pub const SAM_FUNCTION_DEAD_LETTER_QUEUE: &str = "DeadLetterQueue";
pub const SAM_FUNCTION_TARGET_ARN: &str = "TargetArn";
pub const SAM_FUNCTION_PROVISIONED_CONCURRENCY: &str = "ProvisionedConcurrencyConfig";
pub const SAM_FUNCTION_CAPACITY_PROVIDER: &str = "CapacityProviderConfig";
pub const SAM_FUNCTION_VPC_CONFIG: &str = "VpcConfig";
pub const SAM_FUNCTION_SCALING_CONFIG: &str = "FunctionScalingConfig";
pub const SAM_FUNCTION_VERSION_DELETION_POLICY: &str = "VersionDeletionPolicy";
pub const SAM_FUNCTION_IMAGE_URI: &str = "ImageUri";
pub const SAM_FUNCTION_IMAGE_CONFIG: &str = "ImageConfig";
pub const SAM_FUNCTION_URL_CONFIG: &str = "FunctionUrlConfig";
pub const SAM_FUNCTION_URL_AUTH_TYPE: &str = "AuthType";
pub const SAM_FUNCTION_DEPLOYMENT_PREFERENCE: &str = "DeploymentPreference";
pub const SAM_PACKAGE_TYPE_ZIP: &str = "Zip";
pub const SAM_PACKAGE_TYPE_IMAGE: &str = "Image";
/// Valid DeadLetterQueue target types.
pub const SAM_DLQ_TYPES: &[&str] = &["SQS", "SNS"];
/// Valid FunctionUrlConfig auth types.
pub const SAM_FUNCTION_URL_AUTH_TYPES: &[&str] = &["AWS_IAM", "NONE"];

// LayerVersion properties involved in transform-error validation.
pub const SAM_LAYER_RETENTION_POLICY: &str = "RetentionPolicy";
pub const SAM_LAYER_COMPATIBLE_ARCHITECTURES: &str = "CompatibleArchitectures";
/// Valid LayerVersion RetentionPolicy values.
pub const SAM_LAYER_RETENTION_POLICIES: &[&str] = &["Retain", "Delete"];
/// Valid Lambda architectures (LayerVersion CompatibleArchitectures).
pub const SAM_ARCHITECTURES: &[&str] = &["x86_64", "arm64"];

/// Maps each `Globals` template-section key to the SAM resource type whose
/// defaults it carries.
pub const SAM_GLOBALS_TYPE_MAP: &[(&str, &str)] = &[
    (SAM_FUNCTION_GLOBALS_KEY, SAM_FUNCTION_TYPE),
    (SAM_API_GLOBALS_KEY, SAM_API_TYPE),
    (SAM_HTTP_API_GLOBALS_KEY, SAM_HTTP_API_TYPE),
    (SAM_SIMPLE_TABLE_GLOBALS_KEY, SAM_SIMPLE_TABLE_TYPE),
];

// Keys under the `Globals` template section, each naming the SAM resource type
// whose defaults follow (see `SAM_GLOBALS_TYPE_MAP`).
pub const SAM_FUNCTION_GLOBALS_KEY: &str = "Function";
pub const SAM_API_GLOBALS_KEY: &str = "Api";
pub const SAM_HTTP_API_GLOBALS_KEY: &str = "HttpApi";
pub const SAM_SIMPLE_TABLE_GLOBALS_KEY: &str = "SimpleTable";

pub const CDK_METADATA_TYPE: &str = "AWS::CDK::Metadata";

pub const OUTPUT_PSEUDO_RESOURCE_PREFIX: &str = "__output__";
pub const OUTPUTS_PSEUDO_RESOURCE: &str = "__outputs__";

/// Sentinel value used by the satisfiability search to represent "any value
/// other than the literals the parameter is compared against". Added to the
/// candidate-value set of a parameter (or pseudo-parameter) without an explicit
/// `AllowedValues` list or override, so the SAT solver treats the symbol as a
/// free variable that can also disagree with every literal it is compared to.
/// Without this sentinel a parameter compared against a single literal would be
/// pinned to that literal and the SAT solver would mark the negative branch
/// unreachable.
pub const PARAM_UNKNOWN_SENTINEL: &str = "__unknown__";

pub const RULE_PSEUDO_RESOURCE_PREFIX: &str = "__rule__";

pub const MAX_TEMPLATE_SIZE_BYTES: usize = 10 * 1024 * 1024;

/// Maximum number of distinct (value, condition-assignment) scenarios a single
/// value may resolve into before that value's scenario enumeration is
/// truncated. A value composed from or gated by many conditions/parameters can
/// take many concrete forms; this bounds that set so per-scenario rule
/// evaluation stays bounded. This is a *per-value* cap only — the cumulative
/// scenario work across an entire validation is bounded separately by
/// `MAX_TOTAL_SCENARIO_COMBINATIONS`. Sits above `MAX_ENUM_EXPANSION` (per-value
/// variant expansion) and below the parameter/satisfiability bounds.
pub const MAX_SCENARIO_COMBINATIONS: usize = 262_144;

/// Cumulative scenario-expansion budget across all values resolved during a
/// single validation. `MAX_SCENARIO_COMBINATIONS` bounds one value's expansion,
/// but scenario resolution runs per resource property and per rule, so the
/// *number* of expansions is itself unbounded on adversarial input — a template
/// packed with many heavily-gated values would otherwise drive up to
/// `num_values * MAX_SCENARIO_COMBINATIONS` of work with no global ceiling. This
/// caps the total scenarios materialized for one model; once it is reached,
/// further scenario resolution yields no scenarios rather than continuing to
/// expand. Sized far above the worst legitimate template — real values resolve
/// to a single scenario and conditional ones to a handful — while still cutting
/// off a pathological blow-up. Mirrors the SAT path's `MAX_TOTAL_SAT_ITERATIONS`
/// (here 128x the per-value cap).
pub const MAX_TOTAL_SCENARIO_COMBINATIONS: u64 = 33_554_432;

pub const MAX_RESOLVE_DEPTH: u32 = 512;

/// Maximum number of concrete variants a single value may expand to during
/// intrinsic resolution (e.g. an `Fn::Join` over enumerated elements). Bounds
/// per-value combinatorial blow-up and the memory a resolved value holds;
/// beyond it the expansion is truncated. The narrowest analysis bound — it
/// operates on a single value.
pub const MAX_ENUM_EXPANSION: usize = 4_096;

/// Per-query budget for a single satisfiability search: the maximum number of
/// evaluation steps `ConditionModel::is_satisfiable` performs before returning a
/// conservative `true`. This is the *effective* per-query work bound —
/// `MAX_PARAM_COMBINATIONS` is only an O(1) pre-filter on the size of a query's
/// parameter space, so a query that passes that pre-filter is still explored only
/// up to this budget.
///
/// A query searches parameter assignments, abandons a branch as soon as the values
/// bound so far decide an assumed condition against its assumption, and derives
/// what the assumptions force on conditions the parameters leave undetermined — so
/// the steps a real template needs are far fewer than its parameter space is wide.
/// Measured across templates built to be expensive on purpose — two hundred
/// conditions layered over a few shared pseudo-parameters, two hundred independent
/// flags, six parameters with twenty values each combined six at a time — and a
/// real deployment template with over two hundred conditions and ninety
/// parameters, no single query exceeded ~18K steps. This budget sits roughly fifty
/// times above that, so exactness is never traded away on a template anyone would
/// write, while one query stays bounded to milliseconds.
///
/// It does *not* guarantee exact enumeration for every query: one whose branches
/// cannot be pruned and whose parameter space is near the pre-filter cap can cost
/// more than this budget and fall back to the conservative `true`. That is
/// acceptable because such a query is pathological, not realistic.
/// `MAX_TOTAL_SAT_ITERATIONS` then bounds the sum of these per-query budgets
/// across a whole validation.
pub const MAX_SAT_ITERATIONS: u64 = 1_000_000;

/// Largest parameter space a single satisfiability query will search. The query
/// searches assignments of concrete values to the parameters its conditions read;
/// the number of such assignments is the product of each parameter's candidate
/// values, and so is exponential in the number of distinct parameters. When that
/// product exceeds this cap the query returns a conservative `true` without
/// searching — see `ConditionModel::is_satisfiable` for the exact
/// diagnostic-direction guarantee, including that through a negated use
/// (`condition_implies`) a conservative `true` can surface an extra false-positive
/// diagnostic.
///
/// Because of that false-positive risk the cap is sized generously: 2^20 covers a
/// query reading up to twenty binary parameters (or, e.g., eight five-valued
/// ones), well beyond any realistic condition — a condition rarely reads more
/// than a handful of parameters — so legitimate templates resolve exactly and
/// never reach the conservative path. This cap is only an O(1) pre-filter on the
/// size of the space; the per-query budget (`MAX_SAT_ITERATIONS`) bounds the work
/// actually performed inside it, and the cumulative budget
/// (`MAX_TOTAL_SAT_ITERATIONS`) bounds how much such work one validation can do
/// in total.
pub const MAX_PARAM_COMBINATIONS: u64 = 1_048_576;

/// Cumulative satisfiability search budget across all queries of a single
/// validation. `MAX_SAT_ITERATIONS` bounds one query, but the condition model
/// issues a query per pairwise condition-compatibility check — quadratic in the
/// condition count — plus per-resource and per-rule checks, so the *number* of
/// queries is itself unbounded on adversarial input. This caps the total search
/// work for one model so no template can drive validation into a denial of
/// service.
///
/// This budget is what ultimately bounds how long one template can spend deciding
/// conditions, so it is sized from measurement rather than from a round number. A
/// real deployment template with over two hundred conditions and ninety
/// parameters, whose quadratic pairwise pass is analyzed in full, consumes about 7M
/// steps; the most expensive shape built on purpose — two hundred conditions all
/// connected through three shared inputs, with resources gated on them — consumes
/// about 17M. This budget sits about six times above that worst measured case:
/// enough that a template anyone would write always resolves exactly, while the
/// worst case adversarial input can reach stays in seconds rather than minutes.
/// Raising it gives that latency ceiling away; lowering it starts costing precision
/// on real templates.
///
/// Once the budget is spent, further queries fall back to the conservative
/// "assume satisfiable" answer rather than being rejected, and reaching it is
/// reported so a truncated analysis is never silent.
pub const MAX_TOTAL_SAT_ITERATIONS: u64 = 100_000_000;

pub const FORMAT_VERSION: &str = "2010-09-09";

// Used by serialization.rs to encode unresolved values in diagnostic JSON.
// Engines check these markers to detect dynamic/unresolvable content.

pub const MARKER_DYNAMIC: &str = "__dynamic";
pub const MARKER_REF: &str = "__ref";
pub const MARKER_CONDITIONAL: &str = "__conditional";
pub const MARKER_INTRINSIC: &str = "__intrinsic";
pub const MARKER_ENUM: &str = "__enum";
pub const MARKER_PARAM_TYPE: &str = "__param_type";
pub const MARKER_KIND: &str = "__kind";
pub const MARKER_IF_TRUE: &str = "__if_true";
pub const MARKER_IF_FALSE: &str = "__if_false";

pub const KEY_RULE_CONDITION: &str = "RuleCondition";
pub const KEY_ASSERTIONS: &str = "Assertions";
pub const KEY_ASSERT: &str = "Assert";
pub const KEY_ASSERT_DESCRIPTION: &str = "AssertDescription";

pub const FN_PREFIX: &str = "Fn::";

pub const FN_REF: &str = "Ref";
pub const FN_GET_ATT: &str = "Fn::GetAtt";
pub const FN_SUB: &str = "Fn::Sub";
pub const FN_JOIN: &str = "Fn::Join";
pub const FN_SELECT: &str = "Fn::Select";
pub const FN_IF: &str = "Fn::If";
pub const FN_FIND_IN_MAP: &str = "Fn::FindInMap";
pub const FN_SPLIT: &str = "Fn::Split";
pub const FN_BASE64: &str = "Fn::Base64";
pub const FN_CIDR: &str = "Fn::Cidr";
pub const FN_GET_AZS: &str = "Fn::GetAZs";
pub const FN_GET_STACK_OUTPUT: &str = "Fn::GetStackOutput";
pub const FN_IMPORT_VALUE: &str = "Fn::ImportValue";
pub const FN_TRANSFORM: &str = "Fn::Transform";
pub const FN_AND: &str = "Fn::And";
pub const FN_OR: &str = "Fn::Or";
pub const FN_NOT: &str = "Fn::Not";
pub const FN_EQUALS: &str = "Fn::Equals";
pub const FN_TO_JSON_STRING: &str = "Fn::ToJsonString";
pub const FN_LENGTH: &str = "Fn::Length";
pub const FN_FOR_EACH: &str = "Fn::ForEach";
pub const FN_CONDITION: &str = "Condition";

pub const FN_VALUE_OF: &str = "Fn::ValueOf";
pub const FN_VALUE_OF_ALL: &str = "Fn::ValueOfAll";
pub const FN_REF_ALL: &str = "Fn::RefAll";
pub const FN_CONTAINS: &str = "Fn::Contains";
pub const FN_EACH_MEMBER_EQUALS: &str = "Fn::EachMemberEquals";
pub const FN_EACH_MEMBER_IN: &str = "Fn::EachMemberIn";

pub const FN_FOR_EACH_KEY_PREFIX: &str = "Fn::ForEach::";

/// Every intrinsic-function key that the parser can write into a node's build
/// path. Path-based checks that ask "is this string nested inside a function?"
/// must match against this list rather than the bare `Fn::` prefix: a user map
/// key may legitimately start with `Fn::` (e.g. a Lambda environment variable
/// named `Fn::Custom`) without being a function.
pub const INTRINSIC_FN_PATH_SEGMENTS: &[&str] = &[
    FN_GET_ATT,
    FN_SUB,
    FN_JOIN,
    FN_SELECT,
    FN_IF,
    FN_FIND_IN_MAP,
    FN_SPLIT,
    FN_BASE64,
    FN_CIDR,
    FN_GET_AZS,
    FN_GET_STACK_OUTPUT,
    FN_IMPORT_VALUE,
    FN_TRANSFORM,
    FN_AND,
    FN_OR,
    FN_NOT,
    FN_EQUALS,
    FN_TO_JSON_STRING,
    FN_LENGTH,
    FN_FOR_EACH,
    FN_VALUE_OF,
    FN_VALUE_OF_ALL,
    FN_REF_ALL,
    FN_CONTAINS,
    FN_EACH_MEMBER_EQUALS,
    FN_EACH_MEMBER_IN,
];

/// Resource property paths where an `ssm-secure` dynamic reference is
/// supported — the fixed set CloudFormation documents for secure-string
/// resolution. Paths use the resource *type*
/// (not the logical ID) and `*` for array indices.
pub const SSM_SECURE_ALLOWED_PROPERTY_PATHS: &[&str] = &[
    "Resources/AWS::DirectoryService::MicrosoftAD/Properties/Password",
    "Resources/AWS::DirectoryService::SimpleAD/Properties/Password",
    "Resources/AWS::ElastiCache::ReplicationGroup/Properties/AuthToken",
    "Resources/AWS::IAM::User/Properties/LoginProfile/Password",
    "Resources/AWS::KinesisFirehose::DeliveryStream/Properties/RedshiftDestinationConfiguration/Password",
    "Resources/AWS::OpsWorks::App/Properties/AppSource/Password",
    "Resources/AWS::OpsWorks::Stack/Properties/RdsDbInstances/*/DbPassword",
    "Resources/AWS::OpsWorks::Stack/Properties/CustomCookbooksSource/Password",
    "Resources/AWS::RDS::DBCluster/Properties/MasterUserPassword",
    "Resources/AWS::RDS::DBInstance/Properties/MasterUserPassword",
    "Resources/AWS::Redshift::Cluster/Properties/MasterUserPassword",
];

/// The YAML 1.1 merge key. A mapping entry `<<: <alias-or-list-of-aliases>` splices
/// the referenced mapping(s) into the enclosing mapping, with explicit keys winning
/// over merged ones and earlier merge sources winning over later ones.
pub const YAML_MERGE_KEY: &str = "<<";

// Short (bare) intrinsic names — the suffix after the `Fn::` prefix that appears in
// YAML shorthand tags (`!GetAtt`) and in the serialized reference graph. `Ref` and
// `Condition` have no `Fn::` form, so their short and long spellings coincide.
pub const TAG_REF: &str = "Ref";
pub const TAG_GET_ATT: &str = "GetAtt";
pub const TAG_SUB: &str = "Sub";
pub const TAG_JOIN: &str = "Join";
pub const TAG_SELECT: &str = "Select";
pub const TAG_IF: &str = "If";
pub const TAG_FIND_IN_MAP: &str = "FindInMap";
pub const TAG_SPLIT: &str = "Split";
pub const TAG_BASE64: &str = "Base64";
pub const TAG_CIDR: &str = "Cidr";
pub const TAG_GET_AZS: &str = "GetAZs";
pub const TAG_GET_STACK_OUTPUT: &str = "GetStackOutput";
pub const TAG_IMPORT_VALUE: &str = "ImportValue";
pub const TAG_TRANSFORM: &str = "Transform";
pub const TAG_AND: &str = "And";
pub const TAG_OR: &str = "Or";
pub const TAG_NOT: &str = "Not";
pub const TAG_EQUALS: &str = "Equals";
pub const TAG_CONDITION: &str = "Condition";
pub const TAG_TO_JSON_STRING: &str = "ToJsonString";
pub const TAG_LENGTH: &str = "Length";
pub const TAG_FOR_EACH: &str = "ForEach";
pub const TAG_VALUE_OF: &str = "ValueOf";
pub const TAG_VALUE_OF_ALL: &str = "ValueOfAll";
pub const TAG_REF_ALL: &str = "RefAll";
pub const TAG_CONTAINS: &str = "Contains";
pub const TAG_EACH_MEMBER_EQUALS: &str = "EachMemberEquals";
pub const TAG_EACH_MEMBER_IN: &str = "EachMemberIn";

/// Display label for the expression form of `Fn::If` (the condition is itself an
/// intrinsic rather than a named condition). This is an internal variant, not a
/// CloudFormation tag, so it is deliberately absent from `SHORT_TAG_TO_FN_KEY`.
pub const TAG_IF_EXPR: &str = "IfExpr";

/// YAML shorthand tags map their bare suffix to the canonical `Fn::`-prefixed key
/// used everywhere downstream. `Ref` and `Condition` map to themselves.
pub const SHORT_TAG_TO_FN_KEY: &[(&str, &str)] = &[
    (TAG_REF, FN_REF),
    (TAG_GET_ATT, FN_GET_ATT),
    (TAG_SUB, FN_SUB),
    (TAG_JOIN, FN_JOIN),
    (TAG_SELECT, FN_SELECT),
    (TAG_IF, FN_IF),
    (TAG_FIND_IN_MAP, FN_FIND_IN_MAP),
    (TAG_SPLIT, FN_SPLIT),
    (TAG_BASE64, FN_BASE64),
    (TAG_CIDR, FN_CIDR),
    (TAG_GET_AZS, FN_GET_AZS),
    (TAG_GET_STACK_OUTPUT, FN_GET_STACK_OUTPUT),
    (TAG_IMPORT_VALUE, FN_IMPORT_VALUE),
    (TAG_TRANSFORM, FN_TRANSFORM),
    (TAG_AND, FN_AND),
    (TAG_OR, FN_OR),
    (TAG_NOT, FN_NOT),
    (TAG_EQUALS, FN_EQUALS),
    (TAG_CONDITION, FN_CONDITION),
    (TAG_TO_JSON_STRING, FN_TO_JSON_STRING),
    (TAG_LENGTH, FN_LENGTH),
    (TAG_FOR_EACH, FN_FOR_EACH),
    (TAG_VALUE_OF, FN_VALUE_OF),
    (TAG_VALUE_OF_ALL, FN_VALUE_OF_ALL),
    (TAG_REF_ALL, FN_REF_ALL),
    (TAG_CONTAINS, FN_CONTAINS),
    (TAG_EACH_MEMBER_EQUALS, FN_EACH_MEMBER_EQUALS),
    (TAG_EACH_MEMBER_IN, FN_EACH_MEMBER_IN),
];

/// Keys that identify a well-formed boolean condition expression when used
/// as the sole key of a single-key mapping. Inputs to `Fn::And`, `Fn::Or`,
/// and `Fn::Not` must be one of these.
///
/// Includes both Conditions-section intrinsics (`Fn::Equals`, `Fn::And`,
/// `Fn::Or`, `Fn::Not`, `Condition`) and Rules-section boolean-producing
/// intrinsics (`Fn::Contains`, `Fn::EachMemberEquals`, `Fn::EachMemberIn`).
/// Section-placement constraints are enforced separately in `rules.rs` via
/// `validate_allowed_functions`.
pub const BOOLEAN_FN_KEYS: &[&str] =
    &[FN_CONDITION, FN_EQUALS, FN_AND, FN_OR, FN_NOT, FN_CONTAINS, FN_EACH_MEMBER_EQUALS, FN_EACH_MEMBER_IN];

/// Intrinsic functions whose output can stand in for an `Fn::Equals` argument.
/// An `Fn::Equals` argument that is a single-key mapping must use one of these
/// keys to be considered well-formed. An `Fn::Equals` operand must resolve to a
/// scalar, so only the string/value-producing functions are permitted. Boolean
/// and reference-shaped functions (`Fn::And`/`Fn::Or`/`Fn::Not`, a nested
/// `Fn::Equals`, `Condition`, `Fn::GetAtt`, `Fn::GetAZs`, `Fn::ImportValue`,
/// `Fn::Base64`, and the Rules-section membership functions) produce a
/// non-scalar and are rejected here, matching CloudFormation's own restriction
/// on comparison operands.
pub const EQUALS_ARG_FN_KEYS: &[&str] =
    &[FN_REF, FN_FIND_IN_MAP, FN_SUB, FN_JOIN, FN_SELECT, FN_SPLIT, FN_LENGTH, FN_TO_JSON_STRING];

// Edge kind values used in the serialized reference graph.
// These are distinct from FN_* names (e.g. EDGE_KIND_GET_ATT = "GetAtt" vs FN_GET_ATT = "Fn::GetAtt").
pub const EDGE_KIND_REF: &str = "Ref";
pub const EDGE_KIND_GET_ATT: &str = "GetAtt";
pub const EDGE_KIND_SUB: &str = "Sub";
pub const EDGE_KIND_DEPENDS_ON: &str = "DependsOn";
pub const EDGE_KIND_SELECT: &str = "Select";
pub const EDGE_KIND_CONDITION: &str = "Condition";

// Serialized DiagnosticModel field keys (camelCase, produced by serde rename_all).
pub const FIELD_RESOURCES: &str = "resources";
pub const FIELD_PARAMETERS: &str = "parameters";
pub const FIELD_CONDITIONS: &str = "conditions";
pub const FIELD_MAPPINGS: &str = "mappings";
pub const FIELD_OUTPUTS: &str = "outputs";
pub const FIELD_EDGES: &str = "edges";
pub const FIELD_TRANSFORMS: &str = "transforms";
pub const FIELD_RESOURCE_TYPE: &str = "resourceType";
pub const FIELD_PROPERTIES: &str = "properties";
pub const FIELD_DEPENDS_ON: &str = "dependsOn";
pub const FIELD_CONDITION: &str = "condition";
pub const FIELD_OUTGOING_REFS: &str = "outgoingRefs";
pub const FIELD_INCOMING_REFS: &str = "incomingRefs";
pub const FIELD_DELETION_POLICY: &str = "deletionPolicy";
pub const FIELD_UPDATE_REPLACE_POLICY: &str = "updateReplacePolicy";
pub const FIELD_CREATION_POLICY: &str = "creationPolicy";
pub const FIELD_UPDATE_POLICY: &str = "updatePolicy";
pub const FIELD_KIND: &str = "kind";
pub const FIELD_TARGET: &str = "target";
pub const FIELD_SOURCE: &str = "source";
pub const FIELD_SOURCE_PATH: &str = "sourcePath";
pub const FIELD_ATTR: &str = "attr";
pub const FIELD_CONDITION_CONTEXT: &str = "conditionContext";

// CloudFormation transform identifiers.
pub const TRANSFORM_LANGUAGE_EXTENSIONS: &str = "AWS::LanguageExtensions";
pub const TRANSFORM_SERVERLESS: &str = "AWS::Serverless-2016-10-31";
pub const TRANSFORM_INCLUDE: &str = "AWS::Include";

// DeletionPolicy / UpdateReplacePolicy values.
pub const POLICY_DELETE: &str = "Delete";
pub const POLICY_RETAIN: &str = "Retain";
pub const POLICY_SNAPSHOT: &str = "Snapshot";
pub const POLICY_RETAIN_EXCEPT_ON_CREATE: &str = "RetainExceptOnCreate";

// Convention prefix for encoding condition references inside Ref nodes.
pub const CONDITION_REF_PREFIX: &str = "Condition:";

pub const PARAM_TYPE_STRING: &str = "String";
pub const PARAM_TYPE_NUMBER: &str = "Number";
pub const PARAM_TYPE_COMMA_DELIMITED_LIST: &str = "CommaDelimitedList";

// SAM transform-error identity. The transform is applied while building the
// semantic model, so this crate owns the rule ID and message prefix that mark
// a failed transform; downstream layers gate on them because a failed SAM
// transform stops CloudFormation before resource validation.
pub const SAM_TRANSFORM_ERROR_RULE_ID: &str = "E0001";

/// Message prefix shared by every SAM transform-error finding, regardless of
/// which layer produced it.
pub const SAM_TRANSFORM_ERROR_PREFIX: &str = "Error transforming template:";

/// Returns `true` when `message` belongs to a SAM transform-error finding.
pub fn is_sam_transform_error_message(message: &str) -> bool {
    message.starts_with(SAM_TRANSFORM_ERROR_PREFIX)
}
