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

pub const DEFAULT_REGION: &str = "us-east-1";
pub const DEFAULT_ACCOUNT_ID: &str = "123456789012";
pub const DEFAULT_PARTITION: &str = "aws";
pub const DEFAULT_STACK_NAME: &str = "teststack";
pub const DEFAULT_URL_SUFFIX: &str = "amazonaws.com";

const CN_REGIONS: &[&str] = &["cn-north-1", "cn-northwest-1"];
const GOV_REGIONS: &[&str] = &["us-gov-east-1", "us-gov-west-1"];

pub fn partition_for_region(region: &str) -> &'static str {
    if CN_REGIONS.contains(&region) {
        "aws-cn"
    } else if GOV_REGIONS.contains(&region) {
        "aws-us-gov"
    } else {
        DEFAULT_PARTITION
    }
}

pub fn url_suffix_for_region(region: &str) -> &'static str {
    if CN_REGIONS.contains(&region) {
        "amazonaws.com.cn"
    } else {
        DEFAULT_URL_SUFFIX
    }
}

pub const SECTION_PARAMETERS: &str = "Parameters";
pub const SECTION_MAPPINGS: &str = "Mappings";
pub const SECTION_CONDITIONS: &str = "Conditions";
pub const SECTION_RESOURCES: &str = "Resources";
pub const SECTION_OUTPUTS: &str = "Outputs";
pub const SECTION_RULES: &str = "Rules";
pub const SECTION_METADATA: &str = "Metadata";
pub const SECTION_GLOBALS: &str = "Globals";
pub const SECTION_FORMAT_VERSION: &str = "AWSTemplateFormatVersion";
pub const SECTION_DESCRIPTION: &str = "Description";
pub const SECTION_TRANSFORM: &str = "Transform";

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

pub const SAM_TRANSFORM_MARKER: &str = "Serverless";
pub const SAM_SERVERLESS_TYPE_PREFIX: &str = "AWS::Serverless::";
pub const SAM_FUNCTION_TYPE: &str = "AWS::Serverless::Function";
pub const SAM_EVENT_TYPE_API: &str = "Api";
pub const SAM_IMPLICIT_REST_API: &str = "ServerlessRestApi";
pub const SAM_AUTO_PUBLISH_ALIAS: &str = "AutoPublishAlias";

pub const SAM_GLOBALS_TYPE_MAP: &[(&str, &str)] = &[
    ("Function", "AWS::Serverless::Function"),
    ("Api", "AWS::Serverless::Api"),
    ("HttpApi", "AWS::Serverless::HttpApi"),
    ("SimpleTable", "AWS::Serverless::SimpleTable"),
];

pub const CDK_METADATA_TYPE: &str = "AWS::CDK::Metadata";

pub const OUTPUT_PSEUDO_RESOURCE_PREFIX: &str = "__output__";
pub const OUTPUTS_PSEUDO_RESOURCE: &str = "__outputs__";

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
/// search/evaluation steps `ConditionModel::is_satisfiable` performs before
/// returning a conservative `true`. This is the *effective* per-query work
/// bound — `MAX_PARAM_COMBINATIONS` is only an O(1) pre-filter on the size of a
/// query's parameter space, so a closure that passes that pre-filter is still
/// enumerated only up to this budget. At ~10x `MAX_PARAM_COMBINATIONS` it lets a
/// realistic closure — a handful of parameters compared against a few literals
/// each, with shallow condition expressions — enumerate exactly with margin. It
/// does *not* guarantee exact enumeration for every closure that clears the
/// pre-filter: one sitting just under `MAX_PARAM_COMBINATIONS` whose conditions
/// have deep expressions can cost more than this budget across the full product
/// and fall back to the conservative `true`. That is acceptable because such a
/// closure is pathological, not realistic. `MAX_TOTAL_SAT_ITERATIONS` then
/// bounds the sum of these per-query budgets across a whole validation.
pub const MAX_SAT_ITERATIONS: u64 = 10_000_000;

/// Largest parameter cartesian product a single satisfiability query will
/// enumerate. The consistency check explores combinations of the values of the
/// parameters referenced by the query's relevant conditions; that product is
/// exponential in the number of distinct parameters. When it exceeds this cap
/// the query returns a conservative `true` rather than enumerate — see
/// `ConditionModel::is_satisfiable` for the exact diagnostic-direction
/// guarantee, including that through a negated use (`condition_implies`) a
/// conservative `true` can surface an extra false-positive diagnostic.
///
/// Because of that false-positive risk the cap is sized generously: 2^20 covers
/// a relevant closure spanning up to twenty binary parameters (or, e.g., eight
/// five-valued parameters), well beyond any realistic condition — a single
/// condition's closure rarely references more than a handful of parameters — so
/// legitimate templates resolve exactly and never reach the conservative path.
/// The per-query iteration budget (`MAX_SAT_ITERATIONS`) is the backstop for a
/// closure that slips under this cap but still cannot be enumerated affordably,
/// and the cumulative budget (`MAX_TOTAL_SAT_ITERATIONS`) bounds how many such
/// queries a single validation can run.
pub const MAX_PARAM_COMBINATIONS: u64 = 1_048_576;

/// Cumulative satisfiability search budget across all queries of a single
/// validation. `MAX_SAT_ITERATIONS` bounds one query, but the condition model
/// issues a query per pairwise condition-compatibility check — quadratic in the
/// condition count — plus per-resource and per-rule checks, so the *number* of
/// queries is itself unbounded on adversarial input. This caps the total search
/// work for one model so a template packed with many large-closure conditions
/// cannot drive validation into a denial of service.
///
/// Sized far above the worst legitimate template: the 200-condition
/// CloudFormation maximum yields a ~20K-query pairwise pass, and this budget
/// leaves headroom for ~100 of those queries to hit the full per-query cap
/// (`MAX_SAT_ITERATIONS`). That headroom matters because the raised
/// `MAX_PARAM_COMBINATIONS` now lets wider closures enumerate exactly rather
/// than short-circuit cheaply, so each such query can charge up to
/// `MAX_SAT_ITERATIONS`; keeping the cumulative budget well above their
/// realistic total ensures valid templates still resolve exactly. Only
/// pathological inputs reach the cap, and they then fall back to the
/// conservative "assume satisfiable" answer rather than being rejected.
pub const MAX_TOTAL_SAT_ITERATIONS: u64 = 1_000_000_000;

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

/// Keys that identify a well-formed boolean condition expression when used
/// as the sole key of a single-key mapping. Inputs to `Fn::And`, `Fn::Or`,
/// and `Fn::Not` must be one of these.
///
/// Includes both Conditions-section intrinsics (`Fn::Equals`, `Fn::And`,
/// `Fn::Or`, `Fn::Not`, `Condition`) and Rules-section boolean-producing
/// intrinsics (`Fn::Contains`, `Fn::EachMemberEquals`, `Fn::EachMemberIn`).
/// Section-placement constraints are enforced separately in `rules.rs` via
/// `validate_allowed_functions`.
pub const BOOLEAN_FN_KEYS: &[&str] = &[
    FN_CONDITION,
    FN_EQUALS,
    FN_AND,
    FN_OR,
    FN_NOT,
    FN_CONTAINS,
    FN_EACH_MEMBER_EQUALS,
    FN_EACH_MEMBER_IN,
];

/// Intrinsic functions whose output can stand in for a string-typed
/// argument to `Fn::Equals`. An `Fn::Equals` argument that is a single-key
/// mapping must use one of these keys to be considered well-formed.
pub const EQUALS_ARG_FN_KEYS: &[&str] = &[
    FN_REF,
    FN_FIND_IN_MAP,
    FN_SUB,
    FN_JOIN,
    FN_SELECT,
    FN_SPLIT,
    FN_LENGTH,
    FN_TO_JSON_STRING,
    FN_IF,
    FN_BASE64,
    FN_GET_ATT,
    FN_GET_AZS,
    FN_IMPORT_VALUE,
];

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

// Parameter type constants.
pub const PARAM_TYPE_STRING: &str = "String";
pub const PARAM_TYPE_NUMBER: &str = "Number";
pub const PARAM_TYPE_COMMA_DELIMITED_LIST: &str = "CommaDelimitedList";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_for_standard_regions() {
        assert_eq!(partition_for_region("us-east-1"), "aws");
        assert_eq!(partition_for_region("eu-west-1"), "aws");
        assert_eq!(partition_for_region("ap-southeast-1"), "aws");
    }

    #[test]
    fn partition_for_china_regions() {
        assert_eq!(partition_for_region("cn-north-1"), "aws-cn");
        assert_eq!(partition_for_region("cn-northwest-1"), "aws-cn");
    }

    #[test]
    fn partition_for_govcloud_regions() {
        assert_eq!(partition_for_region("us-gov-east-1"), "aws-us-gov");
        assert_eq!(partition_for_region("us-gov-west-1"), "aws-us-gov");
    }

    #[test]
    fn url_suffix_for_standard_regions() {
        assert_eq!(url_suffix_for_region("us-east-1"), "amazonaws.com");
        assert_eq!(url_suffix_for_region("eu-west-1"), "amazonaws.com");
        assert_eq!(url_suffix_for_region("us-gov-west-1"), "amazonaws.com");
    }

    #[test]
    fn url_suffix_for_china_regions() {
        assert_eq!(url_suffix_for_region("cn-north-1"), "amazonaws.com.cn");
        assert_eq!(url_suffix_for_region("cn-northwest-1"), "amazonaws.com.cn");
    }
}
