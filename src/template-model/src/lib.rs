#[cfg(feature = "uniffi-bindings")]
uniffi::setup_scaffolding!();

pub mod coercion;
pub mod conditions;
pub mod consts;
pub mod defect;
pub mod diagnostic;
pub(crate) mod dynamic_ref;
pub(crate) mod graph;
pub mod hardcoded_az;
pub(crate) mod intrinsic_arg_shapes;
pub mod ir;
pub mod json_value;
pub(crate) mod lang_ext_shapes;
pub(crate) mod language_extensions;
pub mod message;
pub mod model;
pub(crate) mod nesting;
pub(crate) mod parser;
pub mod pattern;
pub mod region_enums;
pub mod regions;
pub mod resolved_value;
pub mod resolver;
pub(crate) mod rules;
pub(crate) mod sam;
pub mod schedule;
pub(crate) mod serialization;
pub mod span;
pub mod template_section;
pub(crate) mod transform_expansion;
pub mod value_identity;
pub mod value_patterns;

pub use consts::PSEUDO_PARAMETERS;
pub use consts::{
    DEFAULT_ACCOUNT_ID, DEFAULT_STACK_NAME, FORMAT_VERSION, MARKER_CONDITIONAL, MARKER_DYNAMIC, MARKER_ENUM,
    MARKER_IF_FALSE, MARKER_IF_TRUE, MARKER_INTRINSIC, MARKER_KIND, MARKER_PARAM_TYPE, MARKER_REF,
    SAM_TRANSFORM_ERROR_PREFIX, SAM_TRANSFORM_ERROR_RULE_ID, is_sam_transform_error_message,
};
pub use defect::{DefectPhase, ParseDefect};
pub use ir::*;
pub use json_value::JsonValue;
pub use message::{quote, render_str_list, render_value, render_value_list};
pub use model::{ParseConfig, ParseResult, PseudoParameterOverrides, SemanticModel};
pub use pattern::{
    CompiledPattern, anchor_allowed_pattern, compile as compile_pattern, default_matches_pattern, is_service_valid,
};
pub use regions::{
    AVAILABILITY_ZONES, AWS_REGIONS, DEFAULT_PARTITION, DEFAULT_REGION, DEFAULT_URL_SUFFIX,
    availability_zones_for_region, is_known_region, partition_for_region, url_suffix_for_region,
};
pub use schedule::schedule_expression_errors;
pub use span::{SourceSpan, SpanProvider, UNKNOWN_SPAN, span_to_option};
pub use template_section::{EntityType, TopLevelSection, entity_identity};
pub use value_identity::expression_fingerprint;
pub use value_patterns::{
    AMI_ID_PATTERN, AVAILABILITY_ZONE_PATTERN, CAA_RECORD_PATTERN, IAM_ROLE_ARN_PATTERN, IAM_ROLE_ARN_RULE_PATTERN,
    MX_RECORD_PATTERN, SECURITY_GROUP_NAME_PATTERN,
};

pub(crate) use defect::{make_parse_defect, make_parse_defect_at, make_parse_defect_for_resource};
