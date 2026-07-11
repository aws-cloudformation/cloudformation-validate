#[cfg(feature = "uniffi-bindings")]
uniffi::setup_scaffolding!();

pub mod coercion;
pub mod conditions;
pub mod consts;
pub mod diagnostic;
pub(crate) mod graph;
pub mod hardcoded_az;
pub mod ir;
pub(crate) mod language_extensions;
pub mod model;
pub(crate) mod nesting;
pub(crate) mod parser;
pub mod region_enums;
pub mod regions;
pub mod resolved_value;
pub mod resolver;
pub(crate) mod rules;
pub(crate) mod sam;
pub(crate) mod serialization;

pub use consts::PSEUDO_PARAMETERS;
pub use consts::{
    DEFAULT_ACCOUNT_ID, DEFAULT_STACK_NAME, FORMAT_VERSION, MARKER_CONDITIONAL, MARKER_DYNAMIC, MARKER_ENUM,
    MARKER_IF_FALSE, MARKER_IF_TRUE, MARKER_INTRINSIC, MARKER_KIND, MARKER_PARAM_TYPE, MARKER_REF,
};
pub use ir::*;
pub use model::{ParseConfig, ParseResult, PseudoParameterOverrides, SemanticModel};
pub use regions::{
    AVAILABILITY_ZONES, AWS_REGIONS, DEFAULT_PARTITION, DEFAULT_REGION, DEFAULT_URL_SUFFIX,
    availability_zones_for_region, is_known_region, partition_for_region, url_suffix_for_region,
};

use diagnostics::{Diagnostic, Phase, RegisteredDiagnostic, SourceSpan};

pub(crate) fn make_parse_diagnostic(rule_id: &str, message: String, span: SourceSpan) -> Diagnostic {
    RegisteredDiagnostic::new(rule_id, message).location(span).phase(Phase::Parse).build()
}

/// Like [`make_parse_diagnostic`], but attaches a locating anchor derived from a
/// builder path such as `Resources/R/Properties/X/Fn::If` or
/// `Conditions/C/Fn::And`. A resource-property defect carries the logical ID and a
/// dotted property path so it lands where consumers expect. Defects in other
/// sections (`Conditions`, `Outputs`, …) carry the build path itself as the
/// property path, so that when the exact node has no byte span yet, downstream
/// span resolution can walk up to the nearest enclosing element (the named
/// condition/output) instead of leaving the diagnostic unlocated.
pub(crate) fn make_parse_diagnostic_at(
    rule_id: &str,
    message: String,
    span: SourceSpan,
    build_path: &str,
) -> Diagnostic {
    let mut builder = RegisteredDiagnostic::new(rule_id, message).location(span).phase(Phase::Parse);
    let segments: Vec<&str> = build_path.split('/').collect();
    if segments.len() >= 4
        && segments[0] == consts::SECTION_RESOURCES
        && matches!(segments[2], consts::KEY_PROPERTIES | consts::SECTION_METADATA)
    {
        builder = builder.resource(segments[1], None);
        builder = builder.property_path(segments[2..].join("."));
    } else if segments.len() >= 2 {
        // Non-resource section (e.g. Conditions/<name>/Fn::And): keep the full
        // slash path so span resolution can walk up to the enclosing element.
        builder = builder.property_path(build_path);
    }
    builder.build()
}
