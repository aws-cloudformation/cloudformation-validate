#[cfg(feature = "uniffi-bindings")]
uniffi::setup_scaffolding!();

pub mod coercion;
pub mod conditions;
pub mod consts;
pub mod diagnostic;
pub(crate) mod graph;
pub mod ir;
pub mod model;
pub(crate) mod nesting;
pub(crate) mod parser;
pub mod resolved_value;
pub mod resolver;
pub(crate) mod rules;
pub(crate) mod sam;
pub(crate) mod serialization;

pub use consts::PSEUDO_PARAMETERS;
pub use consts::{
    DEFAULT_ACCOUNT_ID, DEFAULT_PARTITION, DEFAULT_REGION, DEFAULT_STACK_NAME, DEFAULT_URL_SUFFIX, FORMAT_VERSION,
    MARKER_CONDITIONAL, MARKER_DYNAMIC, MARKER_ENUM, MARKER_IF_FALSE, MARKER_IF_TRUE, MARKER_INTRINSIC, MARKER_KIND,
    MARKER_PARAM_TYPE, MARKER_REF,
};
pub use ir::*;
pub use model::{ParseConfig, ParseResult, PseudoParameterOverrides, SemanticModel};

use diagnostics::{Diagnostic, Phase, RegisteredDiagnostic, SourceSpan};

pub(crate) fn make_parse_diagnostic(rule_id: &str, message: String, span: SourceSpan) -> Diagnostic {
    RegisteredDiagnostic::new(rule_id, message).location(span).phase(Phase::Parse).build()
}

/// Like [`make_parse_diagnostic`], but attaches the resource and property path
/// derived from a builder path such as `Resources/R/Properties/X/Fn::If`. A
/// structural defect anchored at a resource property carries the logical ID and
/// a dotted property path so it lands at the same location consumers expect;
/// paths outside `Resources/<id>/Properties/...` (e.g. `Conditions/...`) keep
/// the bare parse diagnostic.
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
    }
    builder.build()
}
