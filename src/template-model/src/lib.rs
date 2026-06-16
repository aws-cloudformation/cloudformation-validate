#[cfg(feature = "uniffi-bindings")]
uniffi::setup_scaffolding!();

pub mod coercion;
pub mod conditions;
pub mod consts;
pub mod diagnostic;
pub(crate) mod graph;
pub mod ir;
pub mod model;
pub mod aws_regions;
pub(crate) mod condition_shape;
pub(crate) mod intrinsic_arg_shapes;
pub(crate) mod nesting;
pub(crate) mod parser;
pub mod resolved_value;
pub mod resolver;
pub(crate) mod rules;
pub(crate) mod sam;
pub(crate) mod serialization;
pub(crate) mod transform_expansion;
pub(crate) mod lang_ext_shapes;

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
