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
    DEFAULT_ACCOUNT_ID, DEFAULT_PARTITION, DEFAULT_REGION, DEFAULT_STACK_NAME, DEFAULT_URL_SUFFIX,
    FORMAT_VERSION, MARKER_CONDITIONAL, MARKER_DYNAMIC, MARKER_ENUM, MARKER_IF_FALSE,
    MARKER_IF_TRUE, MARKER_INTRINSIC, MARKER_KIND, MARKER_PARAM_TYPE, MARKER_REF,
};
pub use ir::*;
pub use model::{ParseConfig, ParseResult, PseudoParameterOverrides, SemanticModel};

pub(crate) fn make_parse_diagnostic(
    rule_id: &str,
    severity: rules_crate::Severity,
    message: String,
    span: diagnostics::SourceSpan,
) -> diagnostics::Diagnostic {
    diagnostics::Diagnostic {
        rule_id: rule_id.into(),
        severity,
        message,
        resource: None,
        property_path: None,
        suggested_fix: None,
        documentation_url: None,
        category: Some(rules_crate::Category::Structure.as_str().into()),
        phase: Some(diagnostics::Phase::Parse),
        source: diagnostics::source_for_rule(rule_id),
        location: if span == diagnostics::UNKNOWN_SPAN {
            None
        } else {
            Some(span)
        },
        related_resources: None,
        condition_scenario: None,
        rule_description: None,
        section: None,
        context: None,
    }
}
