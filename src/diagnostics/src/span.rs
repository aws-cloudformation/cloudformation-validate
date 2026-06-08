use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct SourceSpan {
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32,
}

pub const UNKNOWN_SPAN: SourceSpan = SourceSpan {
    start_line: u32::MAX,
    start_column: u32::MAX,
    end_line: u32::MAX,
    end_column: u32::MAX,
};

/// Resolves a section path to its source span. Implemented by `SemanticModel`.
pub trait SpanProvider {
    fn source_location(&self, path: &str) -> Option<SourceSpan>;
}
