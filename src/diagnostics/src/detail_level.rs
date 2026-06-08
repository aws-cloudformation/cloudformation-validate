use serde::{Deserialize, Serialize};

/// Controls the level of detail in validation output.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm-bindings", tsify(from_wasm_abi))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Enum))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DetailLevel {
    /// Flattened diagnostics without violation context.
    Standard,
    /// Includes violation context with actual values, constraints, and resolution sources.
    #[default]
    Detailed,
}

impl DetailLevel {
    /// Whether diagnostics should be enriched with metadata (section, phase, category).
    pub fn needs_enrichment(&self) -> bool {
        matches!(self, DetailLevel::Detailed)
    }

    /// Whether this detail level requires violation context to be populated.
    pub fn needs_context(&self) -> bool {
        matches!(self, DetailLevel::Detailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_detailed() {
        assert_eq!(DetailLevel::default(), DetailLevel::Detailed);
    }

    #[test]
    fn standard_skips_context_and_enrichment() {
        assert!(!DetailLevel::Standard.needs_context());
        assert!(!DetailLevel::Standard.needs_enrichment());
    }

    #[test]
    fn detailed_requires_context_and_enrichment() {
        assert!(DetailLevel::Detailed.needs_context());
        assert!(DetailLevel::Detailed.needs_enrichment());
    }
}
