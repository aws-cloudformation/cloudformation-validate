use serde::{Deserialize, Serialize};
use std::fmt;
use template_model::DefectPhase;

/// Validation pipeline phase a diagnostic originates from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Enum))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Phase {
    Parse,
    Schema,
    Lint,
}

impl Phase {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Phase::Parse => "parse",
            Phase::Schema => "schema",
            Phase::Lint => "lint",
        }
    }
}

impl From<DefectPhase> for Phase {
    fn from(phase: DefectPhase) -> Self {
        match phase {
            DefectPhase::Parse => Phase::Parse,
            DefectPhase::Lint => Phase::Lint,
        }
    }
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_str_returns_lowercase_for_all_variants() {
        assert_eq!(Phase::Parse.as_str(), "parse");
        assert_eq!(Phase::Schema.as_str(), "schema");
        assert_eq!(Phase::Lint.as_str(), "lint");
    }

    #[test]
    fn serde_round_trips_all_variants() {
        for phase in [Phase::Parse, Phase::Schema, Phase::Lint] {
            let json = serde_json::to_string(&phase).unwrap();
            let back: Phase = serde_json::from_str(&json).unwrap();
            assert_eq!(back, phase, "round-trip failed for {:?}", phase);
        }
    }

    #[test]
    fn serializes_as_screaming_snake_case() {
        assert_eq!(serde_json::to_string(&Phase::Lint).unwrap(), "\"LINT\"");
        assert_eq!(serde_json::to_string(&Phase::Parse).unwrap(), "\"PARSE\"");
        assert_eq!(serde_json::to_string(&Phase::Schema).unwrap(), "\"SCHEMA\"");
    }
}
