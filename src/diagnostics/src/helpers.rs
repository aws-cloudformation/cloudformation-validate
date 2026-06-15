use rules::{RuleOrigin, section_for_rule_id};

use crate::span::{SourceSpan, SpanProvider, UNKNOWN_SPAN};

pub const SAM_TRANSFORM_ERROR_RULE_ID: &str = "E0001";

/// Message prefix shared by every SAM transform-error diagnostic, regardless
/// of which engine produced it. The pipeline gates non-transform diagnostics
/// on this prefix because a failed SAM transform stops CloudFormation before
/// resource validation.
pub const SAM_TRANSFORM_ERROR_PREFIX: &str = "Error transforming template:";

/// Returns `true` when `message` belongs to a SAM transform-error diagnostic.
pub fn is_sam_transform_error_message(message: &str) -> bool {
    message.starts_with(SAM_TRANSFORM_ERROR_PREFIX)
}

/// Looks up the `RuleOrigin` for a rule ID from the registry.
/// Panics if the rule is not registered — every built-in rule must be in the registry.
/// For custom/guard rules (not in the registry), callers must set `source` directly.
pub fn source_for_rule(rule_id: &str) -> RuleOrigin {
    rules::lookup_rule(rule_id).unwrap_or_else(|| panic!("Rule '{}' not found in RULE_REGISTRY", rule_id)).origin
}

/// Maps a rule ID to its template section (via `section_for_rule_id`) and
/// looks up the span through the given `SpanProvider`. Returns `UNKNOWN_SPAN`
/// if the rule has no associated section or the section has no span.
pub fn resolve_section_span(rule_id: &str, span_provider: &dyn SpanProvider) -> SourceSpan {
    match section_for_rule_id(None, rule_id) {
        Some(section) => span_provider.source_location(section).unwrap_or(UNKNOWN_SPAN),
        None => UNKNOWN_SPAN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeSpanProvider {
        known_section: &'static str,
        span: SourceSpan,
    }

    impl SpanProvider for FakeSpanProvider {
        fn source_location(&self, path: &str) -> Option<SourceSpan> {
            if path == self.known_section { Some(self.span) } else { None }
        }
    }

    struct EmptySpanProvider;
    impl SpanProvider for EmptySpanProvider {
        fn source_location(&self, _path: &str) -> Option<SourceSpan> {
            None
        }
    }

    #[test]
    fn resolve_section_span_returns_span_when_section_and_provider_match() {
        let expected = SourceSpan { start_line: 5, start_column: 0, end_line: 10, end_column: 0 };
        let provider = FakeSpanProvider { known_section: "Resources", span: expected };

        let result = resolve_section_span("F0001", &provider);
        assert_eq!(result, expected);
    }

    #[test]
    fn resolve_section_span_returns_unknown_when_provider_has_no_match() {
        let provider = EmptySpanProvider;
        let result = resolve_section_span("F0001", &provider);
        assert_eq!(result, UNKNOWN_SPAN);
    }

    #[test]
    fn resolve_section_span_returns_unknown_for_unmapped_rule() {
        let provider = FakeSpanProvider {
            known_section: "Resources",
            span: SourceSpan { start_line: 1, start_column: 0, end_line: 1, end_column: 0 },
        };
        let result = resolve_section_span("ZZZZZ", &provider);
        assert_eq!(result, UNKNOWN_SPAN);
    }
}
