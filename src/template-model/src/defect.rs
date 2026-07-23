//! Parse-time findings emitted while building the semantic model.
//!
//! A [`ParseDefect`] is plain data: a rule ID, a message, and locating anchors.
//! It deliberately carries no severity, category, or origin — those are rule
//! metadata that downstream reporting layers source from the rule registry when
//! they convert defects into full diagnostics. This keeps the template model a
//! leaf crate with no knowledge of the reporting vocabulary.

use crate::consts;
use crate::span::{SourceSpan, UNKNOWN_SPAN};

/// The pipeline stage a defect belongs to, for downstream phase attribution.
///
/// Most defects are found while parsing and resolving the template
/// ([`DefectPhase::Parse`]). Findings produced by whole-template analysis over
/// the finished model — such as reference-cycle detection — belong to the lint
/// stage ([`DefectPhase::Lint`]). A defect may also leave the phase unset, in
/// which case downstream enrichment derives it from the rule's severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefectPhase {
    Parse,
    Lint,
}

/// A finding produced while parsing a template and building the semantic model.
///
/// Field semantics mirror the diagnostic they are converted into downstream:
/// `span` is [`UNKNOWN_SPAN`] when no source location is known, and the
/// optional anchors attribute the defect to a named template entity.
#[derive(Debug, Clone, PartialEq)]
pub struct ParseDefect {
    /// Registry rule ID of the check this defect belongs to.
    pub rule_id: String,
    pub message: String,
    /// Source location, or [`UNKNOWN_SPAN`] when none has been resolved yet.
    pub span: SourceSpan,
    /// Logical ID of the resource (or output pseudo-resource) the defect is
    /// anchored to, when it targets one.
    pub resource_id: Option<String>,
    /// Slash- or dot-separated path locating the defect within the template.
    pub property_path: Option<String>,
    /// Pipeline stage attribution; `None` lets downstream enrichment derive it.
    pub phase: Option<DefectPhase>,
}

impl ParseDefect {
    /// Starts a defect for `rule_id` carrying `message`. All anchors default to
    /// absent and are added through the builder-style methods below.
    pub fn new(rule_id: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            rule_id: rule_id.into(),
            message: message.into(),
            span: UNKNOWN_SPAN,
            resource_id: None,
            property_path: None,
            phase: None,
        }
    }

    /// Sets the source span.
    #[must_use]
    pub fn location(mut self, span: SourceSpan) -> Self {
        self.span = span;
        self
    }

    /// Anchors the defect to a resource logical ID. An empty ID is dropped so
    /// callers can pass through an ID that may be blank.
    #[must_use]
    pub fn resource(mut self, resource_id: impl Into<String>) -> Self {
        let id = resource_id.into();
        if !id.is_empty() {
            self.resource_id = Some(id);
        }
        self
    }

    /// Records the property path. An empty path is ignored so callers can pass
    /// through a path that may be blank.
    #[must_use]
    pub fn property_path(mut self, property_path: impl Into<String>) -> Self {
        let path = property_path.into();
        if !path.is_empty() {
            self.property_path = Some(path);
        }
        self
    }

    /// Pins the pipeline stage the defect belongs to.
    #[must_use]
    pub fn phase(mut self, phase: DefectPhase) -> Self {
        self.phase = Some(phase);
        self
    }

    /// Whether this defect represents a fatal structural failure. Built-in rule
    /// IDs encode severity in their prefix letter, and this crate assigns every
    /// parse rule ID, so the prefix is authoritative here.
    #[must_use]
    pub fn is_fatal(&self) -> bool {
        self.rule_id.starts_with('F')
    }

    /// Logical ID of the resource the defect is anchored to, when it targets one.
    #[must_use]
    pub fn resource_logical_id(&self) -> Option<&str> {
        self.resource_id.as_deref()
    }
}

/// A parse-time defect anchored to a specific resource (or output pseudo-
/// resource), so consumers and the accuracy comparison can key it by resource id
/// the same way an engine-emitted resource diagnostic would.
pub(crate) fn make_parse_defect_for_resource(
    rule_id: &str,
    message: String,
    span: SourceSpan,
    resource_id: &str,
) -> ParseDefect {
    ParseDefect::new(rule_id, message).location(span).resource(resource_id).phase(DefectPhase::Parse)
}

pub(crate) fn make_parse_defect(rule_id: &str, message: String, span: SourceSpan) -> ParseDefect {
    ParseDefect::new(rule_id, message).location(span).phase(DefectPhase::Parse)
}

/// Like [`make_parse_defect`], but attaches a locating anchor derived from a
/// builder path such as `Resources/R/Properties/X/Fn::If` or
/// `Conditions/C/Fn::And`. A resource-property defect carries the logical ID and a
/// dotted property path so it lands where consumers expect. Defects in other
/// sections (`Conditions`, `Outputs`, …) carry the build path itself as the
/// property path, so that when the exact node has no byte span yet, downstream
/// span resolution can walk up to the nearest enclosing element (the named
/// condition/output) instead of leaving the defect unlocated.
pub(crate) fn make_parse_defect_at(rule_id: &str, message: String, span: SourceSpan, build_path: &str) -> ParseDefect {
    let mut defect = ParseDefect::new(rule_id, message).location(span).phase(DefectPhase::Parse);
    let segments: Vec<&str> = build_path.split('/').collect();
    if segments.len() >= 4
        && segments[0] == consts::SECTION_RESOURCES
        && matches!(segments[2], consts::KEY_PROPERTIES | consts::SECTION_METADATA)
    {
        defect = defect.resource(segments[1]);
        defect = defect.property_path(segments[2..].join("."));
    } else if segments.len() >= 2 {
        // Non-resource section (e.g. Conditions/<name>/Fn::And): keep the full
        // slash path so span resolution can walk up to the enclosing element.
        defect = defect.property_path(build_path);
    }
    defect
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_resource_id_and_property_path_are_dropped() {
        let defect = ParseDefect::new("F0001", "msg").resource("").property_path("");
        assert_eq!(defect.resource_id, None, "an empty resource ID must not create an anchor");
        assert_eq!(defect.property_path, None, "an empty property path must not be recorded");
    }

    #[test]
    fn is_fatal_follows_the_rule_id_prefix() {
        assert!(ParseDefect::new("F8600", "msg").is_fatal());
        assert!(!ParseDefect::new("E0001", "msg").is_fatal());
        assert!(!ParseDefect::new("W1103", "msg").is_fatal());
    }

    #[test]
    fn make_parse_defect_at_splits_resource_property_paths() {
        let defect = make_parse_defect_at("F1032", "msg".into(), UNKNOWN_SPAN, "Resources/R/Properties/X/Fn::If");
        assert_eq!(defect.resource_id.as_deref(), Some("R"));
        assert_eq!(defect.property_path.as_deref(), Some("Properties.X.Fn::If"));
        assert_eq!(defect.phase, Some(DefectPhase::Parse));
    }

    #[test]
    fn make_parse_defect_at_keeps_non_resource_paths_verbatim() {
        let defect = make_parse_defect_at("E8005", "msg".into(), UNKNOWN_SPAN, "Conditions/C/Fn::And");
        assert_eq!(defect.resource_id, None);
        assert_eq!(defect.property_path.as_deref(), Some("Conditions/C/Fn::And"));
    }
}
