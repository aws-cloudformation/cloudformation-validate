use crate::diagnostic::{Diagnostic, RelatedResource, ResourceRef};
use crate::phase::Phase;
use crate::span::{SourceSpan, UNKNOWN_SPAN};
use rules::lookup_rule;
use std::collections::HashMap;

/// Builds a [`Diagnostic`] for a rule that is registered in the rule registry.
///
/// Severity, category, origin, and description are taken from the registry entry
/// for `rule_id` — this is the single place those four fields are sourced for
/// built-in diagnostics, so every built-in finding is consistent regardless of
/// which crate produced it. [`build`](Self::build) panics if the rule is not
/// registered, turning an unregistered built-in rule into a loud failure instead
/// of a silently inconsistent diagnostic.
///
/// Custom and Guard rules are intentionally absent from the registry; they carry
/// their own severity, category, and origin from the parsed rule definition and
/// must construct diagnostics directly rather than through this builder.
#[must_use = "RegisteredDiagnostic does nothing until `build` is called"]
pub struct RegisteredDiagnostic {
    rule_id: String,
    message: String,
    resource: Option<ResourceRef>,
    property_path: Option<String>,
    location: Option<SourceSpan>,
    suggested_fix: Option<String>,
    condition_scenario: Option<HashMap<String, bool>>,
    phase: Option<Phase>,
    related_resources: Option<Vec<RelatedResource>>,
}

impl RegisteredDiagnostic {
    /// Starts a diagnostic for `rule_id` carrying `message`. All other fields
    /// default to absent and are added through the builder methods.
    pub fn new(rule_id: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            rule_id: rule_id.into(),
            message: message.into(),
            resource: None,
            property_path: None,
            location: None,
            suggested_fix: None,
            condition_scenario: None,
            phase: None,
            related_resources: None,
        }
    }

    /// Attaches the offending resource: its logical ID and, when known, its
    /// CloudFormation type.
    pub fn resource(mut self, resource_id: impl Into<String>, resource_type: Option<String>) -> Self {
        self.resource = Some(ResourceRef { id: Some(resource_id.into()), resource_type });
        self
    }

    /// Records the property path within the resource. An empty path is ignored
    /// so callers can pass through a path that may be blank.
    pub fn property_path(mut self, property_path: impl Into<String>) -> Self {
        let path = property_path.into();
        if !path.is_empty() {
            self.property_path = Some(path);
        }
        self
    }

    /// Sets the source span. [`UNKNOWN_SPAN`] is treated as "no location".
    pub fn location(mut self, span: SourceSpan) -> Self {
        self.location = if span == UNKNOWN_SPAN { None } else { Some(span) };
        self
    }

    /// Sets an optional suggested fix.
    pub fn suggested_fix(mut self, suggested_fix: Option<impl Into<String>>) -> Self {
        self.suggested_fix = suggested_fix.map(Into::into);
        self
    }

    /// Sets the condition scenario under which the diagnostic applies.
    pub fn condition_scenario(mut self, condition_scenario: Option<HashMap<String, bool>>) -> Self {
        self.condition_scenario = condition_scenario;
        self
    }

    /// Pins the pipeline phase. When left unset, downstream enrichment derives
    /// the phase from the rule's severity.
    pub fn phase(mut self, phase: Phase) -> Self {
        self.phase = Some(phase);
        self
    }

    /// Attaches related resource references (cross-resource findings).
    pub fn related_resources(mut self, related_resources: Option<Vec<RelatedResource>>) -> Self {
        self.related_resources = related_resources;
        self
    }

    /// Assembles the [`Diagnostic`], sourcing severity, category, origin, and
    /// description from the rule registry. Panics if `rule_id` is not registered.
    pub fn build(self) -> Diagnostic {
        let definition =
            lookup_rule(&self.rule_id).unwrap_or_else(|| panic!("Rule '{}' not found in RULE_REGISTRY", self.rule_id));
        Diagnostic {
            rule_id: self.rule_id,
            severity: definition.severity(),
            message: self.message,
            resource: self.resource,
            property_path: self.property_path,
            suggested_fix: self.suggested_fix,
            documentation_url: None,
            category: Some(definition.category.as_str().into()),
            location: self.location,
            related_resources: self.related_resources,
            condition_scenario: self.condition_scenario,
            rule_description: Some(definition.description.into()),
            phase: self.phase,
            section: None,
            context: None,
            source: definition.origin,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rules::Severity;

    #[test]
    fn build_sources_severity_category_origin_and_description_from_registry() {
        let definition = lookup_rule("E3012").expect("E3012 is registered");
        let diagnostic = RegisteredDiagnostic::new("E3012", "Type mismatch").build();

        assert_eq!(diagnostic.rule_id, "E3012");
        assert_eq!(diagnostic.severity, Severity::Error, "severity derived from the E prefix via the registry");
        assert_eq!(
            diagnostic.category.as_deref(),
            Some(definition.category.as_str()),
            "category taken from the registry entry"
        );
        assert_eq!(diagnostic.source, definition.origin, "origin taken from the registry entry");
        assert!(diagnostic.rule_description.is_some(), "description taken from the registry entry");
    }

    #[test]
    fn fatal_severity_is_derived_for_f_prefixed_rules() {
        let diagnostic = RegisteredDiagnostic::new("F0001", "Resources section missing").build();
        assert_eq!(diagnostic.severity, Severity::Fatal);
    }

    #[test]
    fn resource_and_property_path_are_attached_when_present() {
        let diagnostic = RegisteredDiagnostic::new("E3012", "msg")
            .resource("MyBucket", Some("AWS::S3::Bucket".into()))
            .property_path("Properties.BucketName")
            .build();

        let resource = diagnostic.resource.expect("resource should be set");
        assert_eq!(resource.id.as_deref(), Some("MyBucket"));
        assert_eq!(resource.resource_type.as_deref(), Some("AWS::S3::Bucket"));
        assert_eq!(diagnostic.property_path.as_deref(), Some("Properties.BucketName"));
    }

    #[test]
    fn empty_property_path_is_dropped() {
        let diagnostic = RegisteredDiagnostic::new("F0001", "msg").property_path("").build();
        assert_eq!(diagnostic.property_path, None, "an empty property path must not be recorded");
    }

    #[test]
    fn unknown_span_becomes_no_location() {
        let diagnostic = RegisteredDiagnostic::new("F0001", "msg").location(UNKNOWN_SPAN).build();
        assert_eq!(diagnostic.location, None, "UNKNOWN_SPAN must map to no location");
    }

    #[test]
    fn known_span_is_preserved() {
        let span = SourceSpan { start_line: 3, start_column: 1, end_line: 3, end_column: 9 };
        let diagnostic = RegisteredDiagnostic::new("F0001", "msg").location(span).build();
        assert_eq!(diagnostic.location, Some(span));
    }

    #[test]
    fn phase_is_pinned_when_set() {
        let diagnostic = RegisteredDiagnostic::new("F0001", "msg").phase(Phase::Parse).build();
        assert_eq!(diagnostic.phase, Some(Phase::Parse));
    }

    #[test]
    #[should_panic(expected = "not found in RULE_REGISTRY")]
    fn build_panics_for_unregistered_rule() {
        let _ = RegisteredDiagnostic::new("Z9999", "unregistered").build();
    }
}
