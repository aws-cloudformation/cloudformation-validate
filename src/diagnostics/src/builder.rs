use crate::diagnostic::{Diagnostic, Entity, RelatedResource};
use crate::phase::Phase;
use rules::lookup_rule;
use std::collections::HashMap;
use template_model::{ParseDefect, SourceSpan, span_to_option};

/// Builds a [`Diagnostic`] for a rule that is registered in the rule registry.
///
/// Severity, category, origin, and description are taken from the registry entry
/// for `rule_id` - this is the single place those four fields are sourced for
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
    entity: Option<Entity>,
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
            entity: None,
            property_path: None,
            location: None,
            suggested_fix: None,
            condition_scenario: None,
            phase: None,
            related_resources: None,
        }
    }

    /// Attaches the offending resource as the targeted entity: its logical ID
    /// and, when known, its CloudFormation type. An empty ID is dropped so
    /// callers can pass through an ID that may be blank - mirrors
    /// [`property_path`](Self::property_path).
    pub fn resource(mut self, resource_id: impl Into<String>, resource_type: Option<String>) -> Self {
        self.entity = Entity::resource(resource_id, resource_type);
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

    /// Sets the source span. [`UNKNOWN_SPAN`](template_model::UNKNOWN_SPAN) is
    /// treated as "no location".
    pub fn location(mut self, span: SourceSpan) -> Self {
        self.location = span_to_option(span);
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
            entity: self.entity,
            property_path: self.property_path,
            suggested_fix: self.suggested_fix,
            documentation_url: None,
            category: Some(definition.category.as_str().into()),
            location: self.location,
            related_resources: self.related_resources,
            condition_scenario: self.condition_scenario,
            rule_description: Some(definition.description.into()),
            phase: self.phase,
            context: None,
            source: definition.origin,
        }
    }
}

/// Converts a parse-time defect from the template model into a full
/// [`Diagnostic`], sourcing severity, category, origin, and description from
/// the rule registry. This is the single boundary where the model's plain
/// findings acquire reporting metadata; like [`RegisteredDiagnostic::build`],
/// it panics if the defect's rule ID is not registered.
pub fn diagnostic_from_parse_defect(defect: &ParseDefect) -> Diagnostic {
    let mut builder = RegisteredDiagnostic::new(defect.rule_id.clone(), defect.message.clone()).location(defect.span);
    if let Some(resource_id) = &defect.resource_id {
        builder = builder.resource(resource_id.clone(), None);
    }
    if let Some(property_path) = &defect.property_path {
        builder = builder.property_path(property_path.clone());
    }
    if let Some(phase) = defect.phase {
        builder = builder.phase(phase.into());
    }
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rules::Severity;
    use template_model::{DefectPhase, UNKNOWN_SPAN};

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

        let entity = diagnostic.entity.expect("entity should be set");
        assert_eq!(entity.logical_id, "MyBucket");
        assert_eq!(entity.entity_type, template_model::EntityType::Resource);
        assert_eq!(entity.resource_type.as_deref(), Some("AWS::S3::Bucket"));
        assert_eq!(diagnostic.property_path.as_deref(), Some("Properties.BucketName"));
    }

    #[test]
    fn empty_resource_id_yields_no_entity() {
        let diagnostic = RegisteredDiagnostic::new("F0001", "msg").resource("", None).build();
        assert!(diagnostic.entity.is_none(), "an empty resource ID must not create an entity");
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

    #[test]
    fn parse_defect_conversion_carries_anchors_and_registry_metadata() {
        let span = SourceSpan { start_line: 7, start_column: 3, end_line: 7, end_column: 9 };
        let defect = ParseDefect::new("F0001", "Resources section missing")
            .location(span)
            .resource("MyBucket")
            .property_path("Properties.BucketName")
            .phase(DefectPhase::Parse);

        let diagnostic = diagnostic_from_parse_defect(&defect);
        assert_eq!(diagnostic.rule_id, "F0001");
        assert_eq!(diagnostic.severity, Severity::Fatal, "severity sourced from the registry");
        assert_eq!(diagnostic.location, Some(span));
        assert_eq!(diagnostic.entity.as_ref().map(|e| e.logical_id.as_str()), Some("MyBucket"));
        assert_eq!(diagnostic.property_path.as_deref(), Some("Properties.BucketName"));
        assert_eq!(diagnostic.phase, Some(Phase::Parse));
    }

    #[test]
    fn parse_defect_conversion_leaves_unset_fields_absent() {
        let defect = ParseDefect::new("F0001", "msg").location(UNKNOWN_SPAN);
        let diagnostic = diagnostic_from_parse_defect(&defect);
        assert_eq!(diagnostic.location, None, "UNKNOWN_SPAN must map to no location");
        assert!(diagnostic.entity.is_none());
        assert_eq!(diagnostic.property_path, None);
        assert_eq!(diagnostic.phase, None, "an unset phase is derived downstream");
    }

    #[test]
    fn lint_stage_defects_convert_to_the_lint_phase() {
        let defect = ParseDefect::new("F3004", "cycle").phase(DefectPhase::Lint);
        assert_eq!(diagnostic_from_parse_defect(&defect).phase, Some(Phase::Lint));
    }
}
