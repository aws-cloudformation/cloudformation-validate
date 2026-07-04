use log::debug;
use rules::FilterConfig;

/// Trait for types that can be filtered by rule ID, category, resource ID, or resource type.
pub trait Filterable {
    fn rule_id(&self) -> &str;
    fn category(&self) -> Option<&str>;
    fn resource_id(&self) -> Option<&str>;
    fn resource_type(&self) -> Option<&str>;
}

/// Remove diagnostics that do not pass the include/exclude filter configuration.
pub fn apply_filters<T: Filterable>(diagnostics: &mut Vec<T>, filters: &FilterConfig) {
    if filters.is_empty() {
        return;
    }
    let before = diagnostics.len();
    diagnostics.retain(|d| filters.matches_rule(d.rule_id(), d.category(), d.resource_id(), d.resource_type()));
    let removed = before - diagnostics.len();
    if removed > 0 {
        debug!("Filters removed {} diagnostics ({} -> {})", removed, before, diagnostics.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rules::{ResourceTypeFilter, RuleFilterConfig};

    struct TestDiagnostic {
        rule_id: String,
        category: Option<String>,
        resource_id: Option<String>,
        resource_type: Option<String>,
    }

    impl Filterable for TestDiagnostic {
        fn rule_id(&self) -> &str {
            &self.rule_id
        }
        fn category(&self) -> Option<&str> {
            self.category.as_deref()
        }
        fn resource_id(&self) -> Option<&str> {
            self.resource_id.as_deref()
        }
        fn resource_type(&self) -> Option<&str> {
            self.resource_type.as_deref()
        }
    }

    fn diag(rule_id: &str, category: &str) -> TestDiagnostic {
        TestDiagnostic {
            rule_id: rule_id.into(),
            category: Some(category.into()),
            resource_id: None,
            resource_type: None,
        }
    }

    fn diag_with_resource(rule_id: &str, category: &str, rid: &str, rtype: &str) -> TestDiagnostic {
        TestDiagnostic {
            rule_id: rule_id.into(),
            category: Some(category.into()),
            resource_id: Some(rid.into()),
            resource_type: Some(rtype.into()),
        }
    }

    #[test]
    fn apply_filters_removes_excluded_diagnostics() {
        let filters = FilterConfig::new(
            RuleFilterConfig::default(),
            RuleFilterConfig { ids: vec!["E3012".into()], ..Default::default() },
        );
        let mut diagnostics = vec![diag("E3012", "schema"), diag("W9037", "security"), diag("E3013", "schema")];
        apply_filters(&mut diagnostics, &filters);
        let ids: Vec<&str> = diagnostics.iter().map(|d| d.rule_id()).collect();
        assert_eq!(ids, vec!["W9037", "E3013"]);
    }

    #[test]
    fn apply_filters_is_noop_when_filters_empty() {
        let filters = FilterConfig::default();
        let mut diagnostics = vec![diag("E3012", "schema"), diag("W9037", "security")];
        apply_filters(&mut diagnostics, &filters);
        assert_eq!(diagnostics.len(), 2);
    }

    #[test]
    fn apply_filters_excludes_by_resource_type() {
        let filters = FilterConfig::new(
            RuleFilterConfig::default(),
            RuleFilterConfig {
                resource_types: vec![ResourceTypeFilter {
                    rule_id: Some("E3012".into()),
                    resource_type: "AWS::S3::Bucket".into(),
                }],
                ..Default::default()
            },
        );
        let mut diagnostics = vec![
            diag_with_resource("E3012", "schema", "MyBucket", "AWS::S3::Bucket"),
            diag_with_resource("E3012", "schema", "MyInstance", "AWS::EC2::Instance"),
        ];
        apply_filters(&mut diagnostics, &filters);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].resource_type(), Some("AWS::EC2::Instance"));
    }
}
