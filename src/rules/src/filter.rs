use log::warn;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::OnceLock;

/// Numeric range filter for rule IDs sharing a common letter prefix, matching an
/// inclusive span of the trailing numbers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm-bindings", tsify(from_wasm_abi))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct IdRange {
    pub prefix: String,
    pub start: u32,
    pub end: u32,
}

/// Suppress a rule for a specific logical resource ID. An absent `rule_id`
/// scopes the filter to every rule on that resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm-bindings", tsify(from_wasm_abi))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct ResourceIdFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "wasm-bindings", tsify(optional))]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub rule_id: Option<String>,
    pub resource_id: String,
}

/// Suppress a rule for a specific resource type. An absent `rule_id` scopes the
/// filter to every rule on that type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm-bindings", tsify(from_wasm_abi))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct ResourceTypeFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "wasm-bindings", tsify(optional))]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub rule_id: Option<String>,
    pub resource_type: String,
}

/// Suppress a rule for every resource belonging to a service — the
/// `service-provider::service-name` prefix of the resource type (its first two
/// `::`-delimited segments, for example `AWS::AutoScaling` in
/// `AWS::AutoScaling::LaunchConfiguration`, or `Alexa::ASK` in
/// `Alexa::ASK::Skill`). An absent `rule_id` scopes the filter to every rule on
/// that service.
///
/// The service string is compared verbatim against that prefix.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm-bindings", tsify(from_wasm_abi))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct ServiceFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "wasm-bindings", tsify(optional))]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub rule_id: Option<String>,
    pub service: String,
}

/// Filter criteria across seven dimensions: rule IDs, categories, ID ranges, regex
/// patterns, resource IDs, resource types, and services.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm-bindings", tsify(from_wasm_abi))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct RuleFilterConfig {
    #[serde(default)]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub ids: Vec<String>,
    #[serde(default)]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub categories: Vec<String>,
    #[serde(default)]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub id_ranges: Vec<IdRange>,
    #[serde(default)]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub id_patterns: Vec<String>,
    #[serde(default)]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub resource_ids: Vec<ResourceIdFilter>,
    #[serde(default)]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub resource_types: Vec<ResourceTypeFilter>,
    #[serde(default)]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub services: Vec<ServiceFilter>,
}

impl RuleFilterConfig {
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
            && self.categories.is_empty()
            && self.id_ranges.is_empty()
            && self.id_patterns.is_empty()
            && self.resource_ids.is_empty()
            && self.resource_types.is_empty()
            && self.services.is_empty()
    }

    fn matches(
        &self,
        rule_id: &str,
        category: Option<&str>,
        resource_id: Option<&str>,
        resource_type: Option<&str>,
        compiled: &CompiledPatterns,
    ) -> bool {
        if self.ids.iter().any(|id| id == rule_id) {
            return true;
        }
        if let Some(cat) = category
            && self.categories.iter().any(|c| c == cat)
        {
            return true;
        }
        if self.id_ranges.iter().any(|r| range_matches(rule_id, r)) {
            return true;
        }
        if compiled.matches(rule_id) {
            return true;
        }
        if let Some(rid) = resource_id
            && self.resource_ids.iter().any(|f| f.resource_id == rid && rule_scope_matches(&f.rule_id, rule_id))
        {
            return true;
        }
        if let Some(rtype) = resource_type {
            if self.resource_types.iter().any(|f| f.resource_type == rtype && rule_scope_matches(&f.rule_id, rule_id)) {
                return true;
            }
            if let Some(service) = service_prefix(rtype)
                && self.services.iter().any(|f| f.service == service && rule_scope_matches(&f.rule_id, rule_id))
            {
                return true;
            }
        }
        false
    }
}

/// A resource-scoped filter's optional `rule_id` matches a diagnostic when it is
/// absent (scoped to every rule) or equals the diagnostic's rule ID.
fn rule_scope_matches(scope: &Option<String>, rule_id: &str) -> bool {
    scope.as_deref().is_none_or(|id| id == rule_id)
}

/// The `service-provider::service-name` prefix of a resource type — its first two
/// `::`-delimited segments (for example `AWS::AutoScaling` in
/// `AWS::AutoScaling::LaunchConfiguration`), or `None` when the type has no second
/// segment or an empty service-name segment.
fn service_prefix(resource_type: &str) -> Option<&str> {
    // Resource types follow `service-provider::service-name::data-type-name`; the
    // service is everything up to (but excluding) the second `::`.
    let first = resource_type.find("::")?;
    let service_name = &resource_type[first + 2..];
    let second_relative = service_name.find("::")?;
    if second_relative == 0 {
        return None; // empty service-name segment (e.g. `AWS::::Widget`)
    }
    Some(&resource_type[..first + 2 + second_relative])
}

/// Include/exclude filter configuration for diagnostics.
///
/// If include filters are non-empty, a diagnostic must match at least one.
/// Any diagnostic matching an exclude filter is removed regardless.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FilterConfig {
    #[serde(default)]
    pub include: RuleFilterConfig,
    #[serde(default)]
    pub exclude: RuleFilterConfig,
    #[serde(skip)]
    compiled: OnceLock<CompiledFilters>,
}

impl Clone for FilterConfig {
    fn clone(&self) -> Self {
        FilterConfig { include: self.include.clone(), exclude: self.exclude.clone(), compiled: OnceLock::new() }
    }
}

impl FilterConfig {
    pub fn new(include: RuleFilterConfig, exclude: RuleFilterConfig) -> Self {
        FilterConfig { include, exclude, compiled: OnceLock::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.include.is_empty() && self.exclude.is_empty()
    }

    fn compiled(&self) -> &CompiledFilters {
        self.compiled.get_or_init(|| CompiledFilters {
            include: CompiledPatterns::new(&self.include.id_patterns),
            exclude: CompiledPatterns::new(&self.exclude.id_patterns),
        })
    }

    #[must_use]
    pub fn matches_rule(
        &self,
        rule_id: &str,
        category: Option<&str>,
        resource_id: Option<&str>,
        resource_type: Option<&str>,
    ) -> bool {
        let compiled = self.compiled();
        if !self.include.is_empty()
            && !self.include.matches(rule_id, category, resource_id, resource_type, &compiled.include)
        {
            return false;
        }
        if self.exclude.matches(rule_id, category, resource_id, resource_type, &compiled.exclude) {
            return false;
        }
        true
    }

    pub fn excluded_categories(&self) -> HashSet<&str> {
        let mut cats: HashSet<&str> = self.exclude.categories.iter().map(|s| s.as_str()).collect();
        for c in &self.include.categories {
            cats.remove(c.as_str());
        }
        cats
    }

    /// Every `id_patterns` entry (from either the include or exclude filter) that is not a valid
    /// regular expression. Callers should surface these rather than let them be silently discarded:
    /// a dropped include pattern in particular would otherwise filter out every diagnostic, because
    /// the include set is treated as non-empty yet matches nothing.
    #[must_use]
    pub fn invalid_patterns(&self) -> Vec<String> {
        let compiled = self.compiled();
        let mut invalid = compiled.include.invalid.clone();
        invalid.extend(compiled.exclude.invalid.iter().cloned());
        invalid
    }
}

#[derive(Debug)]
struct CompiledPatterns {
    regexes: Vec<Regex>,
    invalid: Vec<String>,
}

impl CompiledPatterns {
    fn new(patterns: &[String]) -> Self {
        let mut regexes = Vec::new();
        let mut invalid = Vec::new();
        for pattern in patterns {
            match Regex::new(pattern) {
                Ok(regex) => regexes.push(regex),
                Err(error) => {
                    warn!("Invalid rule-id filter pattern '{}': {}", pattern, error);
                    invalid.push(pattern.clone());
                }
            }
        }
        CompiledPatterns { regexes, invalid }
    }

    fn matches(&self, rule_id: &str) -> bool {
        self.regexes.iter().any(|r| r.is_match(rule_id))
    }
}

#[derive(Debug)]
struct CompiledFilters {
    include: CompiledPatterns,
    exclude: CompiledPatterns,
}

fn range_matches(rule_id: &str, range: &IdRange) -> bool {
    let Some(suffix) = rule_id.strip_prefix(&range.prefix) else {
        return false;
    };
    let Ok(num) = suffix.parse::<u32>() else {
        return false;
    };
    num >= range.start && num <= range.end
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_filter_matches_all_rules() {
        let f = FilterConfig::default();
        assert!(f.matches_rule("E3012", Some("schema"), None, None));
        assert!(f.matches_rule("W9037", Some("security"), Some("Bucket"), Some("AWS::S3::Bucket")));
    }

    #[test]
    fn include_by_id_accepts_matching_and_rejects_others() {
        let f = FilterConfig {
            include: RuleFilterConfig { ids: vec!["E3012".into()], ..Default::default() },
            ..Default::default()
        };
        assert!(f.matches_rule("E3012", Some("schema"), None, None));
        assert!(!f.matches_rule("E3013", Some("schema"), None, None));
    }

    #[test]
    fn exclude_by_id_rejects_matching_and_accepts_others() {
        let f = FilterConfig {
            exclude: RuleFilterConfig { ids: vec!["E3012".into()], ..Default::default() },
            ..Default::default()
        };
        assert!(!f.matches_rule("E3012", Some("schema"), None, None));
        assert!(f.matches_rule("E3013", Some("schema"), None, None));
    }

    #[test]
    fn include_by_category_accepts_matching_category_only() {
        let f = FilterConfig {
            include: RuleFilterConfig { categories: vec!["schema".into()], ..Default::default() },
            ..Default::default()
        };
        assert!(f.matches_rule("E3012", Some("schema"), None, None));
        assert!(!f.matches_rule("W9501", Some("security"), None, None));
    }

    #[test]
    fn exclude_by_category_rejects_matching_category() {
        let f = FilterConfig {
            exclude: RuleFilterConfig { categories: vec!["best-practice".into()], ..Default::default() },
            ..Default::default()
        };
        assert!(f.matches_rule("E3012", Some("schema"), None, None));
        assert!(!f.matches_rule("I9040", Some("best-practice"), None, None));
    }

    #[test]
    fn include_by_id_range_accepts_within_bounds_only() {
        let f = FilterConfig {
            include: RuleFilterConfig {
                id_ranges: vec![IdRange { prefix: "E".into(), start: 3000, end: 3099 }],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(f.matches_rule("E3012", Some("schema"), None, None));
        assert!(f.matches_rule("E3099", Some("schema"), None, None));
        assert!(!f.matches_rule("E3100", Some("schema"), None, None));
    }

    #[test]
    fn include_by_regex_matches_pattern() {
        let f = FilterConfig {
            include: RuleFilterConfig { id_patterns: vec!["^E3\\d{3}$".into()], ..Default::default() },
            ..Default::default()
        };
        assert!(f.matches_rule("E3012", Some("schema"), None, None));
        assert!(!f.matches_rule("W9037", Some("security"), None, None));
    }

    #[test]
    fn exclude_by_resource_id_suppresses_specific_resource() {
        let f = FilterConfig {
            exclude: RuleFilterConfig {
                resource_ids: vec![ResourceIdFilter { rule_id: Some("E3012".into()), resource_id: "MyBucket".into() }],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(!f.matches_rule("E3012", Some("schema"), Some("MyBucket"), Some("AWS::S3::Bucket")));
        assert!(f.matches_rule("E3012", Some("schema"), Some("OtherBucket"), Some("AWS::S3::Bucket")));
    }

    #[test]
    fn exclude_by_resource_id_without_rule_id_suppresses_every_rule_on_resource() {
        let f = FilterConfig {
            exclude: RuleFilterConfig {
                resource_ids: vec![ResourceIdFilter { rule_id: None, resource_id: "MyBucket".into() }],
                ..Default::default()
            },
            ..Default::default()
        };
        // Every rule on MyBucket is suppressed, regardless of rule id.
        assert!(!f.matches_rule("E3012", Some("schema"), Some("MyBucket"), Some("AWS::S3::Bucket")));
        assert!(!f.matches_rule("W3697", Some("best-practice"), Some("MyBucket"), Some("AWS::S3::Bucket")));
        // A different resource is untouched.
        assert!(f.matches_rule("E3012", Some("schema"), Some("OtherBucket"), Some("AWS::S3::Bucket")));
    }

    #[test]
    fn exclude_by_resource_type_suppresses_specific_type() {
        let f = FilterConfig {
            exclude: RuleFilterConfig {
                resource_types: vec![ResourceTypeFilter {
                    rule_id: Some("E3012".into()),
                    resource_type: "AWS::S3::Bucket".into(),
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(!f.matches_rule("E3012", Some("schema"), Some("B"), Some("AWS::S3::Bucket")));
        assert!(f.matches_rule("E3012", Some("schema"), Some("I"), Some("AWS::EC2::Instance")));
    }

    #[test]
    fn exclude_by_resource_type_without_rule_id_suppresses_every_rule_on_type() {
        let f = FilterConfig {
            exclude: RuleFilterConfig {
                resource_types: vec![ResourceTypeFilter { rule_id: None, resource_type: "AWS::S3::Bucket".into() }],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(!f.matches_rule("E3012", Some("schema"), Some("B"), Some("AWS::S3::Bucket")));
        assert!(!f.matches_rule("W9037", Some("security"), Some("B"), Some("AWS::S3::Bucket")));
        assert!(f.matches_rule("E3012", Some("schema"), Some("I"), Some("AWS::EC2::Instance")));
    }

    #[test]
    fn exclude_by_service_suppresses_one_rule_across_the_whole_service() {
        // Issue #37: silence W3697 for every AutoScaling resource without touching
        // the same rule on other services. The service is the fully qualified
        // `service-provider::service-name` prefix, e.g. `AWS::AutoScaling`.
        let f = FilterConfig {
            exclude: RuleFilterConfig {
                services: vec![ServiceFilter { rule_id: Some("W3697".into()), service: "AWS::AutoScaling".into() }],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(!f.matches_rule(
            "W3697",
            Some("best-practice"),
            Some("Lc"),
            Some("AWS::AutoScaling::LaunchConfiguration")
        ));
        assert!(!f.matches_rule(
            "W3697",
            Some("best-practice"),
            Some("Asg"),
            Some("AWS::AutoScaling::AutoScalingGroup")
        ));
        // A different rule on the same service still fires.
        assert!(f.matches_rule("E3012", Some("schema"), Some("Lc"), Some("AWS::AutoScaling::LaunchConfiguration")));
        // The same rule on a different service still fires.
        assert!(f.matches_rule("W3697", Some("best-practice"), Some("Q"), Some("AWS::SQS::Queue")));
    }

    #[test]
    fn exclude_by_service_without_rule_id_suppresses_every_rule_on_service() {
        let f = FilterConfig {
            exclude: RuleFilterConfig {
                services: vec![ServiceFilter { rule_id: None, service: "AWS::AutoScaling".into() }],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(!f.matches_rule(
            "W3697",
            Some("best-practice"),
            Some("Lc"),
            Some("AWS::AutoScaling::LaunchConfiguration")
        ));
        assert!(!f.matches_rule("E3012", Some("schema"), Some("Lc"), Some("AWS::AutoScaling::LaunchConfiguration")));
        assert!(f.matches_rule("E3012", Some("schema"), Some("Q"), Some("AWS::SQS::Queue")));
    }

    #[test]
    fn include_by_service_accepts_matching_service_only() {
        let f = FilterConfig {
            include: RuleFilterConfig {
                services: vec![ServiceFilter { rule_id: None, service: "AWS::AutoScaling".into() }],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(f.matches_rule(
            "W3697",
            Some("best-practice"),
            Some("Lc"),
            Some("AWS::AutoScaling::LaunchConfiguration")
        ));
        assert!(!f.matches_rule("W3697", Some("best-practice"), Some("Q"), Some("AWS::SQS::Queue")));
    }

    #[test]
    fn service_filter_requires_the_full_provider_and_service_prefix() {
        // The bare service segment does not match — the filter is the fully
        // qualified `service-provider::service-name` prefix, so `AutoScaling`
        // alone must not silence `AWS::AutoScaling::LaunchConfiguration`.
        let f = FilterConfig {
            exclude: RuleFilterConfig {
                services: vec![ServiceFilter { rule_id: None, service: "AutoScaling".into() }],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(f.matches_rule(
            "W3697",
            Some("best-practice"),
            Some("Lc"),
            Some("AWS::AutoScaling::LaunchConfiguration")
        ));
    }

    #[test]
    fn service_filter_matches_non_aws_provider_prefix() {
        // The prefix includes the provider, so a non-AWS provider is matched too.
        let f = FilterConfig {
            exclude: RuleFilterConfig {
                services: vec![ServiceFilter { rule_id: None, service: "Alexa::ASK".into() }],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(!f.matches_rule("E3012", Some("schema"), Some("S"), Some("Alexa::ASK::Skill")));
        assert!(f.matches_rule("E3012", Some("schema"), Some("Lc"), Some("AWS::AutoScaling::LaunchConfiguration")));
    }

    #[test]
    fn service_filter_matches_by_string_equality_on_the_prefix() {
        // Matching is pure string equality on the service prefix, so any prefix —
        // including a custom namespace — is honored as written.
        let f = FilterConfig {
            exclude: RuleFilterConfig {
                services: vec![ServiceFilter { rule_id: None, service: "AWS::MadeUpService".into() }],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(!f.matches_rule("E3012", Some("schema"), Some("R"), Some("AWS::MadeUpService::Widget")));
        assert!(f.matches_rule("E3012", Some("schema"), Some("R"), Some("Custom::MadeUpService::Thing")));
    }

    #[test]
    fn service_filter_does_not_match_when_resource_type_has_no_service_prefix() {
        let f = FilterConfig {
            exclude: RuleFilterConfig {
                services: vec![ServiceFilter { rule_id: None, service: "Bucket".into() }],
                ..Default::default()
            },
            ..Default::default()
        };
        // A single-segment type has no service prefix, so the service filter never matches it.
        assert!(f.matches_rule("E3012", Some("schema"), Some("R"), Some("Bucket")));
    }

    #[test]
    fn include_and_exclude_combined_applies_both() {
        let f = FilterConfig {
            include: RuleFilterConfig { categories: vec!["schema".into()], ..Default::default() },
            exclude: RuleFilterConfig { ids: vec!["E3012".into()], ..Default::default() },
            ..Default::default()
        };
        assert!(!f.matches_rule("E3012", Some("schema"), None, None));
        assert!(f.matches_rule("E3013", Some("schema"), None, None));
        assert!(!f.matches_rule("W9501", Some("security"), None, None));
    }

    #[test]
    fn excluded_categories_omits_categories_also_in_include() {
        let f = FilterConfig {
            exclude: RuleFilterConfig {
                categories: vec!["best-practice".into(), "schema".into()],
                ..Default::default()
            },
            include: RuleFilterConfig { categories: vec!["schema".into()], ..Default::default() },
            ..Default::default()
        };
        let cats = f.excluded_categories();
        assert!(cats.contains("best-practice"), "expected 'best-practice' in excluded categories");
        assert!(!cats.contains("schema"), "'schema' should not be in excluded categories");
    }

    #[test]
    fn invalid_regex_pattern_is_skipped_and_valid_patterns_still_match() {
        let f = FilterConfig {
            include: RuleFilterConfig { id_patterns: vec!["[invalid".into(), "^E3\\d+$".into()], ..Default::default() },
            ..Default::default()
        };
        assert!(f.matches_rule("E3012", Some("schema"), None, None));
    }

    #[test]
    fn invalid_patterns_are_reported_for_include_and_exclude() {
        let f = FilterConfig {
            include: RuleFilterConfig { id_patterns: vec!["[bad-include".into(), "^E3".into()], ..Default::default() },
            exclude: RuleFilterConfig { id_patterns: vec!["(bad-exclude".into()], ..Default::default() },
            ..Default::default()
        };
        let invalid = f.invalid_patterns();
        assert!(invalid.contains(&"[bad-include".to_string()));
        assert!(invalid.contains(&"(bad-exclude".to_string()));
        assert!(!invalid.contains(&"^E3".to_string()), "valid patterns must not be reported");
    }

    #[test]
    fn valid_patterns_report_no_invalid() {
        let f = FilterConfig {
            include: RuleFilterConfig { id_patterns: vec!["^E3\\d+$".into()], ..Default::default() },
            ..Default::default()
        };
        assert!(f.invalid_patterns().is_empty());
    }

    #[test]
    fn service_prefix_extracts_provider_and_service() {
        assert_eq!(service_prefix("AWS::AutoScaling::LaunchConfiguration"), Some("AWS::AutoScaling"));
        assert_eq!(service_prefix("AWS::S3::Bucket"), Some("AWS::S3"));
        assert_eq!(service_prefix("Alexa::ASK::Skill"), Some("Alexa::ASK"));
        // A subproperty type (four segments) still resolves to the same service prefix.
        assert_eq!(service_prefix("AWS::S3::Bucket::Tag"), Some("AWS::S3"));
    }

    #[test]
    fn service_prefix_none_without_a_second_segment_or_empty_service_name() {
        assert_eq!(service_prefix("Bucket"), None, "no `::` at all");
        assert_eq!(service_prefix("Custom::MyResource"), None, "only a provider segment, no data-type segment");
        assert_eq!(service_prefix("AWS::"), None, "provider then empty, no second `::`");
        assert_eq!(service_prefix("AWS::::Widget"), None, "empty service-name segment");
        assert_eq!(service_prefix(""), None);
    }

    #[test]
    fn cloned_filter_recompiles_patterns_and_matches() {
        let f = FilterConfig {
            include: RuleFilterConfig { id_patterns: vec!["^E3\\d+$".into()], ..Default::default() },
            ..Default::default()
        };
        assert!(f.matches_rule("E3012", Some("schema"), None, None));
        let f2 = f.clone();
        assert!(f2.matches_rule("E3012", Some("schema"), None, None));
    }
}
