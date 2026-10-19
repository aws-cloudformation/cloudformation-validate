use crate::SemanticModel;
use crate::resolver::ResolvedValue;
use std::collections::{BTreeSet, HashMap};

const EVENT_PATTERN_RESOURCE_TYPES: [&str; 2] = ["AWS::Events::Rule", "AWS::Events::Archive"];
const EVENT_PATTERN_PROPERTY_PATH: &str = "Properties.EventPattern";
const EVENT_PATTERN_ROOT_LABEL: &str = "EventPattern";
const OR_KEY: &str = "$or";

const PREFIX_OPERATOR: &str = "prefix";
const SUFFIX_OPERATOR: &str = "suffix";
const ANYTHING_BUT_OPERATOR: &str = "anything-but";
const NUMERIC_OPERATOR: &str = "numeric";
const EXISTS_OPERATOR: &str = "exists";
const CIDR_OPERATOR: &str = "cidr";
const WILDCARD_OPERATOR: &str = "wildcard";
const EQUALS_IGNORE_CASE_OPERATOR: &str = "equals-ignore-case";

const NUMERIC_COMPARISONS: [&str; 5] = ["<", "<=", "=", ">=", ">"];
const ANYTHING_BUT_NESTED_OPERATORS: [&str; 4] =
    [PREFIX_OPERATOR, SUFFIX_OPERATOR, WILDCARD_OPERATOR, EQUALS_IGNORE_CASE_OPERATOR];
const CONSECUTIVE_WILDCARDS: &str = "**";

const UNKNOWN_OPERATOR_FIX: &str =
    "Use one of prefix, suffix, anything-but, numeric, exists, cidr, wildcard or equals-ignore-case";
const NUMERIC_COMPARISON_FIX: &str = "Use <, <=, =, >= or >";
const ANYTHING_BUT_FIX: &str =
    "Give anything-but a value, an array of values, or an object using prefix, suffix, wildcard or equals-ignore-case";
const EXISTS_FIX: &str = "Set exists to an unquoted true or false";
const WILDCARD_FIX: &str = "Separate literal characters with a single *";
const OR_SIBLINGS_FIX: &str = "Move the sibling keys into each $or branch";
const EMPTY_ARRAY_FIX: &str = "Give the key at least one value, or remove the key";
const SCALAR_VALUE_FIX: &str = "Wrap the value in an array";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EventPatternViolation {
    pub resource_id: String,
    pub message: String,
    pub suggested_fix: String,
}

/// Event patterns that EventBridge rejects when the rule or archive is created.
///
/// A pattern is skipped when any part of it comes from a parameter the caller can
/// still override, and parts the model cannot resolve (references, conditional
/// values, deploy-time strings) are never judged.
#[must_use]
pub fn event_pattern_violations(model: &SemanticModel) -> Vec<EventPatternViolation> {
    let mut violations = BTreeSet::new();
    for resource_type in EVENT_PATTERN_RESOURCE_TYPES {
        for resource_id in model.resources_of_type(resource_type) {
            if model.scenario_uses_unresolved_parameter(resource_id, EVENT_PATTERN_PROPERTY_PATH, &HashMap::new()) {
                continue;
            }
            let Some(pattern) = model.resolve(resource_id, EVENT_PATTERN_PROPERTY_PATH) else {
                continue;
            };
            let mut findings = Vec::new();
            match pattern {
                ResolvedValue::Concrete { value } if value.0.is_string() => {
                    if let Some(parsed) = value.0.as_str().and_then(|text| serde_json::from_str(text).ok()) {
                        check_pattern_root(PatternValue::Json(&parsed), &mut findings);
                    }
                }
                _ => check_pattern_root(PatternValue::Resolved(pattern), &mut findings),
            }
            violations.extend(findings.into_iter().map(|(message, suggested_fix)| EventPatternViolation {
                resource_id: resource_id.clone(),
                message,
                suggested_fix,
            }));
        }
    }
    violations.into_iter().collect()
}

#[derive(Clone, Copy)]
enum PatternValue<'a> {
    Json(&'a serde_json::Value),
    Resolved(&'a ResolvedValue),
}

enum PatternShape<'a> {
    Object(Vec<(&'a str, PatternValue<'a>)>),
    Array(Vec<PatternValue<'a>>),
    Scalar(&'a serde_json::Value),
    Unknown,
}

impl<'a> PatternValue<'a> {
    fn shape(self) -> PatternShape<'a> {
        match self {
            PatternValue::Json(serde_json::Value::Object(entries)) => PatternShape::Object(
                entries.iter().map(|(key, value)| (key.as_str(), PatternValue::Json(value))).collect(),
            ),
            PatternValue::Json(serde_json::Value::Array(items)) => {
                PatternShape::Array(items.iter().map(PatternValue::Json).collect())
            }
            PatternValue::Json(serde_json::Value::Null) => PatternShape::Unknown,
            PatternValue::Json(scalar) => PatternShape::Scalar(scalar),
            PatternValue::Resolved(ResolvedValue::Concrete { value }) => PatternValue::Json(&value.0).shape(),
            PatternValue::Resolved(ResolvedValue::Map { entries }) => PatternShape::Object(
                entries.iter().map(|entry| (entry.key.as_str(), PatternValue::Resolved(&entry.value))).collect(),
            ),
            PatternValue::Resolved(ResolvedValue::List { items }) => {
                PatternShape::Array(items.iter().map(PatternValue::Resolved).collect())
            }
            // A conditional branch or deploy-time value is only known once the stack is created.
            PatternValue::Resolved(
                ResolvedValue::Enum { .. }
                | ResolvedValue::Conditional { .. }
                | ResolvedValue::Reference { .. }
                | ResolvedValue::Dynamic { .. }
                | ResolvedValue::TypedDynamic { .. },
            ) => PatternShape::Unknown,
        }
    }
}

type Finding = (String, String);

fn check_pattern_root(pattern: PatternValue<'_>, findings: &mut Vec<Finding>) {
    if let PatternShape::Object(entries) = pattern.shape() {
        check_pattern_object(EVENT_PATTERN_ROOT_LABEL, &entries, findings);
    }
}

/// Objects in a pattern are either nested field selectors or `$or` branches; arrays
/// hold the values to match, where an object element is a matcher such as
/// `{"prefix": "a"}` and is never read as another field selector.
fn check_pattern_object(location: &str, entries: &[(&str, PatternValue<'_>)], findings: &mut Vec<Finding>) {
    if entries.iter().any(|(key, _)| *key == OR_KEY) && entries.len() > 1 {
        let mut sibling_keys: Vec<&str> = entries.iter().map(|(key, _)| *key).filter(|key| *key != OR_KEY).collect();
        sibling_keys.sort_unstable();
        findings.push((
            format!("$or in '{location}' cannot share its object with {}", sibling_keys.join(", ")),
            OR_SIBLINGS_FIX.to_string(),
        ));
    }
    for (key, value) in entries {
        let field_location = format!("{location}.{key}");
        if *key == OR_KEY {
            check_or_branches(&field_location, *value, findings);
            continue;
        }
        match value.shape() {
            PatternShape::Object(nested) => check_pattern_object(&field_location, &nested, findings),
            PatternShape::Array(items) => check_match_values(&field_location, &items, findings),
            PatternShape::Scalar(_) => findings
                .push((format!("'{field_location}' must be an array or an object"), SCALAR_VALUE_FIX.to_string())),
            PatternShape::Unknown => {}
        }
    }
}

fn check_or_branches(location: &str, branches: PatternValue<'_>, findings: &mut Vec<Finding>) {
    let PatternShape::Array(branches) = branches.shape() else {
        return;
    };
    for (index, branch) in branches.iter().enumerate() {
        if let PatternShape::Object(entries) = branch.shape() {
            check_pattern_object(&format!("{location}[{index}]"), &entries, findings);
        }
    }
}

fn check_match_values(location: &str, match_values: &[PatternValue<'_>], findings: &mut Vec<Finding>) {
    if match_values.is_empty() {
        findings.push((format!("'{location}' is an empty array"), EMPTY_ARRAY_FIX.to_string()));
    }
    for match_value in match_values {
        if let PatternShape::Object(operators) = match_value.shape() {
            for (operator, operand) in operators {
                check_matcher_operator(location, operator, operand, findings);
            }
        }
    }
}

fn check_matcher_operator(location: &str, operator: &str, operand: PatternValue<'_>, findings: &mut Vec<Finding>) {
    let operand_shape = operand.shape();
    match operator {
        PREFIX_OPERATOR | SUFFIX_OPERATOR => {
            let is_string_or_object = match &operand_shape {
                PatternShape::Scalar(scalar) => scalar.is_string(),
                PatternShape::Object(_) | PatternShape::Unknown => true,
                PatternShape::Array(_) => false,
            };
            if !is_string_or_object {
                findings.push((
                    format!("{operator} in '{location}' must be a string or an equals-ignore-case object"),
                    format!("Give {operator} a string value"),
                ));
            }
        }
        EXISTS_OPERATOR => {
            let is_boolean = match &operand_shape {
                PatternShape::Scalar(scalar) => scalar.is_boolean(),
                PatternShape::Unknown => true,
                PatternShape::Object(_) | PatternShape::Array(_) => false,
            };
            if !is_boolean {
                findings.push((format!("exists in '{location}' must be true or false"), EXISTS_FIX.to_string()));
            }
        }
        NUMERIC_OPERATOR => {
            if let PatternShape::Array(bounds) = operand_shape {
                for bound in bounds {
                    if let PatternShape::Scalar(serde_json::Value::String(comparison)) = bound.shape()
                        && !NUMERIC_COMPARISONS.contains(&comparison.as_str())
                    {
                        findings.push((
                            format!("'{comparison}' in '{location}' is not a numeric comparison operator"),
                            NUMERIC_COMPARISON_FIX.to_string(),
                        ));
                    }
                }
            }
        }
        ANYTHING_BUT_OPERATOR => {
            if let PatternShape::Object(nested) = operand_shape {
                for (nested_operator, _) in nested {
                    if !ANYTHING_BUT_NESTED_OPERATORS.contains(&nested_operator) {
                        findings.push((
                            format!("anything-but in '{location}' cannot use '{nested_operator}'"),
                            ANYTHING_BUT_FIX.to_string(),
                        ));
                    }
                }
            }
        }
        WILDCARD_OPERATOR => {
            if let PatternShape::Scalar(serde_json::Value::String(wildcard)) = operand_shape
                && wildcard.contains(CONSECUTIVE_WILDCARDS)
            {
                findings.push((
                    format!("wildcard '{wildcard}' in '{location}' has consecutive wildcard characters"),
                    WILDCARD_FIX.to_string(),
                ));
            }
        }
        CIDR_OPERATOR | EQUALS_IGNORE_CASE_OPERATOR => {}
        unknown_operator => findings.push((
            format!("'{unknown_operator}' in '{location}' is not an event pattern operator"),
            UNKNOWN_OPERATOR_FIX.to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn messages(event_pattern_yaml: &str) -> Vec<String> {
        let template = format!(
            "Resources:\n  Rule:\n    Type: AWS::Events::Rule\n    Properties:\n      EventPattern: {event_pattern_yaml}\n"
        );
        let model = SemanticModel::from_bytes(template.as_bytes()).expect("template parses");
        event_pattern_violations(&model).into_iter().map(|violation| violation.message).collect()
    }

    #[test]
    fn matcher_objects_are_not_read_as_field_selectors() {
        assert!(messages(r#"{"detail": {"x": [{"prefix": "a"}, {"anything-but": {"prefix": "b"}}]}}"#).is_empty());
    }

    #[test]
    fn nested_field_selectors_are_checked_at_any_depth() {
        assert_eq!(
            messages(r#"{"detail": {"a": {"b": {"c": {"d": "plain"}}}}}"#),
            vec!["'EventPattern.detail.a.b.c.d' must be an array or an object"]
        );
    }

    #[test]
    fn or_branches_are_checked_as_field_selectors() {
        assert_eq!(
            messages(r#"{"$or": [{"source": ["a"]}, {"detail-type": []}]}"#),
            vec!["'EventPattern.$or[1].detail-type' is an empty array"]
        );
    }

    #[test]
    fn json_string_pattern_is_parsed_before_checking() {
        assert_eq!(
            messages(r#"'{"source": [{"startsWith": "aws."}]}'"#),
            vec!["'startsWith' in 'EventPattern.source' is not an event pattern operator"]
        );
    }

    #[test]
    fn pattern_from_overridable_parameter_is_not_judged() {
        let template = r#"
Parameters:
  Pattern:
    Type: String
    Default: '{"source": "aws.ec2"}'
Resources:
  Rule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern: !Ref Pattern
"#;
        let model = SemanticModel::from_bytes(template.as_bytes()).expect("template parses");
        let findings = event_pattern_violations(&model);
        assert!(findings.is_empty(), "a caller can override the parameter before deployment: {findings:?}");
    }

    #[test]
    fn unparseable_json_string_pattern_is_not_judged() {
        assert!(messages("'not json'").is_empty());
    }
}
