use serde_json::Value;
use std::collections::BTreeSet;

/// Wraps `value` in single quotes: `foo` becomes `'foo'`.
///
/// This is the single convention for surfacing an identifier, property name, or
/// literal inside a message. It never emits double quotes, so the rendered
/// message survives JSON serialization without `\"` escaping.
pub fn quote(value: impl AsRef<str>) -> String {
    format!("'{}'", value.as_ref())
}

/// Renders a JSON value for display inside a message.
///
/// Strings are single-quoted; numbers, booleans, and null render as their bare
/// literal. Arrays and objects recurse so their nested strings are single-quoted
/// too, unlike `serde_json::to_string`, which would emit double quotes and force
/// `\"` escaping in the final JSON report.
pub fn render_value(value: &Value) -> String {
    match value {
        Value::String(s) => quote(s),
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::Array(items) => render_value_list(items),
        Value::Object(map) => {
            let entries =
                map.iter().map(|(k, v)| format!("{}: {}", quote(k), render_value(v))).collect::<Vec<_>>().join(", ");
            format!("{{{}}}", entries)
        }
    }
}

/// Renders a slice of JSON values as a bracketed list, e.g. `['a', 'b']` or
/// `[1, 2]`, with each element formatted by [`render_value`].
pub fn render_value_list(values: &[Value]) -> String {
    format!("[{}]", values.iter().map(render_value).collect::<Vec<_>>().join(", "))
}

/// Renders a sequence of string-like items as a single-quoted, bracketed list,
/// e.g. `['Enabled', 'Suspended']`. Use this for enum candidates, valid
/// attribute names, and other lists of plain strings.
pub fn render_str_list<I, S>(items: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let rendered = items.into_iter().map(|item| quote(item.as_ref())).collect::<Vec<_>>().join(", ");
    format!("[{}]", rendered)
}

const S3_BUCKET_POLICY_RESOURCE_TYPE: &str = "AWS::S3::BucketPolicy";
const S3_BUCKET_IDENTIFIER_PROPERTY: &str = "Bucket";

/// Describes resources whose authored primary identifiers resolve to the same
/// physical resource. Bucket policies receive target-oriented wording because
/// their identifier names the bucket they modify rather than a resource they create.
pub fn primary_identifier_conflict_message(
    resource_type: &str,
    identifier_properties: &[String],
    identifier_values: &[String],
    resource_ids: &BTreeSet<String>,
) -> String {
    let rendered_resources = render_string_set(resource_ids);
    if resource_type == S3_BUCKET_POLICY_RESOURCE_TYPE
        && identifier_properties.first().is_some_and(|property| property == S3_BUCKET_IDENTIFIER_PROPERTY)
        && identifier_properties.len() == 1
        && identifier_values.len() == 1
    {
        return format!(
            "Only one {S3_BUCKET_POLICY_RESOURCE_TYPE} resource can target a given bucket; resources {rendered_resources} all target bucket {}",
            quote(&identifier_values[0])
        );
    }

    let rendered_identifier = render_primary_identifier(identifier_properties, identifier_values);
    format!(
        "Primary identifiers {rendered_identifier} should have unique values across the resources {rendered_resources}"
    )
}

fn render_primary_identifier(identifier_properties: &[String], identifier_values: &[String]) -> String {
    let entries = identifier_properties
        .iter()
        .zip(identifier_values)
        .map(|(property, value)| format!("{}: {}", quote(property), quote(value)))
        .collect::<Vec<_>>()
        .join(", ");
    format!("{{{entries}}}")
}

fn render_string_set(values: &BTreeSet<String>) -> String {
    let rendered = values.iter().map(quote).collect::<Vec<_>>().join(", ");
    format!("{{{rendered}}}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn quote_wraps_in_single_quotes() {
        assert_eq!(quote("foo"), "'foo'");
        assert_eq!(quote(String::from("bar")), "'bar'");
    }

    #[test]
    fn render_value_single_quotes_strings() {
        assert_eq!(render_value(&json!("hello")), "'hello'");
    }

    #[test]
    fn render_value_renders_scalars_bare() {
        assert_eq!(render_value(&json!(42)), "42");
        assert_eq!(render_value(&json!(3.5)), "3.5");
        assert_eq!(render_value(&json!(true)), "true");
        assert_eq!(render_value(&json!(null)), "null");
    }

    #[test]
    fn render_value_array_uses_single_quotes_not_double() {
        let rendered = render_value(&json!(["a", "b"]));
        assert_eq!(rendered, "['a', 'b']");
        assert!(!rendered.contains('"'), "rendered list must not contain double quotes");
    }

    #[test]
    fn render_value_object_uses_single_quotes() {
        let rendered = render_value(&json!({"BucketName": "shared"}));
        assert_eq!(rendered, "{'BucketName': 'shared'}");
        assert!(!rendered.contains('"'));
    }

    #[test]
    fn render_value_nested_mixed_types() {
        assert_eq!(render_value(&json!([1, "two", true])), "[1, 'two', true]");
    }

    #[test]
    fn render_value_list_matches_render_value_of_array() {
        let values = vec![json!("x"), json!("y")];
        assert_eq!(render_value_list(&values), "['x', 'y']");
    }

    #[test]
    fn render_str_list_single_quotes_each_item() {
        assert_eq!(render_str_list(["Enabled", "Suspended"]), "['Enabled', 'Suspended']");
        assert_eq!(render_str_list(Vec::<String>::new()), "[]");
    }

    #[test]
    fn bucket_policy_conflict_message_explains_the_shared_target() {
        let properties = vec!["Bucket".to_string()];
        let values = vec!["Ref(\"SharedBucket\")".to_string()];
        let resources = BTreeSet::from(["FirstPolicy".to_string(), "SecondPolicy".to_string()]);

        let message = primary_identifier_conflict_message("AWS::S3::BucketPolicy", &properties, &values, &resources);

        assert_eq!(
            message,
            "Only one AWS::S3::BucketPolicy resource can target a given bucket; resources {'FirstPolicy', 'SecondPolicy'} all target bucket 'Ref(\"SharedBucket\")'"
        );
    }

    #[test]
    fn non_bucket_policy_conflict_message_preserves_generic_wording() {
        let properties = vec!["BucketName".to_string()];
        let values = vec!["shared".to_string()];
        let resources = BTreeSet::from(["FirstBucket".to_string(), "SecondBucket".to_string()]);

        let message = primary_identifier_conflict_message("AWS::S3::Bucket", &properties, &values, &resources);

        assert_eq!(
            message,
            "Primary identifiers {'BucketName': 'shared'} should have unique values across the resources {'FirstBucket', 'SecondBucket'}"
        );
    }
}
