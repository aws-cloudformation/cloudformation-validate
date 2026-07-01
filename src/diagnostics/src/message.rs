use serde_json::Value;

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
}
