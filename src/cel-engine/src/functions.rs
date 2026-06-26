/// CEL custom functions for use in user-provided custom rules.
/// Built-in rules evaluate directly in Rust for performance;
/// these functions are only registered when custom CEL rules are loaded.
use cel_interpreter::{Context, Value};
use std::collections::HashMap;
use std::sync::Arc;
use template_model::SemanticModel;
use template_model::consts::{FIELD_PROPERTIES, FIELD_RESOURCES};
use template_model::resolved_value::contains_dynamic_resolved;
use template_model::resolver::ResolvedValue;

pub fn json_to_cel(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Int(i)
            } else if let Some(f) = n.as_f64() {
                Value::Float(f)
            } else {
                Value::Null
            }
        }
        serde_json::Value::String(s) => Value::String(Arc::new(s.clone())),
        serde_json::Value::Array(arr) => Value::from(arr.iter().map(json_to_cel).collect::<Vec<_>>()),
        serde_json::Value::Object(map) => {
            let hm: HashMap<String, Value> = map.iter().map(|(k, v)| (k.clone(), json_to_cel(v))).collect();
            Value::from(hm)
        }
    }
}

pub fn resolved_to_cel(rv: &ResolvedValue) -> Value {
    match rv {
        ResolvedValue::Concrete { value: v } => json_to_cel(v),
        ResolvedValue::List { items } => Value::from(items.iter().map(resolved_to_cel).collect::<Vec<_>>()),
        ResolvedValue::Map { entries } => {
            let hm: HashMap<String, Value> =
                entries.iter().map(|e| (e.key.clone(), resolved_to_cel(&e.value))).collect();
            Value::from(hm)
        }
        ResolvedValue::Enum { variants: vals } => {
            for v in vals {
                if let ResolvedValue::Concrete { value: c } = v {
                    return json_to_cel(c);
                }
            }
            Value::Null
        }
        ResolvedValue::Conditional { condition: _, if_true: t, if_false: _ } => resolved_to_cel(t),
        ResolvedValue::Reference { target, kind: _ } => Value::String(Arc::new(target.clone())),
        ResolvedValue::Dynamic { reason: _ } | ResolvedValue::TypedDynamic { reason: _, param_type: _ } => Value::Null,
    }
}

pub fn contains_unresolvable_content(rv: &ResolvedValue) -> bool {
    contains_dynamic_resolved(rv)
}

/// Builds a CEL evaluation context from the pre-resolved `input` JSON.
/// When `rid` is provided, binds `name`, `resource`, `properties`, and
/// `resolved_properties` for per-resource evaluation. `resolved_properties`
/// contains values converted via `resolved_to_cel`, giving custom CEL rules
/// access to clean resolved values.
pub fn build_custom_context(
    input: &serde_json::Value,
    rid: Option<&str>,
    model: Option<&SemanticModel>,
) -> Context<'static> {
    let mut ctx = Context::default();
    if let Some(obj) = input.as_object() {
        for (k, v) in obj {
            let _ = ctx.add_variable(k.as_str(), json_to_cel(v));
        }
    }
    if let Some(rid) = rid {
        let _ = ctx.add_variable("name", Value::String(Arc::new(rid.to_string())));
        if let Some(res) = input.get(FIELD_RESOURCES).and_then(|r| r.get(rid)) {
            let _ = ctx.add_variable("resource", json_to_cel(res));
            if let Some(props) = res.get(FIELD_PROPERTIES) {
                let _ = ctx.add_variable("properties", json_to_cel(props));
            }
        }
        if let Some(model) = model
            && let Some(res) = model.resources.get(rid)
        {
            let resolved: HashMap<String, Value> =
                res.properties.iter().map(|(k, v)| (k.clone(), resolved_to_cel(v))).collect();
            let _ = ctx.add_variable("resolved_properties", Value::from(resolved));
        }
    }
    ctx
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use template_model::SemanticModel;
    use template_model::resolver::{MapEntry, RefKind, ResolvedValue};

    #[test]
    fn json_null_to_cel() {
        assert_eq!(json_to_cel(&json!(null)), Value::Null);
    }

    #[test]
    fn json_bool_to_cel() {
        assert_eq!(json_to_cel(&json!(true)), Value::Bool(true));
        assert_eq!(json_to_cel(&json!(false)), Value::Bool(false));
    }

    #[test]
    fn json_int_to_cel() {
        assert_eq!(json_to_cel(&json!(42)), Value::Int(42));
    }

    #[test]
    fn json_float_to_cel() {
        assert_eq!(json_to_cel(&json!(3.14)), Value::Float(3.14));
    }

    #[test]
    fn json_string_to_cel() {
        assert_eq!(json_to_cel(&json!("hello")), Value::String(Arc::new("hello".into())));
    }

    #[test]
    fn json_array_to_cel() {
        let val = json_to_cel(&json!([1, "two"]));
        match val {
            Value::List(items) => {
                assert_eq!(items.len(), 2);
            }
            _ => panic!("Expected List, got {:?}", val),
        }
    }

    #[test]
    fn json_object_to_cel() {
        let val = json_to_cel(&json!({"key": "value"}));
        match val {
            Value::Map(ref _map) => {} // Map type is opaque; just verify variant
            _ => panic!("Expected Map, got {:?}", val),
        }
    }

    #[test]
    fn resolved_concrete_delegates_to_json_to_cel() {
        let rv = ResolvedValue::Concrete { value: json!(42).into() };
        assert_eq!(resolved_to_cel(&rv), Value::Int(42));
    }

    #[test]
    fn resolved_list_converts_items() {
        let rv = ResolvedValue::List {
            items: vec![
                ResolvedValue::Concrete { value: json!(1).into() },
                ResolvedValue::Concrete { value: json!(2).into() },
            ],
        };
        match resolved_to_cel(&rv) {
            Value::List(items) => assert_eq!(items.len(), 2),
            other => panic!("Expected List, got {:?}", other),
        }
    }

    #[test]
    fn resolved_map_converts_entries() {
        let rv = ResolvedValue::Map {
            entries: vec![MapEntry { key: "a".into(), value: ResolvedValue::Concrete { value: json!(1).into() } }],
        };
        match resolved_to_cel(&rv) {
            Value::Map(ref _map) => {} // Map type is opaque; just verify variant
            other => panic!("Expected Map, got {:?}", other),
        }
    }

    #[test]
    fn resolved_enum_picks_first_concrete() {
        let rv = ResolvedValue::Enum {
            variants: vec![
                ResolvedValue::Dynamic { reason: "ref".into() },
                ResolvedValue::Concrete { value: json!("picked").into() },
            ],
        };
        assert_eq!(resolved_to_cel(&rv), Value::String(Arc::new("picked".into())));
    }

    #[test]
    fn resolved_enum_all_dynamic_returns_null() {
        let rv = ResolvedValue::Enum { variants: vec![ResolvedValue::Dynamic { reason: "ref".into() }] };
        assert_eq!(resolved_to_cel(&rv), Value::Null);
    }

    #[test]
    fn resolved_reference_returns_target_string() {
        let rv = ResolvedValue::Reference { target: "MyBucket".into(), kind: RefKind::Ref };
        assert_eq!(resolved_to_cel(&rv), Value::String(Arc::new("MyBucket".into())));
    }

    #[test]
    fn resolved_dynamic_returns_null() {
        let rv = ResolvedValue::Dynamic { reason: "something".into() };
        assert_eq!(resolved_to_cel(&rv), Value::Null);
    }

    #[test]
    fn resolved_typed_dynamic_returns_null() {
        let rv = ResolvedValue::TypedDynamic { reason: "x".into(), param_type: "String".into() };
        assert_eq!(resolved_to_cel(&rv), Value::Null);
    }

    #[test]
    fn resolved_conditional_uses_true_branch() {
        let rv = ResolvedValue::Conditional {
            condition: "cond".into(),
            if_true: Box::new(ResolvedValue::Concrete { value: json!("yes").into() }),
            if_false: Box::new(ResolvedValue::Concrete { value: json!("no").into() }),
        };
        assert_eq!(resolved_to_cel(&rv), Value::String(Arc::new("yes".into())));
    }

    #[test]
    fn concrete_is_resolvable() {
        assert!(!contains_unresolvable_content(&ResolvedValue::Concrete { value: json!(1).into() }));
    }

    #[test]
    fn dynamic_is_unresolvable() {
        assert!(contains_unresolvable_content(&ResolvedValue::Dynamic { reason: "x".into() }));
    }

    #[test]
    fn build_context_without_resource_binds_top_level() {
        let input = json!({
            "resources": {"Bucket": {"properties": {"Name": "test"}}},
            "parameters": {}
        });
        let ctx = build_custom_context(&input, None, None);
        // Should not panic — variables are bound
        let prog = cel_interpreter::Program::compile("resources").unwrap();
        let result = prog.execute(&ctx);
        result.expect("executing 'resources' should succeed");
    }

    #[test]
    fn build_context_with_resource_binds_name_and_properties() {
        let input = json!({
            "resources": {
                "MyBucket": {
                    "properties": {"BucketName": "test-bucket"}
                }
            }
        });
        let ctx = build_custom_context(&input, Some("MyBucket"), None);
        let prog = cel_interpreter::Program::compile("name").unwrap();
        let result = prog.execute(&ctx).unwrap();
        assert_eq!(result, Value::String(Arc::new("MyBucket".into())));
    }

    #[test]
    fn build_context_with_missing_resource_still_binds_name() {
        let input = json!({"resources": {}});
        let ctx = build_custom_context(&input, Some("Missing"), None);
        let prog = cel_interpreter::Program::compile("name").unwrap();
        let result = prog.execute(&ctx).unwrap();
        assert_eq!(result, Value::String(Arc::new("Missing".into())));
    }

    #[test]
    fn build_context_with_model_binds_resolved_properties() {
        let model = SemanticModel::from_bytes(
            br#"
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-bucket
"#,
        )
        .unwrap();
        let input = serde_json::to_value(model.to_diagnostic_json()).unwrap();
        let ctx = build_custom_context(&input, Some("MyBucket"), Some(&model));
        let prog = cel_interpreter::Program::compile("resolved_properties.BucketName == 'my-bucket'").unwrap();
        let result = prog.execute(&ctx).unwrap();
        assert_eq!(result, Value::Bool(true), "resolved_properties should contain clean resolved values");
    }
}
