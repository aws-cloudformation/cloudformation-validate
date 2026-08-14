use serde_json::Value;
use template_model::{
    AMI_ID_PATTERN, AVAILABILITY_ZONE_PATTERN, CAA_RECORD_PATTERN, IAM_ROLE_ARN_PATTERN, MX_RECORD_PATTERN,
    SECURITY_GROUP_NAME_PATTERN, compile_pattern,
};

/// Collect every string value stored under a `"pattern"` key anywhere in the JSON tree.
fn collect_patterns(node: &Value, out: &mut Vec<String>) {
    match node {
        Value::Object(map) => {
            for (key, value) in map {
                if key == "pattern"
                    && let Value::String(pattern) = value
                {
                    out.push(pattern.clone());
                } else {
                    collect_patterns(value, out);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_patterns(item, out);
            }
        }
        _ => {}
    }
}

fn patterns_from(bytes: &[u8]) -> Vec<String> {
    let root: Value = serde_json::from_slice(bytes).expect("embedded data is valid JSON");
    let mut patterns = Vec::new();
    collect_patterns(&root, &mut patterns);
    patterns
}

#[test]
fn every_shipped_schema_pattern_compiles() {
    let mut patterns = patterns_from(&data_source::embedded::COMPILED_SCHEMAS_BYTES);
    patterns.extend(patterns_from(&data_source::embedded::EXTENSIONS_BYTES));
    assert!(!patterns.is_empty(), "expected to find schema patterns to check");

    let uncompilable: Vec<&String> = patterns.iter().filter(|pattern| compile_pattern(pattern).is_none()).collect();

    assert!(
        uncompilable.is_empty(),
        "{} shipped schema pattern(s) cannot be compiled by template_model::compile_pattern and would have \
         their constraint silently dropped; add the necessary normalization in template_model::pattern:\n{}",
        uncompilable.len(),
        uncompilable.iter().take(20).map(|p| format!("  - {p}")).collect::<Vec<_>>().join("\n")
    );
}

#[test]
fn shared_handwritten_patterns_compile() {
    for pattern in [
        AMI_ID_PATTERN,
        AVAILABILITY_ZONE_PATTERN,
        CAA_RECORD_PATTERN,
        IAM_ROLE_ARN_PATTERN,
        MX_RECORD_PATTERN,
        SECURITY_GROUP_NAME_PATTERN,
    ] {
        assert!(compile_pattern(pattern).is_some(), "shared pattern must compile: {pattern}");
    }
}
