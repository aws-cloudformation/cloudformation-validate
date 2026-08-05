//! CloudFormation stringifies all scalar values before sending them to resource
//! handlers, so `512` and `"512"` are equivalent. YAML 1.1 also parses `yes`/`no`
//! as booleans. These helpers implement the same loose type semantics so that
//! constraint checks (min/max, enum, pattern, length) work on coerced values.

use serde_json::Value;

pub fn coerce_to_number(val: &Value) -> Option<f64> {
    match val {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse::<f64>().ok(),
        _ => None,
    }
}

pub fn coerce_to_integer(val: &Value) -> Option<i64> {
    match val {
        Value::Number(n) => n.as_i64().or_else(|| {
            let f = n.as_f64()?;
            if f.fract() == 0.0 && f >= i64::MIN as f64 && f <= i64::MAX as f64 { Some(f as i64) } else { None }
        }),
        Value::String(s) => coerce_str_to_integer(s),
        _ => None,
    }
}

/// The string arm of [`coerce_to_integer`], for callers that hold a scalar
/// outside a `serde_json::Value` (such as the parser's `ParseValue` values).
pub fn coerce_str_to_integer(s: &str) -> Option<i64> {
    let s = s.trim();
    s.parse::<i64>().ok().or_else(|| {
        let f = s.parse::<f64>().ok()?;
        if f.fract() == 0.0 && f >= i64::MIN as f64 && f <= i64::MAX as f64 { Some(f as i64) } else { None }
    })
}

pub fn coerce_to_string(val: &Value) -> Option<String> {
    match val {
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(if *b { "true" } else { "false" }.into()),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(i.to_string())
            } else {
                Some(n.to_string())
            }
        }
        _ => None,
    }
}

/// Accepts YAML 1.1 boolean strings in addition to native bools.
///
/// CloudFormation uses a YAML 1.1 parser which treats `yes`/`no`/`on`/`off`
/// (and their case variants) as booleans. This function matches that behavior
/// so that schema validation doesn't reject values the service would accept.
///
/// Only the three standard YAML 1.1 casings are accepted per variant
/// (lowercase, Titlecase, UPPERCASE). Non-spec casings like `"yEs"` are rejected.
pub fn coerce_to_bool(val: &Value) -> Option<bool> {
    match val {
        Value::Bool(b) => Some(*b),
        Value::String(s) => match s.as_str() {
            "true" | "True" | "TRUE" | "yes" | "Yes" | "YES" | "on" | "On" | "ON" | "y" | "Y" | "1" => Some(true),
            "false" | "False" | "FALSE" | "no" | "No" | "NO" | "off" | "Off" | "OFF" | "n" | "N" | "0" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// The text of a value written as a string or an integer, or `None` for every
/// other shape.
///
/// A non-integer number (e.g. `80.0`), a boolean, `null`, and composites yield
/// `None`, so a caller comparing or classifying written sizes never matches on a
/// value CloudFormation would not accept in that position. An integer-valued
/// float such as `80.0` is deliberately excluded — the value counts only when
/// written as an integer or a string.
///
/// This is the single definition of that notion. Both rule engines use it (the
/// Rego engine through a builtin of the same name), so a value classifies
/// identically no matter which engine evaluates the rule.
pub fn coerce_string_or_integer_to_string(val: &Value) -> Option<String> {
    match val {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => n.as_i64().map(|i| i.to_string()).or_else(|| n.as_u64().map(|u| u.to_string())),
        _ => None,
    }
}

/// Stringify a value for port-style comparison, accepting only string and
/// integer scalars.
///
/// Some rules compare port-like values (host/container ports, target-group
/// ports) by their string form — a quoted `"80"` and an unquoted `80` are the
/// same port. Only strings and integers participate: a non-integer number
/// (e.g. `80.0`), a boolean, or a composite is not a valid port form and yields
/// `None` so the comparison is skipped rather than matched on a coerced value.
/// An integer-valued float such as `80.0` is deliberately excluded — the value
/// is only treated as a port when written as an integer or a string.
pub fn coerce_port_to_string(val: &Value) -> Option<String> {
    coerce_string_or_integer_to_string(val)
}

/// Whether two values are equal under CloudFormation's loose scalar semantics.
///
/// CloudFormation stringifies scalar values before comparison, so `512` and
/// `"512"`, or `true` and `"true"`, are equal. Numeric scalars compare
/// numerically when either operand is a native number, so `30`, `30.0`, and
/// `"30.0"` are all the same value — an integral float must never mismatch its
/// integer form just because they stringify differently. Two string operands
/// keep exact string comparison. Non-scalar values have no coercion, so
/// distinct arrays/objects/nulls never collapse together — only native
/// equality can make them match.
pub fn scalar_eq(a: &Value, b: &Value) -> bool {
    if a == b {
        return true;
    }
    if (a.is_number() || b.is_number())
        && let (Some(na), Some(nb)) = (coerce_to_number(a), coerce_to_number(b))
    {
        return na == nb;
    }
    match (coerce_to_string(a), coerce_to_string(b)) {
        (Some(sa), Some(sb)) => sa == sb,
        _ => false,
    }
}

/// Check if a value is compatible with the expected JSON Schema type using
/// CFN's loose semantics.
///
/// - `"string"`: anything except object/array/null
/// - `"integer"`: anything parseable as a whole number (not bool)
/// - `"number"`: anything parseable as a number (not bool)
/// - `"boolean"`: native bool or YAML 1.1 boolean strings (true/false/yes/no/on/off/y/n/1/0 with standard casings)
/// - `"object"`, `"array"`, `"null"`: strict native type only
pub fn type_compatible(val: &Value, expected: &str) -> bool {
    match expected {
        // Type CHECK is strict: integer/boolean are NOT type "string".
        // Coercion for constraint evaluation uses coerce_to_string separately.
        "string" => val.is_string(),
        "integer" => {
            if val.is_boolean() {
                return false;
            }
            coerce_to_integer(val).is_some()
        }
        "number" => {
            if val.is_boolean() {
                return false;
            }
            coerce_to_number(val).is_some()
        }
        "boolean" => coerce_to_bool(val).is_some(),
        "object" => val.is_object(),
        "array" => val.is_array(),
        "null" => val.is_null(),
        _ => false,
    }
}

/// Result of attempting to coerce a JSON value to match an expected schema type.
#[derive(Debug, Clone, PartialEq)]
pub enum CoerceResult {
    /// Value already matches the expected type — no coercion needed.
    AlreadyCorrect,
    /// Value was coerced to the expected type. Contains the coerced value and
    /// a human-readable description of the conversion (e.g. "string to integer").
    Coerced(Value, String),
    /// Value cannot be coerced to the expected type.
    Failed,
}

/// Attempt to coerce a JSON value to match the expected schema type.
///
/// Returns `AlreadyCorrect` if the native type matches, `Coerced` with the
/// converted value if CloudFormation would silently accept the mismatch, or
/// `Failed` if the types are incompatible.
pub fn coerce_value(val: &Value, expected: &str) -> CoerceResult {
    let native_match = match expected {
        "string" => val.is_string(),
        "integer" => {
            val.is_i64() || val.is_u64() || (val.is_f64() && val.as_f64().map(|f| f.fract() == 0.0).unwrap_or(false))
        }
        "number" | "double" | "float" => val.is_number(),
        "boolean" => val.is_boolean(),
        "object" => val.is_object(),
        "array" => val.is_array(),
        "null" => val.is_null(),
        _ => return CoerceResult::Failed,
    };
    if native_match {
        return CoerceResult::AlreadyCorrect;
    }

    match expected {
        "string" => coerce_to_string(val)
            .map(|s| {
                let from = if val.is_boolean() { "boolean" } else { "number" };
                CoerceResult::Coerced(Value::String(s), format!("{from} to string"))
            })
            .unwrap_or(CoerceResult::Failed),
        "integer" => {
            if val.is_boolean() {
                return CoerceResult::Failed;
            }
            coerce_to_integer(val)
                .map(|i| CoerceResult::Coerced(Value::Number(i.into()), "string to integer".into()))
                .unwrap_or(CoerceResult::Failed)
        }
        "number" | "double" | "float" => {
            if val.is_boolean() {
                return CoerceResult::Failed;
            }
            coerce_to_number(val)
                .and_then(|f| {
                    serde_json::Number::from_f64(f)
                        .map(|n| CoerceResult::Coerced(Value::Number(n), "string to number".into()))
                })
                .unwrap_or(CoerceResult::Failed)
        }
        "boolean" => coerce_to_bool(val)
            .map(|b| CoerceResult::Coerced(Value::Bool(b), "string to boolean".into()))
            .unwrap_or(CoerceResult::Failed),
        _ => CoerceResult::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn coerce_to_number_from_string() {
        assert_eq!(coerce_to_number(&json!("512")), Some(512.0));
        assert_eq!(coerce_to_number(&json!("3.14")), Some(3.14));
        assert_eq!(coerce_to_number(&json!(" 42 ")), Some(42.0));
        assert_eq!(coerce_to_number(&json!("abc")), None);
        assert_eq!(coerce_to_number(&json!("")), None);
    }

    #[test]
    fn coerce_to_number_from_number() {
        assert_eq!(coerce_to_number(&json!(512)), Some(512.0));
        assert_eq!(coerce_to_number(&json!(3.14)), Some(3.14));
    }

    #[test]
    fn coerce_to_number_rejects_non_scalars() {
        assert_eq!(coerce_to_number(&json!(true)), None);
        assert_eq!(coerce_to_number(&json!(null)), None);
        assert_eq!(coerce_to_number(&json!([1])), None);
        assert_eq!(coerce_to_number(&json!({"a": 1})), None);
    }

    #[test]
    fn coerce_to_integer_from_string() {
        assert_eq!(coerce_to_integer(&json!("512")), Some(512));
        assert_eq!(coerce_to_integer(&json!("3.0")), Some(3));
        assert_eq!(coerce_to_integer(&json!("3.5")), None);
        assert_eq!(coerce_to_integer(&json!("abc")), None);
    }

    #[test]
    fn coerce_to_string_from_bool() {
        assert_eq!(coerce_to_string(&json!(true)), Some("true".into()));
        assert_eq!(coerce_to_string(&json!(false)), Some("false".into()));
    }

    #[test]
    fn coerce_to_string_from_number() {
        assert_eq!(coerce_to_string(&json!(512)), Some("512".into()));
    }

    #[test]
    fn coerce_to_string_rejects_complex() {
        assert_eq!(coerce_to_string(&json!(null)), None);
        assert_eq!(coerce_to_string(&json!([1])), None);
        assert_eq!(coerce_to_string(&json!({"a": 1})), None);
    }

    #[test]
    fn coerce_to_bool_from_string() {
        assert_eq!(coerce_to_bool(&json!("true")), Some(true));
        assert_eq!(coerce_to_bool(&json!("True")), Some(true));
        assert_eq!(coerce_to_bool(&json!("TRUE")), Some(true));
        assert_eq!(coerce_to_bool(&json!("false")), Some(false));
        assert_eq!(coerce_to_bool(&json!("False")), Some(false));
        assert_eq!(coerce_to_bool(&json!("FALSE")), Some(false));
    }

    #[test]
    fn coerce_to_bool_yaml11_true_variants() {
        assert_eq!(coerce_to_bool(&json!("yes")), Some(true));
        assert_eq!(coerce_to_bool(&json!("Yes")), Some(true));
        assert_eq!(coerce_to_bool(&json!("YES")), Some(true));
        assert_eq!(coerce_to_bool(&json!("on")), Some(true));
        assert_eq!(coerce_to_bool(&json!("On")), Some(true));
        assert_eq!(coerce_to_bool(&json!("ON")), Some(true));
        assert_eq!(coerce_to_bool(&json!("y")), Some(true));
        assert_eq!(coerce_to_bool(&json!("Y")), Some(true));
        assert_eq!(coerce_to_bool(&json!("1")), Some(true));
    }

    #[test]
    fn coerce_to_bool_yaml11_false_variants() {
        assert_eq!(coerce_to_bool(&json!("no")), Some(false));
        assert_eq!(coerce_to_bool(&json!("No")), Some(false));
        assert_eq!(coerce_to_bool(&json!("NO")), Some(false));
        assert_eq!(coerce_to_bool(&json!("off")), Some(false));
        assert_eq!(coerce_to_bool(&json!("Off")), Some(false));
        assert_eq!(coerce_to_bool(&json!("OFF")), Some(false));
        assert_eq!(coerce_to_bool(&json!("n")), Some(false));
        assert_eq!(coerce_to_bool(&json!("N")), Some(false));
        assert_eq!(coerce_to_bool(&json!("0")), Some(false));
    }

    #[test]
    fn coerce_to_bool_rejects_nonspec_casings() {
        assert_eq!(coerce_to_bool(&json!("tRuE")), None);
        assert_eq!(coerce_to_bool(&json!("yEs")), None);
        assert_eq!(coerce_to_bool(&json!("oN")), None);
        assert_eq!(coerce_to_bool(&json!("fAlSe")), None);
        assert_eq!(coerce_to_bool(&json!("nO")), None);
        assert_eq!(coerce_to_bool(&json!("oFf")), None);
        assert_eq!(coerce_to_bool(&json!("maybe")), None);
        assert_eq!(coerce_to_bool(&json!("")), None);
        assert_eq!(coerce_to_bool(&json!("2")), None);
    }

    #[test]
    fn coerce_string_or_integer_to_string_keeps_the_text_as_written() {
        assert_eq!(coerce_string_or_integer_to_string(&json!("512")), Some("512".into()));
        assert_eq!(coerce_string_or_integer_to_string(&json!(512)), Some("512".into()));
        // Zero padding is part of the written text: a caller matching against an
        // exact spelling must be able to tell '0512' from '512'.
        assert_eq!(coerce_string_or_integer_to_string(&json!("0512")), Some("0512".into()));
        assert_eq!(coerce_string_or_integer_to_string(&json!(".25 vCPU")), Some(".25 vCPU".into()));
    }

    #[test]
    fn coerce_string_or_integer_to_string_rejects_every_other_shape() {
        for rejected in [json!(512.0), json!(512.5), json!(true), json!(null), json!([512]), json!({"Cpu": 512})] {
            assert_eq!(coerce_string_or_integer_to_string(&rejected), None, "{rejected} must not yield text");
        }
    }

    #[test]
    fn coerce_port_to_string_accepts_string_and_integer_only() {
        assert_eq!(coerce_port_to_string(&json!("80")), Some("80".into()));
        assert_eq!(coerce_port_to_string(&json!(80)), Some("80".into()));
        assert_eq!(coerce_port_to_string(&json!(0)), Some("0".into()));
        // Non-integer numbers, booleans, and composites are not valid port forms.
        assert_eq!(coerce_port_to_string(&json!(80.0)), None);
        assert_eq!(coerce_port_to_string(&json!(80.5)), None);
        assert_eq!(coerce_port_to_string(&json!(true)), None);
        assert_eq!(coerce_port_to_string(&json!(null)), None);
        assert_eq!(coerce_port_to_string(&json!([80])), None);
    }

    #[test]
    fn scalar_eq_native_and_coerced_scalars() {
        assert!(scalar_eq(&json!(512), &json!("512")));
        assert!(scalar_eq(&json!("512"), &json!(512)));
        assert!(scalar_eq(&json!(true), &json!("true")));
        assert!(scalar_eq(&json!("hello"), &json!("hello")));
        assert!(!scalar_eq(&json!(512), &json!("513")));
        assert!(!scalar_eq(&json!(true), &json!("false")));
    }

    #[test]
    fn scalar_eq_integral_float_equals_integer() {
        // A whole number is the same value in every written form —
        // 30, 30.0, and "30.0" must all compare equal (issue: a Number
        // parameter resolving to 30.0 failed the integer enum [.., 30, ..]).
        assert!(scalar_eq(&json!(30.0), &json!(30)), "30.0 must equal 30");
        assert!(scalar_eq(&json!(30), &json!(30.0)), "30 must equal 30.0");
        assert!(scalar_eq(&json!(30.0), &json!("30")), "30.0 must equal '30'");
        assert!(scalar_eq(&json!("30.0"), &json!(30)), "'30.0' must equal 30");
        assert!(!scalar_eq(&json!(30.5), &json!(30)), "30.5 must not equal 30");
        assert!(!scalar_eq(&json!(30.0), &json!(31)), "30.0 must not equal 31");
    }

    #[test]
    fn scalar_eq_non_numeric_string_keeps_exact_comparison() {
        assert!(!scalar_eq(&json!("30x"), &json!(30)), "'30x' is not a number and must not equal 30");
        assert!(!scalar_eq(&json!("tcp"), &json!("TCP")), "string comparison stays case-sensitive");
    }

    #[test]
    fn scalar_eq_distinct_non_scalars_never_collapse() {
        // Arrays/objects/null have no string coercion; only native equality can
        // make them match. Distinct composites must NOT be treated as equal.
        assert!(!scalar_eq(&json!([1]), &json!([2])));
        assert!(!scalar_eq(&json!({"a": 1}), &json!({"b": 2})));
        assert!(!scalar_eq(&json!([1]), &json!("[1]")));
        assert!(!scalar_eq(&json!(null), &json!("null")));
        // Native equality still holds for identical composites/null.
        assert!(scalar_eq(&json!([1, 2]), &json!([1, 2])));
        assert!(scalar_eq(&json!(null), &json!(null)));
    }

    #[test]
    fn type_compatible_string() {
        assert!(type_compatible(&json!("hello"), "string"));
        assert!(!type_compatible(&json!(512), "string"));
        assert!(!type_compatible(&json!(true), "string"));
        assert!(!type_compatible(&json!(null), "string"));
        assert!(!type_compatible(&json!([1]), "string"));
        assert!(!type_compatible(&json!({"a": 1}), "string"));
    }

    #[test]
    fn type_compatible_integer() {
        assert!(type_compatible(&json!(512), "integer"));
        assert!(type_compatible(&json!("512"), "integer"));
        assert!(!type_compatible(&json!("3.5"), "integer"));
        assert!(!type_compatible(&json!("abc"), "integer"));
        assert!(!type_compatible(&json!(true), "integer"));
    }

    #[test]
    fn type_compatible_number() {
        assert!(type_compatible(&json!(3.14), "number"));
        assert!(type_compatible(&json!("3.14"), "number"));
        assert!(type_compatible(&json!(512), "number"));
        assert!(!type_compatible(&json!("abc"), "number"));
        assert!(!type_compatible(&json!(true), "number"));
    }

    #[test]
    fn type_compatible_boolean() {
        assert!(type_compatible(&json!(true), "boolean"));
        assert!(type_compatible(&json!("true"), "boolean"));
        assert!(type_compatible(&json!("FALSE"), "boolean"));
        assert!(type_compatible(&json!("yes"), "boolean"));
        assert!(type_compatible(&json!("Yes"), "boolean"));
        assert!(type_compatible(&json!("on"), "boolean"));
        assert!(type_compatible(&json!("OFF"), "boolean"));
        assert!(type_compatible(&json!("y"), "boolean"));
        assert!(type_compatible(&json!("N"), "boolean"));
        assert!(type_compatible(&json!("1"), "boolean"));
        assert!(type_compatible(&json!("0"), "boolean"));
        assert!(!type_compatible(&json!(1), "boolean"));
        assert!(!type_compatible(&json!("maybe"), "boolean"));
    }

    #[test]
    fn type_compatible_object_array_null() {
        assert!(type_compatible(&json!({}), "object"));
        assert!(!type_compatible(&json!("s"), "object"));
        assert!(type_compatible(&json!([]), "array"));
        assert!(!type_compatible(&json!(1), "array"));
        assert!(type_compatible(&json!(null), "null"));
        assert!(!type_compatible(&json!(""), "null"));
    }

    #[test]
    fn type_compatible_unknown_type_returns_false() {
        assert!(!type_compatible(&json!("x"), "foobar"));
    }

    #[test]
    fn coerce_value_already_correct() {
        assert_eq!(coerce_value(&json!("hello"), "string"), CoerceResult::AlreadyCorrect);
        assert_eq!(coerce_value(&json!(42), "integer"), CoerceResult::AlreadyCorrect);
        assert_eq!(coerce_value(&json!(3.14), "number"), CoerceResult::AlreadyCorrect);
        assert_eq!(coerce_value(&json!(true), "boolean"), CoerceResult::AlreadyCorrect);
        assert_eq!(coerce_value(&json!({}), "object"), CoerceResult::AlreadyCorrect);
        assert_eq!(coerce_value(&json!([]), "array"), CoerceResult::AlreadyCorrect);
        assert_eq!(coerce_value(&json!(null), "null"), CoerceResult::AlreadyCorrect);
    }

    #[test]
    fn coerce_value_string_to_integer() {
        match coerce_value(&json!("42"), "integer") {
            CoerceResult::Coerced(v, desc) => {
                assert_eq!(v, json!(42));
                assert!(desc.contains("integer"));
            }
            other => panic!("expected Coerced, got {:?}", other),
        }
    }

    #[test]
    fn coerce_value_string_to_number() {
        match coerce_value(&json!("3.14"), "number") {
            CoerceResult::Coerced(v, _) => assert_eq!(v.as_f64().unwrap(), 3.14),
            other => panic!("expected Coerced, got {:?}", other),
        }
    }

    #[test]
    fn coerce_value_string_to_boolean() {
        match coerce_value(&json!("yes"), "boolean") {
            CoerceResult::Coerced(v, _) => assert_eq!(v, json!(true)),
            other => panic!("expected Coerced, got {:?}", other),
        }
    }

    #[test]
    fn coerce_value_bool_to_string() {
        match coerce_value(&json!(true), "string") {
            CoerceResult::Coerced(v, desc) => {
                assert_eq!(v, json!("true"));
                assert!(desc.contains("boolean"));
            }
            other => panic!("expected Coerced, got {:?}", other),
        }
    }

    #[test]
    fn coerce_value_number_to_string() {
        match coerce_value(&json!(42), "string") {
            CoerceResult::Coerced(v, desc) => {
                assert_eq!(v, json!("42"));
                assert!(desc.contains("number"));
            }
            other => panic!("expected Coerced, got {:?}", other),
        }
    }

    #[test]
    fn coerce_value_bool_to_integer_fails() {
        assert_eq!(coerce_value(&json!(true), "integer"), CoerceResult::Failed);
    }

    #[test]
    fn coerce_value_bool_to_number_fails() {
        assert_eq!(coerce_value(&json!(true), "number"), CoerceResult::Failed);
    }

    #[test]
    fn coerce_value_incompatible_fails() {
        assert_eq!(coerce_value(&json!(null), "string"), CoerceResult::Failed);
        assert_eq!(coerce_value(&json!([1]), "string"), CoerceResult::Failed);
        assert_eq!(coerce_value(&json!("abc"), "integer"), CoerceResult::Failed);
        assert_eq!(coerce_value(&json!("abc"), "number"), CoerceResult::Failed);
        assert_eq!(coerce_value(&json!("maybe"), "boolean"), CoerceResult::Failed);
    }

    #[test]
    fn coerce_value_double_and_float_aliases() {
        assert_eq!(coerce_value(&json!(1.5), "double"), CoerceResult::AlreadyCorrect);
        assert_eq!(coerce_value(&json!(1.5), "float"), CoerceResult::AlreadyCorrect);
        match coerce_value(&json!("1.5"), "double") {
            CoerceResult::Coerced(v, _) => assert_eq!(v.as_f64().unwrap(), 1.5),
            other => panic!("expected Coerced, got {:?}", other),
        }
    }

    #[test]
    fn coerce_value_unknown_type_fails() {
        assert_eq!(coerce_value(&json!("x"), "foobar"), CoerceResult::Failed);
    }

    #[test]
    fn coerce_to_integer_from_float_number() {
        assert_eq!(coerce_to_integer(&json!(3.0)), Some(3));
        assert_eq!(coerce_to_integer(&json!(3.5)), None);
    }
}
