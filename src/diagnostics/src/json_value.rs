use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::ops::Deref;

/// Newtype around `serde_json::Value` that provides WASM (via `tsify`) and
/// UniFFI bindings. WASM serializes through serde into native JS values.
/// UniFFI bridges through a recursive `JsonValueEnum` so JVM consumers get
/// typed data without parsing JSON strings.
#[derive(Debug, Clone, PartialEq)]
pub struct JsonValue(pub serde_json::Value);

impl JsonValue {
    pub fn into_inner(self) -> serde_json::Value {
        self.0
    }
}

impl Deref for JsonValue {
    type Target = serde_json::Value;
    fn deref(&self) -> &serde_json::Value {
        &self.0
    }
}

impl From<serde_json::Value> for JsonValue {
    fn from(v: serde_json::Value) -> Self {
        JsonValue(v)
    }
}

impl From<JsonValue> for serde_json::Value {
    fn from(v: JsonValue) -> Self {
        v.0
    }
}

impl Serialize for JsonValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for JsonValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        serde_json::Value::deserialize(deserializer).map(JsonValue)
    }
}

#[cfg(feature = "uniffi-bindings")]
use std::collections::HashMap;

#[cfg(feature = "uniffi-bindings")]
#[derive(Debug, Clone, uniffi::Enum)]
pub enum JsonValueEnum {
    Null,
    Bool { value: bool },
    Int { value: i64 },
    Float { value: f64 },
    String { value: String },
    Array { items: Vec<JsonValueEnum> },
    Object { entries: HashMap<String, JsonValueEnum> },
}

#[cfg(feature = "uniffi-bindings")]
impl From<&serde_json::Value> for JsonValueEnum {
    fn from(v: &serde_json::Value) -> Self {
        match v {
            serde_json::Value::Null => JsonValueEnum::Null,
            serde_json::Value::Bool(b) => JsonValueEnum::Bool { value: *b },
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    JsonValueEnum::Int { value: i }
                } else {
                    JsonValueEnum::Float { value: n.as_f64().unwrap_or(0.0) }
                }
            }
            serde_json::Value::String(s) => JsonValueEnum::String { value: s.clone() },
            serde_json::Value::Array(arr) => {
                JsonValueEnum::Array { items: arr.iter().map(JsonValueEnum::from).collect() }
            }
            serde_json::Value::Object(obj) => JsonValueEnum::Object {
                entries: obj.iter().map(|(k, v)| (k.clone(), JsonValueEnum::from(v))).collect(),
            },
        }
    }
}

#[cfg(feature = "uniffi-bindings")]
impl From<JsonValueEnum> for serde_json::Value {
    fn from(v: JsonValueEnum) -> Self {
        match v {
            JsonValueEnum::Null => serde_json::Value::Null,
            JsonValueEnum::Bool { value } => serde_json::Value::Bool(value),
            JsonValueEnum::Int { value } => serde_json::json!(value),
            JsonValueEnum::Float { value } => {
                serde_json::Number::from_f64(value).map(serde_json::Value::Number).unwrap_or(serde_json::Value::Null)
            }
            JsonValueEnum::String { value } => serde_json::Value::String(value),
            JsonValueEnum::Array { items } => serde_json::Value::Array(items.into_iter().map(Into::into).collect()),
            JsonValueEnum::Object { entries } => {
                serde_json::Value::Object(entries.into_iter().map(|(k, v)| (k, v.into())).collect())
            }
        }
    }
}

#[cfg(feature = "uniffi-bindings")]
uniffi::custom_type!(JsonValue, JsonValueEnum, {
    lower: |v| JsonValueEnum::from(&v.0),
    try_lift: |e| Ok(JsonValue(serde_json::Value::from(e))),
});

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn serde_round_trips_nested_object() {
        let original = JsonValue(json!({"key": [1, "two", true, null]}));
        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: JsonValue = serde_json::from_str(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn serde_round_trips_null() {
        let original = JsonValue(json!(null));
        let serialized = serde_json::to_string(&original).unwrap();
        assert_eq!(serialized, "null");
        let deserialized: JsonValue = serde_json::from_str(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn serde_round_trips_all_primitive_types() {
        for value in [json!(42), json!(3.14), json!(true), json!("hello")] {
            let jv = JsonValue(value.clone());
            let json = serde_json::to_string(&jv).unwrap();
            let back: JsonValue = serde_json::from_str(&json).unwrap();
            assert_eq!(jv, back);
        }
    }

    #[test]
    fn deref_delegates_to_inner_value_methods() {
        let jv = JsonValue(json!("hello"));
        assert_eq!(jv.as_str(), Some("hello"));

        let jv = JsonValue(json!(42));
        assert_eq!(jv.as_i64(), Some(42));

        let jv = JsonValue(json!(true));
        assert_eq!(jv.as_bool(), Some(true));
    }

    #[test]
    fn into_inner_unwraps_to_serde_value() {
        let jv = JsonValue(json!({"a": 1}));
        let inner: serde_json::Value = jv.into_inner();
        assert_eq!(inner, json!({"a": 1}));
    }

    #[test]
    fn from_conversions_round_trip_through_serde_value() {
        let raw = json!({"nested": [1, 2]});
        let jv: JsonValue = raw.clone().into();
        let back: serde_json::Value = jv.into();
        assert_eq!(raw, back);
    }
}
