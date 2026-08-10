//! Format-agnostic view of a parsed scalar/collection value.
//!
//! Both the JSON (`serde_json::Value`) and YAML (`yaml_rust2::Yaml`) front-ends
//! implement [`ParseValue`] so the intrinsic dispatch in [`super::builder`] can be
//! written once. Keeping the two formats behind one trait is what guarantees JSON
//! and YAML produce identical diagnostics - there is a single code path, so they
//! cannot drift.
//!
//! Scalar coercion follows YAML/CloudFormation semantics: an unquoted scalar where
//! a string is expected (e.g. `Ref: 123`) is coerced to its textual form rather
//! than rejected, because CloudFormation itself coerces it and then performs the
//! name/reference check. JSON's `serde_json` numbers/bools are coerced the same way
//! so both formats agree.

use crate::ir::Node;

/// The structural kind of a value, used for type-checks and diagnostic wording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueKind {
    Null,
    Bool,
    Number,
    String,
    Array,
    Object,
}

/// A read-only, format-agnostic view over a parsed value.
///
/// Implementors are lightweight `Copy` wrappers borrowing from the underlying
/// `serde_json::Value` / `Yaml` tree, so `as_array`/`as_object` hand back fresh
/// wrappers (not owned clones of the data).
pub trait ParseValue {
    /// Structural kind of this value.
    fn kind(&self) -> ValueKind;

    /// The value as a string, coercing non-string scalars (number/bool) to their
    /// textual form. Returns `None` only for arrays, objects, and null. This is the
    /// CloudFormation-faithful behavior for string-typed intrinsic arguments.
    fn as_coerced_str(&self) -> Option<String>;

    /// The elements of an array value, or `None` if this is not an array.
    fn as_array(&self) -> Option<Vec<Self>>
    where
        Self: Sized;

    /// The entries of an object value (key, value) in source order, or `None` if
    /// this is not an object.
    fn as_object(&self) -> Option<Vec<(String, Self)>>
    where
        Self: Sized;

    /// If this value is an integer scalar, its `i64` value (used for `Fn::Cidr`
    /// range checks). Non-integers (including floats and coerced strings) yield
    /// `None`.
    fn as_integer(&self) -> Option<i64>;

    /// Renders a scalar value for diagnostic messages: strings single-quoted,
    /// numbers/bools/null bare. Composites are rendered by [`describe_value`], which
    /// recurses through the structural accessors so JSON and YAML produce identical
    /// text. Only called for scalars.
    fn describe_scalar(&self) -> String;

    /// Builds the arena leaf [`Node`] for this scalar value. Only ever called for
    /// scalars (null/bool/number/string); composites are walked by the builder.
    fn scalar_node(&self) -> Node;

    fn is_object(&self) -> bool {
        self.kind() == ValueKind::Object
    }

    fn is_null(&self) -> bool {
        self.kind() == ValueKind::Null
    }

    /// True when this value is a single-key object - the shape every intrinsic
    /// function takes (`{ "Fn::X": ... }` / `{ "Ref": ... }` / `{ "Condition": ... }`).
    fn single_key(&self) -> Option<(String, Self)>
    where
        Self: Sized,
    {
        let entries = self.as_object()?;
        if entries.len() == 1 { entries.into_iter().next() } else { None }
    }

    /// A human-readable rendering of this value for diagnostic messages.
    fn describe(&self) -> String
    where
        Self: Sized,
    {
        describe_value(self)
    }
}

/// Renders any value for diagnostic messages in the canonical form: single-quoted
/// strings, bare scalars, `['a', 'b']` arrays, and `{'key': value}` objects.
/// Recurses through the structural accessors so the text is byte-identical
/// regardless of source format.
pub fn describe_value<V: ParseValue>(val: &V) -> String {
    match val.kind() {
        ValueKind::Array => {
            let items = val.as_array().unwrap_or_default();
            let rendered: Vec<String> = items.iter().map(describe_value).collect();
            format!("[{}]", rendered.join(", "))
        }
        ValueKind::Object => {
            let entries = val.as_object().unwrap_or_default();
            let rendered: Vec<String> =
                entries.iter().map(|(k, v)| format!("'{}': {}", k, describe_value(v))).collect();
            format!("{{{}}}", rendered.join(", "))
        }
        _ => val.describe_scalar(),
    }
}
