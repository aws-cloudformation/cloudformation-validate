use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;

/// Definitions are stored separately and referenced by name to avoid exponential blowup.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CompiledSchema {
    #[serde(default)]
    pub type_name: String,
    #[serde(default)]
    pub properties: HashMap<String, PropSchema>,
    #[serde(default)]
    pub definitions: HashMap<String, PropSchema>,
    #[serde(default)]
    pub required: Vec<String>,
    /// Whether root-level `required` was explicitly stated in the source that
    /// produced this schema. When `true`, merging replaces the base's root
    /// required list (even if the list is empty, which clears it); when `false`,
    /// merging preserves the base. Not serialized - existing committed artifacts
    /// deserialize with the default (`false`), which is correct: bundled schemas
    /// are never overlay sources.
    #[serde(default, skip_serializing, skip_deserializing)]
    pub required_present: bool,
    #[serde(default)]
    pub additional_properties: Option<bool>,
    #[serde(default)]
    pub read_only_properties: Vec<String>,
    #[serde(default)]
    pub write_only_properties: Vec<String>,
    #[serde(default)]
    pub create_only_properties: Vec<String>,
    #[serde(default)]
    pub deprecated_properties: Vec<String>,
    #[serde(default)]
    pub conditional_create_only_properties: Vec<String>,
    #[serde(default)]
    pub primary_identifier: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement_strategy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub documentation_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub all_of: Vec<SubSchema>,
    #[serde(default)]
    pub any_of: Vec<SubSchema>,
    #[serde(default)]
    pub one_of: Vec<SubSchema>,
    #[serde(default)]
    pub if_then_else: Vec<IfThenElse>,
    #[serde(default)]
    pub dependent_required: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub dependent_excluded: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub required_or: Vec<String>,
    #[serde(default)]
    pub required_xor: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IfThenElse {
    pub condition: ConditionSchema,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub then_schema: Option<SubSchema>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub else_schema: Option<SubSchema>,
    /// Whether the selected branch is enforced in full (required,
    /// additionalProperties, value constraints) rather than dependencies-only.
    ///
    /// Set for conditionals an overlay supplies: the overlay author states the
    /// conditional deliberately and no dedicated rule covers it. Bundled
    /// conditionals stay dependencies-only, because their richer semantics are
    /// owned by dedicated resource-specific rules (with their own IDs and
    /// severities) and enforcing them generically would double-report. Never
    /// serialized - the committed artifact stays unchanged and deserializes to
    /// dependencies-only.
    #[serde(skip)]
    pub enforce_full_branch: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConditionSchema {
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub properties: HashMap<String, PropSchema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,
    /// The instance type the condition requires (`if: {"type": ...}`). A
    /// condition stating a type only matches an instance of that type; resource
    /// roots are always objects, so `"object"` is a no-op there while any other
    /// type makes the condition unsatisfiable at the root.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub prop_type: Option<PropType>,
    /// When set, the condition matches if ANY of these sub-conditions match.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub any_of: Vec<ConditionSchema>,
}

/// `$ref` is stored as `ref_name` and resolved at validation time against the parent schema's `definitions`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PropSchema {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ref_name: Option<String>,
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub prop_type: Option<PropType>,
    #[serde(default, rename = "enum", skip_serializing_if = "Vec::is_empty")]
    pub enum_values: Vec<serde_json::Value>,
    /// Allowed values compared case-insensitively - used for properties whose
    /// service accepts any casing of the documented value. A schema carries
    /// either this or `enum_values` for a given property, never both.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enum_case_insensitive: Vec<serde_json::Value>,
    /// JSON Schema `not: { enum: [...] }` - value must NOT match any of these.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_enum: Vec<serde_json::Value>,
    #[serde(default, rename = "const", skip_serializing_if = "Option::is_none")]
    pub const_value: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclusive_minimum: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclusive_maximum: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multiple_of: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_length: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_length: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_items: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_items: Option<u64>,
    /// `None` when the schema omits `uniqueItems`; `Some(false)` when it is
    /// explicitly relaxed. Keeping the distinction lets an overlay clear a
    /// bundled `true`.
    #[serde(default, skip_serializing_if = "skip_unless_true")]
    pub unique_items: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_properties: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_properties: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub properties: HashMap<String, PropSchema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,
    /// Whether `required` was explicitly stated at this property, definition, or
    /// item schema level. When `true`, merging replaces the corresponding nested
    /// required list (even if the list is empty, which clears it); when `false`,
    /// merging preserves the base. Not serialized - existing artifacts
    /// deserialize unchanged.
    #[serde(default, skip_serializing, skip_deserializing)]
    pub required_present: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additional_properties: Option<bool>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub pattern_properties: HashMap<String, PropSchema>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<Box<PropSchema>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub all_of: Vec<SubSchema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub any_of: Vec<SubSchema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub one_of: Vec<SubSchema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub if_then_else: Vec<IfThenElse>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub dependent_required: HashMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub dependent_excluded: HashMap<String, Vec<String>>,
    /// At least one of these properties must be present (`requiredOr`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_or: Vec<String>,
    /// Exactly one of these properties must be present (`requiredXor`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_xor: Vec<String>,
}

fn skip_unless_true(value: &Option<bool>) -> bool {
    *value != Some(true)
}

/// A composition branch is now a full property schema - every constraint that
/// can appear on a property is available in a branch and evaluated at runtime.
/// This alias preserves naming clarity at usage sites.
pub type SubSchema = PropSchema;

/// Upper bound on the length of a `$ref` chain followed by
/// `PropSchema::resolve`. Real provider schemas chain at most a handful of
/// hops; the bound exists so a malformed definition graph cannot make resolution
/// unbounded.
pub(crate) const MAX_REF_CHAIN: usize = 64;

impl PropSchema {
    /// The schema that actually applies to this property: the terminal target of
    /// its `$ref` chain, with any fields stated alongside the reference merged on
    /// top.
    ///
    /// A property may carry both a `$ref` and its own constraints - that is what
    /// an overlay extending a referenced property produces. Resolving them here,
    /// rather than folding the referenced definition into the property when the
    /// overlay is applied, keeps the reference live: a later overlay that changes
    /// the definition still reaches every property pointing at it, and the result
    /// does not depend on the order definitions happened to be merged in.
    ///
    /// Resolution is iterative and cycle-safe: a definition graph that loops back
    /// on itself, or a chain longer than [`MAX_REF_CHAIN`], stops at the last
    /// schema reached instead of recursing forever. Cyclic graphs are rejected
    /// when an overlay is applied, so this is the second line of defence - a
    /// caller-supplied schema must never be able to exhaust the stack and abort
    /// the process.
    pub fn resolve<'a>(&'a self, defs: &'a HashMap<String, PropSchema>) -> Cow<'a, PropSchema> {
        if self.ref_name.is_none() {
            return Cow::Borrowed(self);
        }
        // Every hop may state constraints of its own beside its reference, so the
        // whole chain is collected rather than just its ends.
        let mut chain: Vec<&PropSchema> = vec![self];
        let mut seen: Vec<&str> = Vec::new();
        for _ in 0..MAX_REF_CHAIN {
            let Some(name) = chain.last().and_then(|hop| hop.ref_name.as_deref()) else {
                break;
            };
            if seen.contains(&name) {
                break;
            }
            seen.push(name);
            match defs.get(name) {
                Some(next) => chain.push(next),
                None => break,
            }
        }
        let (terminal, referrers) = match chain.split_last() {
            Some(pair) => pair,
            // `chain` is initialized with `self`, so it is never empty. This
            // branch is structurally unreachable but avoids a panic path.
            None => return Cow::Borrowed(self),
        };
        if !referrers.iter().any(|hop| hop.has_own_constraints()) {
            return Cow::Borrowed(terminal);
        }
        let mut effective = (*terminal).clone();
        effective.ref_name = None;
        // Nearest wins: apply the innermost referrer first and this schema last.
        for hop in referrers.iter().rev() {
            if !hop.has_own_constraints() {
                continue;
            }
            let mut own = (*hop).clone();
            own.ref_name = None;
            crate::overlay::merge_prop(&mut effective, own);
        }
        Cow::Owned(effective)
    }

    /// Whether this property states anything of its own beside a `$ref`.
    ///
    /// Destructured exhaustively so a new field cannot be forgotten here and make
    /// a property's own constraints silently disappear at resolution time.
    /// Whether this schema states anything `schema_value_matches` could fail a
    /// value against. Destructured exhaustively so a newly added constraint
    /// field cannot be omitted and silently skip branch value matching.
    ///
    /// `description` never constrains; a `ref_name` counts because a dangling
    /// reference makes matching fail.
    pub(crate) fn constrains_value(&self) -> bool {
        let PropSchema {
            ref_name,
            prop_type,
            enum_values,
            enum_case_insensitive,
            not_enum,
            const_value,
            pattern,
            minimum,
            maximum,
            exclusive_minimum,
            exclusive_maximum,
            multiple_of,
            min_length,
            max_length,
            min_items,
            max_items,
            unique_items,
            min_properties,
            max_properties,
            format,
            description: _,
            properties,
            required,
            required_present: _,
            additional_properties,
            pattern_properties,
            items,
            all_of,
            any_of,
            one_of,
            if_then_else,
            dependent_required,
            dependent_excluded,
            required_or,
            required_xor,
        } = self;
        ref_name.is_some()
            || prop_type.is_some()
            || !enum_values.is_empty()
            || !enum_case_insensitive.is_empty()
            || !not_enum.is_empty()
            || const_value.is_some()
            || pattern.is_some()
            || minimum.is_some()
            || maximum.is_some()
            || exclusive_minimum.is_some()
            || exclusive_maximum.is_some()
            || multiple_of.is_some()
            || min_length.is_some()
            || max_length.is_some()
            || min_items.is_some()
            || max_items.is_some()
            || unique_items == &Some(true)
            || min_properties.is_some()
            || max_properties.is_some()
            || format.is_some()
            || !properties.is_empty()
            || !required.is_empty()
            || additional_properties.is_some()
            || !pattern_properties.is_empty()
            || items.is_some()
            || !all_of.is_empty()
            || !any_of.is_empty()
            || !one_of.is_empty()
            || !if_then_else.is_empty()
            || !dependent_required.is_empty()
            || !dependent_excluded.is_empty()
            || !required_or.is_empty()
            || !required_xor.is_empty()
    }

    fn has_own_constraints(&self) -> bool {
        let PropSchema {
            ref_name: _,
            prop_type,
            enum_values,
            enum_case_insensitive,
            not_enum,
            const_value,
            pattern,
            minimum,
            maximum,
            exclusive_minimum,
            exclusive_maximum,
            multiple_of,
            min_length,
            max_length,
            min_items,
            max_items,
            unique_items,
            min_properties,
            max_properties,
            format,
            description,
            properties,
            required,
            required_present: _,
            additional_properties,
            pattern_properties,
            items,
            all_of,
            any_of,
            one_of,
            if_then_else,
            dependent_required,
            dependent_excluded,
            required_or,
            required_xor,
        } = self;
        prop_type.is_some()
            || !enum_values.is_empty()
            || !enum_case_insensitive.is_empty()
            || !not_enum.is_empty()
            || const_value.is_some()
            || pattern.is_some()
            || minimum.is_some()
            || maximum.is_some()
            || exclusive_minimum.is_some()
            || exclusive_maximum.is_some()
            || multiple_of.is_some()
            || min_length.is_some()
            || max_length.is_some()
            || min_items.is_some()
            || max_items.is_some()
            || unique_items.is_some()
            || min_properties.is_some()
            || max_properties.is_some()
            || format.is_some()
            || description.is_some()
            || !properties.is_empty()
            || !required.is_empty()
            || additional_properties.is_some()
            || !pattern_properties.is_empty()
            || items.is_some()
            || !all_of.is_empty()
            || !any_of.is_empty()
            || !one_of.is_empty()
            || !if_then_else.is_empty()
            || !dependent_required.is_empty()
            || !dependent_excluded.is_empty()
            || !required_or.is_empty()
            || !required_xor.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PropType {
    Single(String),
    Multi(Vec<String>),
}

impl PropType {
    pub fn primary(&self) -> Option<&str> {
        match self {
            PropType::Single(s) => Some(s),
            PropType::Multi(v) => v.iter().find(|s| s.as_str() != "null").map(|s| s.as_str()),
        }
    }

    /// Every type name this `type` keyword admits.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        match self {
            PropType::Single(s) => std::slice::from_ref(s).iter(),
            PropType::Multi(v) => v.iter(),
        }
        .map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::ptr;

    #[test]
    fn primary_single_returns_the_type() {
        let pt = PropType::Single("string".into());
        assert_eq!(pt.primary(), Some("string"));
    }

    #[test]
    fn primary_multi_skips_null() {
        let pt = PropType::Multi(vec!["null".into(), "integer".into()]);
        assert_eq!(pt.primary(), Some("integer"));
    }

    #[test]
    fn primary_multi_all_null_returns_none() {
        let pt = PropType::Multi(vec!["null".into()]);
        assert_eq!(pt.primary(), None);
    }

    #[test]
    fn primary_multi_empty_returns_none() {
        let pt = PropType::Multi(vec![]);
        assert_eq!(pt.primary(), None);
    }

    #[test]
    fn primary_multi_first_non_null() {
        let pt = PropType::Multi(vec!["string".into(), "null".into(), "integer".into()]);
        assert_eq!(pt.primary(), Some("string"));
    }

    #[test]
    fn resolve_no_ref_returns_self() {
        let schema = PropSchema { prop_type: Some(PropType::Single("string".into())), ..Default::default() };
        let defs = HashMap::new();
        let resolved = schema.resolve(&defs);
        assert!(matches!(resolved, Cow::Borrowed(borrowed) if ptr::eq(borrowed, &schema)));
    }

    #[test]
    fn resolve_follows_ref_to_definition() {
        let target = PropSchema { prop_type: Some(PropType::Single("integer".into())), ..Default::default() };
        let mut defs = HashMap::new();
        defs.insert("MyDef".into(), target);

        let schema = PropSchema { ref_name: Some("MyDef".into()), ..Default::default() };
        let resolved = schema.resolve(&defs);
        assert_eq!(resolved.prop_type.as_ref().unwrap().primary(), Some("integer"));
    }

    #[test]
    fn resolve_chained_refs() {
        let final_target = PropSchema { prop_type: Some(PropType::Single("boolean".into())), ..Default::default() };
        let intermediate = PropSchema { ref_name: Some("Final".into()), ..Default::default() };
        let mut defs = HashMap::new();
        defs.insert("Final".into(), final_target);
        defs.insert("Intermediate".into(), intermediate);

        let schema = PropSchema { ref_name: Some("Intermediate".into()), ..Default::default() };
        let resolved = schema.resolve(&defs);
        assert_eq!(resolved.prop_type.as_ref().unwrap().primary(), Some("boolean"));
    }

    #[test]
    fn resolve_missing_ref_returns_self() {
        let schema = PropSchema { ref_name: Some("NonExistent".into()), ..Default::default() };
        let defs = HashMap::new();
        let resolved = schema.resolve(&defs);
        assert!(matches!(resolved, Cow::Borrowed(borrowed) if ptr::eq(borrowed, &schema)));
    }

    /// Cyclic graphs are rejected when an overlay is applied, so these cover the
    /// second line of defence: resolution must terminate on its own rather than
    /// recursing until the stack is gone, because a stack overflow aborts the
    /// host process instead of surfacing as a catchable error.
    #[test]
    fn resolve_terminates_on_a_self_referential_definition() {
        let mut defs = HashMap::new();
        defs.insert("Loop".to_string(), PropSchema { ref_name: Some("Loop".into()), ..Default::default() });

        let schema = PropSchema { ref_name: Some("Loop".into()), ..Default::default() };
        let resolved = schema.resolve(&defs);

        assert_eq!(
            resolved.ref_name.as_deref(),
            Some("Loop"),
            "resolution stops at the definition it has already visited"
        );
    }

    #[test]
    fn resolve_terminates_on_a_multi_node_definition_cycle() {
        let mut defs = HashMap::new();
        defs.insert("First".to_string(), PropSchema { ref_name: Some("Second".into()), ..Default::default() });
        defs.insert("Second".to_string(), PropSchema { ref_name: Some("First".into()), ..Default::default() });

        let schema = PropSchema { ref_name: Some("First".into()), ..Default::default() };
        let resolved = schema.resolve(&defs);

        assert_eq!(resolved.ref_name.as_deref(), Some("First"), "resolution stops at the hop that closes the cycle");
    }

    #[test]
    fn resolve_stops_at_the_chain_limit_and_keeps_the_property_own_constraints() {
        let unreachable_hop = MAX_REF_CHAIN + 5;
        let mut defs = HashMap::new();
        for hop in 0..unreachable_hop {
            defs.insert(
                format!("Hop{hop}"),
                PropSchema { ref_name: Some(format!("Hop{}", hop + 1)), ..Default::default() },
            );
        }
        defs.insert(
            format!("Hop{unreachable_hop}"),
            PropSchema { pattern: Some("^unreachable$".into()), ..Default::default() },
        );

        let schema = PropSchema { ref_name: Some("Hop0".into()), max_length: Some(10), ..Default::default() };
        let resolved = schema.resolve(&defs);

        assert_eq!(
            resolved.max_length,
            Some(10),
            "a chain too long to follow must not discard what the property itself states"
        );
        assert_eq!(
            resolved.pattern, None,
            "the constraint beyond the resolution limit is not reachable, which is why such a chain is rejected on input"
        );
    }

    #[test]
    fn prop_schema_roundtrip_json() {
        let schema = PropSchema {
            prop_type: Some(PropType::Single("string".into())),
            enum_values: vec![json!("a"), json!("b")],
            pattern: Some("^[a-z]+$".into()),
            minimum: Some(0.0),
            maximum: Some(100.0),
            min_length: Some(1),
            max_length: Some(256),
            unique_items: Some(true),
            ..Default::default()
        };
        let json_str = serde_json::to_string(&schema).unwrap();
        let deserialized: PropSchema = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.prop_type.as_ref().unwrap().primary(), Some("string"));
        assert_eq!(deserialized.enum_values.len(), 2);
        assert_eq!(deserialized.pattern.as_deref(), Some("^[a-z]+$"));
        assert_eq!(deserialized.minimum, Some(0.0));
        assert_eq!(deserialized.maximum, Some(100.0));
        assert_eq!(deserialized.min_length, Some(1));
        assert_eq!(deserialized.max_length, Some(256));
        assert_eq!(deserialized.unique_items, Some(true), "unique_items should round trip as true");
    }

    #[test]
    fn prop_type_single_deserializes_from_string() {
        let pt: PropType = serde_json::from_str(r#""string""#).unwrap();
        assert_eq!(pt.primary(), Some("string"));
    }

    #[test]
    fn prop_type_multi_deserializes_from_array() {
        let pt: PropType = serde_json::from_str(r#"["string", "null"]"#).unwrap();
        assert_eq!(pt.primary(), Some("string"));
    }

    #[test]
    fn compiled_schema_defaults_are_empty() {
        let json_str = r#"{"type_name": "AWS::Test::Resource"}"#;
        let schema: CompiledSchema = serde_json::from_str(json_str).unwrap();
        assert_eq!(schema.type_name, "AWS::Test::Resource");
        assert_eq!(schema.properties.len(), 0, "properties should be empty");
        assert_eq!(schema.definitions.len(), 0, "definitions should be empty");
        assert_eq!(schema.required.len(), 0, "required should be empty");
        assert_eq!(schema.additional_properties, None, "additional_properties should be None");
        assert_eq!(schema.read_only_properties.len(), 0, "read_only_properties should be empty");
        assert_eq!(schema.if_then_else.len(), 0, "if_then_else should be empty");
    }

    #[test]
    fn if_then_else_roundtrip() {
        let ite = IfThenElse {
            enforce_full_branch: false,
            condition: ConditionSchema {
                properties: {
                    let mut m = HashMap::new();
                    m.insert("Engine".into(), PropSchema { enum_values: vec![json!("aurora")], ..Default::default() });
                    m
                },
                ..Default::default()
            },
            then_schema: Some(SubSchema { required: vec!["Port".into()], ..Default::default() }),
            else_schema: None,
        };
        let json_str = serde_json::to_string(&ite).unwrap();
        let deserialized: IfThenElse = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.condition.properties.len(), 1);
        assert!(deserialized.then_schema.is_some(), "then_schema should be present");
        assert!(deserialized.else_schema.is_none(), "else_schema should be None");
    }

    #[test]
    fn prop_schema_skip_serializing_defaults() {
        let schema = PropSchema::default();
        let json_str = serde_json::to_string(&schema).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        let obj = val.as_object().unwrap();
        assert!(obj.is_empty(), "expected empty JSON for default PropSchema, got: {}", json_str);
    }

    #[test]
    fn sub_schema_with_dependent_required() {
        let sub = SubSchema {
            dependent_required: {
                let mut m = HashMap::new();
                m.insert("A".into(), vec!["B".into(), "C".into()]);
                m
            },
            ..Default::default()
        };
        let json_str = serde_json::to_string(&sub).unwrap();
        let deserialized: SubSchema = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.dependent_required.get("A").unwrap(), &vec!["B".to_string(), "C".to_string()]);
    }
}
