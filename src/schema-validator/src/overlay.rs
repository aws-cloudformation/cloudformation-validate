//! Runtime compilation and merging of overlay CloudFormation resource provider
//! schemas on top of the bundled compiled schemas.
//!
//! Bundled schemas are compiled at build time by `data-source`'s
//! `codegen_schema_validator`, which transforms raw CloudFormation registry JSON
//! into the [`CompiledSchema`] representation baked into the binary. This module
//! ports the *same* raw-CFN → compiled transformation to run at engine
//! construction time, so callers can supply additional schemas — for example the
//! pre-GA properties the CDK ships as temporary schemas before the property is
//! published to the CloudFormation registry — and have them validated exactly
//! like the bundled schemas.
//!
//! Merge semantics (see the feature spec) when an overlay shares a `typeName`
//! with a bundled schema:
//! - **properties** and **definitions** are deep-merged (the overlay adds new
//!   entries and recursively merges shared ones),
//! - **required** arrays are unioned,
//! - **enum** values on an overlay property replace the bundled enum for that
//!   property path,
//! - scalar constraints present on the overlay override the bundled value.
//!
//! A schema whose `typeName` is not bundled is inserted verbatim.

use crate::compiled::{CompiledSchema, PropSchema};
use serde_json::Value;

/// Compile a raw CloudFormation resource provider schema (registry JSON) into the
/// runtime [`CompiledSchema`].
///
/// The raw → compiled transform is single-sourced in
/// [`data_source::compiled_schema::compile_schema`], the same function the build
/// pipeline uses for bundled schemas. We route overlays through it and then round
/// trip the result through serde into the runtime schema type, so an overlay is
/// compiled byte-for-byte identically to a bundled schema. The serialize +
/// deserialize step bridges the build type (`BTreeMap`, deterministic output) and
/// the runtime type (`HashMap`, fast lookups); both share the same JSON shape, so
/// the round trip is total.
pub(crate) fn compile(type_name: &str, raw: &Value) -> CompiledSchema {
    let compiled = data_source::compiled_schema::compile_schema(type_name, raw);
    let value = serde_json::to_value(&compiled).expect("a compiled overlay schema must serialize");
    serde_json::from_value(value).expect("a compiled overlay schema must deserialize into the runtime schema")
}

/// Deep-merge an overlay [`CompiledSchema`] into an existing bundled schema in
/// place. See the module docs for the merge semantics.
pub(crate) fn merge_into(base: &mut CompiledSchema, overlay: CompiledSchema) {
    for (name, prop) in overlay.properties {
        match base.properties.get_mut(&name) {
            Some(existing) => merge_prop(existing, prop),
            None => {
                base.properties.insert(name, prop);
            }
        }
    }
    for (name, def) in overlay.definitions {
        match base.definitions.get_mut(&name) {
            Some(existing) => merge_prop(existing, def),
            None => {
                base.definitions.insert(name, def);
            }
        }
    }

    union_extend(&mut base.required, overlay.required);

    if overlay.additional_properties.is_some() {
        base.additional_properties = overlay.additional_properties;
    }
    if overlay.replacement_strategy.is_some() {
        base.replacement_strategy = overlay.replacement_strategy;
    }
    if overlay.documentation_url.is_some() {
        base.documentation_url = overlay.documentation_url;
    }
    if overlay.source_url.is_some() {
        base.source_url = overlay.source_url;
    }
    if overlay.description.is_some() {
        base.description = overlay.description;
    }

    // Property-path metadata: the overlay replaces the bundled list when it
    // supplies one, otherwise the bundled list is kept.
    replace_if_present(&mut base.read_only_properties, overlay.read_only_properties);
    replace_if_present(&mut base.write_only_properties, overlay.write_only_properties);
    replace_if_present(&mut base.create_only_properties, overlay.create_only_properties);
    replace_if_present(&mut base.deprecated_properties, overlay.deprecated_properties);
    replace_if_present(&mut base.conditional_create_only_properties, overlay.conditional_create_only_properties);
    replace_if_present(&mut base.primary_identifier, overlay.primary_identifier);

    base.all_of.extend(overlay.all_of);
    base.any_of.extend(overlay.any_of);
    base.one_of.extend(overlay.one_of);
    base.if_then_else.extend(overlay.if_then_else);

    for (k, v) in overlay.dependent_required {
        base.dependent_required.insert(k, v);
    }
    for (k, v) in overlay.dependent_excluded {
        base.dependent_excluded.insert(k, v);
    }
    union_extend(&mut base.required_or, overlay.required_or);
    union_extend(&mut base.required_xor, overlay.required_xor);
}

/// Deep-merge an overlay property schema into an existing one in place.
fn merge_prop(base: &mut PropSchema, overlay: PropSchema) {
    // An overlay that redefines the property as a `$ref` replaces it wholesale;
    // mixing a ref with the base's inline shape would be ambiguous.
    if overlay.ref_name.is_some() {
        *base = overlay;
        return;
    }

    // A `$ref` base being extended with an inline overlay can no longer be a pure
    // ref, or the inline additions would be lost when the ref is resolved. Compute
    // this before the overlay's fields are consumed below.
    let overlay_has_inline_shape =
        !overlay.properties.is_empty() || overlay.prop_type.is_some() || overlay.items.is_some();
    if base.ref_name.is_some() && overlay_has_inline_shape {
        base.ref_name = None;
    }

    if overlay.prop_type.is_some() {
        base.prop_type = overlay.prop_type;
    }
    // Enum values on the overlay replace the bundled enum for this property path.
    if !overlay.enum_values.is_empty() {
        base.enum_values = overlay.enum_values;
    }
    if !overlay.not_enum.is_empty() {
        base.not_enum = overlay.not_enum;
    }
    if overlay.const_value.is_some() {
        base.const_value = overlay.const_value;
    }
    if overlay.pattern.is_some() {
        base.pattern = overlay.pattern;
    }
    if overlay.minimum.is_some() {
        base.minimum = overlay.minimum;
    }
    if overlay.maximum.is_some() {
        base.maximum = overlay.maximum;
    }
    if overlay.exclusive_minimum.is_some() {
        base.exclusive_minimum = overlay.exclusive_minimum;
    }
    if overlay.exclusive_maximum.is_some() {
        base.exclusive_maximum = overlay.exclusive_maximum;
    }
    if overlay.min_length.is_some() {
        base.min_length = overlay.min_length;
    }
    if overlay.max_length.is_some() {
        base.max_length = overlay.max_length;
    }
    if overlay.min_items.is_some() {
        base.min_items = overlay.min_items;
    }
    if overlay.max_items.is_some() {
        base.max_items = overlay.max_items;
    }
    if overlay.unique_items {
        base.unique_items = true;
    }
    if overlay.min_properties.is_some() {
        base.min_properties = overlay.min_properties;
    }
    if overlay.max_properties.is_some() {
        base.max_properties = overlay.max_properties;
    }
    if overlay.format.is_some() {
        base.format = overlay.format;
    }
    if overlay.description.is_some() {
        base.description = overlay.description;
    }
    if overlay.additional_properties.is_some() {
        base.additional_properties = overlay.additional_properties;
    }

    for (name, prop) in overlay.properties {
        match base.properties.get_mut(&name) {
            Some(existing) => merge_prop(existing, prop),
            None => {
                base.properties.insert(name, prop);
            }
        }
    }
    union_extend(&mut base.required, overlay.required);
    for (k, v) in overlay.pattern_properties {
        base.pattern_properties.insert(k, v);
    }
    if let Some(overlay_items) = overlay.items {
        match base.items.as_mut() {
            Some(base_items) => merge_prop(base_items, *overlay_items),
            None => base.items = Some(overlay_items),
        }
    }
    base.all_of.extend(overlay.all_of);
    base.any_of.extend(overlay.any_of);
    base.one_of.extend(overlay.one_of);
    for (k, v) in overlay.dependent_required {
        base.dependent_required.insert(k, v);
    }
    for (k, v) in overlay.dependent_excluded {
        base.dependent_excluded.insert(k, v);
    }
}

/// Append items from `extra` not already present in `base`.
fn union_extend(base: &mut Vec<String>, extra: Vec<String>) {
    for item in extra {
        if !base.contains(&item) {
            base.push(item);
        }
    }
}

/// Replace `base` with `overlay` only when the overlay is non-empty.
fn replace_if_present(base: &mut Vec<String>, overlay: Vec<String>) {
    if !overlay.is_empty() {
        *base = overlay;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn compile_basic_schema() {
        let raw = json!({
            "typeName": "AWS::Foo::Bar",
            "properties": {
                "Name": { "type": "string" },
                "Size": { "type": "integer", "enum": [1, 2, 3] }
            },
            "required": ["Name"],
            "additionalProperties": false
        });
        let c = compile("AWS::Foo::Bar", &raw);
        assert_eq!(c.type_name, "AWS::Foo::Bar");
        assert!(c.properties.contains_key("Name"));
        assert_eq!(c.additional_properties, Some(false));
        assert_eq!(c.required, vec!["Name".to_string()]);
        assert_eq!(c.properties["Size"].enum_values, vec![json!(1), json!(2), json!(3)]);
    }

    #[test]
    fn compile_ref_and_property_paths() {
        let raw = json!({
            "properties": { "Cfg": { "$ref": "#/definitions/Config" } },
            "definitions": { "Config": { "type": "object" } },
            "readOnlyProperties": ["/properties/Arn", "/properties/Nested/Id"],
            "primaryIdentifier": ["/properties/Id"]
        });
        let c = compile("AWS::Test::T", &raw);
        assert_eq!(c.properties["Cfg"].ref_name.as_deref(), Some("Config"));
        assert!(c.definitions.contains_key("Config"));
        assert_eq!(c.read_only_properties, vec!["Arn".to_string(), "Nested.Id".to_string()]);
        assert_eq!(c.primary_identifier, vec!["Id".to_string()]);
    }

    #[test]
    fn merge_adds_new_property_and_keeps_base() {
        // Mirrors the AcceleratorConfig-on-Lambda spec scenario.
        let mut base = compile(
            "AWS::Lambda::Function",
            &json!({ "properties": { "Handler": { "type": "string" } }, "additionalProperties": false }),
        );
        let overlay =
            compile("AWS::Lambda::Function", &json!({ "properties": { "AcceleratorConfig": { "type": "object" } } }));
        merge_into(&mut base, overlay);
        assert!(base.properties.contains_key("Handler"), "bundled property must be retained");
        assert!(base.properties.contains_key("AcceleratorConfig"), "overlay property must be added");
        assert_eq!(base.additional_properties, Some(false), "bundled additionalProperties must be retained");
    }

    #[test]
    fn merge_replaces_enum_for_property() {
        let mut base = compile("T", &json!({ "properties": { "Mode": { "type": "string", "enum": ["A", "B"] } } }));
        let overlay = compile("T", &json!({ "properties": { "Mode": { "type": "string", "enum": ["A", "B", "C"] } } }));
        merge_into(&mut base, overlay);
        let vals: Vec<&str> = base.properties["Mode"].enum_values.iter().filter_map(|v| v.as_str()).collect();
        assert_eq!(vals, vec!["A", "B", "C"], "overlay enum must replace the bundled enum");
    }

    #[test]
    fn merge_unions_required() {
        let mut base = compile("T", &json!({ "required": ["A"] }));
        let overlay = compile("T", &json!({ "required": ["A", "B"] }));
        merge_into(&mut base, overlay);
        assert_eq!(
            base.required,
            vec!["A".to_string(), "B".to_string()],
            "required must be unioned without duplicates"
        );
    }

    #[test]
    fn merge_deep_merges_nested_properties() {
        let mut base = compile(
            "T",
            &json!({
                "properties": {
                    "Cfg": {
                        "type": "object",
                        "properties": { "X": { "type": "string" } },
                        "additionalProperties": false
                    }
                }
            }),
        );
        let overlay = compile(
            "T",
            &json!({ "properties": { "Cfg": { "type": "object", "properties": { "Y": { "type": "integer" } } } } }),
        );
        merge_into(&mut base, overlay);
        let cfg = &base.properties["Cfg"];
        assert!(cfg.properties.contains_key("X"), "nested bundled property must be retained");
        assert!(cfg.properties.contains_key("Y"), "nested overlay property must be added");
        assert_eq!(cfg.additional_properties, Some(false), "nested additionalProperties must be retained");
    }

    #[test]
    fn merge_prop_overrides_all_scalar_constraints() {
        let mut base = compile("T", &json!({ "properties": { "P": { "type": "string" } } }));
        let overlay = compile(
            "T",
            &json!({
                "properties": {
                    "P": {
                        "type": "string",
                        "pattern": "^a+$",
                        "minLength": 1, "maxLength": 10,
                        "minimum": 0.0, "maximum": 100.0,
                        "exclusiveMinimum": 1.0, "exclusiveMaximum": 99.0,
                        "minItems": 1, "maxItems": 5,
                        "uniqueItems": true,
                        "minProperties": 1, "maxProperties": 3,
                        "format": "uri",
                        "description": "desc",
                        "const": "a",
                        "not": { "enum": ["bad"] },
                        "additionalProperties": false
                    }
                }
            }),
        );
        merge_into(&mut base, overlay);
        let p = &base.properties["P"];
        assert_eq!(p.pattern.as_deref(), Some("^a+$"));
        assert_eq!(p.min_length, Some(1));
        assert_eq!(p.max_length, Some(10));
        assert_eq!(p.minimum, Some(0.0));
        assert_eq!(p.maximum, Some(100.0));
        assert_eq!(p.exclusive_minimum, Some(1.0));
        assert_eq!(p.exclusive_maximum, Some(99.0));
        assert_eq!(p.min_items, Some(1));
        assert_eq!(p.max_items, Some(5));
        assert!(p.unique_items, "unique_items must be overridden to true");
        assert_eq!(p.min_properties, Some(1));
        assert_eq!(p.max_properties, Some(3));
        assert_eq!(p.format.as_deref(), Some("uri"));
        assert_eq!(p.description.as_deref(), Some("desc"));
        assert_eq!(p.const_value, Some(json!("a")));
        assert_eq!(p.not_enum, vec![json!("bad")]);
        assert_eq!(p.additional_properties, Some(false));
    }

    #[test]
    fn merge_prop_merges_pattern_properties_and_items() {
        let mut base = compile(
            "T",
            &json!({
                "properties": {
                    "Arr": { "type": "array", "items": { "type": "string" } },
                    "Map": { "type": "object" }
                }
            }),
        );
        let overlay = compile(
            "T",
            &json!({
                "properties": {
                    "Arr": { "type": "array", "items": { "type": "string", "pattern": "^x$" } },
                    "Map": { "type": "object", "patternProperties": { "^k$": { "type": "string" } } }
                }
            }),
        );
        merge_into(&mut base, overlay);
        // items present in both → recursive merge sets the overlay's pattern.
        let items = base.properties["Arr"].items.as_ref().expect("items retained");
        assert_eq!(items.pattern.as_deref(), Some("^x$"), "nested items must be merged");
        // patternProperties absent in base → inserted from overlay.
        assert!(base.properties["Map"].pattern_properties.contains_key("^k$"), "patternProperties must be added");
    }

    #[test]
    fn merge_prop_inserts_items_when_base_has_none() {
        let mut base = compile("T", &json!({ "properties": { "Arr": { "type": "array" } } }));
        let overlay =
            compile("T", &json!({ "properties": { "Arr": { "type": "array", "items": { "type": "string" } } } }));
        merge_into(&mut base, overlay);
        assert!(base.properties["Arr"].items.is_some(), "items must be inserted when base has none");
    }

    #[test]
    fn merge_prop_merges_dependent_maps() {
        let mut base = compile("T", &json!({ "properties": { "P": { "type": "object" } } }));
        let overlay = compile(
            "T",
            &json!({
                "properties": {
                    "P": {
                        "type": "object",
                        "dependentRequired": { "A": ["B"] },
                        "dependentExcluded": { "C": ["D"] }
                    }
                }
            }),
        );
        merge_into(&mut base, overlay);
        let p = &base.properties["P"];
        assert_eq!(p.dependent_required.get("A"), Some(&vec!["B".to_string()]));
        assert_eq!(p.dependent_excluded.get("C"), Some(&vec!["D".to_string()]));
    }

    #[test]
    fn merge_prop_ref_overlay_replaces_wholesale() {
        let mut base = compile(
            "T",
            &json!({
                "properties": { "P": { "type": "string" } },
                "definitions": { "D": { "type": "object" } }
            }),
        );
        let overlay = compile(
            "T",
            &json!({
                "properties": { "P": { "$ref": "#/definitions/D" } },
                "definitions": { "D": { "type": "object" } }
            }),
        );
        merge_into(&mut base, overlay);
        assert_eq!(base.properties["P"].ref_name.as_deref(), Some("D"), "a $ref overlay replaces the property");
    }

    #[test]
    fn merge_prop_clears_ref_when_overlay_is_inline() {
        let mut base = compile("T", &json!({ "properties": { "P": { "$ref": "#/definitions/D" } } }));
        let overlay = compile(
            "T",
            &json!({ "properties": { "P": { "type": "object", "properties": { "X": { "type": "string" } } } } }),
        );
        merge_into(&mut base, overlay);
        let p = &base.properties["P"];
        assert!(p.ref_name.is_none(), "the $ref must be cleared when merged with an inline overlay");
        assert!(p.properties.contains_key("X"), "inline overlay properties must be merged in");
    }

    #[test]
    fn merge_into_overrides_schema_metadata() {
        let mut base = compile("T", &json!({ "additionalProperties": true, "description": "old" }));
        let overlay = compile(
            "T",
            &json!({
                "additionalProperties": false,
                "replacementStrategy": "delete",
                "documentationUrl": "http://docs",
                "sourceUrl": "http://src",
                "description": "new",
                "readOnlyProperties": ["/properties/Arn"]
            }),
        );
        merge_into(&mut base, overlay);
        assert_eq!(base.additional_properties, Some(false));
        assert_eq!(base.replacement_strategy.as_deref(), Some("delete"));
        assert_eq!(base.documentation_url.as_deref(), Some("http://docs"));
        assert_eq!(base.source_url.as_deref(), Some("http://src"));
        assert_eq!(base.description.as_deref(), Some("new"));
        // Non-empty overlay list replaces the (empty) bundled one.
        assert_eq!(base.read_only_properties, vec!["Arn".to_string()]);
    }

    #[test]
    fn merge_into_merges_existing_definition_and_inserts_new() {
        let mut base = compile(
            "T",
            &json!({
                "definitions": {
                    "D": { "type": "object", "properties": { "X": { "type": "string" } }, "additionalProperties": false }
                }
            }),
        );
        let overlay = compile(
            "T",
            &json!({
                "definitions": {
                    "D": { "type": "object", "properties": { "Y": { "type": "integer" } } },
                    "E": { "type": "string" }
                }
            }),
        );
        merge_into(&mut base, overlay);
        let d = &base.definitions["D"];
        assert!(d.properties.contains_key("X"), "existing definition property must be retained");
        assert!(d.properties.contains_key("Y"), "overlay definition property must be merged in");
        assert_eq!(d.additional_properties, Some(false), "existing definition metadata must be retained");
        assert!(base.definitions.contains_key("E"), "a new definition must be inserted");
    }

    #[test]
    fn merge_into_merges_schema_level_dependent_maps() {
        let mut base = compile("T", &json!({ "dependentRequired": { "A": ["B"] } }));
        let overlay =
            compile("T", &json!({ "dependentRequired": { "C": ["D"] }, "dependentExcluded": { "E": ["F"] } }));
        merge_into(&mut base, overlay);
        assert_eq!(base.dependent_required.get("A"), Some(&vec!["B".to_string()]), "base entry retained");
        assert_eq!(base.dependent_required.get("C"), Some(&vec!["D".to_string()]), "overlay entry added");
        assert_eq!(base.dependent_excluded.get("E"), Some(&vec!["F".to_string()]));
    }

    #[test]
    fn merge_prop_recurses_into_shared_nested_property() {
        // A sub-property present in BOTH base and overlay forces merge_prop to
        // recurse (the `Some` arm of its inner properties loop) rather than insert.
        let mut base = compile(
            "T",
            &json!({
                "properties": {
                    "Cfg": {
                        "type": "object",
                        "properties": {
                            "Inner": { "type": "object", "properties": { "A": { "type": "string" } } }
                        }
                    }
                }
            }),
        );
        let overlay = compile(
            "T",
            &json!({
                "properties": {
                    "Cfg": {
                        "type": "object",
                        "properties": {
                            "Inner": { "type": "object", "properties": { "B": { "type": "integer" } } }
                        }
                    }
                }
            }),
        );
        merge_into(&mut base, overlay);
        let inner = &base.properties["Cfg"].properties["Inner"].properties;
        assert!(inner.contains_key("A"), "deep bundled sub-property must be retained");
        assert!(inner.contains_key("B"), "deep overlay sub-property must be merged in");
    }
}
