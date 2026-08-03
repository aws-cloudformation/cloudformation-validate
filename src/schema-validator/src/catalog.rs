//! A centralized catalog of rule-engine–visible metadata derived from the
//! **final merged** [`CompiledSchemaStore`] for only the resource types that
//! were touched by at least one overlay.
//!
//! The catalog gives Rego and CEL engines overlay-aware data without coupling
//! them to the schema-validator internals or paying the cost of deriving it on
//! every validation call. It is built once when overlays are applied and carried
//! into the engines by reference.

use crate::compiled::{CompiledSchema, PropSchema};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Catalog of rule-engine metadata for overlaid resource types.
///
/// All vectors are sorted and deduplicated. The catalog is derived from the
/// *merged* store, so it reflects the bundled schema with overlays on top —
/// exactly what the schema validator sees.
#[derive(Debug, Clone, Default)]
pub struct OverlayCatalog {
    /// Sorted, deduplicated type names that had at least one overlay applied.
    pub type_names: Vec<String>,
    /// GetAtt attribute names per resource type (sorted/deduped readOnly paths).
    pub getatt_attributes: HashMap<String, Vec<String>>,
    /// GetAtt attribute return types per resource type: includes resolved types
    /// for ALL top-level properties, plus full-path readOnly attributes where
    /// the type is resolvable.
    pub getatt_attribute_types: HashMap<String, HashMap<String, String>>,
    /// Primary identifier property names per resource type. Excludes the entry
    /// entirely if any primary path is readOnly; includes only non-nested root
    /// property names.
    pub primary_identifiers: HashMap<String, Vec<String>>,
    /// Ref return type per resource type (derived from primary identifier types).
    /// No entry when primaryIdentifier is empty; "string" when multiple, readOnly,
    /// or unresolvable; otherwise the resolved single property type.
    pub ref_returns: HashMap<String, String>,
    /// Schema metadata matching the shape the Rego/CEL engines expect: top-level
    /// keys are resource type names, values mirror the `schema_metadata` JSON
    /// structure consumed by `schema_properties`, `schema_required`,
    /// `schema_type`, `schema_enum`, and `schema_string_length`.
    pub schema_metadata: HashMap<String, SchemaMetadataEntry>,
}

/// Per-resource-type schema metadata matching the JSON structure the engines
/// consume from the build-time `schema_metadata` artifact.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SchemaMetadataEntry {
    /// Top-level property names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub properties: Vec<String>,
    /// Top-level required property names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,
    /// Maps property name → type string (e.g. "string", "integer", "object").
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub property_types: HashMap<String, String>,
    /// Maps property name → list of allowed enum values.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub property_enums: HashMap<String, Vec<serde_json::Value>>,
    /// Maps property name → constraint object (scalar constraints like
    /// minLength, maxLength, pattern, min/max items, format, nested
    /// sub_properties, array items type/schema, etc.).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub property_constraints: HashMap<String, serde_json::Value>,
    /// Maps trigger property → list of properties that must also be present.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub dependent_required: HashMap<String, Vec<String>>,
    /// Maps trigger property → list of properties that must NOT be present.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub dependent_excluded: HashMap<String, Vec<String>>,
    /// At-least-one-of group (logical OR of required properties).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_or: Vec<String>,
    /// Exactly-one-of group (logical XOR of required properties).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_xor: Vec<String>,
}

impl OverlayCatalog {
    /// Whether the catalog is empty (no overlays contributed anything).
    pub fn is_empty(&self) -> bool {
        self.type_names.is_empty()
    }

    /// Derive the catalog from a compiled schema store for the given set of
    /// overlaid type names. Only the named types are processed.
    pub fn from_store(store: &crate::store::CompiledSchemaStore, overlaid_type_names: &[String]) -> Self {
        if overlaid_type_names.is_empty() {
            return Self::default();
        }

        let mut type_names: Vec<String> = overlaid_type_names.to_vec();
        type_names.sort();
        type_names.dedup();

        let mut getatt_attributes: HashMap<String, Vec<String>> = HashMap::new();
        let mut getatt_attribute_types: HashMap<String, HashMap<String, String>> = HashMap::new();
        let mut primary_identifiers: HashMap<String, Vec<String>> = HashMap::new();
        let mut ref_returns: HashMap<String, String> = HashMap::new();
        let mut schema_metadata: HashMap<String, SchemaMetadataEntry> = HashMap::new();

        for type_name in &type_names {
            let Some(schema) = store.get(type_name) else {
                continue;
            };

            // GetAtt attributes from read_only_properties (sorted/deduped paths)
            let attrs = derive_getatt_attributes(schema);
            if !attrs.is_empty() {
                getatt_attributes.insert(type_name.clone(), attrs.clone());
            }

            // GetAtt attribute types: ALL top-level properties plus full-path
            // readOnly attributes where type is resolvable
            let attr_types = derive_getatt_attribute_types(schema, &attrs);
            if !attr_types.is_empty() {
                getatt_attribute_types.insert(type_name.clone(), attr_types);
            }

            // Primary identifiers: exclude the whole entry if any primary path
            // is readOnly; include only non-nested root property names.
            let read_only_set: HashSet<&str> = schema.read_only_properties.iter().map(|s| s.as_str()).collect();
            if let Some(pids) = derive_primary_identifiers(schema, &read_only_set) {
                primary_identifiers.insert(type_name.clone(), pids);
            }

            // Ref return type: no entry when primaryIdentifier is empty;
            // "string" when multiple, readOnly, or unresolvable; otherwise
            // the resolved single property type.
            if let Some(ref_type) = derive_ref_return_type(schema, &read_only_set) {
                ref_returns.insert(type_name.clone(), ref_type);
            }

            // Schema metadata for the engines
            let entry = derive_schema_metadata(schema);
            schema_metadata.insert(type_name.clone(), entry);
        }

        OverlayCatalog {
            type_names,
            getatt_attributes,
            getatt_attribute_types,
            primary_identifiers,
            ref_returns,
            schema_metadata,
        }
    }
}

/// Derive GetAtt attribute names from `read_only_properties`.
///
/// Each entry in `read_only_properties` is a dot-delimited path like
/// `"Arn"` or `"Nested.Id"` (the `/properties/` prefix is stripped during
/// compilation). GetAtt attributes are the full dot paths — matching how
/// `Fn::GetAtt` uses them. Result is sorted and deduplicated.
fn derive_getatt_attributes(schema: &CompiledSchema) -> Vec<String> {
    let mut attrs: Vec<String> = schema.read_only_properties.clone();
    attrs.sort();
    attrs.dedup();
    attrs
}

/// Derive GetAtt attribute return types. Includes:
/// - Resolved types for ALL top-level properties (used for output type checking)
/// - Full-path readOnly attributes where the type is resolvable
fn derive_getatt_attribute_types(schema: &CompiledSchema, read_only_attrs: &[String]) -> HashMap<String, String> {
    let mut types = HashMap::new();

    // ALL top-level properties (matching build-time codegen which iterates
    // over raw `properties` and extracts `type`)
    for (name, prop) in &schema.properties {
        let resolved = prop.resolve(&schema.definitions);
        if let Some(pt) = resolved.prop_type.as_ref().and_then(|p| p.primary()) {
            types.insert(name.clone(), pt.to_string());
        }
    }

    // Full-path readOnly attributes (nested paths like "Config.Endpoint")
    for attr in read_only_attrs {
        if attr.contains('.')
            && let Some(prop_type) = resolve_property_type(schema, attr)
        {
            types.insert(attr.clone(), prop_type);
        }
    }

    types
}

/// Derive primary identifier property names, matching build-time semantics:
/// - Exclude the whole entry if any primary path is readOnly
/// - Include only non-nested root property names
/// - Returns None if the schema has no primaryIdentifier or should be excluded
fn derive_primary_identifiers(schema: &CompiledSchema, read_only_set: &HashSet<&str>) -> Option<Vec<String>> {
    if schema.primary_identifier.is_empty() {
        return None;
    }

    // Skip if any primary ID path is readOnly (service-generated)
    if schema.primary_identifier.iter().any(|p| read_only_set.contains(p.as_str())) {
        return None;
    }

    // Only non-nested root property names
    let props: Vec<String> = schema
        .primary_identifier
        .iter()
        .filter_map(|p| {
            // Skip nested paths
            if p.contains('.') {
                return None;
            }
            Some(p.clone())
        })
        .collect();

    // Must have the same count as primaryIdentifier (all paths must be valid roots)
    if props.is_empty() || props.len() != schema.primary_identifier.len() {
        return None;
    }

    Some(props)
}

/// Derive the Ref return type from the primary identifier's property type.
///
/// - No entry when primaryIdentifier is empty
/// - "string" when multiple identifiers, readOnly, or unresolvable
/// - Otherwise the resolved single property type
fn derive_ref_return_type(schema: &CompiledSchema, read_only_set: &HashSet<&str>) -> Option<String> {
    if schema.primary_identifier.is_empty() {
        return None;
    }

    // Multiple primary identifiers → always "string"
    if schema.primary_identifier.len() > 1 {
        return Some("string".to_string());
    }

    // Single primary identifier that is readOnly → "string"
    let id_prop = &schema.primary_identifier[0];
    if read_only_set.contains(id_prop.as_str()) {
        return Some("string".to_string());
    }

    // Single primary identifier — resolve type or fall back to "string"
    match resolve_property_type(schema, id_prop) {
        Some(t) => Some(t),
        None => Some("string".to_string()),
    }
}

/// Resolve the type of a property along a dot-separated path, following `$ref`
/// chains. Guards against recursive references.
pub(crate) fn resolve_property_type(schema: &CompiledSchema, path: &str) -> Option<String> {
    let parts: Vec<&str> = path.split('.').collect();
    resolve_nested_property_type(schema, &parts, &schema.properties, &mut HashSet::new())
}

/// Helper to resolve the type of a nested property path starting from a given
/// properties map, with cycle detection for recursive definitions.
fn resolve_nested_property_type(
    schema: &CompiledSchema,
    remaining_parts: &[&str],
    properties: &HashMap<String, PropSchema>,
    visited_refs: &mut HashSet<String>,
) -> Option<String> {
    if remaining_parts.is_empty() {
        return None;
    }
    let prop = properties.get(remaining_parts[0])?;

    // Track $ref to guard against cycles
    if let Some(ref ref_name) = prop.ref_name {
        if visited_refs.contains(ref_name) {
            return None;
        }
        visited_refs.insert(ref_name.clone());
    }

    let resolved = prop.resolve(&schema.definitions);
    if remaining_parts.len() == 1 {
        return resolved.prop_type.as_ref().and_then(|pt| pt.primary()).map(|s| s.to_string());
    }
    resolve_nested_property_type(schema, &remaining_parts[1..], &resolved.properties, visited_refs)
}

/// Build the schema metadata entry for a resource type matching the JSON shape
/// consumed by the rule engines. Recursively processes nested sub-properties
/// and array items to match the build-time `process.rs` output.
fn derive_schema_metadata(schema: &CompiledSchema) -> SchemaMetadataEntry {
    let mut properties: Vec<String> = schema.properties.keys().cloned().collect();
    properties.sort();

    let required = schema.required.clone();

    let mut property_types: HashMap<String, String> = HashMap::new();
    let mut property_enums: HashMap<String, Vec<serde_json::Value>> = HashMap::new();
    let mut property_constraints: HashMap<String, serde_json::Value> = HashMap::new();

    let mut visiting: HashSet<String> = HashSet::new();

    for (name, prop) in &schema.properties {
        // Guard recursive refs deterministically
        let ref_name = prop.ref_name.clone();
        if let Some(ref rn) = ref_name {
            if visiting.contains(rn) {
                continue;
            }
            visiting.insert(rn.clone());
        }

        let resolved = prop.resolve(&schema.definitions);
        // Type
        if let Some(pt) = resolved.prop_type.as_ref().and_then(|p| p.primary()) {
            property_types.insert(name.clone(), pt.to_string());
        }
        // Enums
        if !resolved.enum_values.is_empty() {
            property_enums.insert(name.clone(), resolved.enum_values.clone());
        } else if !resolved.enum_case_insensitive.is_empty() {
            property_enums.insert(name.clone(), resolved.enum_case_insensitive.clone());
        }
        // Constraints (scalar/format/nested/items)
        let constraint = build_property_constraint(&resolved, &schema.definitions, &mut visiting);
        if !constraint.is_null() {
            property_constraints.insert(name.clone(), constraint);
        }

        if let Some(ref rn) = ref_name {
            visiting.remove(rn);
        }
    }

    SchemaMetadataEntry {
        properties,
        required,
        property_types,
        property_enums,
        property_constraints,
        dependent_required: schema.dependent_required.clone(),
        dependent_excluded: schema.dependent_excluded.clone(),
        required_or: schema.required_or.clone(),
        required_xor: schema.required_xor.clone(),
    }
}

fn string_list_map_to_value(values: &HashMap<String, Vec<String>>) -> serde_json::Value {
    let mut keys: Vec<&String> = values.keys().collect();
    keys.sort();
    let mut object = serde_json::Map::new();
    for key in keys {
        object.insert(
            key.clone(),
            serde_json::Value::Array(values[key].iter().cloned().map(serde_json::Value::String).collect()),
        );
    }
    serde_json::Value::Object(object)
}

/// Serialize an f64 as a JSON integer when it represents a whole number,
/// matching the JSON representation that process.rs produces from raw schema
/// values (which are always parsed as serde_json::Number, not f64).
fn f64_to_json(v: f64) -> serde_json::Value {
    if v.fract() == 0.0 && v.abs() < (i64::MAX as f64) { serde_json::json!(v as i64) } else { serde_json::json!(v) }
}

/// Build the constraint JSON object for a resolved property schema.
/// Matches the build-time `extract_property_constraints` in process.rs.
fn build_property_constraint(
    prop: &PropSchema,
    definitions: &HashMap<String, PropSchema>,
    visiting: &mut HashSet<String>,
) -> serde_json::Value {
    let mut obj = serde_json::Map::new();

    if let Some(ref v) = prop.pattern {
        obj.insert("pattern".into(), serde_json::json!(v));
    }
    if let Some(v) = prop.minimum {
        obj.insert("minimum".into(), f64_to_json(v));
    }
    if let Some(v) = prop.maximum {
        obj.insert("maximum".into(), f64_to_json(v));
    }
    if let Some(v) = prop.min_length {
        obj.insert("minLength".into(), serde_json::json!(v));
    }
    if let Some(v) = prop.max_length {
        obj.insert("maxLength".into(), serde_json::json!(v));
    }
    if let Some(v) = prop.min_items {
        obj.insert("minItems".into(), serde_json::json!(v));
    }
    if let Some(v) = prop.max_items {
        obj.insert("maxItems".into(), serde_json::json!(v));
    }
    if let Some(ref v) = prop.format {
        obj.insert("format".into(), serde_json::json!(v));
    }
    if let Some(true) = prop.unique_items {
        obj.insert("uniqueItems".into(), serde_json::json!(true));
    }

    // Nested sub-properties (object type with properties)
    if !prop.properties.is_empty() {
        let sub = build_nested_metadata(&prop.properties, &prop.required, definitions, visiting);
        obj.insert("sub_properties".into(), sub);
        if !prop.dependent_required.is_empty() {
            obj.insert("dependent_required".into(), string_list_map_to_value(&prop.dependent_required));
        }
        if !prop.dependent_excluded.is_empty() {
            obj.insert("dependent_excluded".into(), string_list_map_to_value(&prop.dependent_excluded));
        }
    }

    // Array items
    if let Some(ref items_schema) = prop.items {
        let item_ref_name = items_schema.ref_name.clone();
        let skip_items = item_ref_name.as_ref().map(|n| visiting.contains(n)).unwrap_or(false);
        if !skip_items {
            if let Some(ref rn) = item_ref_name {
                visiting.insert(rn.clone());
            }
            let resolved_items = items_schema.resolve(definitions);
            let mut item_obj = serde_json::Map::new();
            if let Some(pt) = resolved_items.prop_type.as_ref().and_then(|p| p.primary()) {
                item_obj.insert("type".into(), serde_json::Value::String(pt.to_string()));
            }
            if !resolved_items.properties.is_empty() {
                let nested =
                    build_nested_metadata(&resolved_items.properties, &resolved_items.required, definitions, visiting);
                item_obj.insert("schema".into(), nested);
            }
            if !resolved_items.dependent_required.is_empty() {
                item_obj
                    .insert("dependent_required".into(), string_list_map_to_value(&resolved_items.dependent_required));
            }
            if !resolved_items.dependent_excluded.is_empty() {
                item_obj
                    .insert("dependent_excluded".into(), string_list_map_to_value(&resolved_items.dependent_excluded));
            }
            if !item_obj.is_empty() {
                obj.insert("items".into(), serde_json::Value::Object(item_obj));
            }
            if let Some(ref rn) = item_ref_name {
                visiting.remove(rn);
            }
        }
    }

    if obj.is_empty() { serde_json::Value::Null } else { serde_json::Value::Object(obj) }
}

/// Builds a nested metadata object for sub-properties, matching the recursive
/// `build_property_schema_obj` shape from process.rs.
fn build_nested_metadata(
    properties: &HashMap<String, PropSchema>,
    required: &[String],
    definitions: &HashMap<String, PropSchema>,
    visiting: &mut HashSet<String>,
) -> serde_json::Value {
    let mut props: Vec<String> = properties.keys().cloned().collect();
    props.sort();
    let req: Vec<String> = required.to_vec();
    let mut pt: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
    let mut pe: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
    let mut pc: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();

    for (pn, ps) in properties {
        let ref_name = ps.ref_name.clone();
        if let Some(ref rn) = ref_name {
            if visiting.contains(rn) {
                continue;
            }
            visiting.insert(rn.clone());
        }

        let resolved = ps.resolve(definitions);
        if let Some(t) = resolved.prop_type.as_ref().and_then(|p| p.primary()) {
            pt.insert(pn.clone(), serde_json::Value::String(t.to_string()));
        }
        if !resolved.enum_values.is_empty() {
            pe.insert(pn.clone(), serde_json::json!(resolved.enum_values));
        } else if !resolved.enum_case_insensitive.is_empty() {
            pe.insert(pn.clone(), serde_json::json!(resolved.enum_case_insensitive));
        }
        let constraints = build_property_constraint(&resolved, definitions, visiting);
        if !constraints.is_null() {
            pc.insert(pn.clone(), constraints);
        }

        if let Some(ref rn) = ref_name {
            visiting.remove(rn);
        }
    }

    let mut obj = serde_json::json!({
        "properties": props,
        "required": req,
        "property_types": pt,
        "property_enums": pe,
    });
    if !pc.is_empty() {
        obj["property_constraints"] = serde_json::Value::Object(pc);
    }
    obj
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::CompiledSchemaStore;
    use serde_json::json;

    #[test]
    fn empty_overlay_produces_empty_catalog() {
        let catalog = OverlayCatalog::from_store(&CompiledSchemaStore::new(), &[]);
        assert!(catalog.is_empty());
        assert!(catalog.type_names.is_empty());
    }

    #[test]
    fn catalog_for_existing_type_extracts_getatt_and_primary_id() {
        let store = CompiledSchemaStore::new();
        let catalog = OverlayCatalog::from_store(&store, &["AWS::S3::Bucket".to_string()]);
        assert_eq!(catalog.type_names, vec!["AWS::S3::Bucket".to_string()]);
        assert!(
            catalog.getatt_attributes.contains_key("AWS::S3::Bucket"),
            "S3 Bucket must have GetAtt attributes derived from read_only_properties"
        );
        // Attribute types must include ALL top-level properties
        let attr_types = catalog.getatt_attribute_types.get("AWS::S3::Bucket").expect("must have attr types");
        assert!(
            attr_types.len() > catalog.getatt_attributes.get("AWS::S3::Bucket").unwrap().len(),
            "attribute types must include more entries than just readOnly attributes"
        );
    }

    #[test]
    fn catalog_type_names_are_sorted_and_deduped() {
        let store = CompiledSchemaStore::new();
        let catalog = OverlayCatalog::from_store(
            &store,
            &["AWS::Lambda::Function".to_string(), "AWS::S3::Bucket".to_string(), "AWS::Lambda::Function".to_string()],
        );
        assert_eq!(catalog.type_names, vec!["AWS::Lambda::Function".to_string(), "AWS::S3::Bucket".to_string()]);
    }

    #[test]
    fn catalog_schema_metadata_includes_properties_and_types() {
        let store = CompiledSchemaStore::new();
        let catalog = OverlayCatalog::from_store(&store, &["AWS::S3::Bucket".to_string()]);
        let entry = catalog.schema_metadata.get("AWS::S3::Bucket").expect("S3 metadata must exist");
        assert!(!entry.properties.is_empty(), "S3 Bucket must have properties");
        assert!(!entry.property_types.is_empty(), "S3 Bucket must have property types");
    }

    #[test]
    fn catalog_for_unknown_type_is_skipped() {
        let store = CompiledSchemaStore::new();
        let catalog = OverlayCatalog::from_store(&store, &["AWS::Fake::NotExist".to_string()]);
        assert_eq!(catalog.type_names, vec!["AWS::Fake::NotExist".to_string()]);
        assert!(!catalog.getatt_attributes.contains_key("AWS::Fake::NotExist"));
        assert!(!catalog.schema_metadata.contains_key("AWS::Fake::NotExist"));
    }

    #[test]
    fn catalog_derives_overlay_only_type_metadata() {
        let mut store = CompiledSchemaStore::new();
        store
            .apply_overlay(
                "AWS::Test::OverlayOnly",
                &json!({
                    "properties": {
                        "Name": { "type": "string", "minLength": 1, "maxLength": 64 },
                        "Count": { "type": "integer", "enum": [1, 2, 3] },
                        "Arn": { "type": "string" }
                    },
                    "required": ["Name"],
                    "readOnlyProperties": ["/properties/Arn"],
                    "primaryIdentifier": ["/properties/Name"],
                    "additionalProperties": false
                }),
            )
            .expect("overlay applies");

        let catalog = OverlayCatalog::from_store(&store, &["AWS::Test::OverlayOnly".to_string()]);

        // GetAtt attributes (readOnly only)
        let attrs = catalog.getatt_attributes.get("AWS::Test::OverlayOnly").expect("attrs");
        assert_eq!(attrs, &vec!["Arn".to_string()]);

        // GetAtt attribute types — ALL top-level properties
        let attr_types = catalog.getatt_attribute_types.get("AWS::Test::OverlayOnly").expect("attr types");
        assert_eq!(attr_types.get("Arn"), Some(&"string".to_string()));
        assert_eq!(attr_types.get("Name"), Some(&"string".to_string()));
        assert_eq!(attr_types.get("Count"), Some(&"integer".to_string()));

        // Primary identifier (Name is not readOnly, non-nested)
        let pids = catalog.primary_identifiers.get("AWS::Test::OverlayOnly").expect("pids");
        assert_eq!(pids, &vec!["Name".to_string()]);

        // Ref return type — single string primary identifier
        assert_eq!(catalog.ref_returns.get("AWS::Test::OverlayOnly"), Some(&"string".to_string()));

        // Schema metadata
        let meta = catalog.schema_metadata.get("AWS::Test::OverlayOnly").expect("schema metadata");
        assert!(meta.properties.contains(&"Name".to_string()));
        assert!(meta.properties.contains(&"Count".to_string()));
        assert_eq!(meta.required, vec!["Name".to_string()]);
        assert_eq!(meta.property_types.get("Name"), Some(&"string".to_string()));
        assert_eq!(meta.property_types.get("Count"), Some(&"integer".to_string()));
        assert_eq!(meta.property_enums.get("Count"), Some(&vec![json!(1), json!(2), json!(3)]));

        // Constraints for Name
        let name_constraints = meta.property_constraints.get("Name").expect("Name constraints");
        assert_eq!(name_constraints.get("minLength"), Some(&json!(1)));
        assert_eq!(name_constraints.get("maxLength"), Some(&json!(64)));
    }

    #[test]
    fn catalog_readonly_primary_excludes_entry() {
        let mut store = CompiledSchemaStore::new();
        store
            .apply_overlay(
                "AWS::Test::ReadOnlyPrimary",
                &json!({
                    "properties": {
                        "Id": { "type": "string" },
                        "Name": { "type": "string" }
                    },
                    "readOnlyProperties": ["/properties/Id"],
                    "primaryIdentifier": ["/properties/Id"]
                }),
            )
            .expect("overlay applies");

        let catalog = OverlayCatalog::from_store(&store, &["AWS::Test::ReadOnlyPrimary".to_string()]);

        // Should have no primary_identifiers entry — the primary ID is readOnly
        assert!(
            !catalog.primary_identifiers.contains_key("AWS::Test::ReadOnlyPrimary"),
            "readOnly primary identifier must exclude the whole entry"
        );
        // Ref returns should be "string" — the schema has a primary identifier
        // but it's readOnly (matches build-time semantics)
        assert_eq!(
            catalog.ref_returns.get("AWS::Test::ReadOnlyPrimary"),
            Some(&"string".to_string()),
            "readOnly primary identifier produces 'string' ref type"
        );
    }

    #[test]
    fn catalog_no_primary_no_ref_returns_entry() {
        let mut store = CompiledSchemaStore::new();
        store
            .apply_overlay(
                "AWS::Test::NoPrimary",
                &json!({
                    "properties": {
                        "Name": { "type": "string" }
                    }
                }),
            )
            .expect("overlay applies");

        let catalog = OverlayCatalog::from_store(&store, &["AWS::Test::NoPrimary".to_string()]);

        assert!(!catalog.primary_identifiers.contains_key("AWS::Test::NoPrimary"));
        assert!(
            !catalog.ref_returns.contains_key("AWS::Test::NoPrimary"),
            "no ref_returns entry when primaryIdentifier is empty"
        );
    }

    #[test]
    fn catalog_all_property_getatt_types() {
        let mut store = CompiledSchemaStore::new();
        store
            .apply_overlay(
                "AWS::Test::AllProps",
                &json!({
                    "properties": {
                        "Name": { "type": "string" },
                        "Port": { "type": "integer" },
                        "Tags": { "type": "array" },
                        "Config": { "type": "object" }
                    },
                    "readOnlyProperties": ["/properties/Name"]
                }),
            )
            .expect("overlay applies");

        let catalog = OverlayCatalog::from_store(&store, &["AWS::Test::AllProps".to_string()]);

        let attr_types = catalog.getatt_attribute_types.get("AWS::Test::AllProps").expect("attr types");
        assert_eq!(attr_types.get("Name"), Some(&"string".to_string()));
        assert_eq!(attr_types.get("Port"), Some(&"integer".to_string()));
        assert_eq!(attr_types.get("Tags"), Some(&"array".to_string()));
        assert_eq!(attr_types.get("Config"), Some(&"object".to_string()));
    }

    #[test]
    fn catalog_nested_metadata_and_items() {
        let mut store = CompiledSchemaStore::new();
        store
            .apply_overlay(
                "AWS::Test::Nested",
                &json!({
                    "properties": {
                        "Config": {
                            "type": "object",
                            "properties": {
                                "Name": { "type": "string", "maxLength": 32 },
                                "Port": { "type": "integer", "minimum": 1 }
                            },
                            "required": ["Name"]
                        },
                        "Items": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "Key": { "type": "string" },
                                    "Value": { "type": "string" }
                                },
                                "required": ["Key"]
                            }
                        }
                    },
                    "additionalProperties": false
                }),
            )
            .expect("overlay applies");

        let catalog = OverlayCatalog::from_store(&store, &["AWS::Test::Nested".to_string()]);
        let meta = catalog.schema_metadata.get("AWS::Test::Nested").expect("metadata");

        // Config has sub_properties
        let config_c = meta.property_constraints.get("Config").expect("Config constraints");
        let sub = config_c.get("sub_properties").expect("sub_properties for Config");
        assert!(sub["properties"].as_array().unwrap().contains(&json!("Name")));
        assert!(sub["properties"].as_array().unwrap().contains(&json!("Port")));
        assert!(sub["required"].as_array().unwrap().contains(&json!("Name")));
        assert_eq!(sub["property_types"]["Name"], json!("string"));
        assert_eq!(sub["property_types"]["Port"], json!("integer"));
        let name_c = sub["property_constraints"]["Name"].as_object().expect("Name constraints in sub");
        assert_eq!(name_c.get("maxLength"), Some(&json!(32)));
        let port_c = sub["property_constraints"]["Port"].as_object().expect("Port constraints in sub");
        assert_eq!(port_c.get("minimum"), Some(&json!(1)));

        // Items has items schema
        let items_c = meta.property_constraints.get("Items").expect("Items constraints");
        let items = items_c.get("items").expect("items sub-schema");
        assert_eq!(items["type"], json!("object"));
        let items_schema = items.get("schema").expect("items.schema");
        assert!(items_schema["properties"].as_array().unwrap().contains(&json!("Key")));
        assert!(items_schema["required"].as_array().unwrap().contains(&json!("Key")));
    }

    #[test]
    fn catalog_recursive_refs_terminate() {
        let mut store = CompiledSchemaStore::new();
        store
            .apply_overlay(
                "AWS::Test::Recursive",
                &json!({
                    "properties": {
                        "Root": { "$ref": "#/definitions/TreeNode" }
                    },
                    "definitions": {
                        "TreeNode": {
                            "type": "object",
                            "properties": {
                                "Value": { "type": "string" },
                                "Children": {
                                    "type": "array",
                                    "items": { "$ref": "#/definitions/TreeNode" }
                                }
                            }
                        }
                    }
                }),
            )
            .expect("overlay applies");

        let catalog = OverlayCatalog::from_store(&store, &["AWS::Test::Recursive".to_string()]);
        let meta = catalog.schema_metadata.get("AWS::Test::Recursive").expect("metadata");
        // Must not panic from infinite recursion
        assert!(meta.properties.contains(&"Root".to_string()));
        assert_eq!(meta.property_types.get("Root"), Some(&"object".to_string()));
    }

    #[test]
    fn catalog_ref_type_for_integer_primary_id() {
        let mut store = CompiledSchemaStore::new();
        store
            .apply_overlay(
                "AWS::Test::IntId",
                &json!({
                    "properties": {
                        "Id": { "type": "integer" }
                    },
                    "primaryIdentifier": ["/properties/Id"]
                }),
            )
            .expect("overlay applies");

        let catalog = OverlayCatalog::from_store(&store, &["AWS::Test::IntId".to_string()]);
        assert_eq!(catalog.ref_returns.get("AWS::Test::IntId"), Some(&"integer".to_string()));
    }

    #[test]
    fn catalog_resolves_nested_ref_for_primary_id() {
        let mut store = CompiledSchemaStore::new();
        store
            .apply_overlay(
                "AWS::Test::NestedRef",
                &json!({
                    "properties": {
                        "Id": { "$ref": "#/definitions/IdDef" }
                    },
                    "definitions": {
                        "IdDef": { "type": "string", "pattern": "^[a-z]+$" }
                    },
                    "primaryIdentifier": ["/properties/Id"]
                }),
            )
            .expect("overlay applies");

        let catalog = OverlayCatalog::from_store(&store, &["AWS::Test::NestedRef".to_string()]);
        assert_eq!(
            catalog.ref_returns.get("AWS::Test::NestedRef"),
            Some(&"string".to_string()),
            "ref type must resolve through $ref chain"
        );
    }

    #[test]
    fn catalog_multiple_primary_ids_returns_string() {
        let mut store = CompiledSchemaStore::new();
        store
            .apply_overlay(
                "AWS::Test::MultiId",
                &json!({
                    "properties": {
                        "Namespace": { "type": "string" },
                        "Name": { "type": "string" }
                    },
                    "primaryIdentifier": ["/properties/Namespace", "/properties/Name"]
                }),
            )
            .expect("overlay applies");

        let catalog = OverlayCatalog::from_store(&store, &["AWS::Test::MultiId".to_string()]);
        assert_eq!(
            catalog.ref_returns.get("AWS::Test::MultiId"),
            Some(&"string".to_string()),
            "multiple primary identifiers must return 'string'"
        );
    }

    #[test]
    fn catalog_metadata_includes_format_constraint() {
        let mut store = CompiledSchemaStore::new();
        store
            .apply_overlay(
                "AWS::Test::Format",
                &json!({
                    "properties": {
                        "Email": { "type": "string", "format": "email" },
                        "Arn": { "type": "string", "format": "AWS::EC2::VPC.Id" }
                    },
                    "additionalProperties": false
                }),
            )
            .expect("overlay applies");

        let catalog = OverlayCatalog::from_store(&store, &["AWS::Test::Format".to_string()]);
        let meta = catalog.schema_metadata.get("AWS::Test::Format").expect("metadata");
        let email_c = meta.property_constraints.get("Email").expect("Email constraints");
        assert_eq!(email_c.get("format"), Some(&json!("email")));
        let arn_c = meta.property_constraints.get("Arn").expect("Arn constraints");
        assert_eq!(arn_c.get("format"), Some(&json!("AWS::EC2::VPC.Id")));
    }

    #[test]
    fn catalog_metadata_dependent_required_and_excluded() {
        let mut store = CompiledSchemaStore::new();
        store
            .apply_overlay(
                "AWS::Test::Deps",
                &json!({
                    "properties": {
                        "Mode": { "type": "string" },
                        "Config": { "type": "object" },
                        "Legacy": { "type": "boolean" }
                    },
                    "dependentRequired": { "Mode": ["Config"] },
                    "dependentExcluded": { "Mode": ["Legacy"] },
                    "additionalProperties": false
                }),
            )
            .expect("overlay applies");

        let catalog = OverlayCatalog::from_store(&store, &["AWS::Test::Deps".to_string()]);
        let meta = catalog.schema_metadata.get("AWS::Test::Deps").expect("metadata");
        assert_eq!(meta.dependent_required.get("Mode"), Some(&vec!["Config".to_string()]));
        assert_eq!(meta.dependent_excluded.get("Mode"), Some(&vec!["Legacy".to_string()]));
    }

    #[test]
    fn catalog_metadata_required_or_xor() {
        let mut store = CompiledSchemaStore::new();
        store
            .apply_overlay(
                "AWS::Test::OrXor",
                &json!({
                    "properties": {
                        "A": { "type": "string" },
                        "B": { "type": "string" },
                        "C": { "type": "string" }
                    },
                    "requiredOr": ["A", "B"],
                    "requiredXor": ["B", "C"],
                    "additionalProperties": false
                }),
            )
            .expect("overlay applies");

        let catalog = OverlayCatalog::from_store(&store, &["AWS::Test::OrXor".to_string()]);
        let meta = catalog.schema_metadata.get("AWS::Test::OrXor").expect("metadata");
        assert_eq!(meta.required_or, vec!["A".to_string(), "B".to_string()]);
        assert_eq!(meta.required_xor, vec!["B".to_string(), "C".to_string()]);
    }
}
