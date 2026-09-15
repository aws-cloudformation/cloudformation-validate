//! A centralized catalog of rule-engine–visible metadata derived from the
//! **final merged** [`CompiledSchemaStore`] for only the resource types that
//! were touched by at least one overlay.
//!
//! The catalog gives Rego and CEL engines overlay-aware data without coupling
//! them to the schema-validator internals or paying the cost of deriving it on
//! every validation call. It is built once when overlays are applied and carried
//! into the engines by reference.

use crate::compiled::{CompiledSchema, PropSchema};
use data_source::types::{
    SchemaMetadataCatalog, SchemaMetadataEntry, SchemaPropertyConstraints, primary_identifier_override,
};
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

/// Hand-maintained corrections for the type `Fn::GetAtt` actually returns
/// where it differs from the raw schema property type (CloudFormation
/// stringifies many GetAtt values). Applied after every runtime derivation so
/// an overlay touching a corrected type cannot regress the correction the
/// build pipeline bakes into the bundled artifacts.
pub(crate) static GETATT_RETURN_TYPE_OVERRIDES: LazyLock<HashMap<String, HashMap<String, String>>> =
    LazyLock::new(|| {
        let artifact: serde_json::Value =
            serde_json::from_slice(&data_source::embedded::GETATT_RETURN_TYPE_OVERRIDES_BYTES)
                .expect("Embedded getatt_return_type_overrides must be valid JSON");
        let overrides = artifact
            .get("getatt_return_type_overrides")
            .expect("Embedded getatt_return_type_overrides must contain getatt_return_type_overrides");
        let overrides: HashMap<String, HashMap<String, String>> = serde_json::from_value(overrides.clone())
            .expect("Embedded getatt_return_type_overrides must contain a valid override map");
        assert!(!overrides.is_empty(), "Embedded getatt_return_type_overrides must not be empty");
        overrides
    });

/// Applies the hand-maintained GetAtt return-type corrections for `type_name`
/// over a freshly derived attribute-type map.
fn apply_getatt_return_type_overrides(type_name: &str, attr_types: &mut HashMap<String, String>) {
    if let Some(corrections) = GETATT_RETURN_TYPE_OVERRIDES.get(type_name) {
        for (attribute, return_type) in corrections {
            if attr_types.contains_key(attribute) {
                attr_types.insert(attribute.clone(), return_type.clone());
            }
        }
    }
}

/// Catalog of rule-engine metadata for overlaid resource types.
///
/// All vectors are sorted and deduplicated. The catalog is derived from the
/// *merged* store, so it reflects the bundled schema with overlays on top -
/// exactly what the schema validator sees.
#[doc(hidden)]
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
    /// Per-type schema metadata for the overlaid resource types, in the same
    /// typed model the schema validator and both rule engines share. An overlay
    /// entry replaces the base catalog entry for the type it touches.
    pub schema_metadata: SchemaMetadataCatalog,
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

            let attr_types = derive_getatt_attribute_types(schema);
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
/// compilation). GetAtt attributes are the full dot paths - matching how
/// `Fn::GetAtt` uses them. Result is sorted and deduplicated.
fn derive_getatt_attributes(schema: &CompiledSchema) -> Vec<String> {
    let mut attrs: Vec<String> = schema.read_only_properties.clone();
    attrs.sort();
    attrs.dedup();
    attrs
}

/// Derive GetAtt attribute return types, matching the build-time generator:
/// - The resolved primary type of every top-level property (output string-type
///   and property type-mismatch checks look attributes up here)
/// - Every nested readOnly attribute path (such as `Endpoint.Address`) whose
///   type resolves
/// - The hand-maintained return-type corrections applied last, so an overlay
///   cannot regress them
pub(crate) fn derive_getatt_attribute_types(schema: &CompiledSchema) -> HashMap<String, String> {
    let mut types = HashMap::new();

    for (name, prop) in &schema.properties {
        let resolved = prop.resolve(&schema.definitions);
        if let Some(pt) = resolved.prop_type.as_ref().and_then(|p| p.primary()) {
            types.insert(name.clone(), pt.to_string());
        }
    }

    for attr in &schema.read_only_properties {
        if attr.contains('.')
            && let Some(prop_type) = resolve_property_type(schema, attr)
        {
            types.insert(attr.clone(), prop_type);
        }
    }

    apply_getatt_return_type_overrides(&schema.type_name, &mut types);
    types
}

/// Derive primary identifier property names, matching build-time semantics:
/// - A type in the shared override table uses its overriding properties
/// - Exclude the whole entry if any primary path is readOnly
/// - Include only non-nested root property names
/// - Returns None if the schema has no primaryIdentifier or should be excluded
fn derive_primary_identifiers(schema: &CompiledSchema, read_only_set: &HashSet<&str>) -> Option<Vec<String>> {
    if let Some(overridden) = primary_identifier_override(&schema.type_name) {
        return Some(overridden);
    }
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
pub(crate) fn derive_ref_return_type(schema: &CompiledSchema, read_only_set: &HashSet<&str>) -> Option<String> {
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

    // Single primary identifier - resolve type or fall back to "string"
    match resolve_property_type(schema, id_prop) {
        Some(t) => Some(t),
        None => Some("string".to_string()),
    }
}

/// Resolve the type of a property along a dot-separated path, following `$ref`
/// chains. Returns `None` for an empty path and guards against recursive
/// references.
pub(crate) fn resolve_property_type(schema: &CompiledSchema, path: &str) -> Option<String> {
    if path.is_empty() {
        return None;
    }
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

/// Build the schema metadata entry for a resource type in the shared typed
/// model: the type's top-level properties, each with its primary type, allowed
/// values, and own scalar constraints. Matches the build-time `process.rs`
/// output field for field, which the parity test below enforces.
fn derive_schema_metadata(schema: &CompiledSchema) -> SchemaMetadataEntry {
    let mut properties: Vec<String> = schema.properties.keys().cloned().collect();
    properties.sort();

    let mut property_types: HashMap<String, String> = HashMap::new();
    let mut property_enums: HashMap<String, Vec<serde_json::Value>> = HashMap::new();
    let mut property_constraints: HashMap<String, SchemaPropertyConstraints> = HashMap::new();

    for (name, prop) in &schema.properties {
        let resolved = prop.resolve(&schema.definitions);
        if let Some(pt) = resolved.prop_type.as_ref().and_then(|p| p.primary()) {
            property_types.insert(name.clone(), pt.to_string());
        }
        // `enum` and `enumCaseInsensitive` are one value set in two comparison
        // modes; a property carries one of them.
        if !resolved.enum_values.is_empty() {
            property_enums.insert(name.clone(), resolved.enum_values.clone());
        } else if !resolved.enum_case_insensitive.is_empty() {
            property_enums.insert(name.clone(), resolved.enum_case_insensitive.clone());
        }
        if let Some(constraint) = build_property_constraint(&resolved) {
            property_constraints.insert(name.clone(), constraint);
        }
    }

    SchemaMetadataEntry {
        properties,
        required: schema.required.clone(),
        property_types,
        property_enums,
        property_constraints,
        dependent_required: schema.dependent_required.clone(),
        dependent_excluded: schema.dependent_excluded.clone(),
        required_or: schema.required_or.clone(),
        required_xor: schema.required_xor.clone(),
        ..Default::default()
    }
}

/// Convert a schema `minimum`/`maximum` (stored as `f64`) into the JSON number
/// form the build-time artifact records: a whole value becomes an integer, and
/// any other finite value keeps its decimal form. The integer conversion
/// saturates at the `i64` range, which is how the artifact's largest bound
/// (`i64::MAX`, not exactly representable as `f64`) reads back as itself.
/// Returns `None` only for a non-finite value, which a JSON-sourced bound can
/// never be.
fn f64_to_number(value: f64) -> Option<serde_json::Number> {
    if value.fract() == 0.0 && value >= i64::MIN as f64 && value <= i64::MAX as f64 {
        Some(serde_json::Number::from(value as i64))
    } else {
        serde_json::Number::from_f64(value)
    }
}

/// Build the typed constraints for a resolved property schema, or `None` when
/// the property states no scalar constraint of its own. Matches the build-time
/// `extract_property_constraints` in process.rs.
fn build_property_constraint(prop: &PropSchema) -> Option<SchemaPropertyConstraints> {
    let constraints = SchemaPropertyConstraints {
        pattern: prop.pattern.clone(),
        minimum: prop.minimum.and_then(f64_to_number),
        maximum: prop.maximum.and_then(f64_to_number),
        min_length: prop.min_length,
        max_length: prop.max_length,
        min_items: prop.min_items,
        max_items: prop.max_items,
        format: prop.format.clone(),
        unique_items: (prop.unique_items == Some(true)).then_some(true),
        additional: Default::default(),
    };
    let SchemaPropertyConstraints {
        pattern,
        minimum,
        maximum,
        min_length,
        max_length,
        min_items,
        max_items,
        format,
        unique_items,
        additional: _,
    } = &constraints;
    let any = pattern.is_some()
        || minimum.is_some()
        || maximum.is_some()
        || min_length.is_some()
        || max_length.is_some()
        || min_items.is_some()
        || max_items.is_some()
        || format.is_some()
        || unique_items.is_some();
    any.then_some(constraints)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiled::PropType;
    use crate::store::CompiledSchemaStore;
    use serde_json::json;

    #[test]
    fn resolve_property_type_returns_none_for_empty_path() {
        let schema = CompiledSchema {
            properties: HashMap::from([(
                String::new(),
                PropSchema { prop_type: Some(PropType::Single("string".into())), ..Default::default() },
            )]),
            ..Default::default()
        };

        assert_eq!(
            resolve_property_type(&schema, ""),
            None,
            "an empty path must not resolve an empty-string property name"
        );
    }

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

        // GetAtt attribute types - ALL top-level properties
        let attr_types = catalog.getatt_attribute_types.get("AWS::Test::OverlayOnly").expect("attr types");
        assert_eq!(attr_types.get("Arn"), Some(&"string".to_string()));
        assert_eq!(attr_types.get("Name"), Some(&"string".to_string()));
        assert_eq!(attr_types.get("Count"), Some(&"integer".to_string()));

        // Primary identifier (Name is not readOnly, non-nested)
        let pids = catalog.primary_identifiers.get("AWS::Test::OverlayOnly").expect("pids");
        assert_eq!(pids, &vec!["Name".to_string()]);

        // Ref return type - single string primary identifier
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
        assert_eq!(name_constraints.min_length, Some(1));
        assert_eq!(name_constraints.max_length, Some(64));
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

        // Should have no primary_identifiers entry - the primary ID is readOnly
        assert!(
            !catalog.primary_identifiers.contains_key("AWS::Test::ReadOnlyPrimary"),
            "readOnly primary identifier must exclude the whole entry"
        );
        // Ref returns should be "string" - the schema has a primary identifier
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
    fn catalog_metadata_describes_top_level_properties_only() {
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
                            "required": ["Name"],
                            "dependentRequired": { "Name": ["Port"] }
                        },
                        "Items": {
                            "type": "array",
                            "minItems": 1,
                            "uniqueItems": true,
                            "items": {
                                "type": "object",
                                "properties": {
                                    "Key": { "type": "string" },
                                    "Value": { "type": "string" }
                                },
                                "required": ["Key"]
                            }
                        },
                        "Document": { "type": ["object", "string"] },
                        "Mode": { "type": "string", "enumCaseInsensitive": ["fast", "slow"] },
                        "Ratio": { "type": "number", "minimum": 0.5, "maximum": 2.0 }
                    },
                    "additionalProperties": false
                }),
            )
            .expect("overlay applies");

        let catalog = OverlayCatalog::from_store(&store, &["AWS::Test::Nested".to_string()]);
        let meta = catalog.schema_metadata.get("AWS::Test::Nested").expect("metadata");

        // A nested object states no scalar constraint of its own, so it has no
        // constraint entry; its sub-properties and dependency groups belong to the
        // schema validator, not the metadata.
        assert_eq!(meta.property_types.get("Config"), Some(&"object".to_string()));
        assert!(!meta.property_constraints.contains_key("Config"), "nested shape must not be repeated");
        assert!(meta.dependent_required.is_empty(), "a nested dependency group is not lifted to the resource");

        // An array records its own bounds and uniqueness, not its element schema.
        let items_c = meta.property_constraints.get("Items").expect("Items constraints");
        assert_eq!(items_c.min_items, Some(1));
        assert_eq!(items_c.unique_items, Some(true));
        assert!(items_c.additional.is_empty());

        // A union type reports its first declared member; case-insensitive enum
        // values are the property's allowed values; a whole-number bound written
        // as a float reads back as an integer.
        assert_eq!(meta.property_types.get("Document"), Some(&"object".to_string()));
        assert_eq!(meta.property_enums.get("Mode"), Some(&vec![json!("fast"), json!("slow")]));
        let ratio_c = meta.property_constraints.get("Ratio").expect("Ratio constraints");
        assert_eq!(ratio_c.minimum, Some(serde_json::Number::from_f64(0.5).expect("finite")));
        assert_eq!(ratio_c.maximum, Some(serde_json::Number::from(2)));
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
        assert_eq!(email_c.format.as_deref(), Some("email"));
        let arn_c = meta.property_constraints.get("Arn").expect("Arn constraints");
        assert_eq!(arn_c.format.as_deref(), Some("AWS::EC2::VPC.Id"));
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

    /// The runtime derivation (from `CompiledSchema`) and the committed artifact
    /// (built by `process.rs` from the raw provider schemas) are two paths to the
    /// same metadata. An overlaid type replaces its artifact entry with the derived
    /// one, so the two must agree exactly on every bundled type: property names,
    /// required lists, primary types, allowed values, scalar constraints, and
    /// dependency groups. Order-insensitive fields are compared as sets so map
    /// iteration order cannot cause a spurious mismatch.
    #[test]
    fn full_catalog_derivation_matches_committed_artifact() {
        let document: data_source::types::SchemaMetadataDocument =
            serde_json::from_slice(&data_source::embedded::SCHEMA_METADATA_BYTES).expect("committed artifact parses");
        let store = CompiledSchemaStore::new();
        let mut checked = 0usize;
        let mut mismatches: Vec<String> = Vec::new();
        for (type_name, artifact_entry) in &document.schema_metadata {
            let Some(schema) = store.get(type_name) else {
                mismatches.push(format!("{type_name}: in the artifact but not in the compiled store"));
                continue;
            };
            let derived = derive_schema_metadata(schema);
            checked += 1;

            let mut report = |field: &str, artifact: &dyn std::fmt::Debug, derived: &dyn std::fmt::Debug| {
                mismatches
                    .push(format!("{type_name}: {field} diverges\n  artifact: {artifact:?}\n  derived:  {derived:?}"));
            };
            if derived.properties != artifact_entry.properties {
                report("properties", &artifact_entry.properties, &derived.properties);
            }
            if derived.required != artifact_entry.required {
                report("required", &artifact_entry.required, &derived.required);
            }
            if derived.property_types != artifact_entry.property_types {
                report("property_types", &artifact_entry.property_types, &derived.property_types);
            }
            if derived.property_enums != artifact_entry.property_enums {
                report("property_enums", &artifact_entry.property_enums, &derived.property_enums);
            }
            let artifact_constraints = serde_json::to_value(&artifact_entry.property_constraints).expect("serializes");
            let derived_constraints = serde_json::to_value(&derived.property_constraints).expect("serializes");
            if artifact_constraints != derived_constraints {
                report("property_constraints", &artifact_constraints, &derived_constraints);
            }
            if derived.dependent_required != artifact_entry.dependent_required {
                report("dependent_required", &artifact_entry.dependent_required, &derived.dependent_required);
            }
            if derived.dependent_excluded != artifact_entry.dependent_excluded {
                report("dependent_excluded", &artifact_entry.dependent_excluded, &derived.dependent_excluded);
            }
            if derived.required_or != artifact_entry.required_or {
                report("required_or", &artifact_entry.required_or, &derived.required_or);
            }
            if derived.required_xor != artifact_entry.required_xor {
                report("required_xor", &artifact_entry.required_xor, &derived.required_xor);
            }
            assert!(derived.additional.is_empty(), "{type_name}: derived entry must not carry unmodeled fields");
        }
        assert_eq!(
            checked,
            store.len(),
            "every compiled schema must have an artifact entry (artifact has {}, store has {})",
            document.schema_metadata.len(),
            store.len()
        );
        assert!(
            mismatches.is_empty(),
            "{} bundled type(s) derive differently from the committed artifact:\n{}",
            mismatches.len(),
            mismatches.join("\n")
        );
    }

    /// The GetAtt, primary-identifier, and Ref-return catalogs the runtime derives
    /// for an overlaid type must match what the build pipeline records for the
    /// same bundled type, so applying an overlay never changes how an untouched
    /// attribute or identifier is typed. GetAtt attribute *names* are compared as
    /// a subset because the artifact also folds in the attributes CloudFormation
    /// exposes beyond the schema's readOnly properties.
    #[test]
    fn full_catalog_derivation_matches_committed_getatt_primary_and_ref_artifacts() {
        #[derive(serde::Deserialize)]
        struct RefTypesArtifact {
            ref_returns: HashMap<String, String>,
        }
        let getatt: data_source::types::GetattData =
            serde_json::from_slice(&data_source::embedded::GETATT_ATTRIBUTES_BYTES).expect("getatt artifact parses");
        let primary: data_source::types::PrimaryIdentifiers =
            serde_json::from_slice(&data_source::embedded::PRIMARY_IDENTIFIERS_BYTES).expect("primary ids parse");
        let refs: RefTypesArtifact =
            serde_json::from_slice(&data_source::embedded::REF_TYPES_BYTES).expect("ref_types artifact parses");

        let store = CompiledSchemaStore::new();
        let type_names: Vec<String> = store.type_names().map(String::from).collect();
        let catalog = OverlayCatalog::from_store(&store, &type_names);

        let mut mismatches: Vec<String> = Vec::new();
        for type_name in &type_names {
            let artifact_attrs = getatt.getatt_attributes.get(type_name).cloned().unwrap_or_default();
            for attr in catalog.getatt_attributes.get(type_name).into_iter().flatten() {
                if !artifact_attrs.contains(attr) {
                    mismatches
                        .push(format!("{type_name}: derived GetAtt attribute '{attr}' missing from the artifact"));
                }
            }
            let artifact_types = getatt.getatt_attribute_types.get(type_name).cloned().unwrap_or_default();
            let derived_types = catalog.getatt_attribute_types.get(type_name).cloned().unwrap_or_default();
            if artifact_types != derived_types {
                mismatches.push(format!(
                    "{type_name}: getatt_attribute_types diverge\n  artifact: {artifact_types:?}\n  derived:  {derived_types:?}"
                ));
            }
            if primary.primary_identifiers.get(type_name) != catalog.primary_identifiers.get(type_name) {
                mismatches.push(format!(
                    "{type_name}: primary_identifiers diverge\n  artifact: {:?}\n  derived:  {:?}",
                    primary.primary_identifiers.get(type_name),
                    catalog.primary_identifiers.get(type_name)
                ));
            }
            if refs.ref_returns.get(type_name) != catalog.ref_returns.get(type_name) {
                mismatches.push(format!(
                    "{type_name}: ref_returns diverge\n  artifact: {:?}\n  derived:  {:?}",
                    refs.ref_returns.get(type_name),
                    catalog.ref_returns.get(type_name)
                ));
            }
        }
        assert!(
            mismatches.is_empty(),
            "{} bundled type(s) derive differently from the committed artifacts:\n{}",
            mismatches.len(),
            mismatches.join("\n")
        );
    }
}
