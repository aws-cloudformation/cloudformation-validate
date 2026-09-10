use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct KnownResourceTypes {
    pub known_resource_types: Vec<String>,
}

/// Resource type → valid GetAtt attribute names and their return types.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GetattData {
    pub getatt_attributes: HashMap<String, Vec<String>>,
    pub getatt_attribute_types: HashMap<String, HashMap<String, String>>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct StatefulResourceTypes {
    pub stateful_resource_types: HashSet<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RetentionPeriodRequirements {
    pub retention_period_requirements: HashMap<String, Vec<String>>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PrimaryIdentifiers {
    pub primary_identifiers: HashMap<String, Vec<String>>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct IamActionResourcePatterns {
    pub iam_action_resource_patterns: HashMap<String, Vec<String>>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CodepipelineArtifactCounts {
    pub codepipeline_action_artifact_counts: HashMap<String, ArtifactCountEntry>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ArtifactCountEntry {
    pub min_input: usize,
    pub max_input: usize,
    pub min_output: usize,
    pub max_output: usize,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DeprecatedResourceTypes {
    pub deprecated_resource_types: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SensitivePorts {
    pub sensitive_ports: Vec<u16>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SecretsManagerArnFields {
    pub secretsmanager_arn_fields: Vec<String>,
}

/// The committed `schema_metadata` artifact: a wrapper whose single
/// `schema_metadata` field maps each resource type name to its metadata.
///
/// This is the authoritative, recursively typed model consumed by the schema
/// validator and both rule engines. It is lossless: every field the artifact
/// carries has a typed home, and any field the current code does not model is
/// preserved verbatim in the per-level `additional` extension maps, so a future
/// artifact deserializes and reserializes without code changes.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SchemaMetadataDocument {
    pub schema_metadata: SchemaMetadataCatalog,
}

/// Resource type name to its typed schema metadata.
pub type SchemaMetadataCatalog = HashMap<String, SchemaMetadataEntry>;

/// Per-resource-type schema metadata, also used for every nested object level.
///
/// The model is recursive: a nested object reappears as a `SchemaMetadataEntry`
/// under [`SchemaPropertyConstraints::sub_properties`], and an array element
/// object reappears under [`SchemaItemsMetadata::schema`].
///
/// `properties`, `required`, `property_types`, and `property_enums` always
/// serialize, even when empty, because the generator emits them at every level;
/// preserving that presence is required for lossless round-tripping. Fields the
/// current code does not model are retained in [`Self::additional`].
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SchemaMetadataEntry {
    #[serde(default)]
    pub properties: Vec<String>,
    #[serde(default)]
    pub required: Vec<String>,
    #[serde(default)]
    pub property_types: HashMap<String, String>,
    #[serde(default)]
    pub property_enums: HashMap<String, Vec<serde_json::Value>>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub property_constraints: HashMap<String, SchemaPropertyConstraints>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub dependent_required: HashMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub dependent_excluded: HashMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_or: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_xor: Vec<String>,
    #[serde(flatten, default)]
    pub additional: BTreeMap<String, serde_json::Value>,
}

/// The constraints attached to a single property: scalar bounds, format, nested
/// object sub-properties, array item schema, and inter-property dependencies.
///
/// `minimum`/`maximum` keep the authored JSON number verbatim as a
/// [`serde_json::Number`], so an integer bound stays an integer and a decimal or
/// exponent bound keeps its precision. Length and item bounds are non-negative
/// integers and use `u64`. Unknown fields are preserved in [`Self::additional`].
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SchemaPropertyConstraints {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum: Option<serde_json::Number>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum: Option<serde_json::Number>,
    #[serde(rename = "minLength", default, skip_serializing_if = "Option::is_none")]
    pub min_length: Option<u64>,
    #[serde(rename = "maxLength", default, skip_serializing_if = "Option::is_none")]
    pub max_length: Option<u64>,
    #[serde(rename = "minItems", default, skip_serializing_if = "Option::is_none")]
    pub min_items: Option<u64>,
    #[serde(rename = "maxItems", default, skip_serializing_if = "Option::is_none")]
    pub max_items: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(rename = "uniqueItems", default, skip_serializing_if = "Option::is_none")]
    pub unique_items: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_properties: Option<Box<SchemaMetadataEntry>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<Box<SchemaItemsMetadata>>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub dependent_required: HashMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub dependent_excluded: HashMap<String, Vec<String>>,
    #[serde(flatten, default)]
    pub additional: BTreeMap<String, serde_json::Value>,
}

/// Array element metadata: the element type, a nested object schema when the
/// elements are objects, and any element-level dependencies. Recursive through
/// [`Self::schema`]. Unknown fields are preserved in [`Self::additional`].
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SchemaItemsMetadata {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub item_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<Box<SchemaMetadataEntry>>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub dependent_required: HashMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub dependent_excluded: HashMap<String, Vec<String>>,
    #[serde(flatten, default)]
    pub additional: BTreeMap<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_document_fields_must_be_present() {
        assert!(serde_json::from_str::<KnownResourceTypes>("{}").is_err());
        assert!(serde_json::from_str::<GetattData>("{}").is_err());
        assert!(serde_json::from_str::<StatefulResourceTypes>("{}").is_err());
        assert!(serde_json::from_str::<RetentionPeriodRequirements>("{}").is_err());
        assert!(serde_json::from_str::<PrimaryIdentifiers>("{}").is_err());
        assert!(serde_json::from_str::<IamActionResourcePatterns>("{}").is_err());
        assert!(serde_json::from_str::<CodepipelineArtifactCounts>("{}").is_err());
        assert!(serde_json::from_str::<DeprecatedResourceTypes>("{}").is_err());
        assert!(serde_json::from_str::<SensitivePorts>("{}").is_err());
        assert!(serde_json::from_str::<SecretsManagerArnFields>("{}").is_err());
        assert!(serde_json::from_str::<SchemaMetadataDocument>("{}").is_err());
    }

    #[test]
    fn postcard_roundtrip_known_resource_types() {
        let original =
            KnownResourceTypes { known_resource_types: vec!["AWS::S3::Bucket".into(), "AWS::EC2::Instance".into()] };
        let bytes = postcard::to_allocvec(&original).unwrap();
        let restored: KnownResourceTypes = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(restored.known_resource_types.len(), 2);
        assert!(restored.known_resource_types.contains(&"AWS::S3::Bucket".to_string()));
    }

    #[test]
    fn postcard_roundtrip_getatt_data() {
        let mut original = GetattData::default();
        original.getatt_attributes.insert("AWS::S3::Bucket".into(), vec!["Arn".into(), "DomainName".into()]);
        original
            .getatt_attribute_types
            .insert("AWS::EC2::CapacityReservation".into(), [("InstanceCount".into(), "integer".into())].into());
        let bytes = postcard::to_allocvec(&original).unwrap();
        let restored: GetattData = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(restored.getatt_attributes["AWS::S3::Bucket"].len(), 2);
        assert_eq!(restored.getatt_attribute_types["AWS::EC2::CapacityReservation"]["InstanceCount"], "integer");
    }

    #[test]
    fn postcard_roundtrip_stateful_resource_types() {
        let original = StatefulResourceTypes {
            stateful_resource_types: ["AWS::SQS::Queue".into(), "AWS::DynamoDB::Table".into()].into(),
        };
        let bytes = postcard::to_allocvec(&original).unwrap();
        let restored: StatefulResourceTypes = postcard::from_bytes(&bytes).unwrap();
        assert!(restored.stateful_resource_types.contains("AWS::SQS::Queue"));
    }

    #[test]
    fn postcard_roundtrip_retention_period_requirements() {
        let original = RetentionPeriodRequirements {
            retention_period_requirements: [("AWS::SQS::Queue".into(), vec!["MessageRetentionPeriod".into()])].into(),
        };
        let bytes = postcard::to_allocvec(&original).unwrap();
        let restored: RetentionPeriodRequirements = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(restored.retention_period_requirements["AWS::SQS::Queue"], vec!["MessageRetentionPeriod"]);
    }

    /// The whole committed `schema_metadata` artifact must survive a typed
    /// round-trip with no loss: parse it as an untyped value, parse it through
    /// the typed model, serialize the typed model back, and require the two
    /// values to be equal. `serde_json::Value` equality is order-insensitive, so
    /// only content is compared, not key order or whitespace.
    #[test]
    fn committed_schema_metadata_typed_round_trip_is_lossless() {
        let bytes = &crate::embedded::SCHEMA_METADATA_BYTES;
        let original: serde_json::Value =
            serde_json::from_slice(bytes).expect("committed schema_metadata must be valid JSON");
        let document: SchemaMetadataDocument =
            serde_json::from_slice(bytes).expect("committed schema_metadata must parse through the typed model");
        assert!(!document.schema_metadata.is_empty(), "committed schema_metadata must not be empty");
        let reserialized = serde_json::to_value(&document).expect("typed model must reserialize");
        assert_eq!(
            original, reserialized,
            "typed round-trip of the committed schema_metadata artifact dropped or changed a field"
        );
    }

    /// Every entry in the committed artifact must parse through the typed model
    /// without any value landing in an `additional` extension map - if it does,
    /// the model is missing a typed field for a value the generator emits today.
    #[test]
    fn committed_schema_metadata_has_no_unmodeled_fields() {
        let document: SchemaMetadataDocument =
            serde_json::from_slice(&crate::embedded::SCHEMA_METADATA_BYTES).expect("typed parse");
        for (type_name, entry) in &document.schema_metadata {
            assert!(
                entry.additional.is_empty(),
                "{type_name}: entry carries unmodeled fields {:?}",
                entry.additional.keys().collect::<Vec<_>>()
            );
            for (prop, constraints) in &entry.property_constraints {
                assert_constraints_fully_modeled(type_name, prop, constraints);
            }
        }
    }

    fn assert_constraints_fully_modeled(type_name: &str, prop: &str, constraints: &SchemaPropertyConstraints) {
        assert!(
            constraints.additional.is_empty(),
            "{type_name}.{prop}: constraint carries unmodeled fields {:?}",
            constraints.additional.keys().collect::<Vec<_>>()
        );
        if let Some(sub) = &constraints.sub_properties {
            assert!(
                sub.additional.is_empty(),
                "{type_name}.{prop}: sub_properties carries unmodeled fields {:?}",
                sub.additional.keys().collect::<Vec<_>>()
            );
            for (nested_prop, nested) in &sub.property_constraints {
                assert_constraints_fully_modeled(type_name, &format!("{prop}.{nested_prop}"), nested);
            }
        }
        if let Some(items) = &constraints.items {
            assert!(
                items.additional.is_empty(),
                "{type_name}.{prop}: items carries unmodeled fields {:?}",
                items.additional.keys().collect::<Vec<_>>()
            );
            if let Some(schema) = &items.schema {
                for (nested_prop, nested) in &schema.property_constraints {
                    assert_constraints_fully_modeled(type_name, &format!("{prop}[].{nested_prop}"), nested);
                }
            }
        }
    }

    /// Unknown fields at the entry, constraint, and item levels are preserved
    /// verbatim, and numbers keep their integer, decimal, and exponent JSON
    /// semantics through the flattened extension maps.
    #[test]
    fn unknown_fields_and_number_forms_survive_round_trip() {
        let synthetic = serde_json::json!({
            "schema_metadata": {
                "AWS::Test::Synthetic": {
                    "properties": ["A", "B"],
                    "required": ["A"],
                    "property_types": {"A": "string", "B": "array"},
                    "property_enums": {},
                    "property_constraints": {
                        "A": {
                            "minLength": 1,
                            "maxLength": 64,
                            "minimum": 0,
                            "maximum": 3.5,
                            "pattern": "^x$",
                            "future_int": 42,
                            "future_decimal": 1.25,
                            "future_exponent": 1e10
                        },
                        "B": {
                            "items": {
                                "type": "object",
                                "schema": {
                                    "properties": ["K"],
                                    "required": [],
                                    "property_types": {"K": "string"},
                                    "property_enums": {},
                                    "future_item_field": 7
                                },
                                "future_items_int": 99
                            }
                        }
                    },
                    "future_entry_field": {"nested": [1, 2, 3]},
                    "future_entry_int": 123
                }
            }
        });

        let document: SchemaMetadataDocument =
            serde_json::from_value(synthetic.clone()).expect("synthetic document parses");
        let reserialized = serde_json::to_value(&document).expect("synthetic document reserializes");
        assert_eq!(synthetic, reserialized, "an unknown field or number form was not preserved through the model");

        // The integer forms must remain integers, not be widened to floats.
        let entry = &document.schema_metadata["AWS::Test::Synthetic"];
        assert_eq!(entry.additional["future_entry_int"], serde_json::json!(123));
        let a = &entry.property_constraints["A"];
        assert_eq!(a.additional["future_int"], serde_json::json!(42));
        assert_eq!(a.additional["future_exponent"], serde_json::json!(1e10));
        assert_eq!(a.minimum, Some(serde_json::Number::from(0)));
    }

    /// The four always-present entry fields serialize even when empty, at the
    /// top level and at every nested level (`sub_properties`, `items.schema`).
    #[test]
    fn present_empty_base_fields_are_retained_at_every_level() {
        let source = serde_json::json!({
            "schema_metadata": {
                "AWS::Test::Empty": {
                    "properties": [],
                    "required": [],
                    "property_types": {},
                    "property_enums": {},
                    "property_constraints": {
                        "Nested": {
                            "sub_properties": {
                                "properties": [],
                                "required": [],
                                "property_types": {},
                                "property_enums": {}
                            }
                        },
                        "Arr": {
                            "items": {
                                "type": "array",
                                "schema": {
                                    "properties": [],
                                    "required": [],
                                    "property_types": {},
                                    "property_enums": {}
                                }
                            }
                        }
                    }
                }
            }
        });

        let document: SchemaMetadataDocument = serde_json::from_value(source.clone()).expect("parses");
        let reserialized = serde_json::to_value(&document).expect("reserializes");
        assert_eq!(source, reserialized, "a present-empty base field was dropped during round-trip");

        let entry = &reserialized["schema_metadata"]["AWS::Test::Empty"];
        for level in [
            entry,
            &entry["property_constraints"]["Nested"]["sub_properties"],
            &entry["property_constraints"]["Arr"]["items"]["schema"],
        ] {
            for field in ["properties", "required", "property_types", "property_enums"] {
                assert!(level.get(field).is_some(), "expected present-empty '{field}' at this level: {level}");
            }
        }
    }
}
