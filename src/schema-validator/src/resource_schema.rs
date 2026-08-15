use crate::compiled::{CompiledSchema, PropSchema};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// JSON value categories accepted by a CloudFormation resource property.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PropertyValueType {
    Any,
    Array,
    Object,
    Boolean,
    Integer,
    Number,
    String,
}

/// Schema information needed to map an AWS API request into one resource.
///
/// This is intentionally narrower than the validator's compiled schema model:
/// callers can select and type-check resource properties without depending on
/// validation implementation details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceSchemaMetadata {
    pub type_name: String,
    pub property_types: BTreeMap<String, BTreeSet<PropertyValueType>>,
    pub required_properties: BTreeSet<String>,
    pub read_only_properties: BTreeSet<String>,
    pub primary_identifier_properties: BTreeSet<String>,
}

impl ResourceSchemaMetadata {
    pub(crate) fn from_compiled(schema: &CompiledSchema) -> Self {
        let property_types = schema
            .properties
            .iter()
            .map(|(name, property)| (name.clone(), accepted_value_types(property, &schema.definitions)))
            .collect();
        Self {
            type_name: schema.type_name.clone(),
            property_types,
            required_properties: schema.required.iter().cloned().collect(),
            read_only_properties: schema.read_only_properties.iter().cloned().collect(),
            primary_identifier_properties: schema.primary_identifier.iter().cloned().collect(),
        }
    }
}

const MAX_COMPOSITION_DEPTH: usize = 64;

fn accepted_value_types(
    property: &PropSchema,
    definitions: &HashMap<String, PropSchema>,
) -> BTreeSet<PropertyValueType> {
    let mut accepted = BTreeSet::new();
    collect_value_types(property, definitions, 0, &mut accepted);
    accepted.remove(&PropertyValueType::Any);
    if accepted.is_empty() {
        accepted.insert(PropertyValueType::Any);
    }
    accepted
}

fn collect_value_types(
    property: &PropSchema,
    definitions: &HashMap<String, PropSchema>,
    depth: usize,
    accepted: &mut BTreeSet<PropertyValueType>,
) {
    if depth >= MAX_COMPOSITION_DEPTH {
        accepted.insert(PropertyValueType::Any);
        return;
    }

    let property = property.resolve(definitions);
    if let Some(property_type) = &property.prop_type {
        for name in property_type.names() {
            match name {
                "array" => {
                    accepted.insert(PropertyValueType::Array);
                }
                "object" => {
                    accepted.insert(PropertyValueType::Object);
                }
                "boolean" => {
                    accepted.insert(PropertyValueType::Boolean);
                }
                "integer" => {
                    accepted.insert(PropertyValueType::Integer);
                }
                "number" => {
                    accepted.insert(PropertyValueType::Number);
                }
                "string" => {
                    accepted.insert(PropertyValueType::String);
                }
                "null" => {}
                _ => {
                    accepted.insert(PropertyValueType::Any);
                }
            }
        }
    }
    if property.items.is_some() || property.min_items.is_some() || property.max_items.is_some() {
        accepted.insert(PropertyValueType::Array);
    }
    if !property.properties.is_empty()
        || !property.pattern_properties.is_empty()
        || property.additional_properties.is_some()
        || property.min_properties.is_some()
        || property.max_properties.is_some()
    {
        accepted.insert(PropertyValueType::Object);
    }
    for alternative in property.all_of.iter().chain(property.any_of.iter()).chain(property.one_of.iter()) {
        collect_value_types(alternative, definitions, depth + 1, accepted);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiled::PropType;

    #[test]
    fn metadata_resolves_referenced_property_types() {
        let mut definitions = HashMap::new();
        definitions.insert(
            "Configuration".to_string(),
            PropSchema { prop_type: Some(PropType::Single("object".into())), ..Default::default() },
        );
        let schema = CompiledSchema {
            type_name: "AWS::Test::Thing".into(),
            properties: HashMap::from([(
                "Configuration".into(),
                PropSchema { ref_name: Some("Configuration".into()), ..Default::default() },
            )]),
            definitions,
            required: vec!["Configuration".into()],
            read_only_properties: vec!["Arn".into()],
            primary_identifier: vec!["Name".into()],
            ..Default::default()
        };

        let metadata = ResourceSchemaMetadata::from_compiled(&schema);

        assert_eq!(metadata.property_types["Configuration"], BTreeSet::from([PropertyValueType::Object]));
        assert!(metadata.required_properties.contains("Configuration"));
        assert!(metadata.read_only_properties.contains("Arn"));
        assert!(metadata.primary_identifier_properties.contains("Name"));
    }

    #[test]
    fn metadata_unions_composed_property_types() {
        let property = PropSchema {
            one_of: vec![
                PropSchema { prop_type: Some(PropType::Single("string".into())), ..Default::default() },
                PropSchema { prop_type: Some(PropType::Single("integer".into())), ..Default::default() },
            ],
            ..Default::default()
        };

        assert_eq!(
            accepted_value_types(&property, &HashMap::new()),
            BTreeSet::from([PropertyValueType::Integer, PropertyValueType::String])
        );
    }

    #[test]
    fn metadata_uses_any_when_no_value_type_is_known() {
        assert_eq!(
            accepted_value_types(&PropSchema::default(), &HashMap::new()),
            BTreeSet::from([PropertyValueType::Any])
        );
    }
}
