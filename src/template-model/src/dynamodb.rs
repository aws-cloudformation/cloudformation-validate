use crate::SemanticModel;
use crate::resolved_value_to_json;
use crate::resolver::ResolvedValue;
use serde_json::{Map, Value};
use std::collections::{BTreeSet, HashMap};

const ATTRIBUTE_DEFINITIONS: &str = "AttributeDefinitions";
const ATTRIBUTE_NAME: &str = "AttributeName";
const BILLING_MODE: &str = "BillingMode";
const GLOBAL_SECONDARY_INDEXES: &str = "GlobalSecondaryIndexes";
const KEY_SCHEMA: &str = "KeySchema";
const LOCAL_SECONDARY_INDEXES: &str = "LocalSecondaryIndexes";
const PROVISIONED_THROUGHPUT: &str = "ProvisionedThroughput";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DynamoDbAttributeMismatch {
    pub missing: Vec<String>,
    pub unused: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DynamoDbScenarioAnalysis {
    pub attribute_mismatches: Vec<DynamoDbAttributeMismatch>,
    pub explicit_provisioned_missing_throughput: bool,
    pub default_provisioned_missing_throughput: bool,
}

pub fn analyze_dynamodb_table_scenarios(model: &SemanticModel, resource_id: &str) -> DynamoDbScenarioAnalysis {
    let mut analysis = DynamoDbScenarioAnalysis::default();
    let mut attribute_mismatches = BTreeSet::new();

    for (properties, conditions) in model.resolve_properties_scenarios(resource_id) {
        if !scenario_is_reachable(model, resource_id, &conditions) {
            continue;
        }
        let Some(properties) = properties_object(&properties) else {
            continue;
        };

        let throughput_missing = effective_property(&properties, PROVISIONED_THROUGHPUT).is_none();
        match effective_property(&properties, BILLING_MODE) {
            None if throughput_missing => analysis.default_provisioned_missing_throughput = true,
            Some(Value::String(mode)) if mode == "PROVISIONED" && throughput_missing => {
                analysis.explicit_provisioned_missing_throughput = true;
            }
            _ => {}
        }

        let Some(defined) = attribute_definitions(properties.get(ATTRIBUTE_DEFINITIONS)) else {
            continue;
        };
        let mut referenced = BTreeSet::new();
        let table_schema_complete = collect_key_schema(properties.get(KEY_SCHEMA), &mut referenced);
        let global_indexes_complete =
            collect_index_key_schemas(properties.get(GLOBAL_SECONDARY_INDEXES), &mut referenced);
        let local_indexes_complete =
            collect_index_key_schemas(properties.get(LOCAL_SECONDARY_INDEXES), &mut referenced);

        let missing: Vec<String> = referenced.difference(&defined).cloned().collect();
        let unused: Vec<String> = if table_schema_complete && global_indexes_complete && local_indexes_complete {
            defined.difference(&referenced).cloned().collect()
        } else {
            Vec::new()
        };
        if !missing.is_empty() || !unused.is_empty() {
            attribute_mismatches.insert(DynamoDbAttributeMismatch { missing, unused });
        }
    }

    analysis.attribute_mismatches = attribute_mismatches.into_iter().collect();
    analysis
}

fn properties_object(properties: &ResolvedValue) -> Option<Map<String, Value>> {
    match properties {
        ResolvedValue::Map { .. } | ResolvedValue::Concrete { .. } => {
            resolved_value_to_json(properties).as_object().cloned()
        }
        _ => None,
    }
}

fn effective_property<'a>(properties: &'a Map<String, Value>, name: &str) -> Option<&'a Value> {
    properties.get(name).filter(|value| !value.is_null())
}

fn attribute_definitions(value: Option<&Value>) -> Option<BTreeSet<String>> {
    let definitions = value?.as_array()?;
    let mut names = BTreeSet::new();
    for definition in definitions {
        if definition.is_null() {
            continue;
        }
        names.insert(definition.get(ATTRIBUTE_NAME)?.as_str()?.to_string());
    }
    Some(names)
}

fn collect_key_schema(value: Option<&Value>, referenced: &mut BTreeSet<String>) -> bool {
    let Some(keys) = value.and_then(Value::as_array) else {
        return false;
    };
    let mut complete = true;
    for key in keys {
        if key.is_null() {
            continue;
        }
        if let Some(name) = key.get(ATTRIBUTE_NAME).and_then(Value::as_str) {
            referenced.insert(name.to_string());
        } else {
            complete = false;
        }
    }
    complete
}

fn collect_index_key_schemas(value: Option<&Value>, referenced: &mut BTreeSet<String>) -> bool {
    let Some(value) = value else { return true };
    if value.is_null() {
        return true;
    }
    let Some(indexes) = value.as_array() else {
        return false;
    };
    let mut complete = true;
    for index in indexes {
        if index.is_null() {
            continue;
        }
        if !collect_key_schema(index.get(KEY_SCHEMA), referenced) {
            complete = false;
        }
    }
    complete
}

fn scenario_is_reachable(model: &SemanticModel, resource_id: &str, conditions: &HashMap<String, bool>) -> bool {
    let mut assumptions: Vec<(String, bool)> = conditions.iter().map(|(name, value)| (name.clone(), *value)).collect();
    if let Some(resource_condition) = model.resources.get(resource_id).and_then(|resource| resource.condition.as_ref())
    {
        match conditions.get(resource_condition) {
            Some(false) => return false,
            Some(true) => {}
            None => assumptions.push((resource_condition.clone(), true)),
        }
    }
    model.conditions.is_satisfiable(&assumptions)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze(template: &str, resource_id: &str) -> DynamoDbScenarioAnalysis {
        let model = SemanticModel::from_bytes(template.as_bytes()).unwrap();
        analyze_dynamodb_table_scenarios(&model, resource_id)
    }

    #[test]
    fn conditional_index_absence_exposes_unused_definitions() {
        let analysis = analyze(
            r#"
Conditions:
  HasIndex: !Equals [!Ref AWS::Region, us-east-1]
Resources:
  Table:
    Type: AWS::DynamoDB::Table
    Properties:
      BillingMode: PAY_PER_REQUEST
      AttributeDefinitions:
        - {AttributeName: pk, AttributeType: S}
        - {AttributeName: index_pk, AttributeType: S}
      KeySchema: [{AttributeName: pk, KeyType: HASH}]
      GlobalSecondaryIndexes: !If
        - HasIndex
        - - IndexName: by-index
            KeySchema: [{AttributeName: index_pk, KeyType: HASH}]
            Projection: {ProjectionType: ALL}
        - !Ref AWS::NoValue
"#,
            "Table",
        );
        assert_eq!(
            analysis.attribute_mismatches,
            [DynamoDbAttributeMismatch { missing: vec![], unused: vec!["index_pk".to_string()] }]
        );
    }

    #[test]
    fn correlated_index_and_definitions_are_valid_in_every_world() {
        let analysis = analyze(
            r#"
Conditions:
  HasIndex: !Equals [!Ref AWS::Region, us-east-1]
Resources:
  Table:
    Type: AWS::DynamoDB::Table
    Properties:
      BillingMode: PAY_PER_REQUEST
      AttributeDefinitions: !If
        - HasIndex
        - - {AttributeName: pk, AttributeType: S}
          - {AttributeName: index_pk, AttributeType: S}
        - - {AttributeName: pk, AttributeType: S}
      KeySchema: [{AttributeName: pk, KeyType: HASH}]
      GlobalSecondaryIndexes: !If
        - HasIndex
        - - IndexName: by-index
            KeySchema: [{AttributeName: index_pk, KeyType: HASH}]
            Projection: {ProjectionType: ALL}
        - !Ref AWS::NoValue
"#,
            "Table",
        );
        assert!(analysis.attribute_mismatches.is_empty());
    }

    #[test]
    fn throughput_requirement_follows_whole_properties_branches() {
        let template = r#"
Conditions:
  OnDemand: !Equals [!Ref AWS::Region, us-east-1]
Resources:
  Valid:
    Type: AWS::DynamoDB::Table
    Properties: !If
      - OnDemand
      - BillingMode: PAY_PER_REQUEST
      - ProvisionedThroughput: {ReadCapacityUnits: 1, WriteCapacityUnits: 1}
  Invalid:
    Type: AWS::DynamoDB::Table
    Properties: !If
      - OnDemand
      - BillingMode: PAY_PER_REQUEST
      - {}
"#;
        let valid = analyze(template, "Valid");
        assert!(!valid.explicit_provisioned_missing_throughput);
        assert!(!valid.default_provisioned_missing_throughput);
        let invalid = analyze(template, "Invalid");
        assert!(!invalid.explicit_provisioned_missing_throughput);
        assert!(invalid.default_provisioned_missing_throughput);
    }

    #[test]
    fn unknown_index_content_preserves_known_missing_checks_but_not_unused_checks() {
        let analysis = analyze(
            r#"
Parameters:
  Indexes:
    Type: String
Resources:
  Table:
    Type: AWS::DynamoDB::Table
    Properties:
      BillingMode: PAY_PER_REQUEST
      AttributeDefinitions:
        - {AttributeName: pk, AttributeType: S}
        - {AttributeName: maybe_used, AttributeType: S}
      KeySchema:
        - {AttributeName: pk, KeyType: HASH}
        - {AttributeName: missing, KeyType: RANGE}
      GlobalSecondaryIndexes: !Ref Indexes
"#,
            "Table",
        );
        assert_eq!(
            analysis.attribute_mismatches,
            [DynamoDbAttributeMismatch { missing: vec!["missing".to_string()], unused: vec![] }]
        );
    }

    #[test]
    fn resource_condition_excludes_incompatible_index_and_throughput_worlds() {
        let template = r#"
Conditions:
  IsPresent: !Equals [!Ref AWS::Region, us-east-1]
Resources:
  Table:
    Type: AWS::DynamoDB::Table
    Condition: IsPresent
    Properties: !If
      - IsPresent
      - BillingMode: PAY_PER_REQUEST
        AttributeDefinitions:
          - {AttributeName: pk, AttributeType: S}
          - {AttributeName: index_pk, AttributeType: S}
        KeySchema: [{AttributeName: pk, KeyType: HASH}]
        GlobalSecondaryIndexes:
          - IndexName: by-index
            KeySchema: [{AttributeName: index_pk, KeyType: HASH}]
            Projection: {ProjectionType: ALL}
      - AttributeDefinitions:
          - {AttributeName: pk, AttributeType: S}
          - {AttributeName: index_pk, AttributeType: S}
        KeySchema: [{AttributeName: pk, KeyType: HASH}]
"#;
        let analysis = analyze(template, "Table");
        assert!(analysis.attribute_mismatches.is_empty());
        assert!(!analysis.explicit_provisioned_missing_throughput);
        assert!(!analysis.default_provisioned_missing_throughput);
    }

    #[test]
    fn repeated_analysis_reuses_whole_properties_scenarios() {
        let model = SemanticModel::from_bytes(
            br#"{
                "Conditions": {"OnDemand": {"Fn::Equals": [{"Ref": "AWS::Region"}, "us-east-1"]}},
                "Resources": {"Table": {"Type": "AWS::DynamoDB::Table", "Properties": {"Fn::If": [
                    "OnDemand",
                    {"BillingMode": "PAY_PER_REQUEST"},
                    {"ProvisionedThroughput": {"ReadCapacityUnits": 1, "WriteCapacityUnits": 1}}
                ]}}}
            }"#,
        )
        .unwrap();
        let first = analyze_dynamodb_table_scenarios(&model, "Table");
        let combinations_after_first = model.scenario_combinations_used();
        assert!(combinations_after_first > 0);
        let second = analyze_dynamodb_table_scenarios(&model, "Table");
        assert_eq!(second, first);
        assert_eq!(model.scenario_combinations_used(), combinations_after_first);
    }
}
