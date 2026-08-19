use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

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
}
