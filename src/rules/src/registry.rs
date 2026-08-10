use crate::category::Category;
use crate::severity::Severity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::LazyLock;

/// Static definition of a validation rule in the registry.
#[derive(Debug, Clone)]
pub struct RuleDefinition {
    pub id: &'static str,
    pub category: Category,
    pub description: &'static str,
    pub origin: RuleOrigin,
}

/// Metadata describing a validation rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct RuleInfo {
    pub id: String,
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub category: Option<String>,
    pub description: String,
    pub origin: RuleOrigin,
}

/// Where a rule's logic originates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Enum))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuleOrigin {
    /// From CloudFormation's own definitions: the resource provider schemas or
    /// the template language's structural/syntax/shape rules - anything
    /// CloudFormation itself rejects, regardless of whether cfn-lint also
    /// implements the check
    Schema,
    /// Lint judgment ported from cfn-lint
    CfnLint,
    /// Implemented in this validation engine
    Engine,
    /// User supplied custom rule
    Custom,
    /// User supplied CloudFormation Guard rule
    Guard,
}

impl RuleOrigin {
    pub const fn as_str(&self) -> &'static str {
        match self {
            RuleOrigin::Schema => "SCHEMA",
            RuleOrigin::CfnLint => "CFN_LINT",
            RuleOrigin::Engine => "ENGINE",
            RuleOrigin::Custom => "CUSTOM",
            RuleOrigin::Guard => "GUARD",
        }
    }
}

impl fmt::Display for RuleOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl RuleDefinition {
    /// Derive severity from the first character of the rule ID.
    /// Panics if the rule ID is empty - every registered rule must have a valid ID.
    pub fn severity(&self) -> Severity {
        let prefix = self.id.chars().next().unwrap_or_else(|| panic!("RuleDefinition has empty ID"));
        Severity::from_prefix(prefix)
    }

    pub fn to_rule_info(&self) -> RuleInfo {
        RuleInfo::from(self)
    }
}

impl From<&RuleDefinition> for RuleInfo {
    fn from(rule: &RuleDefinition) -> Self {
        RuleInfo {
            id: rule.id.to_string(),
            severity: rule.severity(),
            category: Some(rule.category.as_str().into()),
            description: rule.description.to_string(),
            origin: rule.origin,
        }
    }
}

/// Owned metadata for a single rule, used in engine metadata maps.
#[derive(Debug, Clone, PartialEq)]
pub struct RuleMetadataEntry {
    pub category: Option<String>,
    pub description: String,
    pub severity: Severity,
    pub origin: RuleOrigin,
}

/// Index keyed by rule ID over [`RULE_REGISTRY`] for O(1) lookups. The
/// schema validator routes every fatal/error/warn/info diagnostic through
/// [`lookup_rule`] via the shared `RegisteredDiagnostic` builder, so a per-
/// diagnostic linear scan over so many rules turned construction from O(N) into
/// O(N × R). The registry is `&'static`, so the index borrows directly.
static RULE_REGISTRY_BY_ID: LazyLock<HashMap<&'static str, &'static RuleDefinition>> =
    LazyLock::new(|| RULE_REGISTRY.iter().map(|r| (r.id, r)).collect());

/// Find a rule definition by its ID, or `None` if not registered.
pub fn lookup_rule(id: &str) -> Option<&'static RuleDefinition> {
    RULE_REGISTRY_BY_ID.get(id).copied()
}

/// Build a map of rule ID → metadata for all registered rules.
pub fn build_rule_metadata_map() -> HashMap<String, RuleMetadataEntry> {
    RULE_REGISTRY
        .iter()
        .map(|r| {
            (
                r.id.to_string(),
                RuleMetadataEntry {
                    category: Some(r.category.as_str().into()),
                    description: r.description.to_string(),
                    severity: r.severity(),
                    origin: r.origin,
                },
            )
        })
        .collect()
}

pub const RULE_REGISTRY: &[RuleDefinition] = &[
    RuleDefinition {
        id: "F0000",
        category: Category::Structure,
        description: "Duplicate key in template",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F0001",
        category: Category::Structure,
        description: "Resources section must exist and be non-empty",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "E0001",
        category: Category::Structure,
        description: "SAM (AWS::Serverless) transform would reject the template",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "F0002",
        category: Category::Structure,
        description: "AWSTemplateFormatVersion must be 2010-09-09",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F0003",
        category: Category::Structure,
        description: "Maximum 200 parameters",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F0004",
        category: Category::Structure,
        description: "Maximum 200 outputs",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F0005",
        category: Category::Structure,
        description: "Top-level keys must be valid section names",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F0006",
        category: Category::Structure,
        description: "Logical IDs must be alphanumeric",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F0007",
        category: Category::Structure,
        description: "Maximum 500 resources",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F0008",
        category: Category::Structure,
        description: "Maximum 200 mappings",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F0009",
        category: Category::Structure,
        description: "Maximum 200 conditions",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F0010",
        category: Category::Intrinsic,
        description: "Fn::Sub second argument must be a map",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F0011",
        category: Category::Structure,
        description: "Description exceeds maximum 1024 characters",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F0013",
        category: Category::Intrinsic,
        description: "Fn::If must have exactly 3 elements",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F0014",
        category: Category::Intrinsic,
        description: "Boolean condition function (Fn::Equals/Fn::And/Fn::Or/Fn::Not) has invalid structure",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F0015",
        category: Category::Parameter,
        description: "Default value must match parameter Type",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F0016",
        category: Category::Parameter,
        description: "AllowedValues entries must match parameter Type",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F0017",
        category: Category::Structure,
        description: "Mapping level must be a map",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F1004",
        category: Category::Structure,
        description: "Description must be a string",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F0040",
        category: Category::Structure,
        description: "Output must have Value property",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F0050",
        category: Category::Structure,
        description: "Mapping must have valid 3-level structure",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "E2001",
        category: Category::Parameter,
        description: "Parameters have appropriate properties",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "F2002",
        category: Category::Parameter,
        description: "Parameter Type must be valid",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F2003",
        category: Category::Parameter,
        description: "Parameter name must be alphanumeric",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F2011",
        category: Category::Parameter,
        description: "Parameter name exceeds maximum length",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F2012",
        category: Category::Parameter,
        description: "Parameter Default must be in AllowedValues",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F3007",
        category: Category::Structure,
        description: "Logical ID used as both parameter and resource",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F3016",
        category: Category::Structure,
        description: "DeletionPolicy must be valid",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F0018",
        category: Category::Structure,
        description: "UpdateReplacePolicy must be valid",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "E3038",
        category: Category::Structure,
        description: "Check if Serverless Resources have Serverless Transform",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E5001",
        category: Category::Structure,
        description: "Check that Modules resources are valid",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "F6004",
        category: Category::Structure,
        description: "Output name must be alphanumeric",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F6005",
        category: Category::Structure,
        description: "Output Export name validation",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F6011",
        category: Category::Structure,
        description: "Output name exceeds maximum length",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F6101",
        category: Category::Structure,
        description: "Output value must be a string",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F7002",
        category: Category::Structure,
        description: "Mapping name exceeds maximum length",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "E8002",
        category: Category::Structure,
        description: "Condition referenced by resource is not defined",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "I1003",
        category: Category::Structure,
        description: "Validate if we are approaching the max size of a description",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "I2010",
        category: Category::Structure,
        description: "Parameter limit",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "I2011",
        category: Category::Structure,
        description: "Parameter name limit",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "I3012",
        category: Category::Structure,
        description: "Resource name limit",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "I6010",
        category: Category::Structure,
        description: "Output limit",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "I6011",
        category: Category::Structure,
        description: "Output name limit",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "I7002",
        category: Category::Structure,
        description: "Mapping name limit",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "I7010",
        category: Category::Structure,
        description: "Mapping limit",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W2001",
        category: Category::BestPractice,
        description: "Check if Parameters are Used",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W7001",
        category: Category::BestPractice,
        description: "Check if Mappings are Used",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E8001",
        category: Category::Structure,
        description: "Conditions section must have valid structure",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "E8003",
        category: Category::Intrinsic,
        description: "Fn::Equals must take exactly two scalar operands",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "E8004",
        category: Category::Intrinsic,
        description: "Fn::And must take between 2 and 10 boolean conditions",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "E8005",
        category: Category::Intrinsic,
        description: "Fn::Not must take exactly one boolean condition",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "E8006",
        category: Category::Intrinsic,
        description: "Fn::Or must take between 2 and 10 boolean conditions",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "W8001",
        category: Category::BestPractice,
        description: "Check if Conditions are Used",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W8003",
        category: Category::BestPractice,
        description: "Fn::Equals will always return true or false",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E8007",
        category: Category::Intrinsic,
        description: "Condition function value must be a string referencing a defined condition",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F8600",
        category: Category::Structure,
        description: "Rules section must be an object",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F8601",
        category: Category::Structure,
        description: "Rule must be an object",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F8603",
        category: Category::Structure,
        description: "Rule missing required Assertions property",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F8604",
        category: Category::Structure,
        description: "Rule Assertions must be an array",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F8605",
        category: Category::Structure,
        description: "Rule Assertions must not be empty",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F8606",
        category: Category::Structure,
        description: "Rule RuleCondition must be a condition function",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F8607",
        category: Category::Structure,
        description: "Rule assertion must be an object",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F8609",
        category: Category::Structure,
        description: "Rule assertion missing required Assert property",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F8610",
        category: Category::Structure,
        description: "Rule assertion Assert must be a condition function",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F8611",
        category: Category::Structure,
        description: "Disallowed function in Rules section",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "W8602",
        category: Category::BestPractice,
        description: "Rule has unknown property",
        origin: RuleOrigin::Engine,
    },
    RuleDefinition {
        id: "W8608",
        category: Category::BestPractice,
        description: "Rule assertion has unknown property",
        origin: RuleOrigin::Engine,
    },
    RuleDefinition {
        id: "F1010",
        category: Category::Intrinsic,
        description: "Ref target must exist",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F1012",
        category: Category::Intrinsic,
        description: "FindInMap map name must exist in Mappings",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "E9003",
        category: Category::Intrinsic,
        description: "GetAtt return type may not match usage context",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "F1018",
        category: Category::Intrinsic,
        description: "Sub variables must resolve",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F1020",
        category: Category::Intrinsic,
        description: "Ref/GetAtt target must exist",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "E9004",
        category: Category::Intrinsic,
        description: "GetAtt attribute must exist on target resource type",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "E1029",
        category: Category::Intrinsic,
        description: "Substitution variable ${X} requires Fn::Sub",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E1040",
        category: Category::Intrinsic,
        description: "Check if GetAtt matches destination format",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E1041",
        category: Category::Intrinsic,
        description: "Check if Ref matches destination format",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "F1050",
        category: Category::Intrinsic,
        description: "Select index must be non-negative",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "E1028",
        category: Category::Intrinsic,
        description: "Fn::If condition must exist in Conditions section",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "E1050",
        category: Category::Intrinsic,
        description: "Dynamic reference must match the SSM, ssm-secure, or Secrets Manager format",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W1019",
        category: Category::Intrinsic,
        description: "Parameter in Fn::Sub variable map is not used in the template string",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W1051",
        category: Category::Intrinsic,
        description: "Dynamic reference resolves secret value but property expects the secret ARN",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W1054",
        category: Category::Intrinsic,
        description: "String value matches a pseudo parameter; use Ref instead",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W1100",
        category: Category::Structure,
        description: "YAML merge key '<<' is not supported by CloudFormation",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E9101",
        category: Category::Intrinsic,
        description: "Invalid nesting of intrinsic functions",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "E9106",
        category: Category::Structure,
        description: "Circular dependency in condition definitions",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F1101",
        category: Category::Structure,
        description: "Invalid YAML/JSON syntax",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "W1102",
        category: Category::BestPractice,
        description: "Invalid intrinsic function usage",
        origin: RuleOrigin::Engine,
    },
    RuleDefinition {
        id: "W1103",
        category: Category::Intrinsic,
        description: "Unknown intrinsic function name",
        origin: RuleOrigin::Engine,
    },
    RuleDefinition {
        id: "E1103",
        category: Category::Intrinsic,
        description: "Validate the format of a value",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E1150",
        category: Category::Intrinsic,
        description: "Validate security group format",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E1151",
        category: Category::Intrinsic,
        description: "Validate VPC id format",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E1152",
        category: Category::Intrinsic,
        description: "Validate AMI id format",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E1153",
        category: Category::Intrinsic,
        description: "Validate security group name",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E1154",
        category: Category::Intrinsic,
        description: "Validate VPC subnet id format",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E1155",
        category: Category::Intrinsic,
        description: "Validate CloudWatch logs group name",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E1156",
        category: Category::Intrinsic,
        description: "Validate IAM role ARN format",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "I1022",
        category: Category::Intrinsic,
        description: "Use Sub instead of Join",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W1020",
        category: Category::BestPractice,
        description: "Sub isn't needed if it doesn't have a variable defined",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "F2015",
        category: Category::Parameter,
        description: "Default value is within parameter constraints",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "W2506",
        category: Category::BestPractice,
        description: "Check if ImageId Parameters have the correct type",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "F3004",
        category: Category::Reference,
        description: "Circular dependency detected",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "E3005",
        category: Category::Reference,
        description: "Check DependsOn values for Resources",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W1001",
        category: Category::BestPractice,
        description: "Ref/GetAtt to resource that is available when conditions are applied",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W3005",
        category: Category::BestPractice,
        description: "Check obsolete DependsOn configuration for Resources",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W2503",
        category: Category::BestPractice,
        description: "Resource references conditional resource with mutually exclusive condition",
        origin: RuleOrigin::Engine,
    },
    RuleDefinition {
        id: "E2504",
        category: Category::Resource,
        description: "FIFO queue name must end with .fifo",
        origin: RuleOrigin::Engine,
    },
    RuleDefinition {
        id: "E2529",
        category: Category::Resource,
        description: "Check for SubscriptionFilters beyond 2 attachments to a CloudWatch Log Group",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E2530",
        category: Category::Resource,
        description: "SnapStart supports the configured runtime",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3001",
        category: Category::Resource,
        description: "Basic CloudFormation Resource Check",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3003",
        category: Category::Resource,
        description: "Required Resource properties are missing",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3010",
        category: Category::Resource,
        description: "Resource limit not exceeded",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3013",
        category: Category::Resource,
        description: "CloudFront Aliases",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3019",
        category: Category::Resource,
        description: "Validate that all resources have unique primary identifiers",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3022",
        category: Category::Resource,
        description: "Resource SubnetRouteTableAssociation Properties",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3024",
        category: Category::Resource,
        description: "Validate tag configuration",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3025",
        category: Category::Resource,
        description: "Validates RDS DB Instance Class",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W9006",
        category: Category::BestPractice,
        description: "String length estimation through Fn::Sub",
        origin: RuleOrigin::Engine,
    },
    RuleDefinition {
        id: "W9007",
        category: Category::BestPractice,
        description: "Array items must be unique when required",
        origin: RuleOrigin::Engine,
    },
    RuleDefinition {
        id: "W9012",
        category: Category::BestPractice,
        description: "Provided pseudo-parameter override value is not a valid AWS value",
        origin: RuleOrigin::Engine,
    },
    RuleDefinition {
        id: "F3006",
        category: Category::Schema,
        description: "AWS resource type must be recognized and available in the configured region",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "E3039",
        category: Category::Resource,
        description: "AttributeDefinitions / KeySchemas mismatch",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3041",
        category: Category::Resource,
        description: "RecordSet HostedZoneName is a superdomain of or equal to Name",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3042",
        category: Category::Resource,
        description: "Validate at least one essential container is specified",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3048",
        category: Category::Resource,
        description: "Validate ECS Fargate tasks have required properties and values",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3044",
        category: Category::Resource,
        description: "ECS service using FARGATE or EXTERNAL cannot use DAEMON scheduling",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3045",
        category: Category::Resource,
        description: "Validate AccessControl are set with OwnershipControls",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E9005",
        category: Category::Security,
        description: "IAM policy statement must have Action or NotAction",
        origin: RuleOrigin::Engine,
    },
    RuleDefinition {
        id: "E9002",
        category: Category::Resource,
        description: "SecurityGroup FromPort must be <= ToPort for the TCP and UDP protocols",
        origin: RuleOrigin::Engine,
    },
    RuleDefinition {
        id: "E3047",
        category: Category::Resource,
        description: "Validate ECS Fargate tasks have the right combination of CPU and memory",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W3049",
        category: Category::BestPractice,
        description: "ELB target group health check uses a fixed port that will not follow an ECS dynamic host port",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "I3049",
        category: Category::BestPractice,
        description: "ELB target group relies on the default traffic-port health check for an ECS dynamic host port",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3050",
        category: Category::Resource,
        description: "Check if REFing to a IAM resource with path set",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3051",
        category: Category::Resource,
        description: "Validate the structure of a SSM document",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3052",
        category: Category::Resource,
        description: "Validate ECS service requires NetworkConfiguration",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3053",
        category: Category::Resource,
        description: "Validate ECS task definition has correct values for HostPort",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3054",
        category: Category::Resource,
        description: "Validate ECS service using Fargate uses TaskDefinition that allows Fargate",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3055",
        category: Category::Resource,
        description: "Check CreationPolicy values for Resources",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3057",
        category: Category::Resource,
        description: "Validate that CloudFront TargetOriginId is a specified Origin",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3059",
        category: Category::Resource,
        description: "Validate subnet CIDRs are within the CIDRs of the VPC",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3060",
        category: Category::Resource,
        description: "Validate subnet CIDRs do not overlap with other subnets",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3061",
        category: Category::Resource,
        description: "Validate the days for tierings in IntelligentTieringConfigurations",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3677",
        category: Category::Resource,
        description: "Lambda ZipFile requires nodejs or python runtime",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3501",
        category: Category::Resource,
        description: "Validate SQS queue properties are valid",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3502",
        category: Category::Resource,
        description: "Validate SQS DLQ queues are the same type",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3504",
        category: Category::Resource,
        description: "Check minimum 90 period is met between BackupPlan cold and delete",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3505",
        category: Category::Resource,
        description: "Validate SQS VisibilityTimeout is greater than a function's Timeout",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3510",
        category: Category::Resource,
        description: "Validate identity based IAM policies",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3511",
        category: Category::Resource,
        description: "Validate IAM role arn pattern",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3512",
        category: Category::Resource,
        description: "Validate resource based IAM policies",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3513",
        category: Category::Resource,
        description: "Validate ECR repository policy",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3514",
        category: Category::Resource,
        description: "Validate IAM resource policy resource ARNs",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W3515",
        category: Category::Security,
        description: "IAM Statement must have Effect",
        origin: RuleOrigin::Engine,
    },
    RuleDefinition {
        id: "E3530",
        category: Category::Resource,
        description: "Validate IAM trust policies",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3601",
        category: Category::Resource,
        description: "Validate the structure of a StateMachine definition",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3628",
        category: Category::Resource,
        description: "Validate EC2 instance types based on region",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3635",
        category: Category::Resource,
        description: "Validate Neptune DB instance class",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3636",
        category: Category::Resource,
        description: "Validate CodeBuild projects using S3 also have Location",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3641",
        category: Category::Resource,
        description: "Validate GameLift Fleet EC2 instance type",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3660",
        category: Category::Resource,
        description: "RestApi requires a name when not using an OpenAPI specification",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3663",
        category: Category::Resource,
        description: "Validate Lambda environment variable names aren't reserved",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3667",
        category: Category::Resource,
        description: "Validate Redshift cluster node type",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3670",
        category: Category::Resource,
        description: "Validate the instance types for an AmazonMQ Broker",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3671",
        category: Category::Resource,
        description: "Validate block device mapping configuration",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3675",
        category: Category::Resource,
        description: "Validate EMR cluster instance type",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3676",
        category: Category::Resource,
        description: "Validate ELBv2 protocols that require certificates have a certificate specified",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3679",
        category: Category::Resource,
        description: "Validate ELB protocols that require certificates have a certificate specified",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3680",
        category: Category::Resource,
        description: "Application load balancers require at least 2 subnets",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3685",
        category: Category::Resource,
        description: "Container image functions cannot use Handler, Runtime, or Layers",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E9006",
        category: Category::Schema,
        description: "Property value not valid for conditional extension enum",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3698",
        category: Category::Resource,
        description: "API Gateway Stage and Deployment must use the same RestApi",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3699",
        category: Category::Resource,
        description: "API Gateway Method and Authorizer must use the same RestApi",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3700",
        category: Category::Resource,
        description: "Validate CodePipeline Source actions are only in the first stage",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3701",
        category: Category::Resource,
        description: "Validate input and output artifact names are used properly",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3702",
        category: Category::Resource,
        description: "Validate the number of input and output artifacts in a CodePipeline",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3703",
        category: Category::Resource,
        description: "Validate the configuration of a pipeline action",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3704",
        category: Category::Resource,
        description: "Validate TransitEncryptionEnabled is set when using Valkey engine",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3705",
        category: Category::Resource,
        description: "Validate SQS FIFO queue EventSourceMapping BatchSize is at most 10",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3706",
        category: Category::Resource,
        description: "MaxSize must be greater than or equal to MinSize",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3707",
        category: Category::Resource,
        description: "Validate RDS DBInstance Engine matches DBCluster Engine",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3708",
        category: Category::Resource,
        description: "API Gateway Method AuthorizationType must match Authorizer Type",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "I9002",
        category: Category::BestPractice,
        description: "Property is ignored in this configuration (from extension)",
        origin: RuleOrigin::Engine,
    },
    RuleDefinition {
        id: "I9003",
        category: Category::BestPractice,
        description: "Region-scoped values validated against all regions because no region was supplied",
        origin: RuleOrigin::Engine,
    },
    RuleDefinition {
        id: "I3037",
        category: Category::BestPractice,
        description: "Check if a list that allows duplicates has any duplicates",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "I3510",
        category: Category::Security,
        description: "Validate statement resources match the actions",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W1028",
        category: Category::BestPractice,
        description: "Check Fn::If has a path that cannot be reached",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W1030",
        category: Category::BestPractice,
        description: "Validate the values that come from a Ref function",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W1053",
        category: Category::BestPractice,
        description: "Dynamic references should not contain spaces",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W2010",
        category: Category::Security,
        description: "NoEcho parameters are not masked when used in Metadata and Outputs",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W2502",
        category: Category::BestPractice,
        description: "DependsOn conditional resource without matching condition",
        origin: RuleOrigin::Engine,
    },
    RuleDefinition {
        id: "W2530",
        category: Category::BestPractice,
        description: "Validate that SnapStart is properly configured",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W2533",
        category: Category::BestPractice,
        description: "Check required properties for Lambda if the deployment package is a .zip file",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W3010",
        category: Category::BestPractice,
        description: "Availability zone properties should not be hardcoded",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W1011",
        category: Category::Security,
        description: "Instead of REFing a parameter for a secret use a dynamic reference",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W2501",
        category: Category::Security,
        description: "Check if Password Properties are correctly configured",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W2508",
        category: Category::Security,
        description: "Security group allows open access to sensitive port",
        origin: RuleOrigin::Engine,
    },
    RuleDefinition {
        id: "W2509",
        category: Category::Security,
        description: "Password parameter should have NoEcho",
        origin: RuleOrigin::Engine,
    },
    RuleDefinition {
        id: "W2511",
        category: Category::Security,
        description: "Check IAM Resource Policies syntax",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W2512",
        category: Category::Security,
        description: "IAM policy with NotAction",
        origin: RuleOrigin::Engine,
    },
    RuleDefinition {
        id: "W9008",
        category: Category::Security,
        description: "RDS instance should have StorageEncrypted",
        origin: RuleOrigin::Engine,
    },
    RuleDefinition {
        id: "W9011",
        category: Category::Security,
        description: "RDS instance PubliclyAccessible is true",
        origin: RuleOrigin::Engine,
    },
    RuleDefinition {
        id: "W3663",
        category: Category::Security,
        description: "Validate SourceAccount is required property",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3687",
        category: Category::Resource,
        description: "Validate to and from ports based on the protocol",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W3687",
        category: Category::BestPractice,
        description: "Validate that ports aren't specified for certain protocols",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "I2530",
        category: Category::BestPractice,
        description: "Validate that SnapStart is configured for >= Java11 runtimes",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "I3011",
        category: Category::BestPractice,
        description: "Check stateful resources have a set UpdateReplacePolicy/DeletionPolicy",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "I3013",
        category: Category::BestPractice,
        description: "Check resources with auto expiring content have explicit retention period",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "I9040",
        category: Category::BestPractice,
        description: "Resource should have Tags",
        origin: RuleOrigin::Engine,
    },
    RuleDefinition {
        id: "I3042",
        category: Category::BestPractice,
        description: "ARNs should use correctly placed Pseudo Parameters",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "I3100",
        category: Category::BestPractice,
        description: "Checks for legacy instance type generations",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W9010",
        category: Category::Security,
        description: "Hardcoded AMI ID",
        origin: RuleOrigin::Engine,
    },
    RuleDefinition {
        id: "W9013",
        category: Category::Security,
        description: "Hardcoded account ID in ARN",
        origin: RuleOrigin::Engine,
    },
    RuleDefinition {
        id: "W9053",
        category: Category::BestPractice,
        description: "Conditions are semantically equivalent and can be consolidated",
        origin: RuleOrigin::Engine,
    },
    RuleDefinition {
        id: "I9052",
        category: Category::Structure,
        description: "Condition or intrinsic could not be fully analyzed because the SAT solver budget was exceeded",
        origin: RuleOrigin::Engine,
    },
    RuleDefinition {
        id: "W9002",
        category: Category::BestPractice,
        description: "Hardcoded ARN property",
        origin: RuleOrigin::Engine,
    },
    RuleDefinition {
        id: "W3011",
        category: Category::BestPractice,
        description: "Check resources with UpdateReplacePolicy/DeletionPolicy have both",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E2531",
        category: Category::Deprecation,
        description: "Check if Lambda Function Runtimes are blocked for create",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E2533",
        category: Category::Deprecation,
        description: "Check if Lambda Function Runtimes are updatable",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3710",
        category: Category::Deprecation,
        description: "Resource type is from a service that has been shut down",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W2531",
        category: Category::Deprecation,
        description: "Check if EOL Lambda Function Runtimes are used",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W3045",
        category: Category::Deprecation,
        description: "Controlling access to an S3 bucket should be done with bucket policies",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W3696",
        category: Category::Deprecation,
        description: "Resource type is from a service that is sunsetting",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W3697",
        category: Category::Deprecation,
        description: "Resource type is from a service in maintenance mode",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E6001",
        category: Category::Structure,
        description: "Outputs have appropriate properties",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E6003",
        category: Category::Structure,
        description: "Outputs section must be an object of named output definitions",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E6005",
        category: Category::Structure,
        description: "Condition referenced by an output must exist in the Conditions section",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "E7001",
        category: Category::Structure,
        description: "Mappings are appropriately configured",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3002",
        category: Category::Schema,
        description: "Resource properties are invalid",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3012",
        category: Category::Schema,
        description: "Check resource properties values",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3030",
        category: Category::Schema,
        description: "Check if properties have a valid value",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3031",
        category: Category::Schema,
        description: "Check if property values adhere to a specific pattern",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3032",
        category: Category::Schema,
        description: "Check if an array has between min and max number of values",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3034",
        category: Category::Schema,
        description: "Check if a number is between min and max",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "F3002",
        category: Category::Schema,
        description: "Additional properties are not allowed",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F3003",
        category: Category::Schema,
        description: "Required property missing",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F3012",
        category: Category::Schema,
        description: "Property type mismatch",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F3014",
        category: Category::Schema,
        description: "Exactly one of properties required (requiredXor)",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F3017",
        category: Category::Schema,
        description: "Value not valid under anyOf",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F3018",
        category: Category::Schema,
        description: "Value not valid under oneOf",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F3020",
        category: Category::Schema,
        description: "Mutually exclusive properties",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F3021",
        category: Category::Schema,
        description: "Dependent property required",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F3030",
        category: Category::Schema,
        description: "Value does not match the required constant",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "W3030",
        category: Category::Schema,
        description: "Value not in allowed enum",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "F3031",
        category: Category::Schema,
        description: "Value does not match pattern",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F3032",
        category: Category::Schema,
        description: "Array item count out of bounds",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F3033",
        category: Category::Schema,
        description: "String length out of bounds",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F3034",
        category: Category::Schema,
        description: "Numeric value out of bounds",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F3037",
        category: Category::Schema,
        description: "Array items not unique",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "E3040",
        category: Category::Schema,
        description: "Read only property should not be specified",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W9054",
        category: Category::BestPractice,
        description: "Write-only property referenced in output",
        origin: RuleOrigin::Engine,
    },
    RuleDefinition {
        id: "F3058",
        category: Category::Schema,
        description: "One of properties required (requiredOr)",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "I9001",
        category: Category::BestPractice,
        description: "Create-only property updated triggers resource replacement",
        origin: RuleOrigin::Engine,
    },
    RuleDefinition {
        id: "W9003",
        category: Category::BestPractice,
        description: "Property type coercion warning",
        origin: RuleOrigin::Engine,
    },
    RuleDefinition {
        id: "W9009",
        category: Category::Deprecation,
        description: "Resource type sunset or shutdown",
        origin: RuleOrigin::Engine,
    },
    RuleDefinition {
        id: "E1002",
        category: Category::Structure,
        description: "Validate if a template size is too large",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E1005",
        category: Category::Structure,
        description: "Validate Transform configuration",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E1015",
        category: Category::Intrinsic,
        description: "GetAz validation of parameters",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "E1016",
        category: Category::Intrinsic,
        description: "ImportValue validation of parameters",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "E1011",
        category: Category::Intrinsic,
        description: "Fn::FindInMap operands must be strings or one of Ref/Fn::FindInMap",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "E1017",
        category: Category::Intrinsic,
        description: "Fn::Select requires exactly two operands and a list source",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "E1018",
        category: Category::Intrinsic,
        description: "Fn::Split source must be a string or a string-producing intrinsic",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "E1019",
        category: Category::Intrinsic,
        description: "Fn::Sub variable map values must be strings or string-producing intrinsics",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "E1021",
        category: Category::Intrinsic,
        description: "Fn::Base64 argument must be a string or a string-producing intrinsic",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "E1022",
        category: Category::Intrinsic,
        description: "Fn::Join requires a string delimiter and a list of strings or string-producing intrinsics",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "E1024",
        category: Category::Intrinsic,
        description: "Fn::Cidr requires a CIDR-format ipBlock string and integer count/cidrBits",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "E1027",
        category: Category::Intrinsic,
        description: "Check dynamic references secure strings are in supported locations",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E1030",
        category: Category::Intrinsic,
        description: "Fn::Length argument must be an array or a list-producing function",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "E1031",
        category: Category::Intrinsic,
        description: "Fn::ToJsonString argument must be a non-empty array/object or a supported function",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F1030",
        category: Category::Intrinsic,
        description: "Fn::Length requires the AWS::LanguageExtensions transform",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F1031",
        category: Category::Intrinsic,
        description: "Fn::ToJsonString requires the AWS::LanguageExtensions transform",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "F1032",
        category: Category::Intrinsic,
        description: "Fn::ForEach requires the AWS::LanguageExtensions transform",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "E1033",
        category: Category::Intrinsic,
        description: "GetStackOutput validation of parameters",
        origin: RuleOrigin::Schema,
    },
    RuleDefinition {
        id: "E1051",
        category: Category::Intrinsic,
        description: "Validate dynamic references to secrets manager are only in resource properties",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E1052",
        category: Category::Intrinsic,
        description: "Validate dynamic references to SSM are in a valid location",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3011",
        category: Category::Resource,
        description: "Check property names in Resources",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3023",
        category: Category::Resource,
        description: "Validate Route53 RecordSets",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3026",
        category: Category::Resource,
        description: "Check Elastic Cache Redis Cluster settings",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3027",
        category: Category::Resource,
        description: "Validate AWS Event ScheduleExpression format",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3029",
        category: Category::Resource,
        description: "Validate Route53 record set aliases",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3062",
        category: Category::Resource,
        description: "Validates RDS DB Instance Class based on Engine and EngineVersion",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3617",
        category: Category::Resource,
        description: "Validate ManagedBlockchain instance type",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3620",
        category: Category::Resource,
        description: "Validate a DocDB DB Instance class",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3621",
        category: Category::Resource,
        description: "Validate the instance types for AppStream Fleet",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3647",
        category: Category::Resource,
        description: "Validate ElastiCache cluster cache node type",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3672",
        category: Category::Resource,
        description: "Validate the cluster node type for a DAX Cluster",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3694",
        category: Category::Resource,
        description: "Validates RDS DB Cluster instance class",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3640",
        category: Category::Resource,
        description: "Validate SageMaker processing instance types based on region",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3642",
        category: Category::Resource,
        description: "Validate SageMaker hosting instance types based on region",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3643",
        category: Category::Resource,
        description: "Validate SageMaker transform instance types based on region",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3644",
        category: Category::Resource,
        description: "Validate SageMaker cluster instance types based on region",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3652",
        category: Category::Resource,
        description: "Validate Elasticsearch domain cluster instance",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3653",
        category: Category::Resource,
        description: "Validate OpenSearch domain cluster instance type",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "I2003",
        category: Category::Structure,
        description: "Validate AllowedPattern is a valid regex",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W3002",
        category: Category::BestPractice,
        description: "Warn when properties are configured to only work with the package command",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W3037",
        category: Category::Security,
        description: "Check IAM Permission configuration",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W3660",
        category: Category::BestPractice,
        description: "Validate if multiple resources are modifying a Rest API definition",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W3664",
        category: Category::BestPractice,
        description: "Validate Lambda permission Principal matches SourceArn resource type",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W3671",
        category: Category::BestPractice,
        description: "Iops is ignored for certain EBS volume types",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W3688",
        category: Category::BestPractice,
        description: "When restoring DBCluster certain properties are ignored",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W3689",
        category: Category::BestPractice,
        description: "When using a source DB certain properties are ignored",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W3693",
        category: Category::BestPractice,
        description: "Validate Aurora DB cluster configuration for ignored properties",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W3694",
        category: Category::BestPractice,
        description: "SNS Subscription Endpoint should match Protocol",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "E3715",
        category: Category::Resource,
        description: "VirtualName must use ephemeral device format when Ebs is absent",
        origin: RuleOrigin::CfnLint,
    },
    RuleDefinition {
        id: "W3698",
        category: Category::BestPractice,
        description: "VirtualName is ignored when Ebs is specified",
        origin: RuleOrigin::CfnLint,
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn severity_matches_id_prefix_for_all_rules() {
        for rule in RULE_REGISTRY {
            let prefix = rule.id.chars().next().unwrap();
            let expected = Severity::from_prefix(prefix);
            assert_eq!(rule.severity(), expected, "Rule {} severity mismatch", rule.id);
        }
    }

    #[test]
    fn registry_contains_no_duplicate_ids() {
        let mut seen = HashSet::new();
        for rule in RULE_REGISTRY {
            assert!(seen.insert(rule.id), "Duplicate rule ID: {}", rule.id);
        }
    }

    #[test]
    fn lookup_rule_returns_definition_for_registered_id() {
        let rule = lookup_rule("E9002").expect("E9002 should exist");
        assert_eq!(rule.category, Category::Resource);
    }

    #[test]
    fn lookup_rule_returns_none_for_unregistered_id() {
        assert!(lookup_rule("Z9999").is_none(), "unregistered rule ID Z9999 should return None");
    }

    #[test]
    fn lookup_rule_index_covers_every_registered_rule() {
        for rule in RULE_REGISTRY {
            let looked_up =
                lookup_rule(rule.id).unwrap_or_else(|| panic!("registered rule {} is missing from the index", rule.id));
            assert_eq!(looked_up.id, rule.id);
            assert_eq!(looked_up.category, rule.category, "category mismatch for rule {}", rule.id);
            assert_eq!(looked_up.origin, rule.origin, "origin mismatch for rule {}", rule.id);
        }
        assert_eq!(
            RULE_REGISTRY_BY_ID.len(),
            RULE_REGISTRY.len(),
            "the lookup index must contain exactly one entry per registered rule"
        );
    }

    #[test]
    fn to_rule_info_populates_all_fields_from_definition() {
        let rule = lookup_rule("F0001").unwrap();
        let info = rule.to_rule_info();
        assert_eq!(info.id, "F0001");
        assert_eq!(info.severity, Severity::Fatal);
        assert_eq!(info.category.as_deref(), Some(Category::Structure.as_str()));
        assert_eq!(info.origin, RuleOrigin::Schema);
    }

    #[test]
    fn metadata_map_contains_entry_for_every_registered_rule() {
        let map = build_rule_metadata_map();
        assert_eq!(map.len(), RULE_REGISTRY.len());
        for rule in RULE_REGISTRY {
            assert!(map.contains_key(rule.id), "Missing rule: {}", rule.id);
        }
    }

    #[test]
    fn rule_origin_as_str_returns_screaming_snake_case() {
        assert_eq!(RuleOrigin::Schema.as_str(), "SCHEMA");
        assert_eq!(RuleOrigin::CfnLint.as_str(), "CFN_LINT");
        assert_eq!(RuleOrigin::Engine.as_str(), "ENGINE");
        assert_eq!(RuleOrigin::Custom.as_str(), "CUSTOM");
        assert_eq!(RuleOrigin::Guard.as_str(), "GUARD");
    }

    #[test]
    fn rule_origin_serde_round_trips() {
        for origin in
            [RuleOrigin::Schema, RuleOrigin::CfnLint, RuleOrigin::Engine, RuleOrigin::Custom, RuleOrigin::Guard]
        {
            let json = serde_json::to_string(&origin).unwrap();
            let deserialized: RuleOrigin = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, origin, "round-trip failed for {:?}", origin);
        }
    }

    #[test]
    fn rule_info_serde_round_trips() {
        let rule = lookup_rule("E3012").unwrap();
        let info = rule.to_rule_info();
        let json = serde_json::to_string(&info).unwrap();
        let deserialized: RuleInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, info.id);
        assert_eq!(deserialized.severity, info.severity);
        assert_eq!(deserialized.category, info.category);
        assert_eq!(deserialized.description, info.description);
        assert_eq!(deserialized.origin, info.origin);
    }

    #[test]
    fn rule_ids_match_expected_format() {
        let id_re = regex::Regex::new(r"^[FEWID]\d{4}$").unwrap();
        for rule in RULE_REGISTRY {
            assert!(id_re.is_match(rule.id), "Rule ID '{}' does not match [FEWID]NNNN format", rule.id);
        }
    }

    #[test]
    fn no_empty_descriptions() {
        for rule in RULE_REGISTRY {
            assert!(!rule.description.trim().is_empty(), "Rule {} has empty description", rule.id);
        }
    }
}
