use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;

// ──────────────────────────────────────────────────────────────────────────────
// Extension-derived RuleData (preserved)
// ──────────────────────────────────────────────────────────────────────────────

const LAMBDA_FUNCTION_EXTENSION_KEY: &str = "Aws::Lambda::Function";
const ECS_TASK_DEFINITION_EXTENSION_KEY: &str = "Aws::Ecs::Taskdefinition";
const CLASSIC_LOAD_BALANCER_EXTENSION_KEY: &str = "Aws::Elasticloadbalancing::Loadbalancer";
const LOAD_BALANCER_V2_LISTENER_EXTENSION_KEY: &str = "Aws::Elasticloadbalancingv2::Listener";

#[derive(Debug, Serialize, Deserialize)]
pub struct RuleData {
    pub classic_load_balancer_certificate_protocols: Vec<String>,
    pub fargate_supported_log_drivers: Vec<String>,
    pub lambda_image_excluded_properties: Vec<String>,
    pub lambda_reserved_environment_keys: Vec<String>,
    pub load_balancer_v2_certificate_protocols: Vec<String>,
}

pub fn derive_from_extensions(extensions: &Value) -> Result<RuleData, String> {
    Ok(RuleData {
        classic_load_balancer_certificate_protocols: extract_unique_string_array(
            extensions,
            CLASSIC_LOAD_BALANCER_EXTENSION_KEY,
            "/if/properties/Protocol/enum",
            "classic load balancer certificate protocols",
        )?,
        fargate_supported_log_drivers: extract_unique_string_array(
            extensions,
            ECS_TASK_DEFINITION_EXTENSION_KEY,
            "/then/allOf/1/properties/ContainerDefinitions/items/properties/LogConfiguration/then/properties/LogDriver/enum",
            "Fargate supported log drivers",
        )?,
        lambda_image_excluded_properties: extract_unique_string_array(
            extensions,
            LAMBDA_FUNCTION_EXTENSION_KEY,
            "/then/dependentExcluded/PackageType",
            "Lambda image excluded properties",
        )?,
        lambda_reserved_environment_keys: extract_unique_string_array(
            extensions,
            LAMBDA_FUNCTION_EXTENSION_KEY,
            "/propertyNames/not/enum",
            "Lambda reserved environment keys",
        )?,
        load_balancer_v2_certificate_protocols: extract_unique_string_array(
            extensions,
            LOAD_BALANCER_V2_LISTENER_EXTENSION_KEY,
            "/if/properties/Protocol/enum",
            "load balancer v2 certificate protocols",
        )?,
    })
}

fn extract_unique_string_array(
    extensions: &Value,
    resource_type: &str,
    pointer: &str,
    table_name: &str,
) -> Result<Vec<String>, String> {
    let resource_extensions = extensions
        .get(resource_type)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing {resource_type} extension array"))?;

    let matching_arrays: Vec<&Vec<Value>> = resource_extensions
        .iter()
        .filter_map(|extension| extension.pointer(pointer).and_then(Value::as_array))
        .collect();

    let [string_values] = matching_arrays.as_slice() else {
        return Err(format!("expected exactly one {table_name} extension, found {}", matching_arrays.len()));
    };

    let mut strings = Vec::with_capacity(string_values.len());
    let mut unique_strings = HashSet::with_capacity(string_values.len());
    for value in *string_values {
        let string = value.as_str().ok_or_else(|| format!("{table_name} entry must be a string"))?;
        if !unique_strings.insert(string) {
            return Err(format!("duplicate {table_name} entry: {string}"));
        }
        strings.push(string.to_string());
    }

    if strings.is_empty() {
        return Err(format!("{table_name} extension is empty"));
    }

    Ok(strings)
}

// ──────────────────────────────────────────────────────────────────────────────
// RuleTables: typed representation of the rule tables data document
// ──────────────────────────────────────────────────────────────────────────────

/// A parsed segment from a `Resources/<Type>/...` property path.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PathSegment {
    /// A literal property name (e.g. `Properties`, `BlockDeviceMappings`).
    Literal(String),
    /// A wildcard segment (`*`) representing any array index or map key.
    Wildcard,
}

/// A parsed `Resources/<ResourceType>/Properties/...` path from the rule tables.
///
/// These paths follow the format:
/// `Resources/<resource_type>/Properties/<prop1>/<prop2>/...`
/// where `*` segments represent iteration over array items or map entries.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResourcePropertyPath {
    /// The CloudFormation resource type (e.g. `AWS::EC2::Instance`).
    pub resource_type: String,
    /// The property path segments after `Resources/<type>/` (includes `Properties`).
    pub segments: Vec<PathSegment>,
}

impl ResourcePropertyPath {
    /// Parses a path string of the form `Resources/<type>/Properties/<seg1>/...`.
    ///
    /// Validation rules:
    /// - Must start with `Resources/`
    /// - Resource type must be a nonempty AWS type (e.g. `AWS::S3::Bucket`)
    /// - First segment after the type must be `Properties`
    /// - No literal segment may be empty
    pub fn parse(raw: &str) -> Result<Self, String> {
        let parts: Vec<&str> = raw.split('/').collect();
        if parts.is_empty() || parts[0] != "Resources" {
            return Err(format!("path must start with 'Resources/': {raw}"));
        }
        if parts.len() < 4 {
            return Err(format!("path too short, expected at least Resources/<type>/Properties/<segment>: {raw}"));
        }
        let resource_type = parts[1].to_string();
        if resource_type.is_empty() {
            return Err(format!("empty resource type in path: {raw}"));
        }
        if !resource_type.starts_with("AWS::") {
            return Err(format!("resource type must start with 'AWS::': {raw}"));
        }
        if parts[2] != "Properties" {
            return Err(format!("first segment after resource type must be 'Properties': {raw}"));
        }
        let segments: Vec<PathSegment> = parts[2..]
            .iter()
            .map(|&s| {
                if s == "*" {
                    Ok(PathSegment::Wildcard)
                } else if s.is_empty() {
                    Err(format!("empty literal segment in path: {raw}"))
                } else {
                    Ok(PathSegment::Literal(s.to_string()))
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ResourcePropertyPath { resource_type, segments })
    }
}

/// The outer wrapper for the rule tables JSON document as produced by the sync pipeline.
///
/// The source JSON has a single top-level key `cfnlint_rule_tables` wrapping all fields.
/// `deny_unknown_fields` ensures we detect schema drift at deserialization time.
/// Used at build time for validation of the generated file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleTablesDocument {
    /// The inner rule tables data.
    pub cfnlint_rule_tables: RuleTablesRaw,
}

/// Normalized document wrapper with `rule_tables` as the top-level key.
///
/// The build pipeline normalizes the source-specific outer key to `rule_tables` before
/// embedding, so runtime consumers (engines) deserialize with this struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)] // Used by library consumers; unused in build.rs compilation context.
pub struct NormalizedRuleTablesDocument {
    /// The inner rule tables data, keyed as `rule_tables`.
    pub rule_tables: RuleTablesRaw,
}

/// Raw deserialized rule tables with all 22 fields exactly as stored in JSON.
///
/// Every field uses `deny_unknown_fields` on the outer struct to reject unknown keys.
/// Path fields are stored as raw strings here; [`RuleTables`] holds the parsed forms.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleTablesRaw {
    pub api_gateway_mixing_resource_types: Vec<String>,
    pub ebs_iops_ignored_volume_types: Vec<String>,
    pub ebs_iops_property_paths: Vec<String>,
    pub iam_role_arn_property_paths: Vec<String>,
    pub image_id_parameter_types: Vec<String>,
    pub image_id_property_paths: Vec<String>,
    pub lambda_zip_required_properties: Vec<String>,
    pub package_property_paths: Vec<String>,
    pub password_property_names: Vec<String>,
    pub previous_generation_instance_pattern: String,
    pub previous_generation_instance_property_paths: Vec<String>,
    pub resource_policy_paths: Vec<String>,
    pub secret_dynamic_reference_property_paths: Vec<String>,
    pub snapshot_capable_resource_types: Vec<String>,
    pub snapstart_recommendation_excluded_runtimes: Vec<String>,
    pub snapstart_recommendation_runtime_prefixes: Vec<String>,
    pub snapstart_runtime_prefixes: Vec<String>,
    pub snapstart_supported_regions: Vec<String>,
    pub snapstart_unsupported_runtime_prefixes: Vec<String>,
    pub snapstart_unsupported_runtimes: Vec<String>,
    pub update_policy_resource_types: Vec<String>,
    pub valid_parameter_types: Vec<String>,
}

/// Validated and parsed rule tables, ready for runtime consumption.
///
/// String arrays are checked for non-emptiness and uniqueness. Property path
/// arrays are parsed into [`ResourcePropertyPath`] values. The regex pattern
/// is stored as-is (compiled by the consumer if needed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleTables {
    pub api_gateway_mixing_resource_types: Vec<String>,
    pub ebs_iops_ignored_volume_types: Vec<String>,
    pub ebs_iops_property_paths: Vec<ResourcePropertyPath>,
    pub iam_role_arn_property_paths: Vec<ResourcePropertyPath>,
    pub image_id_parameter_types: Vec<String>,
    pub image_id_property_paths: Vec<ResourcePropertyPath>,
    pub lambda_zip_required_properties: Vec<String>,
    pub package_property_paths: Vec<ResourcePropertyPath>,
    pub password_property_names: Vec<String>,
    pub previous_generation_instance_pattern: String,
    pub previous_generation_instance_property_paths: Vec<ResourcePropertyPath>,
    pub resource_policy_paths: Vec<ResourcePropertyPath>,
    pub secret_dynamic_reference_property_paths: Vec<ResourcePropertyPath>,
    pub snapshot_capable_resource_types: Vec<String>,
    pub snapstart_recommendation_excluded_runtimes: Vec<String>,
    pub snapstart_recommendation_runtime_prefixes: Vec<String>,
    pub snapstart_runtime_prefixes: Vec<String>,
    pub snapstart_supported_regions: Vec<String>,
    pub snapstart_unsupported_runtime_prefixes: Vec<String>,
    pub snapstart_unsupported_runtimes: Vec<String>,
    pub update_policy_resource_types: Vec<String>,
    pub valid_parameter_types: Vec<String>,
}

impl RuleTables {
    /// Validates and parses a [`RuleTablesRaw`] into a fully validated [`RuleTables`].
    ///
    /// Validation rules:
    /// - Every `Vec<String>` field must be non-empty, contain no empty strings, and have no duplicates.
    /// - Every `*_property_paths` / `*_paths` field must parse into valid
    ///   [`ResourcePropertyPath`] values.
    /// - `ebs_iops_property_paths` entries must have exactly 1 or 2 wildcards and end in
    ///   the `Wildcard, Literal("Ebs")` shape required by consumers.
    /// - The `previous_generation_instance_pattern` must be non-empty.
    pub fn validate(raw: RuleTablesRaw) -> Result<Self, String> {
        validate_nonempty_unique(&raw.api_gateway_mixing_resource_types, "api_gateway_mixing_resource_types")?;
        validate_nonempty_unique(&raw.ebs_iops_ignored_volume_types, "ebs_iops_ignored_volume_types")?;
        validate_nonempty_unique(&raw.ebs_iops_property_paths, "ebs_iops_property_paths")?;
        validate_nonempty_unique(&raw.iam_role_arn_property_paths, "iam_role_arn_property_paths")?;
        validate_nonempty_unique(&raw.image_id_parameter_types, "image_id_parameter_types")?;
        validate_nonempty_unique(&raw.image_id_property_paths, "image_id_property_paths")?;
        validate_nonempty_unique(&raw.lambda_zip_required_properties, "lambda_zip_required_properties")?;
        validate_nonempty_unique(&raw.package_property_paths, "package_property_paths")?;
        validate_nonempty_unique(&raw.password_property_names, "password_property_names")?;
        validate_nonempty_unique(
            &raw.previous_generation_instance_property_paths,
            "previous_generation_instance_property_paths",
        )?;
        validate_nonempty_unique(&raw.resource_policy_paths, "resource_policy_paths")?;
        validate_nonempty_unique(
            &raw.secret_dynamic_reference_property_paths,
            "secret_dynamic_reference_property_paths",
        )?;
        validate_nonempty_unique(&raw.snapshot_capable_resource_types, "snapshot_capable_resource_types")?;
        validate_nonempty_unique(
            &raw.snapstart_recommendation_excluded_runtimes,
            "snapstart_recommendation_excluded_runtimes",
        )?;
        validate_nonempty_unique(
            &raw.snapstart_recommendation_runtime_prefixes,
            "snapstart_recommendation_runtime_prefixes",
        )?;
        validate_nonempty_unique(&raw.snapstart_runtime_prefixes, "snapstart_runtime_prefixes")?;
        validate_nonempty_unique(&raw.snapstart_supported_regions, "snapstart_supported_regions")?;
        validate_nonempty_unique(
            &raw.snapstart_unsupported_runtime_prefixes,
            "snapstart_unsupported_runtime_prefixes",
        )?;
        validate_nonempty_unique(&raw.snapstart_unsupported_runtimes, "snapstart_unsupported_runtimes")?;
        validate_nonempty_unique(&raw.update_policy_resource_types, "update_policy_resource_types")?;
        validate_nonempty_unique(&raw.valid_parameter_types, "valid_parameter_types")?;

        if raw.previous_generation_instance_pattern.is_empty() {
            return Err("previous_generation_instance_pattern must not be empty".to_string());
        }

        let ebs_iops_property_paths = parse_paths(&raw.ebs_iops_property_paths, "ebs_iops_property_paths")?;
        validate_ebs_iops_shape(&ebs_iops_property_paths)?;
        let iam_role_arn_property_paths = parse_paths(&raw.iam_role_arn_property_paths, "iam_role_arn_property_paths")?;
        let image_id_property_paths = parse_paths(&raw.image_id_property_paths, "image_id_property_paths")?;
        let package_property_paths = parse_paths(&raw.package_property_paths, "package_property_paths")?;
        let previous_generation_instance_property_paths = parse_paths(
            &raw.previous_generation_instance_property_paths,
            "previous_generation_instance_property_paths",
        )?;
        let resource_policy_paths = parse_paths(&raw.resource_policy_paths, "resource_policy_paths")?;
        let secret_dynamic_reference_property_paths =
            parse_paths(&raw.secret_dynamic_reference_property_paths, "secret_dynamic_reference_property_paths")?;

        Ok(RuleTables {
            api_gateway_mixing_resource_types: raw.api_gateway_mixing_resource_types,
            ebs_iops_ignored_volume_types: raw.ebs_iops_ignored_volume_types,
            ebs_iops_property_paths,
            iam_role_arn_property_paths,
            image_id_parameter_types: raw.image_id_parameter_types,
            image_id_property_paths,
            lambda_zip_required_properties: raw.lambda_zip_required_properties,
            package_property_paths,
            password_property_names: raw.password_property_names,
            previous_generation_instance_pattern: raw.previous_generation_instance_pattern,
            previous_generation_instance_property_paths,
            resource_policy_paths,
            secret_dynamic_reference_property_paths,
            snapshot_capable_resource_types: raw.snapshot_capable_resource_types,
            snapstart_recommendation_excluded_runtimes: raw.snapstart_recommendation_excluded_runtimes,
            snapstart_recommendation_runtime_prefixes: raw.snapstart_recommendation_runtime_prefixes,
            snapstart_runtime_prefixes: raw.snapstart_runtime_prefixes,
            snapstart_supported_regions: raw.snapstart_supported_regions,
            snapstart_unsupported_runtime_prefixes: raw.snapstart_unsupported_runtime_prefixes,
            snapstart_unsupported_runtimes: raw.snapstart_unsupported_runtimes,
            update_policy_resource_types: raw.update_policy_resource_types,
            valid_parameter_types: raw.valid_parameter_types,
        })
    }
}

fn validate_nonempty_unique(values: &[String], field_name: &str) -> Result<(), String> {
    if values.is_empty() {
        return Err(format!("{field_name} must not be empty"));
    }
    let mut seen = HashSet::with_capacity(values.len());
    for v in values {
        if v.is_empty() {
            return Err(format!("empty string entry in {field_name}"));
        }
        if !seen.insert(v.as_str()) {
            return Err(format!("duplicate entry in {field_name}: {v}"));
        }
    }
    Ok(())
}

fn parse_paths(raw_paths: &[String], field_name: &str) -> Result<Vec<ResourcePropertyPath>, String> {
    raw_paths
        .iter()
        .map(|p| ResourcePropertyPath::parse(p).map_err(|e| format!("invalid path in {field_name}: {e}")))
        .collect()
}

/// Validates that every ebs_iops_property_paths entry has exactly 1 or 2 wildcards and
/// ends in the `[..., Wildcard, Literal("Ebs")]` shape required by consumers.
fn validate_ebs_iops_shape(paths: &[ResourcePropertyPath]) -> Result<(), String> {
    for path in paths {
        let wc_count = path.segments.iter().filter(|s| matches!(s, PathSegment::Wildcard)).count();
        if wc_count == 0 || wc_count > 2 {
            return Err(format!(
                "ebs_iops_property_paths entry must have exactly 1 or 2 wildcards, \
                 found {wc_count} in: Resources/{}/{}",
                path.resource_type,
                path.segments
                    .iter()
                    .map(|s| match s {
                        PathSegment::Literal(l) => l.as_str(),
                        PathSegment::Wildcard => "*",
                    })
                    .collect::<Vec<_>>()
                    .join("/")
            ));
        }
        let len = path.segments.len();
        if len < 2 {
            return Err(format!(
                "ebs_iops_property_paths entry too short to end in */Ebs: Resources/{}/...",
                path.resource_type
            ));
        }
        let penultimate = &path.segments[len - 2];
        let last = &path.segments[len - 1];
        if !matches!(penultimate, PathSegment::Wildcard) || !matches!(last, PathSegment::Literal(s) if s == "Ebs") {
            return Err(format!(
                "ebs_iops_property_paths entry must end in */Ebs: Resources/{}/{}",
                path.resource_type,
                path.segments
                    .iter()
                    .map(|s| match s {
                        PathSegment::Literal(l) => l.as_str(),
                        PathSegment::Wildcard => "*",
                    })
                    .collect::<Vec<_>>()
                    .join("/")
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ──────────────────────────────────────────────────────────────────────────
    // Extension-derived RuleData tests (preserved)
    // ──────────────────────────────────────────────────────────────────────────

    #[test]
    fn derives_rule_data_from_synced_extensions() {
        let extensions: Value = serde_json::from_slice(include_bytes!("../generated/schema-validator/extensions.json"))
            .expect("synced extensions should parse");

        let rule_data = derive_from_extensions(&extensions).expect("rule data should derive");

        assert_eq!(rule_data.classic_load_balancer_certificate_protocols, ["HTTPS", "SSL"]);
        assert_eq!(rule_data.fargate_supported_log_drivers, ["awslogs", "splunk", "awsfirelens"]);
        assert_eq!(rule_data.lambda_image_excluded_properties, ["Handler", "Runtime", "Layers"]);
        assert_eq!(rule_data.lambda_reserved_environment_keys.len(), 18);
        assert!(rule_data.lambda_reserved_environment_keys.contains(&"AWS_ACCESS_KEY".to_string()));
        assert!(rule_data.lambda_reserved_environment_keys.contains(&"AWS_LAMBDA_INITIALIZATION_TYPE".to_string()));
        assert_eq!(rule_data.load_balancer_v2_certificate_protocols, ["HTTPS", "TLS"]);
    }

    #[test]
    fn rejects_missing_extension_table() {
        let error = extract_unique_string_array(
            &serde_json::json!({ LAMBDA_FUNCTION_EXTENSION_KEY: [] }),
            LAMBDA_FUNCTION_EXTENSION_KEY,
            "/propertyNames/not/enum",
            "Lambda reserved environment keys",
        )
        .expect_err("missing extension table must fail");

        assert!(error.contains("expected exactly one"));
    }

    #[test]
    fn rejects_duplicate_extension_values() {
        let extensions = serde_json::json!({
            LAMBDA_FUNCTION_EXTENSION_KEY: [{
                "propertyNames": {
                    "not": {
                        "enum": ["AWS_REGION", "AWS_REGION"]
                    }
                }
            }]
        });

        let error = extract_unique_string_array(
            &extensions,
            LAMBDA_FUNCTION_EXTENSION_KEY,
            "/propertyNames/not/enum",
            "Lambda reserved environment keys",
        )
        .expect_err("duplicate extension values must fail");

        assert_eq!(error, "duplicate Lambda reserved environment keys entry: AWS_REGION");
    }

    // ──────────────────────────────────────────────────────────────────────────
    // ResourcePropertyPath tests
    // ──────────────────────────────────────────────────────────────────────────

    #[test]
    fn parses_simple_property_path() {
        let path = ResourcePropertyPath::parse("Resources/AWS::S3::Bucket/Properties/BucketName").unwrap();
        assert_eq!(path.resource_type, "AWS::S3::Bucket");
        assert_eq!(
            path.segments,
            vec![PathSegment::Literal("Properties".into()), PathSegment::Literal("BucketName".into())]
        );
    }

    #[test]
    fn parses_path_with_wildcard() {
        let path =
            ResourcePropertyPath::parse("Resources/AWS::EC2::Instance/Properties/BlockDeviceMappings/*/Ebs").unwrap();
        assert_eq!(path.resource_type, "AWS::EC2::Instance");
        assert_eq!(
            path.segments,
            vec![
                PathSegment::Literal("Properties".into()),
                PathSegment::Literal("BlockDeviceMappings".into()),
                PathSegment::Wildcard,
                PathSegment::Literal("Ebs".into()),
            ]
        );
    }

    #[test]
    fn parses_path_with_multiple_wildcards() {
        let path = ResourcePropertyPath::parse(
            "Resources/AWS::EC2::SpotFleet/Properties/SpotFleetRequestConfigData/LaunchSpecifications/*/BlockDeviceMappings/*/Ebs",
        )
        .unwrap();
        assert_eq!(path.resource_type, "AWS::EC2::SpotFleet");
        assert_eq!(path.segments.iter().filter(|s| **s == PathSegment::Wildcard).count(), 2);
    }

    #[test]
    fn rejects_path_missing_resources_prefix() {
        let err = ResourcePropertyPath::parse("AWS::S3::Bucket/Properties/Name").unwrap_err();
        assert!(err.contains("must start with 'Resources/'"));
    }

    #[test]
    fn rejects_path_too_short() {
        let err = ResourcePropertyPath::parse("Resources/AWS::S3::Bucket/Properties").unwrap_err();
        assert!(err.contains("too short"));
    }

    #[test]
    fn rejects_empty_resource_type() {
        let err = ResourcePropertyPath::parse("Resources//Properties/Name").unwrap_err();
        assert!(err.contains("empty resource type"));
    }

    #[test]
    fn rejects_non_aws_resource_type() {
        let err = ResourcePropertyPath::parse("Resources/Custom::MyThing/Properties/Foo").unwrap_err();
        assert!(err.contains("must start with 'AWS::'"));
    }

    #[test]
    fn rejects_missing_properties_segment() {
        let err = ResourcePropertyPath::parse("Resources/AWS::S3::Bucket/BucketName/Foo").unwrap_err();
        assert!(err.contains("first segment after resource type must be 'Properties'"));
    }

    #[test]
    fn rejects_empty_literal_segment() {
        let err = ResourcePropertyPath::parse("Resources/AWS::S3::Bucket/Properties//Name").unwrap_err();
        assert!(err.contains("empty literal segment"));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // validate_nonempty_unique tests
    // ──────────────────────────────────────────────────────────────────────────

    #[test]
    fn rejects_empty_string_array() {
        let err = validate_nonempty_unique(&[], "test_field").unwrap_err();
        assert!(err.contains("must not be empty"));
    }

    #[test]
    fn rejects_duplicate_entries() {
        let values = vec!["a".to_string(), "b".to_string(), "a".to_string()];
        let err = validate_nonempty_unique(&values, "test_field").unwrap_err();
        assert!(err.contains("duplicate entry"));
        assert!(err.contains("test_field"));
    }

    #[test]
    fn validates_unique_entries_pass() {
        let values = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        validate_nonempty_unique(&values, "test_field").unwrap();
    }

    #[test]
    fn rejects_empty_string_entry() {
        let values = vec!["valid".to_string(), "".to_string()];
        let err = validate_nonempty_unique(&values, "test_field").unwrap_err();
        assert!(err.contains("empty string entry in test_field"));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // ebs_iops shape validation tests
    // ──────────────────────────────────────────────────────────────────────────

    #[test]
    fn ebs_iops_accepts_single_wildcard_ebs_suffix() {
        let paths = vec![
            ResourcePropertyPath::parse("Resources/AWS::EC2::Instance/Properties/BlockDeviceMappings/*/Ebs").unwrap(),
        ];
        validate_ebs_iops_shape(&paths).unwrap();
    }

    #[test]
    fn ebs_iops_accepts_double_wildcard_ebs_suffix() {
        let paths = vec![ResourcePropertyPath::parse(
            "Resources/AWS::EC2::SpotFleet/Properties/SpotFleetRequestConfigData/LaunchSpecifications/*/BlockDeviceMappings/*/Ebs",
        )
        .unwrap()];
        validate_ebs_iops_shape(&paths).unwrap();
    }

    #[test]
    fn ebs_iops_rejects_zero_wildcards() {
        let path = ResourcePropertyPath {
            resource_type: "AWS::EC2::Instance".into(),
            segments: vec![
                PathSegment::Literal("Properties".into()),
                PathSegment::Literal("BlockDeviceMappings".into()),
                PathSegment::Literal("Ebs".into()),
            ],
        };
        let err = validate_ebs_iops_shape(&[path]).unwrap_err();
        assert!(err.contains("exactly 1 or 2 wildcards"));
    }

    #[test]
    fn ebs_iops_rejects_three_wildcards() {
        let path = ResourcePropertyPath {
            resource_type: "AWS::EC2::Instance".into(),
            segments: vec![
                PathSegment::Literal("Properties".into()),
                PathSegment::Wildcard,
                PathSegment::Wildcard,
                PathSegment::Wildcard,
                PathSegment::Literal("Ebs".into()),
            ],
        };
        let err = validate_ebs_iops_shape(&[path]).unwrap_err();
        assert!(err.contains("exactly 1 or 2 wildcards"));
    }

    #[test]
    fn ebs_iops_rejects_missing_ebs_suffix() {
        let path = ResourcePropertyPath {
            resource_type: "AWS::EC2::Instance".into(),
            segments: vec![
                PathSegment::Literal("Properties".into()),
                PathSegment::Literal("BlockDeviceMappings".into()),
                PathSegment::Wildcard,
                PathSegment::Literal("Iops".into()),
            ],
        };
        let err = validate_ebs_iops_shape(&[path]).unwrap_err();
        assert!(err.contains("must end in */Ebs"));
    }

    #[test]
    fn ebs_iops_rejects_non_wildcard_before_ebs() {
        let path = ResourcePropertyPath {
            resource_type: "AWS::EC2::Instance".into(),
            segments: vec![
                PathSegment::Literal("Properties".into()),
                PathSegment::Wildcard,
                PathSegment::Literal("NotWildcard".into()),
                PathSegment::Literal("Ebs".into()),
            ],
        };
        let err = validate_ebs_iops_shape(&[path]).unwrap_err();
        assert!(err.contains("must end in */Ebs"));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // RuleTables deserialization and validation tests
    // ──────────────────────────────────────────────────────────────────────────

    #[test]
    fn deserializes_and_validates_synced_rule_tables() {
        let bytes = include_bytes!("../generated/data/cfnlint_rule_tables.json");
        let doc: RuleTablesDocument = serde_json::from_slice(bytes).expect("rule tables JSON must deserialize");
        let tables = RuleTables::validate(doc.cfnlint_rule_tables).expect("rule tables must validate");

        assert!(!tables.api_gateway_mixing_resource_types.is_empty());
        assert!(!tables.ebs_iops_property_paths.is_empty());
        assert!(!tables.valid_parameter_types.is_empty());
        assert!(!tables.previous_generation_instance_pattern.is_empty());

        // Verify wildcard parsing worked on known paths
        let has_wildcard = tables.ebs_iops_property_paths.iter().any(|p| p.segments.contains(&PathSegment::Wildcard));
        assert!(has_wildcard, "ebs_iops_property_paths should contain wildcard segments");
    }

    #[test]
    fn rejects_unknown_fields_in_rule_tables() {
        let json = r#"{"cfnlint_rule_tables": {"unknown_field": [], "api_gateway_mixing_resource_types": []}}"#;
        let result: Result<RuleTablesDocument, _> = serde_json::from_str(json);
        assert!(result.is_err(), "unknown fields must be rejected");
    }

    #[test]
    fn rule_tables_rejects_empty_pattern() {
        let raw = make_minimal_raw(|r| r.previous_generation_instance_pattern = String::new());
        let err = RuleTables::validate(raw).unwrap_err();
        assert!(err.contains("previous_generation_instance_pattern must not be empty"));
    }

    #[test]
    fn rule_tables_rejects_empty_paths_field() {
        let raw = make_minimal_raw(|r| r.ebs_iops_property_paths = vec![]);
        let err = RuleTables::validate(raw).unwrap_err();
        assert!(err.contains("ebs_iops_property_paths must not be empty"));
    }

    #[test]
    fn rule_tables_rejects_invalid_path_format() {
        let raw = make_minimal_raw(|r| {
            r.ebs_iops_property_paths = vec!["NotResources/Foo/Bar".to_string()];
        });
        let err = RuleTables::validate(raw).unwrap_err();
        assert!(err.contains("invalid path in ebs_iops_property_paths"));
    }

    #[test]
    fn rule_tables_rejects_ebs_iops_without_wildcard_ebs_suffix() {
        let raw = make_minimal_raw(|r| {
            r.ebs_iops_property_paths =
                vec!["Resources/AWS::EC2::Instance/Properties/BlockDeviceMappings/*/Iops".into()];
        });
        let err = RuleTables::validate(raw).unwrap_err();
        assert!(err.contains("must end in */Ebs"));
    }

    #[test]
    fn rule_tables_rejects_ebs_iops_with_zero_wildcards() {
        let raw = make_minimal_raw(|r| {
            r.ebs_iops_property_paths = vec!["Resources/AWS::EC2::Instance/Properties/Ebs".into()];
        });
        let err = RuleTables::validate(raw).unwrap_err();
        assert!(err.contains("exactly 1 or 2 wildcards"));
    }

    #[test]
    fn rule_tables_rejects_empty_string_entry_in_array() {
        let raw = make_minimal_raw(|r| {
            r.password_property_names = vec!["Password".into(), "".into()];
        });
        let err = RuleTables::validate(raw).unwrap_err();
        assert!(err.contains("empty string entry in password_property_names"));
    }

    /// Helper to build a minimal valid `RuleTablesRaw` then apply a mutation.
    fn make_minimal_raw(mutate: impl FnOnce(&mut RuleTablesRaw)) -> RuleTablesRaw {
        let mut raw = RuleTablesRaw {
            api_gateway_mixing_resource_types: vec!["AWS::ApiGateway::Method".into()],
            ebs_iops_ignored_volume_types: vec!["gp2".into()],
            ebs_iops_property_paths: vec!["Resources/AWS::EC2::Instance/Properties/BlockDeviceMappings/*/Ebs".into()],
            iam_role_arn_property_paths: vec![
                "Resources/AWS::Backup::BackupSelection/Properties/BackupSelection/IamRoleArn".into(),
            ],
            image_id_parameter_types: vec!["AWS::EC2::Image::Id".into()],
            image_id_property_paths: vec!["Resources/AWS::AutoScaling::LaunchConfiguration/Properties/ImageId".into()],
            lambda_zip_required_properties: vec!["Handler".into()],
            package_property_paths: vec!["Resources/AWS::ApiGateway::RestApi/Properties/BodyS3Location".into()],
            password_property_names: vec!["Password".into()],
            previous_generation_instance_pattern: "(^|\\\\.)([cmr][1-3])($|\\\\.)".into(),
            previous_generation_instance_property_paths: vec![
                "Resources/AWS::EC2::Instance/Properties/InstanceType".into(),
            ],
            resource_policy_paths: vec!["Resources/AWS::KMS::Key/Properties/KeyPolicy".into()],
            secret_dynamic_reference_property_paths: vec![
                "Resources/AWS::IAM::User/Properties/LoginProfile/Password".into(),
            ],
            snapshot_capable_resource_types: vec!["AWS::RDS::DBInstance".into()],
            snapstart_recommendation_excluded_runtimes: vec!["java8".into()],
            snapstart_recommendation_runtime_prefixes: vec!["java".into()],
            snapstart_runtime_prefixes: vec!["python".into()],
            snapstart_supported_regions: vec!["us-east-1".into()],
            snapstart_unsupported_runtime_prefixes: vec!["dotnetcore".into()],
            snapstart_unsupported_runtimes: vec!["dotnet6".into()],
            update_policy_resource_types: vec!["AWS::AutoScaling::AutoScalingGroup".into()],
            valid_parameter_types: vec!["String".into()],
        };
        mutate(&mut raw);
        raw
    }
}
