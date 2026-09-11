use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub const SOURCE_VERSIONS_FILE: &str = "source_versions.json";
pub const CFN_LINT_SOURCE: &str = "https://github.com/aws-cloudformation/cfn-lint";
pub const RESOURCE_SCHEMA_SOURCE: &str = "https://github.com/aws-cloudformation/resource-provider-enhanced-schemas";
pub const AWS_CLI_SOURCE: &str = "https://github.com/aws/aws-cli";

/// Provenance of every external input behind the committed generated data.
///
/// `sync` records the cfn-lint and resource-schema versions; the AWS CLI
/// operation catalog generator records the AWS CLI release whose bundled
/// botocore models the catalog derives from, so that entry is absent until the
/// catalog has been generated. Each writer preserves the entries it does not own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceVersions {
    pub cfn_lint_version: String,
    pub resource_schema_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aws_cli_version: Option<String>,
}

impl SourceVersions {
    pub fn read(path: &Path) -> Result<Self, String> {
        let contents =
            fs::read_to_string(path).map_err(|error| format!("failed to read {}: {error}", path.display()))?;
        Self::from_json(&contents).map_err(|error| format!("invalid {}: {error}", path.display()))
    }

    pub fn from_json(contents: &str) -> Result<Self, String> {
        let versions: Self = serde_json::from_str(contents).map_err(|error| error.to_string())?;
        versions.validate()?;
        Ok(versions)
    }

    pub fn validate(&self) -> Result<(), String> {
        validate_source_version("cfn_lint_version", &self.cfn_lint_version, CFN_LINT_SOURCE)?;
        validate_source_version("resource_schema_version", &self.resource_schema_version, RESOURCE_SCHEMA_SOURCE)?;
        match &self.aws_cli_version {
            Some(aws_cli_version) => validate_source_version("aws_cli_version", aws_cli_version, AWS_CLI_SOURCE),
            None => Ok(()),
        }
    }
}

fn validate_source_version(field: &str, value: &str, source: &str) -> Result<(), String> {
    let prefix = format!("{source}@");
    let Some(version) = value.strip_prefix(&prefix) else {
        return Err(format!("{field} must start with {prefix}"));
    };
    if version.trim().is_empty() {
        return Err(format!("{field} must include a nonblank version"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYNC_ONLY_MANIFEST: &str = r#"{
        "cfn_lint_version":"https://github.com/aws-cloudformation/cfn-lint@1.54.0",
        "resource_schema_version":"https://github.com/aws-cloudformation/resource-provider-enhanced-schemas@2026-08-07T18:20:13Z"
    }"#;

    const COMPLETE_MANIFEST: &str = r#"{
        "cfn_lint_version":"https://github.com/aws-cloudformation/cfn-lint@1.54.0",
        "resource_schema_version":"https://github.com/aws-cloudformation/resource-provider-enhanced-schemas@2026-08-07T18:20:13Z",
        "aws_cli_version":"https://github.com/aws/aws-cli@2.36.43"
    }"#;

    #[test]
    fn parses_manifest_before_the_catalog_has_been_generated() {
        let versions = SourceVersions::from_json(SYNC_ONLY_MANIFEST).expect("manifest should parse");
        assert_eq!(versions.cfn_lint_version, "https://github.com/aws-cloudformation/cfn-lint@1.54.0");
        assert_eq!(
            versions.resource_schema_version,
            "https://github.com/aws-cloudformation/resource-provider-enhanced-schemas@2026-08-07T18:20:13Z"
        );
        assert_eq!(versions.aws_cli_version, None);
    }

    #[test]
    fn parses_complete_manifest() {
        let versions = SourceVersions::from_json(COMPLETE_MANIFEST).expect("manifest should parse");
        assert_eq!(versions.aws_cli_version.as_deref(), Some("https://github.com/aws/aws-cli@2.36.43"));
    }

    #[test]
    fn serializes_only_recorded_entries() {
        let sync_only = SourceVersions::from_json(SYNC_ONLY_MANIFEST).expect("manifest should parse");
        let json = serde_json::to_value(sync_only).expect("manifest should serialize");
        assert_eq!(json.as_object().expect("manifest should be an object").len(), 2);

        let complete = SourceVersions::from_json(COMPLETE_MANIFEST).expect("manifest should parse");
        let json = serde_json::to_value(complete).expect("manifest should serialize");
        assert_eq!(json.as_object().expect("manifest should be an object").len(), 3);
        assert_eq!(json["aws_cli_version"], format!("{AWS_CLI_SOURCE}@2.36.43"));
    }

    #[test]
    fn missing_sync_field_is_rejected() {
        let manifest = r#"{"resource_schema_version":"https://github.com/aws-cloudformation/resource-provider-enhanced-schemas@2026-08-07T18:20:13Z"}"#;
        assert!(SourceVersions::from_json(manifest).is_err());
    }

    #[test]
    fn malformed_versions_are_rejected() {
        let blank = SYNC_ONLY_MANIFEST.replace("cfn-lint@1.54.0", "cfn-lint@  ");
        let error = SourceVersions::from_json(&blank).expect_err("blank version must fail");
        assert!(error.contains("cfn_lint_version must include a nonblank version"));

        let unqualified = COMPLETE_MANIFEST.replace("https://github.com/aws/aws-cli@2.36.43", "2.36.43");
        let error = SourceVersions::from_json(&unqualified).expect_err("unqualified version must fail");
        assert!(error.contains(AWS_CLI_SOURCE));
    }

    #[test]
    fn unknown_field_is_rejected() {
        let manifest = COMPLETE_MANIFEST.replace("\"aws_cli_version\"", "\"unexpected\":\"value\",\"aws_cli_version\"");
        assert!(SourceVersions::from_json(&manifest).is_err());
    }
}
