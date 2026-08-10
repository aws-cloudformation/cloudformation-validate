use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub const SOURCE_VERSIONS_FILE: &str = "source_versions.json";
pub const CFN_LINT_SOURCE: &str = "https://github.com/aws-cloudformation/cfn-lint";
pub const RESOURCE_SCHEMA_SOURCE: &str = "https://github.com/aws-cloudformation/resource-provider-enhanced-schemas";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceVersions {
    pub cfn_lint_version: String,
    pub resource_schema_version: String,
}

impl SourceVersions {
    pub fn new(cfn_lint_version: String, resource_schema_version: String) -> Result<Self, String> {
        let versions = Self { cfn_lint_version, resource_schema_version };
        versions.validate()?;
        Ok(versions)
    }

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

    fn validate(&self) -> Result<(), String> {
        validate_source_version("cfn_lint_version", &self.cfn_lint_version, CFN_LINT_SOURCE)?;
        validate_source_version("resource_schema_version", &self.resource_schema_version, RESOURCE_SCHEMA_SOURCE)
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

    #[test]
    fn parses_complete_manifest() {
        let versions = SourceVersions::from_json(
            r#"{"cfn_lint_version":"https://github.com/aws-cloudformation/cfn-lint@1.54.0","resource_schema_version":"https://github.com/aws-cloudformation/resource-provider-enhanced-schemas@2026-08-07T18:20:13Z"}"#,
        )
        .expect("manifest should parse");

        assert_eq!(versions.cfn_lint_version, "https://github.com/aws-cloudformation/cfn-lint@1.54.0");
        assert_eq!(
            versions.resource_schema_version,
            "https://github.com/aws-cloudformation/resource-provider-enhanced-schemas@2026-08-07T18:20:13Z"
        );
    }

    #[test]
    fn serializes_complete_manifest() {
        let versions = SourceVersions::new(
            format!("{CFN_LINT_SOURCE}@1.54.0"),
            format!("{RESOURCE_SCHEMA_SOURCE}@2026-08-07T18:20:13Z"),
        )
        .expect("source versions should be valid");

        let json = serde_json::to_value(versions).expect("manifest should serialize");
        assert_eq!(json.as_object().expect("manifest should be an object").len(), 2);
        assert_eq!(json["cfn_lint_version"], format!("{CFN_LINT_SOURCE}@1.54.0"));
        assert_eq!(json["resource_schema_version"], format!("{RESOURCE_SCHEMA_SOURCE}@2026-08-07T18:20:13Z"));
    }

    #[test]
    fn missing_field_is_rejected() {
        let manifest = r#"{"resource_schema_version":"https://github.com/aws-cloudformation/resource-provider-enhanced-schemas@2026-08-07T18:20:13Z"}"#;
        assert!(SourceVersions::from_json(manifest).is_err());
    }

    #[test]
    fn blank_version_suffix_is_rejected() {
        let error = SourceVersions::new(
            format!("{CFN_LINT_SOURCE}@  "),
            format!("{RESOURCE_SCHEMA_SOURCE}@2026-08-07T18:20:13Z"),
        )
        .expect_err("blank version must fail");
        assert!(error.contains("cfn_lint_version must include a nonblank version"));
    }

    #[test]
    fn unqualified_version_is_rejected() {
        let error = SourceVersions::new("1.54.0".to_string(), format!("{RESOURCE_SCHEMA_SOURCE}@2026-08-07T18:20:13Z"))
            .expect_err("unqualified version must fail");
        assert!(error.contains(CFN_LINT_SOURCE));
    }

    #[test]
    fn unknown_field_is_rejected() {
        let manifest = r#"{
            "cfn_lint_version":"https://github.com/aws-cloudformation/cfn-lint@1.54.0",
            "resource_schema_version":"https://github.com/aws-cloudformation/resource-provider-enhanced-schemas@2026-08-07T18:20:13Z",
            "unexpected":"value"
        }"#;
        assert!(SourceVersions::from_json(manifest).is_err());
    }
}
