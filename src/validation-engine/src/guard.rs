//! Guard DSL rules as a validation-pipeline concern shared by every engine.
//!
//! [`GuardRuleSet`] holds the loaded rule files and turns the Guard evaluator's
//! findings into [`Diagnostic`]s: the finding's template path becomes the
//! diagnostic's entity, property path, and source span. Because both built-in
//! engines evaluate Guard rules through this one type, they cannot disagree on a
//! Guard finding.

use crate::engine::{ExternalRuleSource, ValidationError};
use diagnostics::{Diagnostic, Entity};
use guard_translator::{GuardFinding, GuardRuleFile, load_guard_sources_recursive};
use rules::{RuleMetadataEntry, RuleOrigin, Severity};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use template_model::{EntityType, SemanticModel, TopLevelSection, entity_identity, span_to_option};

/// Prefix of the category every Guard rule reports, followed by its pack name.
pub const GUARD_CATEGORY_PREFIX: &str = "guard:";

/// Every Guard finding is reported at this severity; the Guard language has no
/// severity of its own.
const GUARD_SEVERITY: Severity = Severity::Error;

/// The Guard rule files an engine was configured with, parsed once at
/// construction so a syntax error fails engine construction rather than every
/// later validation.
#[derive(Debug, Clone)]
pub struct GuardRuleSet {
    files: Vec<GuardRuleFile>,
    rule_metadata: HashMap<String, RuleMetadataEntry>,
}

impl GuardRuleSet {
    /// Parses every source, or returns `None` when there are none so an engine
    /// can skip Guard evaluation entirely.
    pub fn compile(sources: &[ExternalRuleSource]) -> Result<Option<Self>, String> {
        if sources.is_empty() {
            return Ok(None);
        }
        let mut files = Vec::with_capacity(sources.len());
        let mut rule_metadata = HashMap::new();
        for source in sources {
            let file = GuardRuleFile::parse(source.name.as_str(), source.content.as_str())?;
            for rule in file.rules() {
                rule_metadata.entry(rule.name.clone()).or_insert_with(|| RuleMetadataEntry {
                    category: Some(guard_category(file.pack())),
                    description: rule.custom_message.clone().unwrap_or_else(|| default_description(&rule.name)),
                    severity: GUARD_SEVERITY,
                    origin: RuleOrigin::Guard,
                });
            }
            files.push(file);
        }
        Ok(Some(Self { files, rule_metadata }))
    }

    /// Metadata for every loaded Guard rule, keyed by rule name, in the form the
    /// rule listing and enrichment consume.
    pub fn rule_metadata(&self) -> &HashMap<String, RuleMetadataEntry> {
        &self.rule_metadata
    }

    /// Evaluates every rule file against the authored template and reports one
    /// diagnostic per failed check. An evaluation failure is an error, never a
    /// diagnostic, because it describes a problem with the rules rather than
    /// with the template.
    pub fn evaluate(&self, model: &SemanticModel) -> Result<Vec<Diagnostic>, ValidationError> {
        let template = model.authored_template_json();
        let mut diagnostics = Vec::new();
        for file in &self.files {
            let findings = file.evaluate(template).map_err(ValidationError::Engine)?;
            diagnostics.extend(findings.iter().map(|finding| guard_diagnostic(finding, file.pack(), model)));
        }
        Ok(diagnostics)
    }
}

pub fn guard_category(pack: &str) -> String {
    format!("{GUARD_CATEGORY_PREFIX}{pack}")
}

fn default_description(rule_name: &str) -> String {
    format!("Rule {rule_name} failed")
}

/// A finding located under `Resources/<id>/...` is attributed to that resource
/// with a resource-relative property path; a finding under another section keeps
/// the section's entity; a finding with no path is a template-level diagnostic.
fn guard_diagnostic(finding: &GuardFinding, pack: &str, model: &SemanticModel) -> Diagnostic {
    let location = finding.path.as_deref().map(|path| FindingLocation::from_template_path(path, model));
    Diagnostic {
        rule_id: finding.rule_name.clone(),
        severity: GUARD_SEVERITY,
        message: finding_message(finding, location.as_ref()),
        entity: location.as_ref().and_then(|location| location.entity.clone()),
        property_path: location.as_ref().and_then(|location| location.property_path.clone()),
        suggested_fix: None,
        documentation_url: None,
        category: Some(guard_category(pack)),
        location: location
            .and_then(|location| model.diagnostic_span(None, &location.span_key))
            .and_then(span_to_option),
        related_resources: None,
        condition_scenario: None,
        rule_description: None,
        phase: None,
        context: None,
        source: RuleOrigin::Guard,
    }
}

struct FindingLocation {
    entity: Option<Entity>,
    /// Dotted path relative to the resource (`Properties.BucketName`); only
    /// resource findings have one, matching every other resource diagnostic.
    property_path: Option<String>,
    /// The section-absolute span-index key the finding's path denotes.
    span_key: String,
}

impl FindingLocation {
    fn from_template_path(path: &str, model: &SemanticModel) -> Self {
        let entity = entity_identity(path).map(|(entity_type, logical_id)| Entity {
            logical_id: logical_id.to_string(),
            entity_type,
            resource_type: (entity_type == EntityType::Resource)
                .then(|| model.resource(logical_id).map(|resource| resource.resource_type.clone()))
                .flatten(),
        });
        let property_path = entity
            .as_ref()
            .filter(|entity| entity.entity_type == EntityType::Resource)
            .and_then(|entity| {
                path.strip_prefix(&format!("{}/{}/", TopLevelSection::Resources.name(), entity.logical_id))
            })
            .filter(|relative| !relative.is_empty())
            .map(|relative| relative.replace('/', "."));
        Self { entity, property_path, span_key: path.to_string() }
    }
}

/// The author's message wins. Without one, the message names the failed check
/// and, for a missing property, the property that could not be found.
fn finding_message(finding: &GuardFinding, location: Option<&FindingLocation>) -> String {
    if let Some(custom_message) = &finding.custom_message {
        return custom_message.clone();
    }
    match &finding.missing_query {
        Some(missing_query) => {
            let missing_property = match location.and_then(|location| location.property_path.as_deref()) {
                Some(property_path) => format!("{property_path}.{missing_query}"),
                None => missing_query.clone(),
            };
            format!("Guard check `{}` failed: property `{}` is missing", finding.check, missing_property)
        }
        None => format!("Guard check `{}` failed", finding.check),
    }
}

pub fn resolve_guard_config(rule_source_paths: &[String]) -> Result<Vec<ExternalRuleSource>, String> {
    let mut entries = Vec::new();

    for path in rule_source_paths {
        let p = Path::new(path);
        if p.is_dir() {
            let sources = load_guard_sources_recursive(path)?;
            for (file_path, file_content) in sources {
                entries.push(ExternalRuleSource { name: file_path, content: file_content });
            }
        } else if p.is_file() {
            let file_content =
                fs::read_to_string(p).map_err(|e| format!("Failed to read guard file '{}': {}", path, e))?;
            entries.push(ExternalRuleSource { name: path.clone(), content: file_content });
        } else {
            return Err(format!("Guard rule source not found: {}", path));
        }
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rules::Severity;
    use std::env;
    use std::fs;

    const BUCKET_NAME_EXISTS: &str = r#"
rule check_bucket_name {
    AWS::S3::Bucket {
        Properties.BucketName EXISTS
        <<BucketName must be specified>>
    }
}
"#;

    const TEMPLATE_WITH_AND_WITHOUT_NAME: &str = r#"
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Named:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-bucket
  Unnamed:
    Type: AWS::S3::Bucket
    Properties:
      Tags:
        - Key: Team
          Value: x
"#;

    fn source(name: &str, content: &str) -> ExternalRuleSource {
        ExternalRuleSource { name: name.into(), content: content.into() }
    }

    fn model(yaml: &str) -> SemanticModel {
        SemanticModel::from_bytes(yaml.as_bytes()).expect("template parses")
    }

    fn rule_set(sources: &[ExternalRuleSource]) -> GuardRuleSet {
        GuardRuleSet::compile(sources).expect("guard sources compile").expect("at least one source")
    }

    #[test]
    fn compile_returns_none_without_sources() {
        assert!(GuardRuleSet::compile(&[]).unwrap().is_none());
    }

    #[test]
    fn compile_rejects_a_syntax_error_naming_the_file() {
        let error = GuardRuleSet::compile(&[source("broken.guard", "rule { nope")]).unwrap_err();
        assert!(error.contains("broken.guard"), "got: {error}");
    }

    #[test]
    fn compile_records_error_severity_guard_origin_pack_category_and_custom_message() {
        let set = rule_set(&[source("policies/s3-checks.guard", BUCKET_NAME_EXISTS)]);
        let entry = &set.rule_metadata()["check_bucket_name"];
        assert_eq!(entry.severity, Severity::Error);
        assert_eq!(entry.origin, RuleOrigin::Guard);
        assert_eq!(entry.category.as_deref(), Some("guard:s3_checks"));
        assert_eq!(entry.description, "BucketName must be specified");
    }

    #[test]
    fn compile_describes_a_rule_without_custom_message_by_name() {
        let set = rule_set(&[source("s3.guard", "rule bare { AWS::S3::Bucket { Properties.BucketName EXISTS } }")]);
        assert_eq!(set.rule_metadata()["bare"].description, "Rule bare failed");
    }

    #[test]
    fn evaluate_reports_only_the_resource_missing_the_property_with_its_location() {
        let set = rule_set(&[source("s3.guard", BUCKET_NAME_EXISTS)]);
        let model = model(TEMPLATE_WITH_AND_WITHOUT_NAME);

        let diagnostics = set.evaluate(&model).unwrap();

        assert_eq!(diagnostics.len(), 1, "the named bucket must not be reported, got: {diagnostics:?}");
        let diagnostic = &diagnostics[0];
        assert_eq!(diagnostic.rule_id, "check_bucket_name");
        assert_eq!(diagnostic.severity, Severity::Error);
        assert_eq!(diagnostic.source, RuleOrigin::Guard);
        assert_eq!(diagnostic.category.as_deref(), Some("guard:s3"));
        assert_eq!(diagnostic.message, "BucketName must be specified");
        assert_eq!(diagnostic.resource_logical_id(), Some("Unnamed"));
        assert_eq!(diagnostic.entity.as_ref().unwrap().resource_type.as_deref(), Some("AWS::S3::Bucket"));
        assert_eq!(diagnostic.property_path.as_deref(), Some("Properties"), "located at the deepest existing node");
        let properties_span = model.diagnostic_span(Some("Unnamed"), "Properties").unwrap();
        assert_eq!(diagnostic.location, Some(properties_span));
    }

    #[test]
    fn evaluate_locates_a_failed_comparison_at_the_compared_property() {
        let set = rule_set(&[source(
            "s3.guard",
            r#"rule bucket_name_is_foo { AWS::S3::Bucket { Properties.BucketName == "foo" } }"#,
        )]);
        let model = model(TEMPLATE_WITH_AND_WITHOUT_NAME);

        let diagnostics = set.evaluate(&model).unwrap();

        let named = diagnostics.iter().find(|d| d.resource_logical_id() == Some("Named")).expect("Named fails");
        assert_eq!(named.property_path.as_deref(), Some("Properties.BucketName"));
        assert_eq!(named.location, model.diagnostic_span(Some("Named"), "Properties.BucketName"));
        assert_eq!(named.message, r#"Guard check `Properties.BucketName EQUALS "foo"` failed"#);

        let unnamed = diagnostics.iter().find(|d| d.resource_logical_id() == Some("Unnamed")).expect("Unnamed fails");
        assert_eq!(
            unnamed.message,
            r#"Guard check `Properties.BucketName EQUALS "foo"` failed: property `Properties.BucketName` is missing"#
        );
    }

    #[test]
    fn evaluate_reports_a_finding_without_template_location_at_template_level() {
        let set = rule_set(&[source(
            "deps.guard",
            r#"
rule base { AWS::S3::Bucket { Properties.BucketName EXISTS } }
rule dependent { base <<base must hold>> }
"#,
        )]);

        let diagnostics = set.evaluate(&model(TEMPLATE_WITH_AND_WITHOUT_NAME)).unwrap();

        let dependent = diagnostics.iter().find(|d| d.rule_id == "dependent").expect("dependent rule fails");
        assert!(dependent.entity.is_none(), "a rule dependency failure has no entity");
        assert_eq!(dependent.property_path, None);
        assert_eq!(dependent.location, None);
        assert_eq!(dependent.message, "base must hold");
    }

    #[test]
    fn evaluate_attributes_a_parameter_finding_to_the_parameter_entity() {
        let set = rule_set(&[source(
            "params.guard",
            r#"rule typed_params { Parameters.*.Type == "Number" <<parameters must be numbers>> }"#,
        )]);
        let model = model("Parameters:\n  Env:\n    Type: String\nResources:\n  B:\n    Type: AWS::S3::Bucket\n");

        let diagnostics = set.evaluate(&model).unwrap();

        assert_eq!(diagnostics.len(), 1);
        let entity = diagnostics[0].entity.as_ref().expect("parameter entity");
        assert_eq!(entity.entity_type, EntityType::Parameter);
        assert_eq!(entity.logical_id, "Env");
        assert_eq!(diagnostics[0].property_path, None, "property paths are resource-relative only");
        assert_eq!(diagnostics[0].location, model.diagnostic_span(None, "Parameters/Env/Type"));
    }

    #[test]
    fn evaluate_of_a_compliant_template_reports_nothing() {
        let set = rule_set(&[source("s3.guard", BUCKET_NAME_EXISTS)]);
        let compliant = model("Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: x\n");
        assert!(set.evaluate(&compliant).unwrap().is_empty());
    }

    #[test]
    fn resolve_guard_config_single_file() {
        let dir = env::temp_dir().join("guard_test_single");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("test.guard");
        fs::write(&file, "rule example { true }").unwrap();

        let entries = resolve_guard_config(&[file.to_string_lossy().to_string()]).expect("single file resolves");
        assert_eq!(entries.len(), 1);
        assert!(entries[0].content.contains("rule example"));
        assert!(entries[0].name.contains("test.guard"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_guard_config_directory_recursive() {
        let dir = env::temp_dir().join("guard_test_dir");
        let _ = fs::remove_dir_all(&dir);
        let sub = dir.join("sub");
        fs::create_dir_all(&sub).unwrap();
        fs::write(dir.join("a.guard"), "rule a { true }").unwrap();
        fs::write(sub.join("b.guard"), "rule b { true }").unwrap();

        let entries = resolve_guard_config(&[dir.to_string_lossy().to_string()]).expect("directory resolves");
        assert_eq!(entries.len(), 2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_guard_config_nonexistent_path_returns_error() {
        let err = resolve_guard_config(&["/nonexistent/path/to/guard.guard".into()]).unwrap_err();
        assert!(err.contains("not found"), "error should mention 'not found', got: {err}");
    }

    #[test]
    fn resolve_guard_config_empty_paths_returns_empty() {
        assert!(resolve_guard_config(&[]).expect("empty paths succeed").is_empty());
    }

    #[test]
    fn resolve_guard_config_mixed_file_and_dir_preserves_content() {
        let dir = env::temp_dir().join("guard_test_mixed");
        let _ = fs::remove_dir_all(&dir);
        let sub = dir.join("rules");
        fs::create_dir_all(&sub).unwrap();
        let standalone = dir.join("standalone.guard");
        let guard_source = "rule check_bucket {\n  AWS::S3::Bucket {\n    Properties.BucketName exists\n  }\n}";
        fs::write(&standalone, guard_source).unwrap();
        fs::write(sub.join("packed.guard"), "rule packed { true }").unwrap();

        let entries =
            resolve_guard_config(&[standalone.to_string_lossy().to_string(), sub.to_string_lossy().to_string()])
                .expect("mixed file and dir resolves");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].content, guard_source);

        let _ = fs::remove_dir_all(&dir);
    }
}
