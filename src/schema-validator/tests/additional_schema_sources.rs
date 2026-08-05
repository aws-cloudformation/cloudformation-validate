use diagnostics::Diagnostic;
use schema_validator::{AdditionalSchemaSource, SchemaValidator, SchemaValidatorConfig, SchemaValidatorConfigError};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use template_model::SemanticModel;

const ADDITIONAL_SCHEMA_SOURCES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../resources/additional_schema_sources");
const LAMBDA_SCHEMA: &str = "aws-lambda-function.json";
const WIDGET_SCHEMA: &str = "aws-test-widget.json";
const WIDGET_ATTRIBUTES_SCHEMA: &str = "aws-test-widget-attributes.json";

fn schema_source(file_name: &str) -> AdditionalSchemaSource {
    let path = Path::new(ADDITIONAL_SCHEMA_SOURCES).join(file_name);
    let schema = fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    AdditionalSchemaSource { type_name: None, schema }
}

fn validator_with_sources(file_names: &[&str]) -> SchemaValidator {
    let config = SchemaValidatorConfig::new()
        .with_additional_schemas(file_names.iter().map(|file_name| schema_source(file_name)));
    SchemaValidator::new(config).expect("fixture schemas must build a validator")
}

fn validate_template(validator: &SchemaValidator, template: &[u8]) -> Vec<Diagnostic> {
    let model = Arc::new(SemanticModel::from_bytes(template).expect("test template must parse"));
    validator.validate(&model, Some("us-east-1")).diagnostics
}

fn has_rule(diagnostics: &[Diagnostic], rule_id: &str) -> bool {
    diagnostics.iter().any(|diagnostic| diagnostic.rule_id == rule_id)
}

#[test]
fn additional_schema_source_extends_a_bundled_resource_schema() {
    let template = br#"
Resources:
  Function:
    Type: AWS::Lambda::Function
    Properties:
      Code:
        ZipFile: "exports.handler = async () => {};"
      Handler: index.handler
      Role: arn:aws:iam::123456789012:role/lambda-role
      Runtime: nodejs20.x
      AdditionalSchemaProperty: enabled
"#;

    let baseline = validate_template(&SchemaValidator::default(), template);
    assert!(has_rule(&baseline, "F3002"), "the bundled schema must reject the fixture-only property");

    let diagnostics = validate_template(&validator_with_sources(&[LAMBDA_SCHEMA]), template);
    assert!(
        !has_rule(&diagnostics, "F3002"),
        "the additional source must make its property valid, got: {:?}",
        diagnostics.iter().map(|diagnostic| (&diagnostic.rule_id, &diagnostic.message)).collect::<Vec<_>>()
    );
}

#[test]
fn multiple_additional_schema_sources_compose_a_new_resource_type() {
    let template = br#"
Resources:
  Widget:
    Type: AWS::Test::Widget
    Properties:
      Name: primary-widget
      Port: 443
      Tags:
        - Key: environment
          Value: test
"#;

    let validator = validator_with_sources(&[WIDGET_SCHEMA, WIDGET_ATTRIBUTES_SCHEMA]);
    let diagnostics = validate_template(&validator, template);
    assert!(
        !diagnostics.iter().any(|diagnostic| diagnostic.severity == rules::Severity::Fatal),
        "the composed schema must accept properties from both sources, got: {:?}",
        diagnostics.iter().map(|diagnostic| (&diagnostic.rule_id, &diagnostic.message)).collect::<Vec<_>>()
    );
}

#[test]
fn additional_schema_source_constraints_are_enforced() {
    let template = br#"
Resources:
  Widget:
    Type: AWS::Test::Widget
    Properties:
      Name: x
      Port: 70000
"#;
    let validator = validator_with_sources(&[WIDGET_SCHEMA]);

    let diagnostics = validate_template(&validator, template);

    assert!(has_rule(&diagnostics, "F3033"), "the source's string length constraint must be enforced");
    assert!(has_rule(&diagnostics, "F3034"), "the source's numeric bound must be enforced");
}

#[test]
fn additional_schema_source_definition_constraints_are_enforced_after_composition() {
    let template = br#"
Resources:
  Widget:
    Type: AWS::Test::Widget
    Properties:
      Name: primary-widget
      Port: 443
      Tags:
        - Key: environment
"#;
    let validator = validator_with_sources(&[WIDGET_SCHEMA, WIDGET_ATTRIBUTES_SCHEMA]);

    let diagnostics = validate_template(&validator, template);

    assert!(
        has_rule(&diagnostics, "F3003"),
        "the definition supplied by the second source must require a tag value, got: {:?}",
        diagnostics.iter().map(|diagnostic| (&diagnostic.rule_id, &diagnostic.message)).collect::<Vec<_>>()
    );
}

#[test]
fn invalid_additional_schema_source_is_reported_as_a_source_error() {
    let config = SchemaValidatorConfig::new().with_additional_schemas([AdditionalSchemaSource {
        type_name: Some("AWS::Test::Invalid".to_string()),
        schema: "{ invalid json".to_string(),
    }]);

    let error = match SchemaValidator::new(config) {
        Err(error) => error,
        Ok(_) => panic!("invalid JSON must fail validator construction"),
    };

    assert!(matches!(error, SchemaValidatorConfigError::Source(_)));
    assert!(
        error.to_string().contains("AWS::Test::Invalid"),
        "the source error must identify the failing type: {error}"
    );
}
