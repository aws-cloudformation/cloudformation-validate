package resources

import rego.v1

# W3002: Properties that only work with `aws cloudformation package`
# cfn-lint checks the parent property (e.g. Code, Content, TemplateURL) as a string.
# If the value is a string that doesn't start with s3:// or https://, it warns.
# SAM templates are excluded entirely (has_serverless_transform check).
_w3002_package_props := {
    "AWS::Lambda::Function": ["Code"],
    "AWS::Lambda::LayerVersion": ["Content"],
    "AWS::ElasticBeanstalk::ApplicationVersion": ["SourceBundle"],
    "AWS::StepFunctions::StateMachine": ["DefinitionS3Location"],
    "AWS::AppSync::GraphQLSchema": ["DefinitionS3Location"],
    "AWS::AppSync::Resolver": ["RequestMappingTemplateS3Location", "ResponseMappingTemplateS3Location"],
    "AWS::AppSync::FunctionConfiguration": ["RequestMappingTemplateS3Location", "ResponseMappingTemplateS3Location"],
    "AWS::CloudFormation::Stack": ["TemplateURL"],
    "AWS::CodeCommit::Repository": ["Code.S3"],
    "AWS::ApiGateway::RestApi": ["BodyS3Location"],
}

violation contains make_diag_at("W3002", "WARN", name,
    sprintf("Properties.%s", [prop]),
    "This code may only work with 'package' cli command") if {
    not has_transform("AWS::Serverless-2016-10-31")
    some rtype, props in _w3002_package_props
    some name in resources_of_type(rtype)
    some prop in props
    val := resolve(name, sprintf("Properties.%s", [prop]))
    is_string(val)
    not startswith(val, "s3://")
    not startswith(val, "https://")
}
