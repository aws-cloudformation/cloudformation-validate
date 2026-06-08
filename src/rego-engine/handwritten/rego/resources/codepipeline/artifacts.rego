package resources

import rego.v1

# E3701: CodePipeline artifact validation
violation contains make_diag("E3701", "ERROR", name, issue.message) if {
    some name in resources_of_type("AWS::CodePipeline::Pipeline")
    result := pipeline_artifacts(name)
    some issue in result.issues
}
