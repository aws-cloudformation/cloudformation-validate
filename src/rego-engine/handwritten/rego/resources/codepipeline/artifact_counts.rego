package resources

import rego.v1

# E3702: CodePipeline action artifact-count validation. The count check must
# enumerate every Fn::If branch of an InputArtifacts/OutputArtifacts list (an
# artifact list authored behind a condition can violate the min/max in one
# branch but not another). That branch enumeration is provided by the
# pipeline_artifact_count_issues builtin.
violation contains make_diag_full("E3702", "ERROR", name, issue.path,
    issue.message, "", "") if {
    some name in resources_of_type("AWS::CodePipeline::Pipeline")
    result := pipeline_artifact_count_issues(name)
    some issue in result.issues
}
