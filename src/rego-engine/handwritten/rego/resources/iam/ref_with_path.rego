package resources

import rego.v1

# E3050: When using Ref to an IAM resource, the Path must be '/'
# CodeBuild ServiceRole uses Ref which returns the role name, not ARN.
# If the IAM role has a non-default Path, the name alone won't resolve correctly.
violation contains make_diag_full("E3050", "ERROR", name,
    "Properties.ServiceRole",
    sprintf("Ref to IAM role '%s' with Path '%s' - use GetAtt %s.Arn instead", [target, iam_path, target]),
    "Switch from Ref to !GetAtt <Role>.Arn when Path is not '/'",
    "") if {
    cfn_rule_active("E3050")
    some name in resources_of_type("AWS::CodeBuild::Project")
    target := follow_ref(name, "Properties.ServiceRole")
    target != null
    target_res := get_resource(target)
    target_res != null
    target_res.resourceType == "AWS::IAM::Role"
    iam_path := object.get(target_res.properties, "Path", "/")
    is_string(iam_path)
    iam_path != "/"
}
