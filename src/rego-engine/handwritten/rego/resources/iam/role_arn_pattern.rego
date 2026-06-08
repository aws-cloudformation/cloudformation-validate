package resources

import rego.v1

# E3511: IAM Role ARN must match expected pattern
iam_role_arn_properties := {
    {"type": "AWS::Backup::BackupSelection", "path": "Properties.BackupSelection.IamRoleArn"},
    {"type": "AWS::Batch::ComputeEnvironment", "path": "Properties.ComputeResources.SpotIamFleetRole"},
    {"type": "AWS::Batch::ComputeEnvironment", "path": "Properties.ServiceRole"},
    {"type": "AWS::EC2::SpotFleet", "path": "Properties.SpotFleetRequestConfigData.IamFleetRole"},
    {"type": "AWS::ECS::TaskDefinition", "path": "Properties.ExecutionRoleArn"},
    {"type": "AWS::S3::Bucket", "path": "Properties.ReplicationConfiguration.Role"},
}

violation contains make_diag_full("E3511", "ERROR", name,
    prop.path,
    sprintf("IAM Role ARN '%s' does not match expected pattern", [val]),
    "Use format: arn:aws:iam::123456789012:role/role-name",
    "") if {
    some prop in iam_role_arn_properties
    some name in resources_of_type(prop.type)
    val := resolve(name, prop.path)
    is_string(val)
    not is_dynamic(name, prop.path)
    not regex.match(`^arn:(aws[a-zA-Z-]*)?:iam::[0-9]{12}:role/[a-zA-Z_0-9+=,.@\-_/]+$`, val)
}
