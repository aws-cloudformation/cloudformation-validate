package intrinsics

import rego.v1

# Valid AWS regions for GetAZs validation.
# MUST mirror `template_model::aws_regions::availability_zone_suffixes` in
# src/template-model/src/aws_regions.rs. Whenever a new GA region launches,
# update both this list and the canonical Rust source.
_valid_regions := {
    "af-south-1",
    "ap-east-1", "ap-east-2",
    "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
    "ap-south-1", "ap-south-2",
    "ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ap-southeast-4",
    "ap-southeast-5", "ap-southeast-6", "ap-southeast-7",
    "ca-central-1", "ca-west-1",
    "cn-north-1", "cn-northwest-1",
    "eu-central-1", "eu-central-2",
    "eu-north-1",
    "eu-south-1", "eu-south-2",
    "eu-west-1", "eu-west-2", "eu-west-3",
    "il-central-1",
    "me-central-1", "me-south-1",
    "mx-central-1",
    "sa-east-1",
    "us-east-1", "us-east-2",
    "us-gov-east-1", "us-gov-west-1",
    "us-west-1", "us-west-2",
}

# E1015: GetAZs parameter must be a valid region if non-empty string literal
violation contains make_diag("E1015", "ERROR", name,
    sprintf("Fn::GetAZs parameter '%s' is not a valid region", [region])) if {
    some name, res in input.resources
    some _, prop in res.properties
    region := _find_invalid_getazs_region(prop)
}

_find_invalid_getazs_region(val) := region if {
    is_object(val)
    region := val["Fn::GetAZs"]
    is_string(region)
    region != ""
    not region in _valid_regions
}

_find_invalid_getazs_region(val) := region if {
    is_object(val)
    some _, v in val
    not val["Fn::GetAZs"]
    region := _find_invalid_getazs_region(v)
}

_find_invalid_getazs_region(val) := region if {
    is_array(val)
    some item in val
    region := _find_invalid_getazs_region(item)
}

# E1016: ImportValue cannot use Ref to AWS::StackName
violation contains make_diag_at("E1016", "ERROR", name, edge.sourcePath,
    "Fn::ImportValue cannot use Ref to 'AWS::StackName'") if {
    some name, res in input.resources
    some edge in res.outgoingRefs
    edge.kind == "Ref"
    edge.target == "AWS::StackName"
    contains(edge.sourcePath, "Fn::ImportValue")
}
