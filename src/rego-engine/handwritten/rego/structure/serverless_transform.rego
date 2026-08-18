package structure

import rego.v1

# E3038: Serverless resource types require AWS::Serverless-2016-10-31 transform
violation contains make_diag_full("E3038", "ERROR", name, "Type",
    sprintf("Resource type '%s' requires the AWS::Serverless-2016-10-31 transform", [rtype]),
    "", "") if {
    some name, res in input.resources
    rtype := res.resourceType
    startswith(rtype, "AWS::Serverless::")
    not has_serverless_transform
}

has_serverless_transform if {
    some t in input.template.transforms
    t == "AWS::Serverless-2016-10-31"
}
