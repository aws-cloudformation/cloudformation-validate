package best_practices

import rego.v1

# W9010: Hardcoded AMI ID
violation contains make_diag_at("W9010", "WARN", name,
    "Properties.ImageId",
    "Hardcoded AMI ID — use a parameter or mapping for portability") if {
    some name in resources_of_type("AWS::EC2::Instance")
    val := resolve(name, "Properties.ImageId")
    is_string(val)
    not is_dynamic(name, "Properties.ImageId")
    regex.match(`^ami-[0-9a-f]{8,17}$`, val)
}

# W9013: Hardcoded account ID in ARN
violation contains make_diag("W9013", "WARN", name,
    "Hardcoded account ID in ARN — use AWS::AccountId pseudo-parameter") if {
    some name, res in input.resources
    some key in object.keys(res.properties)
    val := res.properties[key]
    is_string(val)
    regex.match(`arn:[^:]*:[^:]*:[^:]*:[0-9]{12}:`, val)
}

# I3042: Hardcoded partition in Fn::Sub template (only fires inside Fn::Sub, skips SAM)
violation contains make_diag_at("I3042", "INFO", name,
    path,
    sprintf("ARN in Resource %s contains hardcoded Partition in ARN or incorrectly placed Pseudo Parameters", [name])) if {
    not has_transform("AWS::Serverless-2016-10-31")
    some name, res in input.resources
    some path in res.hardcodedPartitionArns
}

# W3011: Both UpdateReplacePolicy and DeletionPolicy needed to protect resource.
# A lone policy set to "Delete" is the default behavior, so its counterpart adds
# no protection and the configuration is valid. Only warn when the single present
# policy asks for something other than Delete.
violation contains make_diag("W3011", "WARN", name,
    "Both 'UpdateReplacePolicy' and 'DeletionPolicy' are needed to protect resource from deletion") if {
    some name, res in input.resources
    res.deletionPolicy != null
    res.deletionPolicy != "Delete"
    res.updateReplacePolicy == null
}

violation contains make_diag("W3011", "WARN", name,
    "Both 'UpdateReplacePolicy' and 'DeletionPolicy' are needed to protect resource from deletion") if {
    some name, res in input.resources
    res.updateReplacePolicy != null
    res.updateReplacePolicy != "Delete"
    res.deletionPolicy == null
}
