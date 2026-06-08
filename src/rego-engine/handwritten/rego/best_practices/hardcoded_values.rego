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

# I3042: Hardcoded partition in ARN (plain string properties)
violation contains make_diag("I3042", "INFO", name,
    "Hardcoded partition 'aws' in ARN — use AWS::Partition pseudo-parameter for portability") if {
    some name, res in input.resources
    some key in object.keys(res.properties)
    val := res.properties[key]
    is_string(val)
    startswith(val, "arn:aws:")
    not is_dynamic(name, sprintf("Properties.%s", [key]))
}

# I3042: Hardcoded partition in Fn::Sub template
violation contains make_diag_at("I3042", "INFO", name,
    sprintf("Properties.%s", [path]),
    sprintf("ARN in Resource %s contains hardcoded Partition in ARN or incorrectly placed Pseudo Parameters", [name])) if {
    some name, res in input.resources
    some path in res.hardcodedPartitionArns
}

# W3011: Both UpdateReplacePolicy and DeletionPolicy needed to protect resource
violation contains make_diag("W3011", "WARN", name,
    "Both 'UpdateReplacePolicy' and 'DeletionPolicy' are needed to protect resource from deletion") if {
    some name, res in input.resources
    res.deletionPolicy != null
    res.updateReplacePolicy == null
}

violation contains make_diag("W3011", "WARN", name,
    "Both 'UpdateReplacePolicy' and 'DeletionPolicy' are needed to protect resource from deletion") if {
    some name, res in input.resources
    res.updateReplacePolicy != null
    res.deletionPolicy == null
}
