package resources

import rego.v1

# W3663: a Lambda Permission needs SourceAccount when its SourceArn cannot by
# itself pin the calling account - either the SourceArn references an S3 bucket
# (bucket ARNs carry no account id) or it is a literal ARN string with no
# ':<12-digit-account>:' segment. The Principal is irrelevant.

# Branch 1: SourceArn references an S3 bucket.
violation contains make_diag_full("W3663", "WARN", name,
    "Properties",
    "Lambda Permission with a SourceArn that has no account id should also specify SourceAccount",
    "Add SourceAccount property",
    "") if {
    cfn_rule_active("W3663")
    some name in resources_of_type("AWS::Lambda::Permission")
    not has_property(name, "SourceAccount")
    target := follow_ref(name, "Properties.SourceArn")
    object.get(input.resources[target], "resourceType", "") == "AWS::S3::Bucket"
}

# Branch 2: SourceArn is a literal ARN string without a 12-digit account segment.
# Guard on `not is_from_intrinsic` so a SourceArn supplied via Ref/GetAtt (whose
# resolved value is not a concrete literal) does not trip the pattern check -
# the account-id pattern check applies only to a literal ARN string here.
violation contains make_diag_full("W3663", "WARN", name,
    "Properties",
    "Lambda Permission with a SourceArn that has no account id should also specify SourceAccount",
    "Add SourceAccount property",
    "") if {
    cfn_rule_active("W3663")
    some name in resources_of_type("AWS::Lambda::Permission")
    not has_property(name, "SourceAccount")
    not is_from_intrinsic(name, "Properties.SourceArn")
    source_arn := resolve(name, "Properties.SourceArn")
    is_string(source_arn)
    not regex.match(`:\d{12}:`, source_arn)
}
