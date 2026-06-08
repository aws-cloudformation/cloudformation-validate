package resources

import rego.v1

# W3664: Lambda Permission — SourceArn should match Principal service
violation contains make_diag_at("W3664", "WARN", name,
    "Properties.SourceArn",
    sprintf("SourceArn references '%s' (type '%s') but Principal 'sns.amazonaws.com' expects an SNS Topic", [target, target_type])) if {
    some name in resources_of_type("AWS::Lambda::Permission")
    principal := resolve(name, "Properties.Principal")
    principal == "sns.amazonaws.com"
    target := follow_ref(name, "Properties.SourceArn")
    target != null
    target_res := get_resource(target)
    target_res != null
    target_type := target_res.resourceType
    target_type != "AWS::SNS::Topic"
}

violation contains make_diag_at("W3664", "WARN", name,
    "Properties.SourceArn",
    sprintf("SourceArn references '%s' (type '%s') but Principal 's3.amazonaws.com' expects an S3 Bucket", [target, target_type])) if {
    some name in resources_of_type("AWS::Lambda::Permission")
    principal := resolve(name, "Properties.Principal")
    principal == "s3.amazonaws.com"
    target := follow_ref(name, "Properties.SourceArn")
    target != null
    target_res := get_resource(target)
    target_res != null
    target_type := target_res.resourceType
    target_type != "AWS::S3::Bucket"
}
