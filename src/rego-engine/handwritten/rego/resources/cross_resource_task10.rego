package resources

import rego.v1

# E3706: AutoScaling MaxSize must be >= MinSize.
# MinSize/MaxSize are usually authored as strings ('10'), which CloudFormation
# coerces to numbers, so compare on the coerced values. The finding is anchored
# at MaxSize and reports the violated constraint (the max is below the minimum),
# rendering the offending MaxSize value in its original form.
violation contains make_diag_at("E3706", "ERROR", name,
    "Properties.MaxSize",
    sprintf("%s is less than the minimum of %d", [render_value(max_raw), min_num])) if {
    cfn_rule_active("E3706")
    some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
    max_raw := resolve(name, "Properties.MaxSize")
    min_num := coerce_to_number(resolve(name, "Properties.MinSize"))
    max_num := coerce_to_number(max_raw)
    min_num > max_num
}

# E3676: HTTPS/TLS listeners require a certificate
violation contains make_diag_at("E3676", "ERROR", name,
    "Properties.Certificates",
    sprintf("%s listener requires Certificates", [proto])) if {
    cfn_rule_active("E3676")
    some name in resources_of_type("AWS::ElasticLoadBalancingV2::Listener")
    proto := resolve(name, "Properties.Protocol")
    proto in data.load_balancer_v2_certificate_protocols
    not has_property(name, "Certificates")
}

# E3663: Lambda environment variable reserved keys
violation contains make_diag_at("E3663", "ERROR", name,
    "Properties.Environment.Variables",
    sprintf("Environment variable '%s' is a Lambda reserved key", [key])) if {
    cfn_rule_active("E3663")
    some name in resources_of_type("AWS::Lambda::Function")
    env := resolve(name, "Properties.Environment.Variables")
    is_object(env)
    some key in object.keys(env)
    key in data.lambda_reserved_environment_keys
}

# E3685: Container image Lambda functions cannot specify Handler, Runtime, or
# Layers. A single finding is emitted with a fixed message, anchored at the
# first offending property present (in schema order), regardless of how many are
# set - so collapse to one diagnostic rather than one per property.
violation contains make_diag_at("E3685", "ERROR", name,
    sprintf("Properties.%s", [first_prop]),
    "Container image functions cannot specify Handler, Runtime, or Layers properties") if {
    cfn_rule_active("E3685")
    some name in resources_of_type("AWS::Lambda::Function")
    resolve(name, "Properties.PackageType") == "Image"
    present := [p | some p in data.lambda_image_excluded_properties; has_property(name, p)]
    count(present) > 0
    first_prop := present[0]
}

# E3660: API Gateway RestApi requires Name when not using Body/BodyS3Location
violation contains make_diag_at("E3660", "ERROR", name,
    "Properties.Name",
    "'Name' is required when 'Body' or 'BodyS3Location' is not provided") if {
    cfn_rule_active("E3660")
    some name in resources_of_type("AWS::ApiGateway::RestApi")
    not has_property(name, "Body")
    not has_property(name, "BodyS3Location")
    not has_property(name, "Name")
}

# E3704: ElastiCache Valkey requires TransitEncryptionEnabled
violation contains make_diag_at("E3704", "ERROR", name,
    "Properties.TransitEncryptionEnabled",
    "TransitEncryptionEnabled must be explicitly set when Engine is 'valkey'") if {
    cfn_rule_active("E3704")
    some name in resources_of_type("AWS::ElastiCache::ReplicationGroup")
    resolve(name, "Properties.Engine") == "valkey"
    not has_property(name, "TransitEncryptionEnabled")
}

# E3680: Application load balancer requires at least 2 subnets
violation contains make_diag_at("E3680", "ERROR", name,
    "Properties.Subnets",
    "Application load balancer requires at least 2 subnets") if {
    cfn_rule_active("E3680")
    some name in resources_of_type("AWS::ElasticLoadBalancingV2::LoadBalancer")
    lb_type := object.get(input.resources[name], "resourceType", "application")
    lb_type in {"application", ""}
    subnets := resolve(name, "Properties.Subnets")
    is_array(subnets)
    count(subnets) < 2
}
