package resources

import rego.v1

# E3706: AutoScaling MinSize must be <= MaxSize
violation contains make_diag_at("E3706", "ERROR", name,
    "Properties.MinSize",
    sprintf("MinSize (%d) must be less than or equal to MaxSize (%d)", [min_val, max_val])) if {
    some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
    min_val := resolve(name, "Properties.MinSize")
    max_val := resolve(name, "Properties.MaxSize")
    is_number(min_val)
    is_number(max_val)
    min_val > max_val
}

# E3676: HTTPS/TLS listeners require a certificate
violation contains make_diag_at("E3676", "ERROR", name,
    "Properties.Certificates",
    sprintf("%s listener requires Certificates", [proto])) if {
    some name in resources_of_type("AWS::ElasticLoadBalancingV2::Listener")
    proto := resolve(name, "Properties.Protocol")
    proto in {"HTTPS", "TLS"}
    not has_property(name, "Certificates")
}

# E3663: Lambda environment variable reserved keys
violation contains make_diag_at("E3663", "ERROR", name,
    "Properties.Environment.Variables",
    sprintf("Environment variable '%s' is a Lambda reserved key", [key])) if {
    some name in resources_of_type("AWS::Lambda::Function")
    env := resolve(name, "Properties.Environment.Variables")
    is_object(env)
    some key in object.keys(env)
    key in _lambda_reserved_env_keys
}

_lambda_reserved_env_keys := {
    "_HANDLER", "_X_AMZN_TRACE_ID", "AWS_DEFAULT_REGION", "AWS_REGION",
    "AWS_EXECUTION_ENV", "AWS_LAMBDA_FUNCTION_NAME", "AWS_LAMBDA_FUNCTION_MEMORY_SIZE",
    "AWS_LAMBDA_FUNCTION_VERSION", "AWS_LAMBDA_LOG_GROUP_NAME",
    "AWS_LAMBDA_LOG_STREAM_NAME", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN", "AWS_LAMBDA_RUNTIME_API", "LAMBDA_TASK_ROOT",
    "LAMBDA_RUNTIME_DIR", "TZ",
}

# E3685: Lambda PackageType Image exclusions
violation contains make_diag_at("E3685", "ERROR", name,
    sprintf("Properties.%s", [prop]),
    sprintf("'%s' is not allowed when PackageType is 'Image'", [prop])) if {
    some name in resources_of_type("AWS::Lambda::Function")
    resolve(name, "Properties.PackageType") == "Image"
    prop := _image_excluded_props[_]
    has_property(name, prop)
}

_image_excluded_props := ["Handler", "Runtime", "Layers"]

# E3660: API Gateway RestApi requires Name when not using Body/BodyS3Location
violation contains make_diag_at("E3660", "ERROR", name,
    "Properties.Name",
    "'Name' is required when 'Body' or 'BodyS3Location' is not provided") if {
    some name in resources_of_type("AWS::ApiGateway::RestApi")
    not has_property(name, "Body")
    not has_property(name, "BodyS3Location")
    not has_property(name, "Name")
}

# E3704: ElastiCache Valkey requires TransitEncryptionEnabled
violation contains make_diag_at("E3704", "ERROR", name,
    "Properties.TransitEncryptionEnabled",
    "TransitEncryptionEnabled must be explicitly set when Engine is 'valkey'") if {
    some name in resources_of_type("AWS::ElastiCache::ReplicationGroup")
    resolve(name, "Properties.Engine") == "valkey"
    not has_property(name, "TransitEncryptionEnabled")
}

# E3680: Application load balancer requires at least 2 subnets
violation contains make_diag_at("E3680", "ERROR", name,
    "Properties.Subnets",
    "Application load balancer requires at least 2 subnets") if {
    some name in resources_of_type("AWS::ElasticLoadBalancingV2::LoadBalancer")
    lb_type := object.get(input.resources[name], "resourceType", "application")
    lb_type in {"application", ""}
    subnets := resolve(name, "Properties.Subnets")
    is_array(subnets)
    count(subnets) < 2
}
