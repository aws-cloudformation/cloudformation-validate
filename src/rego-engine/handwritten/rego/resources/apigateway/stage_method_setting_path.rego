package resources

import rego.v1

# A method setting configures caching, logging, metrics or throttling for one
# resource path and method. Once any such setting is present, API Gateway
# resolves ResourcePath as an absolute path, so it must start with '/'.
_stage_method_setting_keys := {
    "CacheDataEncrypted",
    "CacheTtlInSeconds",
    "CachingEnabled",
    "DataTraceEnabled",
    "LoggingLevel",
    "MetricsEnabled",
    "ThrottlingBurstLimit",
    "ThrottlingRateLimit",
}

_stage_method_setting_configures_something(setting) if {
    some key in _stage_method_setting_keys
    object.get(setting, key, null) != null
}

violation contains make_diag_at("E3723", "ERROR", name,
    sprintf("Properties.MethodSettings.%d.ResourcePath", [idx]),
    sprintf("ResourcePath '%s' must start with '/' when a method setting is configured", [resource_path])) if {
    cfn_rule_active("E3723")
    some name in resources_of_type("AWS::ApiGateway::Stage")
    settings := resolve(name, "Properties.MethodSettings")
    is_array(settings)
    some idx, setting in settings
    is_object(setting)
    _stage_method_setting_configures_something(setting)
    resource_path := object.get(setting, "ResourcePath", null)
    is_string(resource_path)
    not startswith(resource_path, "/")
}
