package resources

import rego.v1

_lambda_logging_resource_types := {"AWS::Lambda::Function", "AWS::Serverless::Function"}

_lambda_log_level_property(name) := "ApplicationLogLevel" if {
    has_property(name, "Properties.LoggingConfig.ApplicationLogLevel")
}

_lambda_log_level_property(name) := "SystemLogLevel" if {
    not has_property(name, "Properties.LoggingConfig.ApplicationLogLevel")
    has_property(name, "Properties.LoggingConfig.SystemLogLevel")
}

violation contains make_diag_full("E3696",
    "ERROR",
    name,
    property_path,
    sprintf("%s is not supported when LoggingConfig.LogFormat is 'Text'", [level_property]),
    sprintf("Set LoggingConfig.LogFormat to 'JSON' or remove %s", [level_property]),
    "",
) if {
    cfn_rule_active("E3696")
    some resource_type in _lambda_logging_resource_types
    some name in resources_of_type(resource_type)
    log_format_path := "Properties.LoggingConfig.LogFormat"
    not is_from_intrinsic(name, log_format_path)
    some log_format_scenario in resolve_scenarios(name, log_format_path)
    count(log_format_scenario.conditions) == 0
    log_format_scenario.value == "Text"
    level_property := _lambda_log_level_property(name)
    property_path := sprintf("Properties.LoggingConfig.%s", [level_property])
}
