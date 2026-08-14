package resources

import rego.v1

# DynamoDB defaults BillingMode to PROVISIONED, which requires
# ProvisionedThroughput in every reachable PROVISIONED deployment.

violation contains make_diag_full("E3639", "ERROR", name,
    "Properties.ProvisionedThroughput",
    "ProvisionedThroughput is required when BillingMode is 'PROVISIONED'",
    "Add ProvisionedThroughput or set BillingMode to 'PAY_PER_REQUEST'",
    "") if {
    some name in resources_of_type("AWS::DynamoDB::Table")
    some billing_scenario in resolve_scenarios(name, "Properties.BillingMode")
    billing_scenario.value == "PROVISIONED"
    _resource_scenario_reachable(name, billing_scenario.conditions)
    _ddb_throughput_missing(name, billing_scenario.conditions)
}

violation contains make_diag_full("E3639", "ERROR", name,
    "Properties.ProvisionedThroughput",
    "ProvisionedThroughput is required when BillingMode defaults to 'PROVISIONED'",
    "Add ProvisionedThroughput or set BillingMode to 'PAY_PER_REQUEST'",
    "") if {
    some name in resources_of_type("AWS::DynamoDB::Table")
    not has_property(name, "BillingMode")
    _resource_scenario_reachable(name, {})
    _ddb_throughput_missing(name, {})
}

violation contains make_diag_full("E3639", "ERROR", name,
    "Properties.ProvisionedThroughput",
    "ProvisionedThroughput is required when BillingMode defaults to 'PROVISIONED'",
    "Add ProvisionedThroughput or set BillingMode to 'PAY_PER_REQUEST'",
    "") if {
    some name in resources_of_type("AWS::DynamoDB::Table")
    some billing_scenario in resolve_scenarios(name, "Properties.BillingMode")
    billing_scenario.value == null
    _resource_scenario_reachable(name, billing_scenario.conditions)
    _ddb_throughput_missing(name, billing_scenario.conditions)
}

_ddb_throughput_missing(name, billing_conditions) if {
    not has_property(name, "ProvisionedThroughput")
    _resource_scenario_reachable(name, billing_conditions)
}

_ddb_throughput_missing(name, billing_conditions) if {
    some throughput_scenario in resolve_scenarios(name, "Properties.ProvisionedThroughput")
    throughput_scenario.value == null
    _scenario_conditions_compatible(name, billing_conditions, throughput_scenario.conditions)
}
