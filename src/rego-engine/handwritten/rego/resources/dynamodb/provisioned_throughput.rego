package resources

import rego.v1

violation contains make_diag_full("E3639", "ERROR", name,
    "Properties.ProvisionedThroughput",
    "ProvisionedThroughput is required when BillingMode is 'PROVISIONED'",
    "Add ProvisionedThroughput or set BillingMode to 'PAY_PER_REQUEST'",
    "") if {
    some name in resources_of_type("AWS::DynamoDB::Table")
    dynamodb_scenario_analysis(name).explicit_provisioned_missing_throughput
}

violation contains make_diag_full("E3639", "ERROR", name,
    "Properties.ProvisionedThroughput",
    "ProvisionedThroughput is required when BillingMode defaults to 'PROVISIONED'",
    "Add ProvisionedThroughput or set BillingMode to 'PAY_PER_REQUEST'",
    "") if {
    some name in resources_of_type("AWS::DynamoDB::Table")
    dynamodb_scenario_analysis(name).default_provisioned_missing_throughput
}
