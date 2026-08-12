package resources

import rego.v1

# DynamoDB defaults BillingMode to PROVISIONED, which requires
# ProvisionedThroughput. AWS::NoValue counts as removing the property.

violation contains make_diag_full("E3639", "ERROR", name,
    "Properties.ProvisionedThroughput",
    "ProvisionedThroughput is required when BillingMode is 'PROVISIONED'",
    "Add ProvisionedThroughput or set BillingMode to 'PAY_PER_REQUEST'",
    "") if {
    some name in resources_of_type("AWS::DynamoDB::Table")
    _ddb_is_explicitly_provisioned(name)
    not _ddb_has_effective_throughput(name)
}

violation contains make_diag_full("E3639", "ERROR", name,
    "Properties.ProvisionedThroughput",
    "ProvisionedThroughput is required when BillingMode defaults to 'PROVISIONED'",
    "Add ProvisionedThroughput or set BillingMode to 'PAY_PER_REQUEST'",
    "") if {
    some name in resources_of_type("AWS::DynamoDB::Table")
    _ddb_defaults_to_provisioned(name)
    not _ddb_has_effective_throughput(name)
}

_ddb_is_explicitly_provisioned(name) if {
    billing_mode := resolve(name, "Properties.BillingMode")
    billing_mode == "PROVISIONED"
}

_ddb_defaults_to_provisioned(name) if {
    not has_property(name, "BillingMode")
}

_ddb_defaults_to_provisioned(name) if {
    has_property(name, "BillingMode")
    billing_mode := resolve(name, "Properties.BillingMode")
    billing_mode == null
}

_ddb_has_effective_throughput(name) if {
    has_property(name, "ProvisionedThroughput")
    provisioned_throughput := resolve(name, "Properties.ProvisionedThroughput")
    provisioned_throughput != null
}

_ddb_has_effective_throughput(name) if {
    has_property(name, "ProvisionedThroughput")
    is_dynamic(name, "Properties.ProvisionedThroughput")
}
