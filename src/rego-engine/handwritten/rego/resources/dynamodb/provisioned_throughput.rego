package resources

import rego.v1

# DynamoDB table with BillingMode PROVISIONED (or default) requires
# ProvisionedThroughput. AWS::NoValue counts as removed (null), so explicit
# null ProvisionedThroughput also fires.

# Case 1: BillingMode is explicitly "PROVISIONED" and ProvisionedThroughput absent
violation contains make_diag_full("E3639", "ERROR", name,
    "Properties.ProvisionedThroughput",
    "ProvisionedThroughput is required when BillingMode is 'PROVISIONED'",
    "Add ProvisionedThroughput or set BillingMode to 'PAY_PER_REQUEST'",
    "") if {
    some name in resources_of_type("AWS::DynamoDB::Table")
    _ddb_is_provisioned(name)
    not _ddb_has_effective_throughput(name)
}

# BillingMode is PROVISIONED when:
# - explicitly set to "PROVISIONED"
# - absent (default is PROVISIONED)
# - null (AWS::NoValue removes the property, so the default applies)
_ddb_is_provisioned(name) if {
    bm := resolve(name, "Properties.BillingMode")
    bm == "PROVISIONED"
}

_ddb_is_provisioned(name) if {
    not has_property(name, "BillingMode")
}

_ddb_is_provisioned(name) if {
    has_property(name, "BillingMode")
    bm := resolve(name, "Properties.BillingMode")
    bm == null
}

# ProvisionedThroughput is effective when it resolves to a non-null value
_ddb_has_effective_throughput(name) if {
    has_property(name, "ProvisionedThroughput")
    pt := resolve(name, "Properties.ProvisionedThroughput")
    pt != null
}

_ddb_has_effective_throughput(name) if {
    has_property(name, "ProvisionedThroughput")
    is_dynamic(name, "Properties.ProvisionedThroughput")
}
