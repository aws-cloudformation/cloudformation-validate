package resources

import rego.v1

# E3039: DynamoDB KeySchema attributes must be defined in AttributeDefinitions
violation contains make_diag_full("E3039", "ERROR", name,
    "Properties.KeySchema",
    sprintf("KeySchema attribute '%s' is not defined in AttributeDefinitions", [attr_name]),
    "Add the attribute to AttributeDefinitions",
    "") if {
    some name in resources_of_type("AWS::DynamoDB::Table")
    key_schema := resolve(name, "Properties.KeySchema")
    is_array(key_schema)
    attr_defs := resolve(name, "Properties.AttributeDefinitions")
    is_array(attr_defs)
    some ks in key_schema
    attr_name := ks.AttributeName
    is_string(attr_name)
    not attr_name in {ad.AttributeName | some ad in attr_defs}
}

# Also check GSI/LSI KeySchema
violation contains make_diag_full("E3039", "ERROR", name,
    sprintf("Properties.GlobalSecondaryIndexes[%d].KeySchema", [idx]),
    sprintf("GSI KeySchema attribute '%s' is not defined in AttributeDefinitions", [attr_name]),
    "Add the attribute to AttributeDefinitions",
    "") if {
    some name in resources_of_type("AWS::DynamoDB::Table")
    gsis := resolve(name, "Properties.GlobalSecondaryIndexes")
    is_array(gsis)
    attr_defs := resolve(name, "Properties.AttributeDefinitions")
    is_array(attr_defs)
    some idx, gsi in gsis
    some ks in gsi.KeySchema
    attr_name := ks.AttributeName
    is_string(attr_name)
    not attr_name in {ad.AttributeName | some ad in attr_defs}
}

# Every defined attribute must be used by some key schema - the table's own,
# a global index's, or a local index's. Unused definitions fail table
# creation. Only reported when every key is defined, so one mistake is not
# reported from both directions.
_ddb_index_key_attrs(name, prop) := {attr |
    indexes := resolve(name, prop)
    is_array(indexes)
    some index in indexes
    some ks in index.KeySchema
    attr := ks.AttributeName
    is_string(attr)
}

_ddb_index_key_attrs(name, prop) := set() if {
    not is_array(resolve(name, prop))
}

violation contains make_diag_full("E3039", "ERROR", name,
    "Properties",
    sprintf("The set of Attributes in AttributeDefinitions: %s and KeySchemas: %s must match",
        [defined_list, used_list]),
    "Remove unused entries from AttributeDefinitions or add key schemas that use them",
    "") if {
    some name in resources_of_type("AWS::DynamoDB::Table")
    key_schema := resolve(name, "Properties.KeySchema")
    is_array(key_schema)
    attr_defs := resolve(name, "Properties.AttributeDefinitions")
    is_array(attr_defs)
    base_keys := {ks.AttributeName | some ks in key_schema; is_string(ks.AttributeName)}
    defined := {ad.AttributeName | some ad in attr_defs; is_string(ad.AttributeName)}
    # every key defined (the reverse direction is reported per key above)
    count(base_keys - defined) == 0
    used := ((base_keys | _ddb_index_key_attrs(name, "Properties.GlobalSecondaryIndexes")) | _ddb_index_key_attrs(name, "Properties.LocalSecondaryIndexes"))
    count(defined - used) > 0
    defined_list := render_list(sort([d | some d in defined]))
    used_list := render_list(sort([u | some u in used]))
}

# An explicitly PROVISIONED table must carry a throughput configuration; the
# table fails to create without one.
_has_provisioned_throughput(name) if {
    resolve(name, "Properties.ProvisionedThroughput") != null
}

violation contains make_diag_full("E3639", "ERROR", name,
    "Properties",
    "'ProvisionedThroughput' is a required property",
    "Add ProvisionedThroughput or use BillingMode PAY_PER_REQUEST",
    "") if {
    some name in resources_of_type("AWS::DynamoDB::Table")
    resolve(name, "Properties.BillingMode") == "PROVISIONED"
    not _has_provisioned_throughput(name)
}
