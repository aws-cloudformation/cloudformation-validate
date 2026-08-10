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
