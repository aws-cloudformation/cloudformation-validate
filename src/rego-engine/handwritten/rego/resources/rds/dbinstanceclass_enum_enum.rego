package resources

import rego.v1

# Region-aware RDS DBInstanceClass validation
violation contains make_diag_full("E3025", "ERROR", name,
    "Properties.DBInstanceClass",
    sprintf("DBInstanceClass '%s' is not valid for AWS::RDS::DBInstance in region '%s'", [val, region]),
    "Use a valid instance class for the configured region",
    "") if {
    some name in resources_of_type("AWS::RDS::DBInstance")
    some val in resolve_all(name, "Properties.DBInstanceClass")
    is_string(val)
    region := input_region()
    region != null
    valid := data.aws_rds_dbinstance_dbinstanceclass_enum[region]
    valid != null
    not val in valid
}
