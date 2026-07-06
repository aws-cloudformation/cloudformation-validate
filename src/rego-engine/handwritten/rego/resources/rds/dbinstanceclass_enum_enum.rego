package resources

import rego.v1

# E3025: Engine/LicenseModel-conditional RDS DBInstanceClass validation.
#
# The per-region document is a conditional schema (an allOf of if/then blocks).
# Every branch whose `if.required` consts (Engine/LicenseModel) match this
# resource applies, so the class must be in ALL matching branches' enums (the
# intersection). `invalid_instance_class_enum` returns the enum to render when the
# class is invalid, or undefined when it is valid or no branch matches (so a
# dynamic or unmatched Engine is not validated). The Engine is matched
# case-insensitively for DBInstance, mirroring the reference tool.
violation contains make_diag_full("E3025", "ERROR", name,
    "Properties.DBInstanceClass",
    sprintf("'%s' is not one of %s in '%s'", [val, render_list(reported), region]),
    "",
    "") if {
    some name in resources_of_type("AWS::RDS::DBInstance")
    val := resolve(name, "Properties.DBInstanceClass")
    is_string(val)
    region := effective_region()
    region_schema := data.aws_rds_dbinstance_dbinstanceclass_enum[region]
    region_schema != null
    reported := invalid_instance_class_enum(region_schema, _rds_engine_props(name), "DBInstanceClass", true, val)
}

# E3694: Engine-conditional RDS DBClusterInstanceClass validation. Same conditional
# schema shape as E3025, but the reference tool does NOT lowercase Engine for
# DBCluster, so match the const case-sensitively (false).
violation contains make_diag_full("E3694", "ERROR", name,
    "Properties.DBClusterInstanceClass",
    sprintf("'%s' is not one of %s in '%s'", [val, render_list(reported), region]),
    "",
    "") if {
    some name in resources_of_type("AWS::RDS::DBCluster")
    val := resolve(name, "Properties.DBClusterInstanceClass")
    is_string(val)
    region := effective_region()
    region_schema := data.aws_rds_dbcluster_dbclusterinstanceclass_enum[region]
    region_schema != null
    reported := invalid_instance_class_enum(region_schema, _rds_engine_props(name), "DBClusterInstanceClass", false, val)
}

# The resource's resolved scalar properties the conditional branches key on.
# A property that does not resolve to a concrete value is simply absent, so its
# branch cannot match.
_rds_engine_props(name) := props if {
    props := {k: v |
        some k in ["Engine", "LicenseModel"]
        v := resolve(name, sprintf("Properties.%s", [k]))
        is_string(v)
    }
}
