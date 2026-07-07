package resources

import rego.v1

# E3025: Engine/LicenseModel-conditional RDS DBInstanceClass validation.
#
# The per-region document is a conditional schema (an allOf of if/then blocks).
# Every branch whose `if.required` consts (Engine/LicenseModel) match this
# resource applies, so the class must be in ALL matching branches' enums (the
# intersection). `region_conditional_invalid` returns the rendered diagnostic
# message when the class is invalid for the effective scope — the configured
# region, or the union of all regions when none is configured (flagged only when
# invalid in every region) — or is undefined when it is valid or no branch
# matches (so a dynamic or unmatched Engine is not validated). The Engine is
# matched case-insensitively for DBInstance.
violation contains make_diag_full("E3025", "ERROR", name,
    "Properties.DBInstanceClass", msg, "", "") if {
    some name in resources_of_type("AWS::RDS::DBInstance")
    val := resolve(name, "Properties.DBInstanceClass")
    is_string(val)
    msg := region_conditional_invalid(data.aws_rds_dbinstance_dbinstanceclass_enum,
        "DBInstanceClass", true, val, _rds_engine_props(name))
}

# E3694: Engine-conditional RDS DBClusterInstanceClass validation. Same conditional
# schema shape as E3025, but Engine is matched case-sensitively for DBCluster
# (false).
violation contains make_diag_full("E3694", "ERROR", name,
    "Properties.DBClusterInstanceClass", msg, "", "") if {
    some name in resources_of_type("AWS::RDS::DBCluster")
    val := resolve(name, "Properties.DBClusterInstanceClass")
    is_string(val)
    msg := region_conditional_invalid(data.aws_rds_dbcluster_dbclusterinstanceclass_enum,
        "DBClusterInstanceClass", false, val, _rds_engine_props(name))
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
