package resources

import rego.v1

# E3062: RDS DBInstance — DBInstanceClass must be valid for Engine/EngineVersion
violation contains make_diag_at("E3062", "ERROR", name,
    "Properties.DBInstanceClass",
    sprintf("DBInstanceClass '%s' is not valid for Engine '%s' EngineVersion '%s'", [cls, eng, ver])) if {
    some name in resources_of_type("AWS::RDS::DBInstance")
    eng := resolve(name, "Properties.Engine")
    is_string(eng)
    ver_raw := resolve(name, "Properties.EngineVersion")
    ver := sprintf("%v", [ver_raw])
    cls := resolve(name, "Properties.DBInstanceClass")
    is_string(cls)
    entries := data.aws_rds_dbinstance_db_instance_class.allOf
    some entry in entries
    cond := entry["if"].properties
    cond.Engine["const"] == eng
    pat := cond.EngineVersion.pattern
    regex.match(pat, ver)
    allowed := entry["then"].properties.DBInstanceClass["enum"]
    not cls in allowed
}
