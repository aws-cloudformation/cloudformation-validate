package best_practices

import rego.v1

# I3100: Previous generation instance type
# Pattern and property paths are data-driven from the rule tables.
_previous_gen_pattern := data.rule_tables.previous_generation_instance_pattern

# Parse property paths into {type, path} records. Each raw entry is of the form
# "Resources/<type>/Properties/<prop/path>". The property path is converted from
# slash-separated to dot-separated for use with resolve().
_previous_gen_checks contains {"type": rtype, "path": prop_path} if {
    some raw_path in data.rule_tables.previous_generation_instance_property_paths
    parts := split(raw_path, "/")
    count(parts) > 2
    parts[0] == "Resources"
    rtype := parts[1]
    prop_parts := array.slice(parts, 2, count(parts))
    prop_path := concat(".", prop_parts)
}

violation contains make_diag_full("I3100", "INFO", name,
    check.path,
    sprintf("Previous generation instance type '%s' - consider upgrading", [val]),
    "Upgrade to a current generation instance type",
    "") if {
    cfn_rule_active("I3100")
    some check in _previous_gen_checks
    some name in resources_of_type(check.type)
    # Only literal string instance types are checked; values from a parameter
    # Ref or other intrinsic are left alone because their deploy-time value is
    # not known here.
    not is_from_parameter(name, check.path)
    not is_from_intrinsic(name, check.path)
    val := resolve(name, check.path)
    is_string(val)
    regex.match(_previous_gen_pattern, val)
}
