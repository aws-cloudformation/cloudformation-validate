package resources

import rego.v1

# E3027: Events Rule ScheduleExpression must be valid rate() or cron()
violation contains make_diag_at("E3027", "ERROR", name,
    "Properties.ScheduleExpression",
    sprintf("ScheduleExpression '%s' must be a rate() or cron() expression", [val])) if {
    some name in resources_of_type("AWS::Events::Rule")
    val := resolve(name, "Properties.ScheduleExpression")
    is_string(val)
    not startswith(val, "rate(")
    not startswith(val, "cron(")
}

violation contains make_diag_at("E3027", "ERROR", name,
    "Properties.ScheduleExpression",
    sprintf("rate() expression '%s' must have format 'rate(value unit)' where unit is minute(s)|hour(s)|day(s)", [val])) if {
    some name in resources_of_type("AWS::Events::Rule")
    val := resolve(name, "Properties.ScheduleExpression")
    is_string(val)
    startswith(val, "rate(")
    not regex.match(`^rate\(\s*\d+(\.\d+)?\s+(minutes?|hours?|days?)\s*\)$`, val)
}

violation contains make_diag_at("E3027", "ERROR", name,
    "Properties.ScheduleExpression",
    sprintf("cron() expression '%s' must have exactly 6 fields", [val])) if {
    some name in resources_of_type("AWS::Events::Rule")
    val := resolve(name, "Properties.ScheduleExpression")
    is_string(val)
    startswith(val, "cron(")
    endswith(val, ")")
    inner := trim_prefix(trim_suffix(val, ")"), "cron(")
    fields := split(trim_space(inner), " ")
    count(fields) != 6
}
