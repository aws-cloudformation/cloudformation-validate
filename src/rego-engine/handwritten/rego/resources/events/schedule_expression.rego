package resources

import rego.v1

# E3027: Events Rule ScheduleExpression must be a valid rate() or cron() expression.

# Neither rate() nor cron().
violation contains make_diag_at("E3027", "ERROR", name,
    "Properties.ScheduleExpression",
    sprintf("'%s' has to be either 'cron()' or 'rate()'", [val])) if {
    cfn_rule_active("E3027")
    some name in resources_of_type("AWS::Events::Rule")
    val := resolve(name, "Properties.ScheduleExpression")
    is_string(val)
    not is_from_parameter(name, "Properties.ScheduleExpression")
    not is_from_intrinsic(name, "Properties.ScheduleExpression")
    not _is_rate(val)
    not _is_cron(val)
}

# rate(): empty body.
violation contains make_diag_at("E3027", "ERROR", name,
    "Properties.ScheduleExpression",
    "'' is not of type 'string'") if {
    cfn_rule_active("E3027")
    some name in resources_of_type("AWS::Events::Rule")
    val := resolve(name, "Properties.ScheduleExpression")
    is_string(val)
    not is_from_parameter(name, "Properties.ScheduleExpression")
    not is_from_intrinsic(name, "Properties.ScheduleExpression")
    _is_rate(val)
    _rate_body(val) == ""
}

# rate(): body is not exactly "Value Unit".
violation contains make_diag_at("E3027", "ERROR", name,
    "Properties.ScheduleExpression",
    sprintf("'%s' has to be of format rate(Value Unit)", [body])) if {
    cfn_rule_active("E3027")
    some name in resources_of_type("AWS::Events::Rule")
    val := resolve(name, "Properties.ScheduleExpression")
    is_string(val)
    not is_from_parameter(name, "Properties.ScheduleExpression")
    not is_from_intrinsic(name, "Properties.ScheduleExpression")
    _is_rate(val)
    body := _rate_body(val)
    body != ""
    count(split(body, " ")) != 2
}

# rate(): value is not an integer.
violation contains make_diag_at("E3027", "ERROR", name,
    "Properties.ScheduleExpression",
    sprintf("'%s' is not of type 'integer'", [value])) if {
    cfn_rule_active("E3027")
    some name in resources_of_type("AWS::Events::Rule")
    val := resolve(name, "Properties.ScheduleExpression")
    is_string(val)
    not is_from_parameter(name, "Properties.ScheduleExpression")
    not is_from_intrinsic(name, "Properties.ScheduleExpression")
    _is_rate(val)
    parts := split(_rate_body(val), " ")
    count(parts) == 2
    value := parts[0]
    not _is_digits(value)
}

# rate(): value is zero (less than the minimum).
violation contains make_diag_at("E3027", "ERROR", name,
    "Properties.ScheduleExpression",
    sprintf("'%s' is less than the minimum of 0", [value])) if {
    cfn_rule_active("E3027")
    some name in resources_of_type("AWS::Events::Rule")
    val := resolve(name, "Properties.ScheduleExpression")
    is_string(val)
    not is_from_parameter(name, "Properties.ScheduleExpression")
    not is_from_intrinsic(name, "Properties.ScheduleExpression")
    _is_rate(val)
    parts := split(_rate_body(val), " ")
    count(parts) == 2
    value := parts[0]
    _is_digits(value)
    _amount(value) == 0
}

# rate(): unit does not agree in number with the value.
violation contains make_diag_at("E3027", "ERROR", name,
    "Properties.ScheduleExpression",
    sprintf("'%s' is not one of %s", [unit, _units_display(_amount(value))])) if {
    cfn_rule_active("E3027")
    some name in resources_of_type("AWS::Events::Rule")
    val := resolve(name, "Properties.ScheduleExpression")
    is_string(val)
    not is_from_parameter(name, "Properties.ScheduleExpression")
    not is_from_intrinsic(name, "Properties.ScheduleExpression")
    _is_rate(val)
    parts := split(_rate_body(val), " ")
    count(parts) == 2
    value := parts[0]
    _is_digits(value)
    unit := parts[1]
    not unit in _valid_units(_amount(value))
}

# cron(): empty body.
violation contains make_diag_at("E3027", "ERROR", name,
    "Properties.ScheduleExpression",
    "'' is not of type 'string'") if {
    cfn_rule_active("E3027")
    some name in resources_of_type("AWS::Events::Rule")
    val := resolve(name, "Properties.ScheduleExpression")
    is_string(val)
    not is_from_parameter(name, "Properties.ScheduleExpression")
    not is_from_intrinsic(name, "Properties.ScheduleExpression")
    _is_cron(val)
    _cron_body(val) == ""
}

# cron(): not exactly six fields.
violation contains make_diag_at("E3027", "ERROR", name,
    "Properties.ScheduleExpression",
    sprintf("'%s' is not of length 6. (Minutes Hours Day-of-month Month Day-of-week Year)", [fields[0]])) if {
    cfn_rule_active("E3027")
    some name in resources_of_type("AWS::Events::Rule")
    val := resolve(name, "Properties.ScheduleExpression")
    is_string(val)
    not is_from_parameter(name, "Properties.ScheduleExpression")
    not is_from_intrinsic(name, "Properties.ScheduleExpression")
    _is_cron(val)
    body := _cron_body(val)
    body != ""
    fields := split(body, " ")
    count(fields) != 6
}

# cron(): pins both Day-of-month and Day-of-week.
violation contains make_diag_at("E3027", "ERROR", name,
    "Properties.ScheduleExpression",
    sprintf("'%s' specifies both Day-of-month and Day-of-week. (Minutes Hours Day-of-month Month Day-of-week Year)", [substring(body, 0, 1)])) if {
    cfn_rule_active("E3027")
    some name in resources_of_type("AWS::Events::Rule")
    val := resolve(name, "Properties.ScheduleExpression")
    is_string(val)
    not is_from_parameter(name, "Properties.ScheduleExpression")
    not is_from_intrinsic(name, "Properties.ScheduleExpression")
    _is_cron(val)
    body := _cron_body(val)
    fields := split(body, " ")
    count(fields) == 6
    fields[2] != "?"
    fields[4] != "?"
}

_is_rate(val) if {
    startswith(val, "rate(")
    endswith(val, ")")
}

_is_cron(val) if {
    startswith(val, "cron(")
    endswith(val, ")")
}

_rate_body(val) := trim_suffix(trim_prefix(val, "rate("), ")")

_cron_body(val) := trim_suffix(trim_prefix(val, "cron("), ")")

# A non-empty run of ASCII digits (matches Python str.isdigit for these inputs).
_is_digits(value) if {
    value != ""
    regex.match(`^[0-9]+$`, value)
}

# Numeric value of a digit string, tolerating leading zeros (which `to_number` rejects because a
# JSON number cannot have them, so `rate(01 minutes)` would otherwise be skipped). Strips leading
# zeros, leaving a single `0` when the string is all zeros.
_amount(value) := to_number(stripped) if {
    trimmed := trim_left(value, "0")
    stripped := _nonempty_or_zero(trimmed)
}

_nonempty_or_zero(s) := s if s != ""

_nonempty_or_zero(s) := "0" if s == ""

_valid_units(amount) := {"minute", "hour", "day"} if amount <= 1

_valid_units(amount) := {"minutes", "hours", "days"} if amount > 1

_units_display(amount) := `["minute", "hour", "day"]` if amount <= 1

_units_display(amount) := `["minutes", "hours", "days"]` if amount > 1
