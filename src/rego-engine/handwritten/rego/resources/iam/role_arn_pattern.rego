package resources

import rego.v1

# E3511: IAM Role ARN must match expected pattern
_iam_role_arn_checks contains {"type": rtype, "path": prop_path} if {
    some raw_path in data.rule_tables.iam_role_arn_property_paths
    parts := split(raw_path, "/")
    count(parts) > 2
    parts[0] == "Resources"
    rtype := parts[1]
    prop_parts := array.slice(parts, 2, count(parts))
    prop_path := concat(".", prop_parts)
}

violation contains make_diag_full("E3511", "ERROR", name,
    prop.path,
    sprintf("IAM Role ARN '%s' does not match expected pattern", [val]),
    "Use format: arn:aws:iam::123456789012:role/role-name",
    "") if {
    cfn_rule_active("E3511")
    some prop in _iam_role_arn_checks
    some name in resources_of_type(prop.type)
    val := resolve(name, prop.path)
    is_string(val)
    not is_dynamic(name, prop.path)
    not regex.match(`^arn:(aws[a-zA-Z-]*)?:iam::\d{12}:role/[a-zA-Z_0-9+=,.@\-_/]+$`, val)
}
