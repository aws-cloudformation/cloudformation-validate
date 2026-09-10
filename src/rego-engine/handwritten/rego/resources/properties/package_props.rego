package resources

import rego.v1

# W3002: Properties that only work with `aws cloudformation package`
# Checks the parent property (e.g. Code, Content, TemplateURL) as a string.
# If the value is a string that doesn't start with s3:// or https://, it warns.
# SAM templates are excluded entirely (has_serverless_transform check).
_w3002_checks contains {"type": rtype, "path": prop_path} if {
    some raw_path in data.rule_tables.package_property_paths
    parts := split(raw_path, "/")
    count(parts) > 2
    parts[0] == "Resources"
    rtype := parts[1]
    prop_parts := array.slice(parts, 2, count(parts))
    prop_path := concat(".", prop_parts)
}

violation contains make_diag_at("W3002", "WARN", name,
    check.path,
    "This code may only work with 'package' cli command") if {
    cfn_rule_active("W3002")
    not has_transform("AWS::Serverless-2016-10-31")
    some check in _w3002_checks
    some name in resources_of_type(check.type)
    # Only string literals are inspected here; a value wrapped in an intrinsic
    # (Fn::Join/Fn::Sub building an S3 URL) resolves at deploy time and is left
    # alone.
    not is_from_intrinsic(name, check.path)
    val := resolve(name, check.path)
    is_string(val)
    not startswith(val, "s3://")
    not startswith(val, "https://")
}
