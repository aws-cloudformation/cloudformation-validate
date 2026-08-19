package best_practices

import rego.v1

# W2501: Password properties must not be hardcoded strings
_password_properties := {n | some n in data.rule_tables.password_property_names}

_is_secure_dynamic_ref(val) if { startswith(val, "{{resolve:ssm-secure:") }
_is_secure_dynamic_ref(val) if { startswith(val, "{{resolve:secretsmanager:") }
_is_secure_dynamic_ref(val) if { contains(val, "{{resolve:ssm-secure:") }
_is_secure_dynamic_ref(val) if { contains(val, "{{resolve:secretsmanager:") }

_is_any_dynamic_ref(val) if { contains(val, "{{resolve:") }

# Extract the last segment from a dotted path
_last_segment(path) := seg if {
    parts := split(path, ".")
    seg := parts[count(parts) - 1]
}

# Check if a sourcePath is a password property (its leaf segment matches)
_is_password_source_path(sp) if {
    startswith(sp, "Properties.")
    prop_path := substring(sp, count("Properties."), -1)
    _last_segment(prop_path) in _password_properties
}

# Enumerate password-named properties at any nesting depth, including values
# nested in arrays. The extension returns dotted paths matching reference edges.
_password_candidate contains {"name": name, "property": candidate.property, "path": candidate.path, "value": candidate.value} if {
    some name, resource in input.resources
    some candidate in matching_property_paths(resource.properties, data.rule_tables.password_property_names)
}

_is_ref_to_param_path(name, property_path) if {
    some edge in input.resources[name].outgoingRefs
    edge.kind == "Ref"
    edge.sourcePath == property_path
    edge.target in object.keys(input.parameters)
}

# W2501: Non-secure dynamic reference used for password (e.g. {{resolve:ssm:...}})
violation contains make_diag_at("W2501", "WARN", candidate.name,
    candidate.path,
    sprintf("Password should use a secure dynamic reference for Resources/%s/%s", [candidate.name, replace(candidate.path, ".", "/")])) if {
    some candidate in _password_candidate
    reason := candidate.value.__dynamic
    _is_any_dynamic_ref(reason)
    not _is_secure_dynamic_ref(reason)
}

# W2501: Hardcoded string password (not a Ref to parameter, not a dynamic reference)
violation contains make_diag_at("W2501", "WARN", candidate.name,
    candidate.path,
    sprintf("Property '%s' should not be a hardcoded string - use a parameter with NoEcho or a dynamic reference", [candidate.property])) if {
    some candidate in _password_candidate
    is_string(candidate.value)
    not is_dynamic(candidate.name, candidate.path)
    not _is_any_dynamic_ref(candidate.value)
    not _is_ref_to_param_path(candidate.name, candidate.path)
}

# A password parameter without NoEcho is reported at the parameter location.
# Detects password property names at any nesting depth by checking the last segment
# of the outgoingRefs sourcePath against the password property names set.
violation contains make_diag_at("W2501", "WARN", "",
    sprintf("Parameters/%s", [pname]),
    sprintf("Parameter %s used as %s, therefore NoEcho should be True", [pname, last_key])) if {
    some name, res in input.resources
    some edge in res.outgoingRefs
    edge.kind == "Ref"
    _is_password_source_path(edge.sourcePath)
    last_key := _last_segment(substring(edge.sourcePath, count("Properties."), -1))
    pname := edge.target
    pname in object.keys(input.parameters)
    not input.parameters[pname].noEcho == true
}

# W1011: Use dynamic references over parameters for secrets
# The secret paths dataset is distinct from password names; it enumerates
# exact resource-type/property combinations where secrets appear. Paths may
# contain wildcards (*) which match array indices in outgoingRefs sourcePaths.
_secret_ref_checks contains {"type": rtype, "pattern": pattern} if {
    some raw_path in data.rule_tables.secret_dynamic_reference_property_paths
    parts := split(raw_path, "/")
    count(parts) > 2
    parts[0] == "Resources"
    rtype := parts[1]
    prop_parts := array.slice(parts, 2, count(parts))
    pattern := _prop_parts_to_pattern(prop_parts)
}

# Convert path parts to a regex pattern for matching outgoingRefs sourcePath.
# Wildcards become [0-9]+ to match array indices.
_prop_parts_to_pattern(parts) := regex_str if {
    segments := [seg |
        some p in parts
        seg := _secret_segment(p)
    ]
    regex_str := sprintf("^%s$", [concat("\\.", segments)])
}

_secret_segment(seg) := "[0-9]+" if { seg == "*" }
_secret_segment(seg) := seg if { seg != "*" }

violation contains make_diag_at("W1011", "WARN", name,
    edge.sourcePath,
    sprintf("Use dynamic references (e.g., SSM SecureString) instead of parameter '%s' for secrets", [pname])) if {
    some check in _secret_ref_checks
    some name in resources_of_type(check.type)
    some edge in input.resources[name].outgoingRefs
    edge.kind == "Ref"
    regex.match(check.pattern, edge.sourcePath)
    pname := edge.target
    pname in object.keys(input.parameters)
}
