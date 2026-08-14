package best_practices

import rego.v1

# W2501: Password properties must not be hardcoded strings
_password_properties := {"MasterUserPassword", "Password", "AdminPassword",
    "MasterPassword", "LoginPassword", "DbPassword", "UserPassword"}

_is_secure_dynamic_ref(val) if { startswith(val, "{{resolve:ssm-secure:") }
_is_secure_dynamic_ref(val) if { startswith(val, "{{resolve:secretsmanager:") }
_is_secure_dynamic_ref(val) if { contains(val, "{{resolve:ssm-secure:") }
_is_secure_dynamic_ref(val) if { contains(val, "{{resolve:secretsmanager:") }

_is_any_dynamic_ref(val) if { contains(val, "{{resolve:") }

# Check if a password property is a Ref to a parameter
_is_ref_to_param(name, prop) if {
    some edge in input.resources[name].outgoingRefs
    edge.kind == "Ref"
    edge.sourcePath == sprintf("Properties.%s", [prop])
    edge.target in object.keys(input.parameters)
}

# W2501: Non-secure dynamic reference used for password (e.g. {{resolve:ssm:...}})
# Check the raw property value for dynamic references that are not secure
violation contains make_diag_at("W2501", "WARN", name,
    sprintf("Properties.%s", [prop]),
    sprintf("Password should use a secure dynamic reference for Resources/%s/Properties/%s", [name, prop])) if {
    some name in object.keys(input.resources)
    some prop in _password_properties
    raw := get_resource(name)
    raw_val := raw.properties[prop]
    reason := raw_val.__dynamic
    _is_any_dynamic_ref(reason)
    not _is_secure_dynamic_ref(reason)
}

# W2501: Hardcoded string password (not a Ref to parameter, not a dynamic reference)
violation contains make_diag_at("W2501", "WARN", name,
    sprintf("Properties.%s", [prop]),
    sprintf("Property '%s' should not be a hardcoded string - use a parameter with NoEcho or a dynamic reference", [prop])) if {
    some name, res in input.resources
    some prop in _password_properties
    val := resolve(name, sprintf("Properties.%s", [prop]))
    is_string(val)
    not is_dynamic(name, sprintf("Properties.%s", [prop]))
    not _is_any_dynamic_ref(val)
    not _is_ref_to_param(name, prop)
}

# W2501: Parameter used as password without NoEcho - emit at parameter location
violation contains make_diag_at("W2501", "WARN", "",
    sprintf("Parameters/%s", [pname]),
    sprintf("Parameter %s used as %s, therefore NoEcho should be True", [pname, prop])) if {
    some name, res in input.resources
    some prop in _password_properties
    some edge in res.outgoingRefs
    edge.kind == "Ref"
    edge.sourcePath == sprintf("Properties.%s", [prop])
    pname := edge.target
    pname in object.keys(input.parameters)
    not input.parameters[pname].noEcho == true
}

# W1011: Use dynamic references over parameters for secrets
violation contains make_diag_at("W1011", "WARN", name,
    sprintf("Properties.%s", [prop]),
    sprintf("Use dynamic references (e.g., SSM SecureString) instead of parameter '%s' for secrets", [pname])) if {
    some name, res in input.resources
    some prop in _password_properties
    some edge in res.outgoingRefs
    edge.kind == "Ref"
    edge.sourcePath == sprintf("Properties.%s", [prop])
    pname := edge.target
    pname in object.keys(input.parameters)
}
