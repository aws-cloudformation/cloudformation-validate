package structure

import rego.v1

_valid_param_types := {t | some t in data.rule_tables.valid_parameter_types}

_parameter_type_inner(ptype) := inner if {
    startswith(ptype, "AWS::SSM::Parameter::Value<")
    endswith(ptype, ">")
    inner := trim_suffix(trim_prefix(ptype, "AWS::SSM::Parameter::Value<"), ">")
    inner != ""
}

_parameter_type_inner(ptype) := inner if {
    startswith(ptype, "List<")
    endswith(ptype, ">")
    inner := trim_suffix(trim_prefix(ptype, "List<"), ">")
    inner != ""
}

_list_type_inner(ptype) := inner if {
    startswith(ptype, "List<")
    endswith(ptype, ">")
    inner := trim_suffix(trim_prefix(ptype, "List<"), ">")
    inner != ""
}

_aws_specific_parameter_type(ptype) if {
    segments := split(ptype, "::")
    count(segments) >= 3
    segments[0] == "AWS"
    every segment in segments { segment != "" }
}

_accepted_undocumented_param_type(ptype) if {
    inner := _parameter_type_inner(ptype)
    _aws_specific_parameter_type(inner)
}

_accepted_undocumented_param_type(ptype) if {
    inner := _parameter_type_inner(ptype)
    base_type := _list_type_inner(inner)
    _aws_specific_parameter_type(base_type)
}

violation contains make_diag_at("F2002", "FATAL", "",
    sprintf("Parameters/%s/Type", [name]),
    sprintf("Parameter '%s' has invalid Type '%s'", [name, ptype])) if {
    some name, param in input.parameters
    ptype := param.type
    ptype != null
    not ptype in _valid_param_types
    not _accepted_undocumented_param_type(ptype)
}

violation contains make_diag_at("W2002", "WARN", "",
    sprintf("Parameters/%s/Type", [name]),
    sprintf("Parameter '%s' Type '%s' is accepted by CloudFormation but is not officially documented; CloudFormation will not validate its values", [name, ptype])) if {
    some name, param in input.parameters
    ptype := param.type
    ptype != null
    not ptype in _valid_param_types
    _accepted_undocumented_param_type(ptype)
}

# F0015: Default value must be numeric when parameter Type is Number
violation contains make_diag_at("F0015", "FATAL", "",
    sprintf("Parameters/%s/Default", [name]),
    sprintf("Parameter '%s' Default '%s' is not a valid number", [name, def])) if {
    some name, param in input.parameters
    param.type == "Number"
    def := object.get(param, "default", null)
    def != null
    is_string(def)
    not regex.match(`^-?[0-9]+(\.[0-9]+)?$`, def)
}

# F0016: AllowedValues entries must be numeric when parameter Type is Number
violation contains make_diag_at("F0016", "FATAL", "",
    sprintf("Parameters/%s/AllowedValues", [name]),
    sprintf("Parameter '%s' AllowedValues entry '%s' is not a valid number", [name, val])) if {
    some name, param in input.parameters
    param.type == "Number"
    avs := param.allowedValues
    avs != null
    some val in avs
    is_string(val)
    not regex.match(`^-?[0-9]+(\.[0-9]+)?$`, val)
}

# F3016: DeletionPolicy must be valid
_base_deletion_policies := {"Delete", "Retain", "RetainExceptOnCreate"}
_snapshot_capable_types := {t | some t in data.rule_tables.snapshot_capable_resource_types}

violation contains make_diag_full("F3016", "FATAL", name, "DeletionPolicy",
    sprintf("DeletionPolicy must be one of Delete, Retain, RetainExceptOnCreate, Snapshot, got '%s'", [dp]),
    "", "") if {
    some name, res in input.resources
    res.resourceType in _snapshot_capable_types
    scenarios := lifecycle_policy_scenarios(name, "DeletionPolicy")
    some dp in scenarios
    is_string(dp)
    not dp in (_base_deletion_policies | {"Snapshot"})
}

violation contains make_diag_full("F3016", "FATAL", name, "DeletionPolicy",
    sprintf("DeletionPolicy must be one of Delete, Retain, RetainExceptOnCreate, got '%s'", [dp]),
    "", "") if {
    some name, res in input.resources
    not res.resourceType in _snapshot_capable_types
    scenarios := lifecycle_policy_scenarios(name, "DeletionPolicy")
    some dp in scenarios
    is_string(dp)
    not dp in _base_deletion_policies
}

violation contains make_diag_full("F3016", "FATAL", name, "DeletionPolicy",
    sprintf("DeletionPolicy must be one of Delete, Retain, RetainExceptOnCreate, Snapshot, got %s", [shape]),
    "", "") if {
    some name, res in input.resources
    res.resourceType in _snapshot_capable_types
    scenarios := lifecycle_policy_scenarios(name, "DeletionPolicy")
    some policy in scenarios
    not is_string(policy)
    shape := policy_value_shape(policy)
}

violation contains make_diag_full("F3016", "FATAL", name, "DeletionPolicy",
    sprintf("DeletionPolicy must be one of Delete, Retain, RetainExceptOnCreate, got %s", [shape]),
    "", "") if {
    some name, res in input.resources
    not res.resourceType in _snapshot_capable_types
    scenarios := lifecycle_policy_scenarios(name, "DeletionPolicy")
    some policy in scenarios
    not is_string(policy)
    shape := policy_value_shape(policy)
}

# W2506: ImageId parameters should use AWS::EC2::Image::Id type
_image_id_param_types := {t | some t in data.rule_tables.image_id_parameter_types}

# Build a mapping from resource type to a set of regex patterns for the
# property paths where ImageId can appear. Each entry from the table is of the
# form "Resources/<type>/Properties/path/possibly/with/*/segments" — we extract
# the type, convert the remainder to a regex anchored to the source-path format
# used by outgoingRefs (dot-separated, array indices as digits).
_image_id_slots[rtype] contains pattern if {
    some raw_path in data.rule_tables.image_id_property_paths
    parts := split(raw_path, "/")
    count(parts) > 2
    parts[0] == "Resources"
    rtype := parts[1]
    prop_parts := array.slice(parts, 2, count(parts))
    pattern := _path_parts_to_regex(prop_parts)
}

# Convert a path parts array (from splitting on /) into an anchored regex
# suitable for matching outgoingRefs sourcePath values. Wildcards (*) become
# [0-9]+ to match array indices.
_path_parts_to_regex(parts) := regex_str if {
    segments := [seg |
        some p in parts
        seg := _path_segment_to_regex(p)
    ]
    regex_str := sprintf("^%s$", [concat("\\.", segments)])
}

_path_segment_to_regex(seg) := "[0-9]+" if {
    seg == "*"
}

_path_segment_to_regex(seg) := seg if {
    seg != "*"
}

violation contains make_diag_at("W2506", "WARN", "",
    sprintf("Parameters/%s", [pname]),
    sprintf("Parameter '%s' is used as an ImageId but has Type '%s' - consider using 'AWS::EC2::Image::Id'", [pname, ptype])) if {
    some name, res in input.resources
    patterns := _image_id_slots[res.resourceType]
    some edge in res.outgoingRefs
    edge.kind == "Ref"
    some pattern in patterns
    regex.match(pattern, edge.sourcePath)
    pname := edge.target
    pname in object.keys(input.parameters)
    ptype := input.parameters[pname].type
    ptype != null
    not ptype in _image_id_param_types
}
