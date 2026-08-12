package structure

import rego.v1

# Output must have Value property
violation contains make_diag_at("F0040", "FATAL", "",
    sprintf("Outputs/%s", [name]),
    sprintf("Output '%s' is missing required 'Value' property", [name])) if {
    some name in object.keys(input.outputs)
    val := input.outputs[name].value
    is_null(val)
}

# GetAtt in an output names an attribute the resource type does not expose.
_output_skip_getatt_types := {
    "AWS::CloudFormation::Stack",
    "AWS::CloudFormation::CustomResource",
    "AWS::CloudFormation::Macro",
}

violation contains make_diag_at("F6101", "FATAL", "",
    edge.sourcePath,
    sprintf("'%s' is not one of %s", [edge.attr, render_list(valid_attrs)])) if {
    some edge in input.edges
    edge.kind == "GetAtt"
    startswith(edge.source, "__output__")
    edge.target in object.keys(input.resources)
    target_type := input.resources[edge.target].resourceType
    not target_type in _output_skip_getatt_types
    not startswith(target_type, "Custom::")
    valid_attrs := data.getatt_attributes[target_type]
    valid_attrs != null
    not edge.attr in valid_attrs
    not _output_attr_is_map_member(edge.attr, target_type)
}

_output_attr_is_map_member(attribute, target_type) if {
    target_type == "AWS::ServiceCatalog::CloudFormationProvisionedProduct"
    startswith(attribute, "Outputs.")
}

_output_pseudo_parameters := {
    "AWS::AccountId", "AWS::NotificationARNs", "AWS::NoValue",
    "AWS::Partition", "AWS::Region", "AWS::StackId", "AWS::StackName", "AWS::URLSuffix",
}

# A Sub edge is recorded only when the variable did not resolve.
violation contains make_diag_at("F6101", "FATAL", "",
    edge.sourcePath,
    sprintf("Fn::Sub variable '${%s}' does not reference a valid resource, parameter, or pseudo-parameter", [edge.target])) if {
    some edge in input.edges
    edge.kind == "Sub"
    startswith(edge.source, "__output__")
    not edge.target in object.keys(input.resources)
    not edge.target in object.keys(input.parameters)
    not edge.target in _output_pseudo_parameters
    not edge.target in object.get(input, "samImplicitResources", [])
}

# GetAtt in output returns a non-string type (direct or nested in Sub/Join).
# Uses top-level edges where source is `__output__<name>` and kind is GetAtt to
# obtain precise source paths. The string-position filter prevents duplicates
# when a GetAtt sits inside a literal container already caught by the parse-time
# output-type check. An array-returning GetAtt is consumed by Fn::Select to
# extract a string element, so only scalar non-string returns are reported.
violation contains make_diag_at("F6101", "FATAL", "",
    edge.sourcePath,
    sprintf("Output '%s': GetAtt '%s.%s' returns type '%s', not 'string'", [output_name, edge.target, edge.attr, ret_type])) if {
    some edge in input.edges
    edge.kind == "GetAtt"
    startswith(edge.source, "__output__")
    output_name := substring(edge.source, count("__output__"), -1)
    _output_edge_in_string_position(edge.sourcePath)
    edge.target in object.keys(input.resources)
    target_type := input.resources[edge.target].resourceType
    ret_type := getatt_return_type(target_type, edge.attr)
    ret_type != "string"
    ret_type != "array"
}

# Determines whether a GetAtt edge from an output is in string position.
# A GetAtt inside a literal list/map (bare index or key after the Value node)
# is NOT in string position - the enclosing container is already caught by
# the parse-time type check.
_output_edge_in_string_position(source_path) if {
    # Extract the part after "/Value" in the source path
    parts := split(source_path, "/Value")
    count(parts) > 1
    tail := parts[count(parts) - 1]
    _tail_is_string_position(tail)
}

_output_edge_in_string_position(source_path) if {
    # Path that is exactly or ends with "/Value" (no tail)
    endswith(source_path, "/Value")
}

# Empty tail means the GetAtt is directly at the Value node
_tail_is_string_position("") if { true }

# Tail starting with . followed by Fn:: is in string position
_tail_is_string_position(tail) if {
    tail != ""
    stripped := substring(tail, 1, -1)
    segments := split(stripped, ".")
    _segments_in_string_position(segments)
}

# Walk segments: Fn::If is transparent (skip branch selector), other Fn:: is
# string position, bare index/key means literal container (not string position).
_segments_in_string_position(segments) if {
    count(segments) == 0
}

_segments_in_string_position(segments) if {
    count(segments) > 0
    segments[0] == "Fn::If"
    # Skip the branch selector and continue with the rest
    rest := array.slice(segments, 2, count(segments))
    _segments_in_string_position(rest)
}

_segments_in_string_position(segments) if {
    count(segments) > 0
    startswith(segments[0], "Fn::")
    segments[0] != "Fn::If"
}
