package resources

import rego.v1

_access_grant_type := "AWS::CloudWatch::AccessGrant"

_access_grant_principal_type_path := "Properties.Principal.PrincipalType"

_access_grant_principal_id_path := "Properties.Principal.PrincipalId"

_access_grant_principal_attributes_path := "Properties.Principal.PrincipalAttributes"

_access_grant_permission_path := "Properties.Permission"

_access_grant_scoped_actions_path := "Properties.ScopedActions"

_access_grant_idc_user_principal_type := "IDC_USER"

_access_grant_alert_principal_type := "ALERT"

_access_grant_all_principal_id := "ALL"

_access_grant_custom_permission := "CUSTOM"

_access_grant_assume_access_profile_action := "cloudwatch:AssumeAccessProfile"

# Only values authored as unconditional literals are judged; a value from an
# intrinsic or a condition is not known until deployment.
_access_grant_literal_values(name, path) := {scenario.value |
    not is_from_intrinsic(name, path)
    some scenario in resolve_scenarios(name, path)
    count(scenario.conditions) == 0
}

# The number of items authored in the list at path, undefined when the list
# itself comes from an intrinsic or a condition. Items are counted even when one
# of them is unknown before deployment, so its siblings can still be judged.
_access_grant_authored_list_len(name, path) := count(items) if {
    items := _access_grant_authored_value(name, path)
    is_array(items)
}

# The value authored at path, undefined when it comes from an intrinsic or
# when the whole Properties block is conditional.
_access_grant_authored_value(name, path) := value if {
    not is_from_intrinsic(name, path)
    not _access_grant_properties_conditional(name)
    value := resolve_preserving_conditionals(name, path)
}

_access_grant_properties_conditional(name) if {
    get_resource(name).Properties["Fn::If"]
}

# Whether the list at path holds an item that is an object in every
# deployment. An AWS::NoValue or conditional item may be removed, so it does
# not count; an object whose fields are unknown before deployment does.
_access_grant_has_unconditional_object_item(name, path) if {
    item_count := _access_grant_authored_list_len(name, path)
    item_count > 0
    some index in numbers.range(0, item_count - 1)
    item := _access_grant_authored_value(name, sprintf("%s.%d", [path, index]))
    is_object(item)
    not item["Fn::If"]
}

violation contains make_diag_full("E9015",
    "ERROR",
    name,
    _access_grant_principal_attributes_path,
    sprintf(
        "PrincipalAttributes is supported only when Principal.PrincipalType is '%s', not '%s'",
        [_access_grant_idc_user_principal_type, principal_type],
    ),
    sprintf("Remove PrincipalAttributes or set PrincipalType to '%s'", [_access_grant_idc_user_principal_type]),
    "",
) if {
    cfn_rule_active("E9015")
    some name in resources_of_type(_access_grant_type)
    _access_grant_has_unconditional_object_item(name, _access_grant_principal_attributes_path)
    some principal_type in _access_grant_literal_values(name, _access_grant_principal_type_path)
    is_string(principal_type)
    principal_type != _access_grant_idc_user_principal_type
}

_access_grant_custom_without_scoped_actions_path(name) := _access_grant_permission_path if {
    not has_property(name, _access_grant_scoped_actions_path)
}

_access_grant_custom_without_scoped_actions_path(name) := _access_grant_scoped_actions_path if {
    has_property(name, _access_grant_scoped_actions_path)
    [] in _access_grant_literal_values(name, _access_grant_scoped_actions_path)
}

violation contains make_diag_full("E9016",
    "ERROR",
    name,
    property_path,
    sprintf("ScopedActions must list at least one action when Permission is '%s'", [_access_grant_custom_permission]),
    "Add ScopedActions or choose a predefined Permission",
    "",
) if {
    cfn_rule_active("E9016")
    some name in resources_of_type(_access_grant_type)
    _access_grant_custom_permission in _access_grant_literal_values(name, _access_grant_permission_path)
    property_path := _access_grant_custom_without_scoped_actions_path(name)
}

# The service applies these limits to grants scoped to every principal of the
# alert type; a grant for one specific alert is not judged.
_access_grant_for_all_alerts(name) if {
    _access_grant_alert_principal_type in _access_grant_literal_values(name, _access_grant_principal_type_path)
    _access_grant_all_principal_id in _access_grant_literal_values(name, _access_grant_principal_id_path)
}

_access_grant_all_alerts_description := sprintf(
    "the grant is for all alerts (PrincipalType '%s', PrincipalId '%s')",
    [_access_grant_alert_principal_type, _access_grant_all_principal_id],
)

violation contains make_diag_full("E9017",
    "ERROR",
    name,
    _access_grant_permission_path,
    sprintf(
        "Permission must be '%s' when %s, not '%s'",
        [_access_grant_custom_permission, _access_grant_all_alerts_description, permission],
    ),
    sprintf(
        "Set Permission to '%s' with the single action '%s'",
        [_access_grant_custom_permission, _access_grant_assume_access_profile_action],
    ),
    "",
) if {
    cfn_rule_active("E9017")
    some name in resources_of_type(_access_grant_type)
    _access_grant_for_all_alerts(name)
    some permission in _access_grant_literal_values(name, _access_grant_permission_path)
    is_string(permission)
    permission != _access_grant_custom_permission
}

violation contains make_diag_full("E9017",
    "ERROR",
    name,
    action_path,
    sprintf(
        "'%s' is not allowed when %s; only '%s' is allowed",
        [action, _access_grant_all_alerts_description, _access_grant_assume_access_profile_action],
    ),
    "Remove the action",
    "",
) if {
    cfn_rule_active("E9017")
    some name in resources_of_type(_access_grant_type)
    _access_grant_for_all_alerts(name)
    _access_grant_custom_permission in _access_grant_literal_values(name, _access_grant_permission_path)
    scoped_action_count := _access_grant_authored_list_len(name, _access_grant_scoped_actions_path)
    scoped_action_count > 0
    some i in numbers.range(0, scoped_action_count - 1)
    actions_path := sprintf("%s.%d.Actions", [_access_grant_scoped_actions_path, i])
    action_count := _access_grant_authored_list_len(name, actions_path)
    action_count > 0
    some j in numbers.range(0, action_count - 1)
    action_path := sprintf("%s.%d", [actions_path, j])
    some action in _access_grant_literal_values(name, action_path)
    is_string(action)
    action != _access_grant_assume_access_profile_action
}
