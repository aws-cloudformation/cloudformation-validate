# I3037: advisory for duplicate scalar items in a list that permits duplicates.
# A list whose schema requires uniqueItems is covered by the Fatal uniqueItems
# check instead, so it is excluded here. The `Command` property of run-command
# resources legitimately repeats values and is exempt.
package resources

import rego.v1

violation contains make_diag_at("I3037", "INFO", name,
    sprintf("Properties.%s", [prop]),
    sprintf("Array property '%s' contains duplicate value: %s", [prop, _format_item(dup)])) if {
    cfn_rule_active("I3037")
    some name, res in input.resources
    some prop in object.keys(res.properties)
    prop != "Command"
    # Only a property the schema actually defines can be a "list that permits
    # duplicates"; an unknown property is a structural error handled elsewhere.
    prop in schema_properties(res.resourceType)
    not schema_requires_unique_items(res.resourceType, prop)
    # Distinct intrinsics can each resolve to the same placeholder and look like
    # duplicates; only literal items are advisory.
    not is_from_intrinsic(name, sprintf("Properties.%s", [prop]))
    val := resolve(name, sprintf("Properties.%s", [prop]))
    is_array(val)
    not _any_intrinsic_item(name, prop, val)
    dup := _first_duplicate_scalar(val)
}

_any_intrinsic_item(name, prop, val) if {
    some i, _ in val
    is_from_intrinsic(name, sprintf("Properties.%s.%d", [prop, i]))
}

_first_duplicate_scalar(arr) := dup if {
    scalars := [x | some x in arr; _is_scalar(x)]
    dups := {x | some k, x in scalars; x in array.slice(scalars, 0, k)}
    count(dups) > 0
    dup := [x | some x in scalars; x in dups][0]
}

_is_scalar(x) if is_string(x)
_is_scalar(x) if is_number(x)
_is_scalar(x) if is_boolean(x)

# Match serde_json::Value::to_string() formatting for consistent output.
_format_item(x) := sprintf("\"%s\"", [x]) if is_string(x)
_format_item(x) := format_int(x, 10) if is_number(x)
_format_item(x) := "true" if x == true
_format_item(x) := "false" if x == false
