# I3037: Advisory when array properties contain duplicate values
package resources

import rego.v1

violation contains make_diag_at("I3037", "INFO", name,
    sprintf("Properties.%s", [prop]),
    sprintf("Array property '%s' contains duplicate value: %s", [prop, _format_item(dup)])) if {
    some name, res in input.resources
    some prop in object.keys(res.properties)
    val := resolve(name, sprintf("Properties.%s", [prop]))
    is_array(val)
    dup := _first_duplicate(val)
}

_first_duplicate(arr) := arr[i] if {
    some i
    i < count(arr)
    some j
    j < i
    arr[j] == arr[i]
}

# Match serde_json::Value::to_string() formatting for parity with cel-engine.
_format_item(x) := sprintf("\"%s\"", [x]) if is_string(x)
_format_item(x) := format_int(x, 10) if is_number(x)
_format_item(x) := "true" if x == true
_format_item(x) := "false" if x == false
_format_item(x) := "null" if x == null
_format_item(x) := json.marshal(x) if {
    not is_string(x)
    not is_number(x)
    not is_boolean(x)
    x != null
}
