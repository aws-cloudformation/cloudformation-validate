# E3010: Resource must not exceed 50 properties
package resources

import rego.v1

violation contains make_diag_at("E3010", "ERROR", name,
    "Properties",
    sprintf("Resource '%s' has %d properties, exceeding maximum 50", [name, cnt])) if {
    cfn_rule_active("E3010")
    some name in object.keys(input.resources)
    cnt := count(object.keys(input.resources[name].properties))
    cnt > 50
}
