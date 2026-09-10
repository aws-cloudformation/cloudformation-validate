package resources

import rego.v1

# E3042: At least one container in a TaskDefinition must have Essential=true
violation contains make_diag("E3042", "ERROR", name,
    "At least one container definition must have Essential set to true") if {
    cfn_rule_active("E3042")
    some name in resources_of_type("AWS::ECS::TaskDefinition")
    cdefs := resolve(name, "Properties.ContainerDefinitions")
    is_array(cdefs)
    count(cdefs) > 1
    every cdef in cdefs { cdef.Essential == false }
}
