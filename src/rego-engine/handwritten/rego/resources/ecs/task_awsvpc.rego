package resources

import rego.v1

# E3053: When NetworkMode is awsvpc, HostPort must equal ContainerPort
violation contains make_diag_full("E3053", "ERROR", name,
    sprintf("Properties.ContainerDefinitions[%d].PortMappings[%d].HostPort", [ci, pi]),
    sprintf("HostPort %v must equal ContainerPort %v when NetworkMode is awsvpc", [hp, cp]),
    "Set HostPort equal to ContainerPort or remove HostPort",
    "") if {
    some name in resources_of_type("AWS::ECS::TaskDefinition")
    nm := resolve(name, "Properties.NetworkMode")
    nm == "awsvpc"
    cdefs := resolve(name, "Properties.ContainerDefinitions")
    is_array(cdefs)
    some ci, cdef in cdefs
    pms := object.get(cdef, "PortMappings", [])
    is_array(pms)
    some pi, pm in pms
    hp := coerce_port_to_string(object.get(pm, "HostPort", null))
    cp := coerce_port_to_string(object.get(pm, "ContainerPort", null))
    hp != cp
}
