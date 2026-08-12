package resources

import rego.v1

# Fargate tasks require NetworkMode awsvpc
violation contains make_diag_full("E3048", "ERROR", name,
    "Properties.NetworkMode",
    sprintf("Fargate requires NetworkMode 'awsvpc', got '%s'", [network_mode]),
    "Set NetworkMode to 'awsvpc'",
    "") if {
    some name in resources_of_type("AWS::ECS::TaskDefinition")
    _is_fargate(name)
    some network_mode in resolve_all(name, "Properties.NetworkMode")
    network_mode != null
    is_string(network_mode)
    network_mode != "awsvpc"
}

# Fargate tasks require NetworkMode in every authored alternative
violation contains make_diag_full("E3048", "ERROR", name,
    "Properties",
    "Fargate requires NetworkMode to be specified as 'awsvpc'",
    "Set NetworkMode to 'awsvpc'",
    "") if {
    some name in resources_of_type("AWS::ECS::TaskDefinition")
    _is_fargate(name)
    some network_mode in resolve_all(name, "Properties.NetworkMode")
    network_mode == null
}

violation contains make_diag_full("E3048", "ERROR", name,
    "Properties",
    "Fargate requires NetworkMode to be specified as 'awsvpc'",
    "Set NetworkMode to 'awsvpc'",
    "") if {
    some name in resources_of_type("AWS::ECS::TaskDefinition")
    _is_fargate(name)
    not has_property(name, "NetworkMode")
}

# Fargate tasks require Cpu
violation contains make_diag_full("E3048", "ERROR", name,
    "Properties",
    "Fargate requires Cpu to be specified",
    "Set Cpu to a valid Fargate value (256, 512, 1024, 2048, 4096, 8192, 16384, or 32768)",
    "") if {
    some name in resources_of_type("AWS::ECS::TaskDefinition")
    _is_fargate(name)
    not has_property(name, "Cpu")
}

violation contains make_diag_full("E3048", "ERROR", name,
    "Properties",
    "Fargate requires Cpu to be specified",
    "Set Cpu to a valid Fargate value (256, 512, 1024, 2048, 4096, 8192, 16384, or 32768)",
    "") if {
    some name in resources_of_type("AWS::ECS::TaskDefinition")
    _is_fargate(name)
    has_property(name, "Cpu")
    some cpu in resolve_all(name, "Properties.Cpu")
    cpu == null
}

# Fargate Cpu must name an offered size
violation contains make_diag_full("E3048", "ERROR", name,
    "Properties.Cpu",
    sprintf("Fargate Cpu value %s is not valid. Must be one of %s", [render_value(cpu), _fargate_cpu_list_str]),
    "Use a valid Fargate Cpu value (256, 512, 1024, 2048, 4096, 8192, 16384, or 32768)",
    "") if {
    some name in resources_of_type("AWS::ECS::TaskDefinition")
    _is_fargate(name)
    some cpu in resolve_all(name, "Properties.Cpu")
    cpu != null
    fargate_cpu_is_offered(cpu) == false
}

# Fargate tasks require Memory
violation contains make_diag_full("E3048", "ERROR", name,
    "Properties",
    "Fargate requires Memory to be specified",
    "Set Memory to a valid Fargate value",
    "") if {
    some name in resources_of_type("AWS::ECS::TaskDefinition")
    _is_fargate(name)
    not has_property(name, "Memory")
}

violation contains make_diag_full("E3048", "ERROR", name,
    "Properties",
    "Fargate requires Memory to be specified",
    "Set Memory to a valid Fargate value",
    "") if {
    some name in resources_of_type("AWS::ECS::TaskDefinition")
    _is_fargate(name)
    has_property(name, "Memory")
    some memory in resolve_all(name, "Properties.Memory")
    memory == null
}

# Fargate does not support PlacementConstraints in any authored alternative
violation contains make_diag_full("E3048", "ERROR", name,
    "Properties.PlacementConstraints",
    "Fargate does not support PlacementConstraints",
    "Remove PlacementConstraints for Fargate tasks",
    "") if {
    some name in resources_of_type("AWS::ECS::TaskDefinition")
    _is_fargate(name)
    has_property(name, "PlacementConstraints")
    _fargate_placement_declared(name)
}

# Fargate unsupported log driver
violation contains make_diag_full("E3048", "ERROR", name,
    sprintf("Properties.ContainerDefinitions.%v.LogConfiguration.LogDriver", [ci]),
    sprintf("Fargate does not support log driver '%s'. Supported drivers: %s", [driver, _fargate_log_drivers_str]),
    "Use 'awslogs', 'splunk', or 'awsfirelens'",
    "") if {
    some name in resources_of_type("AWS::ECS::TaskDefinition")
    _is_fargate(name)
    cdefs := resolve(name, "Properties.ContainerDefinitions")
    is_array(cdefs)
    some ci, cdef in cdefs
    log_config := cdef.LogConfiguration
    driver := log_config.LogDriver
    is_string(driver)
    not driver in _fargate_supported_log_drivers
}

# An unresolved authored value remains potentially present.
_fargate_placement_declared(name) if {
    values := resolve_all(name, "Properties.PlacementConstraints")
    count(values) == 0
}

_fargate_placement_declared(name) if {
    some value in resolve_all(name, "Properties.PlacementConstraints")
    value != null
}

# Helper: check if a task definition requires FARGATE compatibility
_is_fargate(name) if {
    compat := resolve(name, "Properties.RequiresCompatibilities")
    is_array(compat)
    "FARGATE" in compat
}

_fargate_supported_log_drivers := {"awslogs", "splunk", "awsfirelens"}
_fargate_cpu_list_str := "['256', '512', '1024', '2048', '4096', '8192', '16384', '32768']"
_fargate_log_drivers_str := "['awslogs', 'splunk', 'awsfirelens']"
