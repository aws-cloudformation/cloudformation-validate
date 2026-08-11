package resources

import rego.v1

# Fargate tasks require NetworkMode awsvpc
violation contains make_diag_full("E3048", "ERROR", name,
    "Properties.NetworkMode",
    sprintf("Fargate requires NetworkMode 'awsvpc', got '%s'", [nm]),
    "Set NetworkMode to 'awsvpc'",
    "") if {
    some name in resources_of_type("AWS::ECS::TaskDefinition")
    _is_fargate(name)
    nm := resolve(name, "Properties.NetworkMode")
    nm != null
    is_string(nm)
    nm != "awsvpc"
}

# Fargate tasks require NetworkMode (absent or null)
violation contains make_diag_full("E3048", "ERROR", name,
    "Properties",
    "Fargate requires NetworkMode to be specified as 'awsvpc'",
    "Set NetworkMode to 'awsvpc'",
    "") if {
    some name in resources_of_type("AWS::ECS::TaskDefinition")
    _is_fargate(name)
    nm := resolve(name, "Properties.NetworkMode")
    nm == null
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

# Fargate tasks require Cpu (absent)
violation contains make_diag_full("E3048", "ERROR", name,
    "Properties",
    "Fargate requires Cpu to be specified",
    "Set Cpu to a valid Fargate value (256, 512, 1024, 2048, 4096, 8192, or 16384)",
    "") if {
    some name in resources_of_type("AWS::ECS::TaskDefinition")
    _is_fargate(name)
    not has_property(name, "Cpu")
}

# Fargate tasks require Cpu (null/AWS::NoValue)
violation contains make_diag_full("E3048", "ERROR", name,
    "Properties",
    "Fargate requires Cpu to be specified",
    "Set Cpu to a valid Fargate value (256, 512, 1024, 2048, 4096, 8192, or 16384)",
    "") if {
    some name in resources_of_type("AWS::ECS::TaskDefinition")
    _is_fargate(name)
    has_property(name, "Cpu")
    cpu := resolve(name, "Properties.Cpu")
    cpu == null
}

# Fargate Cpu must be a valid offered size
violation contains make_diag_full("E3048", "ERROR", name,
    "Properties.Cpu",
    sprintf("Fargate Cpu value %v is not valid. Must be one of %s", [cpu_int, _fargate_cpu_list_str]),
    "Use a valid Fargate Cpu value (256, 512, 1024, 2048, 4096, 8192, or 16384)",
    "") if {
    some name in resources_of_type("AWS::ECS::TaskDefinition")
    _is_fargate(name)
    cpu := resolve(name, "Properties.Cpu")
    cpu != null
    not is_dynamic(name, "Properties.Cpu")
    cpu_int := _fargate_integer(cpu)
    not cpu_int in _fargate_valid_cpu
}

# Fargate tasks require Memory (absent)
violation contains make_diag_full("E3048", "ERROR", name,
    "Properties",
    "Fargate requires Memory to be specified",
    "Set Memory to a valid Fargate value",
    "") if {
    some name in resources_of_type("AWS::ECS::TaskDefinition")
    _is_fargate(name)
    not has_property(name, "Memory")
}

# Fargate tasks require Memory (null/AWS::NoValue)
violation contains make_diag_full("E3048", "ERROR", name,
    "Properties",
    "Fargate requires Memory to be specified",
    "Set Memory to a valid Fargate value",
    "") if {
    some name in resources_of_type("AWS::ECS::TaskDefinition")
    _is_fargate(name)
    has_property(name, "Memory")
    mem := resolve(name, "Properties.Memory")
    mem == null
}

# Fargate does not support PlacementConstraints (effective/non-null)
violation contains make_diag_full("E3048", "ERROR", name,
    "Properties.PlacementConstraints",
    "Fargate does not support PlacementConstraints",
    "Remove PlacementConstraints for Fargate tasks",
    "") if {
    some name in resources_of_type("AWS::ECS::TaskDefinition")
    _is_fargate(name)
    has_property(name, "PlacementConstraints")
    pc := resolve(name, "Properties.PlacementConstraints")
    pc != null
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

# Helper: check if a task definition requires FARGATE compatibility
_is_fargate(name) if {
    compat := resolve(name, "Properties.RequiresCompatibilities")
    is_array(compat)
    "FARGATE" in compat
}

_fargate_valid_cpu := {256, 512, 1024, 2048, 4096, 8192, 16384}
_fargate_supported_log_drivers := {"awslogs", "splunk", "awsfirelens"}
_fargate_cpu_list_str := "['256', '512', '1024', '2048', '4096', '8192', '16384']"
_fargate_log_drivers_str := "['awslogs', 'splunk', 'awsfirelens']"
