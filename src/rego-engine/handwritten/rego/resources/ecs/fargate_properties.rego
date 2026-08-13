package resources

import rego.v1

violation contains make_diag_full("E3048", "ERROR", name,
    "Properties.NetworkMode",
    sprintf("Fargate requires NetworkMode 'awsvpc', got '%s'", [network_mode]),
    "Set NetworkMode to 'awsvpc'",
    "") if {
    some name in resources_of_type("AWS::ECS::TaskDefinition")
    some network_scenario in _fargate_property_scenarios(name, "Properties.NetworkMode")
    network_mode := network_scenario.value
    network_mode != null
    is_string(network_mode)
    network_mode != "awsvpc"
}

violation contains make_diag_full("E3048", "ERROR", name,
    "Properties",
    "Fargate requires NetworkMode to be specified as 'awsvpc'",
    "Set NetworkMode to 'awsvpc'",
    "") if {
    some name in resources_of_type("AWS::ECS::TaskDefinition")
    some network_scenario in _fargate_property_scenarios(name, "Properties.NetworkMode")
    network_scenario.value == null
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
    some cpu_scenario in _fargate_property_scenarios(name, "Properties.Cpu")
    cpu_scenario.value == null
}

violation contains make_diag_full("E3048", "ERROR", name,
    "Properties.Cpu",
    sprintf("Fargate Cpu value %s is not valid. Must be one of %s", [render_value(cpu), _fargate_cpu_list_str]),
    "Use a valid Fargate Cpu value (256, 512, 1024, 2048, 4096, 8192, 16384, or 32768)",
    "") if {
    some name in resources_of_type("AWS::ECS::TaskDefinition")
    some cpu_scenario in _fargate_property_scenarios(name, "Properties.Cpu")
    cpu := cpu_scenario.value
    cpu != null
    fargate_cpu_is_offered(cpu) == false
}

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
    some memory_scenario in _fargate_property_scenarios(name, "Properties.Memory")
    memory_scenario.value == null
}

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

violation contains make_diag_full("E3048", "ERROR", name,
    sprintf("Properties.ContainerDefinitions.%v.LogConfiguration.LogDriver", [container_index]),
    sprintf("Fargate does not support log driver '%s'. Supported drivers: %s", [driver, _fargate_log_drivers_str]),
    "Use 'awslogs', 'splunk', or 'awsfirelens'",
    "") if {
    some name in resources_of_type("AWS::ECS::TaskDefinition")
    _is_fargate(name)
    container_definitions := resolve(name, "Properties.ContainerDefinitions")
    is_array(container_definitions)
    some container_index, container_definition in container_definitions
    log_configuration := container_definition.LogConfiguration
    driver := log_configuration.LogDriver
    is_string(driver)
    not driver in _fargate_supported_log_drivers
}

_fargate_placement_declared(name) if {
    count(resolve_scenarios(name, "Properties.PlacementConstraints")) == 0
}

_fargate_placement_declared(name) if {
    some placement_scenario in _fargate_property_scenarios(name, "Properties.PlacementConstraints")
    placement_scenario.value != null
}

_fargate_compatibility_scenarios(name) := {scenario |
    some scenario in resolve_scenarios(name, "Properties.RequiresCompatibilities")
    is_array(scenario.value)
    "FARGATE" in scenario.value
    _resource_scenario_reachable(name, scenario.conditions)
}

_fargate_property_scenarios(name, path) := {property_scenario |
    some compatibility_scenario in _fargate_compatibility_scenarios(name)
    some property_scenario in resolve_scenarios(name, path)
    _scenario_conditions_compatible(name, compatibility_scenario.conditions, property_scenario.conditions)
}

_is_fargate(name) if {
    count(_fargate_compatibility_scenarios(name)) > 0
}

_fargate_supported_log_drivers := {"awslogs", "splunk", "awsfirelens"}
_fargate_cpu_list_str := "['256', '512', '1024', '2048', '4096', '8192', '16384', '32768']"
_fargate_log_drivers_str := "['awslogs', 'splunk', 'awsfirelens']"
