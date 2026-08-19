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
    _fargate_property_missing(name, "NetworkMode")
}

violation contains make_diag_full("E3048", "ERROR", name,
    "Properties",
    "Fargate requires Cpu to be specified",
    "Set Cpu to a valid Fargate value (256, 512, 1024, 2048, 4096, 8192, 16384, or 32768)",
    "") if {
    some name in resources_of_type("AWS::ECS::TaskDefinition")
    _fargate_property_missing(name, "Cpu")
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
    _fargate_property_missing(name, "Memory")
}

violation contains make_diag_full("E3048", "ERROR", name,
    "Properties.PlacementConstraints",
    "Fargate does not support PlacementConstraints",
    "Remove PlacementConstraints for Fargate tasks",
    "") if {
    some name in resources_of_type("AWS::ECS::TaskDefinition")
    _fargate_placement_declared(name)
}

violation contains make_diag_full("E3048", "ERROR", name,
    sprintf("Properties.ContainerDefinitions.%v.LogConfiguration.LogDriver", [driver_scenario.path_index]),
    sprintf("Fargate does not support log driver '%s'. Supported drivers: %s", [driver_scenario.value, _fargate_log_drivers_str]),
    _fargate_log_driver_fix,
    "") if {
    some name in resources_of_type("AWS::ECS::TaskDefinition")
    some driver_scenario in _fargate_invalid_log_drivers(name)
}

# Collect unique invalid log drivers across every concrete container-list
# scenario compatible with a Fargate compatibility scenario. Resolving the
# whole list covers both a conditional list and conditionals nested within it.
_fargate_invalid_log_drivers(name) := {scenario |
    some compatibility_scenario in _fargate_compatibility_scenarios(name)
    some container_scenario in resolve_scenarios(name, "Properties.ContainerDefinitions")
    is_array(container_scenario.value)
    _scenario_conditions_compatible(name, compatibility_scenario.conditions, container_scenario.conditions)
    some container_index, container in container_scenario.value
    driver := container.LogConfiguration.LogDriver
    is_string(driver)
    not driver in data.fargate_supported_log_drivers
    scenario := {"path_index": container_index, "value": driver}
}

_fargate_placement_declared(name) if {
    some compatibility_scenario in _fargate_compatibility_scenarios(name)
    some property_scenario in properties_scenarios(name, ["PlacementConstraints"])
    _scenario_conditions_compatible(name, compatibility_scenario.conditions, property_scenario.conditions)
    object.get(property_scenario.properties, "PlacementConstraints", null) != null
}

_fargate_compatibility_scenarios(name) := {scenario |
    some scenario in resolve_scenarios(name, "Properties.RequiresCompatibilities")
    is_array(scenario.value)
    "FARGATE" in scenario.value
    _resource_scenario_reachable(name, scenario.conditions)
}

_fargate_property_missing(name, property_name) if {
    some compatibility_scenario in _fargate_compatibility_scenarios(name)
    some property_scenario in properties_scenarios(name, [property_name])
    _scenario_conditions_compatible(name, compatibility_scenario.conditions, property_scenario.conditions)
    object.get(property_scenario.properties, property_name, null) == null
}

_fargate_property_scenarios(name, path) := {property_scenario |
    some compatibility_scenario in _fargate_compatibility_scenarios(name)
    some property_scenario in resolve_scenarios(name, path)
    _scenario_conditions_compatible(name, compatibility_scenario.conditions, property_scenario.conditions)
}

_fargate_cpu_list_str := "['256', '512', '1024', '2048', '4096', '8192', '16384', '32768']"
_fargate_log_drivers_str := sprintf("['%s']", [concat("', '", data.fargate_supported_log_drivers)])

_fargate_log_driver_fix := sprintf("Use '%s'", [data.fargate_supported_log_drivers[0]]) if {
    count(data.fargate_supported_log_drivers) == 1
}

_fargate_log_driver_fix := sprintf("Use '%s' or '%s'", [
    data.fargate_supported_log_drivers[0],
    data.fargate_supported_log_drivers[1],
]) if {
    count(data.fargate_supported_log_drivers) == 2
}

_fargate_log_driver_fix := sprintf("Use '%s', or '%s'", [
    concat("', '", array.slice(data.fargate_supported_log_drivers, 0, count(data.fargate_supported_log_drivers) - 1)),
    data.fargate_supported_log_drivers[count(data.fargate_supported_log_drivers) - 1],
]) if {
    count(data.fargate_supported_log_drivers) > 2
}
