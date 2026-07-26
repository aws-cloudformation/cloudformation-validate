package resources

import rego.v1

# E3048: A Fargate task definition must declare awsvpc networking, a task-level
# Cpu and Memory size drawn from the sizes Fargate offers, must not pin
# placement (Fargate chooses the infrastructure), and may only use the log
# drivers Fargate supports.

_fargate_tasks contains name if {
    some name in resources_of_type("AWS::ECS::TaskDefinition")
    compat := resolve(name, "Properties.RequiresCompatibilities")
    is_array(compat)
    "FARGATE" in compat
}

_fargate_network_mode := "awsvpc"

_fargate_cpu_units := ["256", "512", "1024", "2048", "4096", "8192", "16384"]

_fargate_log_drivers := ["awslogs", "splunk", "awsfirelens"]

_required_property := ["NetworkMode", "Cpu", "Memory"]

violation contains make_diag_at("E3048", "ERROR", name, "Properties",
    sprintf("'%s' is a required property for a Fargate task", [property])) if {
    some name in _fargate_tasks
    some property in _required_property
    not has_property(name, property)
}

violation contains make_diag_full("E3048", "ERROR", name, "Properties.NetworkMode",
    sprintf("'%s' is not one of %s", [mode, render_list([_fargate_network_mode])]),
    sprintf("Set NetworkMode to '%s'", [_fargate_network_mode]),
    "") if {
    some name in _fargate_tasks
    mode := resolve(name, "Properties.NetworkMode")
    is_string(mode)
    mode != _fargate_network_mode
}

violation contains make_diag_full("E3048", "ERROR", name, "Properties.Cpu",
    sprintf("Cpu '%s' is not one of %s", [cpu, render_list(_fargate_cpu_units)]),
    "Use a task-level Cpu size Fargate offers",
    "") if {
    some name in _fargate_tasks
    cpu := _cpu_text(name)
    regex.match(`^\d+$`, cpu)
    not cpu in _fargate_cpu_units
}

violation contains make_diag_full("E3048", "ERROR", name, "Properties.Cpu",
    sprintf("Cpu '%s' is not a vCPU size Fargate offers", [cpu]),
    "Use a vCPU size such as '.25 vCPU', '1 vCPU', or '16 vCPU'",
    "") if {
    some name in _fargate_tasks
    cpu := _cpu_text(name)
    not regex.match(`^\d+$`, cpu)
    not regex.match(`^(\.25|\.5|1|2|4|8|16)\s*(?i)vCpu$`, cpu)
}

# The declared Cpu as text, so the numeric and vCPU forms can be told apart
# whether the template wrote a number or a string. Unresolvable values are
# skipped: their deploy-time value is unknown.
_cpu_text(name) := text if {
    cpu := resolve(name, "Properties.Cpu")
    not is_dynamic(name, "Properties.Cpu")
    text := sprintf("%v", [cpu])
}

violation contains make_diag_full("E3048", "ERROR", name, "Properties.PlacementConstraints",
    "'PlacementConstraints' is not supported for a Fargate task",
    "Remove PlacementConstraints; Fargate selects the infrastructure",
    "") if {
    some name in _fargate_tasks
    has_property(name, "PlacementConstraints")
}

violation contains make_diag_full("E3048", "ERROR", name,
    sprintf("Properties.ContainerDefinitions.%d.LogConfiguration.LogDriver", [index]),
    sprintf("'%s' is not one of %s", [driver, render_list(_fargate_log_drivers)]),
    sprintf("Use a log driver Fargate supports: %s", [render_list(_fargate_log_drivers)]),
    "") if {
    some name in _fargate_tasks
    container_definitions := resolve(name, "Properties.ContainerDefinitions")
    is_array(container_definitions)
    some index, container in container_definitions
    log_configuration := object.get(container, "LogConfiguration", {})
    driver := object.get(log_configuration, "LogDriver", null)
    is_string(driver)
    not driver in _fargate_log_drivers
}
