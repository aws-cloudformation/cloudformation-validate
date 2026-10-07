package resources

import rego.v1

violation contains make_diag_full("E3047", "ERROR", name,
    "Properties.Cpu",
    sprintf("Cpu %s is not compatible with Memory %s for Fargate", [render_value(cpu), render_value(memory)]),
    "Use a valid Fargate CPU/memory combination (e.g., Cpu: 256 with Memory: 512, 1024, or 2048)",
    "") if {
    cfn_rule_active("E3047")
    some name in resources_of_type("AWS::ECS::TaskDefinition")
    some compatibility_scenario in _fargate_compatibility_scenarios(name)
    some cpu_scenario in resolve_scenarios(name, "Properties.Cpu")
    _scenario_conditions_compatible(name, compatibility_scenario.conditions, cpu_scenario.conditions)
    fargate_cpu_conditions := object.union(compatibility_scenario.conditions, cpu_scenario.conditions)
    some memory_scenario in resolve_scenarios(name, "Properties.Memory")
    _scenario_conditions_compatible(name, fargate_cpu_conditions, memory_scenario.conditions)
    cpu := cpu_scenario.value
    memory := memory_scenario.value
    fargate_task_size_is_offered(cpu, memory) == false
}
