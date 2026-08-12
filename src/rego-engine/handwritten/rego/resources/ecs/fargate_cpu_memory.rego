package resources

import rego.v1

violation contains make_diag_full("E3047", "ERROR", name,
    "Properties.Cpu",
    sprintf("Cpu %s is not compatible with Memory %s for Fargate", [render_value(cpu), render_value(memory)]),
    "Use a valid Fargate CPU/memory combination (e.g., Cpu: 256 with Memory: 512, 1024, or 2048)",
    "") if {
    some name in resources_of_type("AWS::ECS::TaskDefinition")
    compat := resolve(name, "Properties.RequiresCompatibilities")
    is_array(compat)
    "FARGATE" in compat
    not is_dynamic(name, "Properties.Cpu")
    not is_dynamic(name, "Properties.Memory")
    cpu := resolve(name, "Properties.Cpu")
    memory := resolve(name, "Properties.Memory")
    fargate_task_size_is_offered(cpu, memory) == false
}
