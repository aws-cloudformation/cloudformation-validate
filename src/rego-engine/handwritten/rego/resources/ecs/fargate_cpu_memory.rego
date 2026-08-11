package resources

import rego.v1

violation contains make_diag_full("E3047", "ERROR", name,
    "Properties.Cpu",
    sprintf("Cpu %v is not compatible with Memory %v for Fargate", [cpu, memory]),
    "Use a valid Fargate CPU/memory combination (e.g., Cpu: 256 with Memory: 512, 1024, or 2048)",
    "") if {
    some name in resources_of_type("AWS::ECS::TaskDefinition")
    compat := resolve(name, "Properties.RequiresCompatibilities")
    is_array(compat)
    "FARGATE" in compat
    not is_dynamic(name, "Properties.Cpu")
    not is_dynamic(name, "Properties.Memory")
    cpu := _fargate_integer(resolve(name, "Properties.Cpu"))
    memory := _fargate_integer(resolve(name, "Properties.Memory"))
    not valid_fargate_combo(cpu, memory)
}

_fargate_integer(value) := value if {
    is_number(value)
    floor(value) == value
}

_fargate_integer(value) := number if {
    is_string(value)
    number := to_number(value)
    floor(number) == number
}

valid_fargate_combo(cpu, memory) if { cpu == 256;  memory in {512, 1024, 2048} }
valid_fargate_combo(cpu, memory) if { cpu == 512;  memory >= 1024; memory <= 4096 }
valid_fargate_combo(cpu, memory) if { cpu == 1024; memory >= 2048; memory <= 8192 }
valid_fargate_combo(cpu, memory) if { cpu == 2048; memory >= 4096; memory <= 16384 }
valid_fargate_combo(cpu, memory) if { cpu == 4096; memory >= 8192; memory <= 30720 }
valid_fargate_combo(cpu, memory) if { cpu == 8192; memory >= 16384; memory <= 61440 }
valid_fargate_combo(cpu, memory) if { cpu == 16384; memory >= 32768; memory <= 122880 }
