package resources

import rego.v1

# E3047: Invalid Fargate CPU/memory combination
violation contains make_diag_full("E3047", "ERROR", name,
    "Properties.Cpu",
    sprintf("Cpu %v is not compatible with Memory %v for Fargate", [cpu, mem]),
    "Use a valid Fargate CPU/memory combination (e.g., Cpu: 256 with Memory: 512, 1024, or 2048)",
    "") if {
    some name in resources_of_type("AWS::ECS::TaskDefinition")
    compat := resolve(name, "Properties.RequiresCompatibilities")
    is_array(compat)
    "FARGATE" in compat
    cpu := resolve(name, "Properties.Cpu")
    mem := resolve(name, "Properties.Memory")
    cpu != null; mem != null
    not is_dynamic(name, "Properties.Cpu")
    not is_dynamic(name, "Properties.Memory")
    not valid_fargate_combo(cpu, mem)
}

valid_fargate_combo(cpu, mem) if { to_number(cpu) == 256;  to_number(mem) in {512, 1024, 2048} }
valid_fargate_combo(cpu, mem) if { to_number(cpu) == 512;  n := to_number(mem); n >= 1024; n <= 4096 }
valid_fargate_combo(cpu, mem) if { to_number(cpu) == 1024; n := to_number(mem); n >= 2048; n <= 8192 }
valid_fargate_combo(cpu, mem) if { to_number(cpu) == 2048; n := to_number(mem); n >= 4096; n <= 16384 }
valid_fargate_combo(cpu, mem) if { to_number(cpu) == 4096; n := to_number(mem); n >= 8192; n <= 30720 }
valid_fargate_combo(cpu, mem) if { to_number(cpu) == 8192; n := to_number(mem); n >= 16384; n <= 61440 }
valid_fargate_combo(cpu, mem) if { to_number(cpu) == 16384; n := to_number(mem); n >= 32768; n <= 122880 }
