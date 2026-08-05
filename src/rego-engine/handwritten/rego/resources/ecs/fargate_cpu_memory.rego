package resources

import rego.v1

# A Fargate task must use one of the task sizes Fargate offers — a Cpu size
# paired with a Memory size drawn from the range that size supports. Cpu may be
# written in CPU units or vCPU, and Memory in MiB or GB.

_vcpu_to_cpu_units := {".25": 256, ".5": 512, "1": 1024, "2": 2048, "4": 4096, "8": 8192, "16": 16384}

# The Memory range each Cpu size supports, in MiB, and the step between the
# sizes offered within that range. 256 CPU units offers three discrete sizes
# rather than a stepped range, so it is checked separately.
_memory_range := {
    512: {"min": 1024, "max": 4096, "step": 1024},
    1024: {"min": 2048, "max": 8192, "step": 1024},
    2048: {"min": 4096, "max": 16384, "step": 1024},
    4096: {"min": 8192, "max": 30720, "step": 1024},
    8192: {"min": 16384, "max": 61440, "step": 4096},
    16384: {"min": 32768, "max": 122880, "step": 8192},
}

_mib_per_gb := 1024

violation contains make_diag_full("E3047", "ERROR", name,
    "Properties.Cpu",
    sprintf("Cpu %s is not compatible with Memory %s for Fargate", [render_value(cpu), render_value(memory)]),
    "Use a task size Fargate offers (e.g. Cpu 256 with Memory 512, 1024, or 2048)",
    "") if {
    some name in _fargate_tasks
    not is_dynamic(name, "Properties.Cpu")
    not is_dynamic(name, "Properties.Memory")
    cpu := resolve(name, "Properties.Cpu")
    memory := resolve(name, "Properties.Memory")
    # A task size is only declared when both values are written as a string or an
    # integer. Any other shape is a type violation the schema reports, and
    # carries no size to pair.
    cpu_text := coerce_string_or_integer_to_string(cpu)
    memory_text := coerce_string_or_integer_to_string(memory)
    not _offered_task_size(cpu_text, memory_text)
}

# Undefined when either value is in a form Fargate does not accept, which makes
# the declared size an unoffered one.
_offered_task_size(cpu_text, memory_text) if {
    _valid_size_pair(_cpu_units(cpu_text), _memory_mib(memory_text))
}

_valid_size_pair(cpu_units, memory_mib) if {
    cpu_units == 256
    memory_mib in {512, 1024, 2048}
}

_valid_size_pair(cpu_units, memory_mib) if {
    limits := _memory_range[cpu_units]
    memory_mib >= limits.min
    memory_mib <= limits.max
    memory_mib % limits.step == 0
}

# The CPU-unit spelling is matched exactly as written, because Fargate offers a
# fixed set of Cpu values rather than a numeric range: a padded spelling such as
# "0512" names none of them.
_cpu_units(text) := to_number(text) if {
    text in _fargate_cpu_units
}

_cpu_units(text) := _vcpu_to_cpu_units[_size_before_unit(text, "vcpu")]

# Memory is bounded by a range rather than a fixed set of spellings, so a MiB or
# GB size is read as the number it denotes.
_memory_mib(text) := _digits_as_number(text)

_memory_mib(text) := _mib_per_gb / 2 if {
    _size_before_unit(text, "gb") == "0.5"
}

_memory_mib(text) := _digits_as_number(size) * _mib_per_gb if {
    size := _size_before_unit(text, "gb")
    not size == "0.5"
}

# The number a digits-only text denotes. Zero padding does not change the number a
# size is read as, so the padding is stripped before the text is read.
_digits_as_number(text) := 0 if {
    regex.match(`^0+$`, text)
}

_digits_as_number(text) := to_number(trim_left(text, "0")) if {
    regex.match(`^\d+$`, text)
    not regex.match(`^0+$`, text)
}

# The size written before a `vCPU`/`GB` unit suffix, in any casing and with
# optional space before the unit. Undefined when the value carries no such unit.
_size_before_unit(text, unit) := size if {
    lowered := lower(text)
    endswith(lowered, unit)
    size := trim_space(substring(lowered, 0, count(lowered) - count(unit)))
}
