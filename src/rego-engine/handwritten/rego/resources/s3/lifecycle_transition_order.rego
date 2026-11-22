package resources

import rego.v1

# S3 moves objects down a fixed storage-class waterfall and never back up, so a
# lifecycle rule must reach each class later than the classes above it.
_s3_lifecycle_transition_rank := {
    "STANDARD_IA": 1,
    "INTELLIGENT_TIERING": 2,
    "ONEZONE_IA": 3,
    "GLACIER_IR": 4,
    "GLACIER": 5,
    "DEEP_ARCHIVE": 6,
}

# Objects must stay in the class they leave for its minimum storage duration
# before S3 moves them on to an archive class.
_s3_lifecycle_transition_minimum_gap(from_class, to_class) := 30 if {
    from_class in {"STANDARD_IA", "ONEZONE_IA"}
    to_class in {"GLACIER", "DEEP_ARCHIVE"}
}

_s3_lifecycle_transition_minimum_gap(from_class, _) := 90 if {
    from_class in {"GLACIER_IR", "GLACIER"}
}

# A storage class or day count supplied by a parameter or another intrinsic is
# only known at deployment, so its default is not folded into the comparison.
_s3_lifecycle_transition_is_literal(name, path) if {
    not is_from_parameter(name, path)
    not is_from_intrinsic(name, path)
}

_s3_lifecycle_transitions contains transition if {
    some name in resources_of_type("AWS::S3::Bucket")
    rules := input.resources[name].properties.LifecycleConfiguration.Rules
    is_array(rules)
    some rule_idx, rule in rules
    is_object(rule)
    transitions := object.get(rule, "Transitions", null)
    is_array(transitions)
    some transition_idx, authored in transitions
    is_object(authored)
    transition_path := sprintf("Properties.LifecycleConfiguration.Rules.%d.Transitions.%d", [rule_idx, transition_idx])
    days_path := concat(".", [transition_path, "TransitionInDays"])
    _s3_lifecycle_transition_is_literal(name, concat(".", [transition_path, "StorageClass"]))
    _s3_lifecycle_transition_is_literal(name, days_path)
    storage_class := object.get(authored, "StorageClass", null)
    rank := _s3_lifecycle_transition_rank[storage_class]
    days := coerce_to_integer(object.get(authored, "TransitionInDays", null))
    transition := {
        "name": name,
        "rule": rule_idx,
        "storage_class": storage_class,
        "rank": rank,
        "days": days,
        "days_path": days_path,
    }
}

violation contains make_diag_full("E9016", "ERROR", later.name,
    later.days_path,
    sprintf("Transition to %s at %v days must come after the transition to %s at %v days", [later.storage_class, later.days, earlier.storage_class, earlier.days]),
    sprintf("Set TransitionInDays for %s greater than %v", [later.storage_class, earlier.days]),
    "") if {
    cfn_rule_active("E9016")
    some earlier in _s3_lifecycle_transitions
    some later in _s3_lifecycle_transitions
    earlier.name == later.name
    earlier.rule == later.rule
    later.rank > earlier.rank
    later.days <= earlier.days
}

violation contains make_diag_full("E9017", "ERROR", later.name,
    later.days_path,
    sprintf("Transition to %s at %v days must be at least %v days after the transition to %s at %v days", [later.storage_class, later.days, gap, earlier.storage_class, earlier.days]),
    sprintf("Set TransitionInDays for %s to at least %v", [later.storage_class, earlier.days + gap]),
    "") if {
    cfn_rule_active("E9017")
    some earlier in _s3_lifecycle_transitions
    some later in _s3_lifecycle_transitions
    earlier.name == later.name
    earlier.rule == later.rule
    later.rank > earlier.rank
    later.days > earlier.days
    gap := _s3_lifecycle_transition_minimum_gap(earlier.storage_class, later.storage_class)
    later.days - earlier.days < gap
}
