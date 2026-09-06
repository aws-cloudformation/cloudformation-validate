package resources

import rego.v1

# Alias records inherit their target's TTL, so an effective TTL is invalid even when either value is dynamic.
violation contains make_diag_at("E3029", "ERROR", name,
    "Properties.TTL",
    "TTL must not be set when AliasTarget is specified") if {
    cfn_rule_active("E3029")
    some name in resources_of_type("AWS::Route53::RecordSet")
    some scenario in properties_scenarios(name, ["AliasTarget", "TTL"])
    _route53_scenario_reachable(name, scenario.conditions)
    object.get(scenario.properties, "AliasTarget", null) != null
    object.get(scenario.properties, "TTL", null) != null
}

# Route53 never permits NS or SOA alias records; other types depend on the target and cannot be rejected globally.
violation contains make_diag_at("E3029", "ERROR", name,
    "Properties.AliasTarget",
    sprintf("AliasTarget cannot be used with record type '%s'", [record_type])) if {
    cfn_rule_active("E3029")
    some name in resources_of_type("AWS::Route53::RecordSet")
    some scenario in properties_scenarios(name, ["AliasTarget", "Type"])
    _route53_scenario_reachable(name, scenario.conditions)
    object.get(scenario.properties, "AliasTarget", null) != null
    record_type := object.get(scenario.properties, "Type", null)
    record_type in {"NS", "SOA"}
}
