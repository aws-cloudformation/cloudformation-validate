package resources

import rego.v1

# Alias records inherit their target's TTL, so an authored TTL is invalid even when either value is dynamic.
violation contains make_diag_at("E3029", "ERROR", name,
    "Properties.TTL",
    "TTL must not be set when AliasTarget is specified") if {
    some name in resources_of_type("AWS::Route53::RecordSet")
    has_property(name, "AliasTarget")
    has_property(name, "TTL")
}

# Route53 never permits NS or SOA alias records; other types depend on the target and cannot be rejected globally.
violation contains make_diag_at("E3029", "ERROR", name,
    "Properties.AliasTarget",
    sprintf("AliasTarget cannot be used with record type '%s'", [rtype])) if {
    some name in resources_of_type("AWS::Route53::RecordSet")
    has_property(name, "AliasTarget")
    rtype := resolve(name, "Properties.Type")
    rtype in {"NS", "SOA"}
}
