package resources

import rego.v1

# E3029: Route53 RecordSet - TTL must not be set when AliasTarget is specified
violation contains make_diag_at("E3029", "ERROR", name,
    "Properties.TTL",
    "TTL must not be set when AliasTarget is specified") if {
    some name in resources_of_type("AWS::Route53::RecordSet")
    alias := resolve(name, "Properties.AliasTarget")
    alias != null
    ttl := resolve(name, "Properties.TTL")
    ttl != null
}

# E3029: Route53 RecordSet - AliasTarget only valid for A and AAAA
violation contains make_diag_at("E3029", "ERROR", name,
    "Properties.AliasTarget",
    sprintf("AliasTarget cannot be used with record type '%s'", [rtype])) if {
    some name in resources_of_type("AWS::Route53::RecordSet")
    alias := resolve(name, "Properties.AliasTarget")
    alias != null
    rtype := resolve(name, "Properties.Type")
    is_string(rtype)
    rtype != "A"
    rtype != "AAAA"
}
