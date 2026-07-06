package resources

import rego.v1

# E3679: HTTPS/SSL listener requires SSLCertificateId
violation contains make_diag_at("E3679", "ERROR", name,
    "Properties.Listeners",
    sprintf("%s listener requires SSLCertificateId", [proto])) if {
    some name in resources_of_type("AWS::ElasticLoadBalancing::LoadBalancer")
    some item in flatten_list(name, "Properties.Listeners")
    listener := item.value
    is_object(listener)
    proto := object.get(listener, "Protocol", "")
    proto in {"HTTPS", "SSL"}
    # The reference tool requires only that the key be PRESENT (a JSON Schema
    # `required`); an explicit empty-string certificate id satisfies it. Test for
    # an absent key, not an empty value — `not object.get(..., null)` never holds
    # (null is truthy in Rego), so check the key set directly.
    not "SSLCertificateId" in object.keys(listener)
}
