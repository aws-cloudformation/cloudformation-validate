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
    not object.get(listener, "SSLCertificateId", null)
}
