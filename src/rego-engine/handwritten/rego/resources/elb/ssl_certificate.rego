package resources

import rego.v1

# Certificate protocols require SSLCertificateId.
violation contains make_diag_at("E3679", "ERROR", name,
    sprintf("Properties.Listeners.%d", [item.index]),
    sprintf("%s listener requires SSLCertificateId", [proto])) if {
    some name in resources_of_type("AWS::ElasticLoadBalancing::LoadBalancer")
    some item in flatten_list(name, "Properties.Listeners")
    listener := item.value
    is_object(listener)
    proto := object.get(listener, "Protocol", "")
    proto in data.classic_load_balancer_certificate_protocols
    not "SSLCertificateId" in object.keys(listener)
}
