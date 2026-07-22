package resources

import rego.v1

# F3006: An AWS-namespaced resource type that is not in the compiled schema
# set is a typo or nonexistent type — CloudFormation owns the reserved `AWS::`
# namespace, so the embedded schema catalog is authoritative for it. Types in
# any other namespace (private registry types, `Custom::` resources, modules,
# hook-shaped names) may be registered per account/region, so they are skipped
# entirely rather than guessed at.
violation contains make_diag("F3006", "FATAL", name,
    sprintf("Unknown resource type '%s'", [rtype])) if {
    some name, res in input.resources
    rtype := res.resourceType
    is_string(rtype)
    startswith(rtype, "AWS::")
    not rtype in data.known_resource_types
}
