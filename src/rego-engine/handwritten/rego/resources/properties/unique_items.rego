package resources

import rego.v1

# W9007: a property whose items must be unique must not repeat a value.
#
# Two entries are only reported when they are provably one value. An entry that
# resolves before deployment is settled by its contents; an entry that stays
# opaque is settled by the expression that produces it, since two entries written
# the same way always read the same thing. When any entry offers neither, the
# property is left alone: entries that merely look alike because their values are
# unknowable are not a duplicate.
violation contains make_diag_at("W9007", "WARN", name,
    sprintf("Properties.%s", [prop_key]),
    sprintf("Array property '%s' contains duplicate values", [prop_key])) if {
    some name, res in input.resources
    some prop_key, prop_val in res.properties
    is_array(prop_val)
    count(prop_val) > 1
    prop_key in unique_array_properties
    identities := [identity |
        some index, _ in prop_val
        identity := value_identity(name, sprintf("Properties.%s.%d", [prop_key, index]))
    ]
    count(identities) == count(prop_val)
    count(identities) != count({identity | some identity in identities})
}

# Properties known to require unique items
unique_array_properties := {
    "AvailabilityZones",
    "SecurityGroupIds",
    "SecurityGroups",
    "SubnetIds",
    "Subnets",
    "RequiresCompatibilities",
    "PlacementConstraints"
}
