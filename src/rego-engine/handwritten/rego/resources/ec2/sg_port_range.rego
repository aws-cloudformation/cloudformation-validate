package resources

import rego.v1

# E9002: SecurityGroup FromPort must be <= ToPort
violation contains make_diag_full("E9002", "ERROR", name,
    "Properties.SecurityGroupIngress",
    sprintf("FromPort %v is greater than ToPort %v", [from_port, to_port]),
    "Set FromPort to a value less than or equal to ToPort",
    "") if {
    some name in resources_of_type("AWS::EC2::SecurityGroup")
    some key, rule in input.resources[name].properties.SecurityGroupIngress
    is_object(rule)
    from_port := coerce_to_integer(object.get(rule, "FromPort", null))
    to_port := coerce_to_integer(object.get(rule, "ToPort", null))
    from_port > to_port
}
