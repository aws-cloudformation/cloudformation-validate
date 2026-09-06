package resources

import rego.v1

# API Gateway definitions must not mix an inline or packaged body with related
# resources that independently modify the same RestApi.
_apigw_mixing_types := {t | some t in data.rule_tables.api_gateway_mixing_resource_types}

_apigw_body_property(api_id) := "Body" if {
    has_property(api_id, "Body")
}

_apigw_body_property(api_id) := "BodyS3Location" if {
    has_property(api_id, "BodyS3Location")
}

violation contains make_diag_at("W3660", "WARN", api_id,
    sprintf("Properties.%s", [property]),
    sprintf("Defining '%s' with a relation to resource '%s' of type '%s' may result in drift and orphaned resources", [property, name, rtype])) if {
    cfn_rule_active("W3660")
    some rtype in _apigw_mixing_types
    some name in resources_of_type(rtype)
    api_id := follow_ref(name, "Properties.RestApiId")
    api_id != null
    property := _apigw_body_property(api_id)
}
