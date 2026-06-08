package resources

import rego.v1

# W3660: API Gateway — warn when resources reference a RestApi that has Body/BodyS3Location
apigw_has_body(api_id) if {
    body := resolve(api_id, "Properties.Body")
    body != null
}

apigw_has_body(api_id) if {
    body := resolve(api_id, "Properties.BodyS3Location")
    body != null
}

violation contains make_diag_at("W3660", "WARN", name,
    "Properties.RestApiId",
    sprintf("Resource references RestApi '%s' which has Body/BodyS3Location — mixing inline definitions with external body", [api_id])) if {
    apigw_types := {"AWS::ApiGateway::Method", "AWS::ApiGateway::Stage", "AWS::ApiGateway::Deployment"}
    some rtype in apigw_types
    some name in resources_of_type(rtype)
    api_id := follow_ref(name, "Properties.RestApiId")
    api_id != null
    apigw_has_body(api_id)
}
