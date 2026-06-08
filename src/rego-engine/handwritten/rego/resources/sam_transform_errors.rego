package resources

import rego.v1

# E0001: SAM transform errors — cfn-lint reports these as transform errors
# rather than schema errors. These are custom rules that complement the
# codegen-generated E3012 required property checks.

# SAM Serverless::LayerVersion requires ContentUri
violation contains make_diag_full("F0001", "FATAL", "", "",
    sprintf("Error transforming template: Resource with id [%s] is invalid. Missing required property 'ContentUri'.", [name]),
    "", "") if {
    some name in resources_of_type("AWS::Serverless::LayerVersion")
    not has_property(name, "ContentUri")
}

# SAM Serverless::Application requires Location
violation contains make_diag_full("F0001", "FATAL", "", "",
    sprintf("Error transforming template: Resource with id [%s] is invalid. Resource is missing the required [Location] property.", [name]),
    "", "") if {
    some name in resources_of_type("AWS::Serverless::Application")
    not has_property(name, "Location")
}

# SAM Schedule event requires Schedule property
violation contains make_diag_full("F0001", "FATAL", "", "",
    sprintf("Error transforming template: Resource with id [%s%s] is invalid. Missing required property 'Schedule'.",
        [name, event_name]),
    "", "") if {
    some name in resources_of_type("AWS::Serverless::Function")
    events := resolve(name, "Properties.Events")
    is_object(events)
    some event_name, event_def in events
    not startswith(event_name, "__")
    is_object(event_def)
    event_def.Type == "Schedule"
    event_props := object.get(event_def, "Properties", {})
    not object.get(event_props, "Schedule", null) != null
}
