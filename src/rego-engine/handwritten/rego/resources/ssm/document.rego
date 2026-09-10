# E3051: SSM Document Content must have schemaVersion
package resources

import rego.v1

violation contains make_diag_at("E3051", "ERROR", name,
    "Properties.Content",
    "SSM Document Content must include 'schemaVersion'") if {
    cfn_rule_active("E3051")
    some name in resources_of_type("AWS::SSM::Document")
    content := resolve(name, "Properties.Content")
    is_object(content)
    not object.get(content, "schemaVersion", null) != null
}
