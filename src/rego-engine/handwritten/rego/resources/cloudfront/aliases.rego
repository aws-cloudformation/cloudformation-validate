# E3013: CloudFront Aliases must be valid domain names
package resources

import rego.v1

violation contains make_diag_at("E3013", "ERROR", name,
    sprintf("Properties.DistributionConfig.Aliases.%d", [i]),
    sprintf("CloudFront alias '%s' is not a valid domain name", [alias])) if {
    cfn_rule_active("E3013")
    some name in resources_of_type("AWS::CloudFront::Distribution")
    val := resolve(name, "Properties.DistributionConfig.Aliases")
    is_array(val)
    some i, alias in val
    is_string(alias)
    not regex.match(`^(?:[a-z0-9\*](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$`, alias)
}

# Wildcard must not appear in the middle (e.g., foo.*.bar.com)
violation contains make_diag_at("E3013", "ERROR", name,
    sprintf("Properties.DistributionConfig.Aliases.%d", [i]),
    sprintf("CloudFront alias '%s' has wildcard in invalid position", [alias])) if {
    cfn_rule_active("E3013")
    some name in resources_of_type("AWS::CloudFront::Distribution")
    val := resolve(name, "Properties.DistributionConfig.Aliases")
    is_array(val)
    some i, alias in val
    is_string(alias)
    regex.match(`\.\*\.`, alias)
}
