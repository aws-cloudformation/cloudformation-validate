package resources

import rego.v1

# E3008 (Fn::If-at-property-level check) was removed for parity with cel-engine.
# The previous implementation produced false positives when a conditional was
# nested inside a specific property (e.g., AWS::CloudFormation::Stack's
# Properties.Parameters = Fn::If). Nested-stack parameter validation is covered by
# the dedicated schema/guard checks for AWS::CloudFormation::Stack. cfn-lint's own
# E3008 is a different rule (array prefixItems), not a Fn::If property-name check.
