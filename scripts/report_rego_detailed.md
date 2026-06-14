# CfnValidationEngine vs cfn-lint — Parity Report

> Generated: 2026-06-14 15:04:31  
> Engine: **rego**  
> Detail level: **detailed**  
> Matching: `(rule_id, resource_id, path)` two-pass with `(rule_id, resource_id)` fallback + aliases  
> Templates compared: **160**  

## Terminology

| Term | Meaning |
|------|---------|
| **TP** (True Positive) | Engine and cfn-lint agree — correct finding |
| **FP** (False Positive) | Engine reports it, cfn-lint doesn't — noise or engine bug |
| **EE** (Engine Extra) | Correct engine finding that cfn-lint does not cover |
| **FN** (False Negative) | cfn-lint expects it, engine misses it — gap in coverage |
| **Precision** | TP/(TP+FP) — excludes Engine Extra from noise count |
| **Recall** | TP/(TP+FN) — how much of what cfn-lint expects the engine catches |
| **F1** | Harmonic mean of Precision and Recall — single quality score |

## Summary

| Metric | Value |
|--------|------:|
| True Positives | 1026 |
| False Positives (engine bugs) | 0 |
| Engine Extra (correct, cfn-lint gap) | 2090 |
| False Negatives (engine misses) | 153 |
| Precision | 100.00% |
| Recall | 87.02% |
| F1 | 93.06% |
| Unique rules detected | 139 |
| Perfect templates | 110/160 |

### By Severity

| Severity | TP | FP | EE | FN | Precision | Recall |
|----------|---:|---:|---:|---:|----------:|-------:|
| Fatal | 240 | 0 | 78 | 48 | 100.00% | 83.33% |
| Error | 189 | 0 | 71 | 80 | 100.00% | 70.26% |
| Warning | 370 | 0 | 388 | 19 | 100.00% | 95.12% |
| Info | 227 | 0 | 1553 | 6 | 100.00% | 97.42% |

## Performance

| Metric | Value |
|--------|------:|
| Total wall time | 19766.0429 ms |
| Throughput | 113.58 validations/sec |
| Templates | 449 ok, 8 failed |
| Iterations per template | 5 |
| Engine init (p99) | 73.5405 ms |
| Engine init (max) | 74.3175 ms |
| Schema init (p99) | 67.1266 ms |
| Schema init (max) | 68.2576 ms |

### Latency Distribution (ms)

| Phase | Min | Avg | Median | P90 | P95 | P99 | Max |
|-------|----:|----:|-------:|----:|----:|----:|----:|
| Model Build | 0.0018 | 0.2005 | 0.0438 | 0.6338 | 0.8739 | 1.6007 | 2.6788 |
| Schema Validate | 0.0000 | 2.4915 | 0.4363 | 6.7011 | 10.6191 | 24.3414 | 54.0535 |
| Rule Evaluation | 0.9613 | 5.5195 | 2.3592 | 14.2294 | 19.6153 | 33.7613 | 76.6121 |
| Diagnostic Finalize | 0.0003 | 0.0318 | 0.0055 | 0.0926 | 0.1443 | 0.3235 | 0.6330 |
| Engine Internal | 0.9652 | 8.3043 | 3.0515 | 21.6812 | 34.8820 | 57.9015 | 115.3067 |
| Wall Clock | 0.9653 | 8.3047 | 3.0516 | 21.6822 | 34.8833 | 57.9027 | 115.3080 |

## False Negatives — 153 missed findings across 53 rules

These are diagnostics cfn-lint expects but the engine does not report.

### F3014 — 8 missed — Validate only one of a set of required properties are specified

- **F3014** (cfn-lint: E3014) `myInstance2` → `Properties.BlockDeviceMappings.Fn::If.2.0.Fn::If.1.VirtualName` L46 in `bad_core_conditions`
  > Only one of ['VirtualName', 'Ebs', 'NoDevice'] is a required property
- **F3014** (cfn-lint: E3014) `myInstance2` → `Properties.BlockDeviceMappings.Fn::If.2.0.Fn::If.1.Ebs` L47 in `bad_core_conditions`
  > Only one of ['VirtualName', 'Ebs', 'NoDevice'] is a required property
- **F3014** (cfn-lint: E3014) `mySecurityGroupVpc` → `Properties.SecurityGroupIngress.1.CidrIp` L39 in `bad_properties_sg_ingress`
  > Only one of ['CidrIp', 'CidrIpv6', 'SourcePrefixListId', 'SourceSecurityGroupId', 'SourceSecurityGroupName'] is a required property
- **F3014** (cfn-lint: E3014) `mySecurityGroupVpc` → `Properties.SecurityGroupIngress.1.SourceSecurityGroupId` L40 in `bad_properties_sg_ingress`
  > Only one of ['CidrIp', 'CidrIpv6', 'SourcePrefixListId', 'SourceSecurityGroupId', 'SourceSecurityGroupName'] is a required property
- **F3014** (cfn-lint: E3014) `mySecurityGroupVpc` → `Properties.SecurityGroupIngress.4.SourceSecurityGroupId` L49 in `bad_properties_sg_ingress`
  > Only one of ['CidrIp', 'CidrIpv6', 'SourcePrefixListId', 'SourceSecurityGroupId', 'SourceSecurityGroupName'] is a required property
- **F3014** (cfn-lint: E3014) `mySecurityGroupVpc` → `Properties.SecurityGroupIngress.4.CidrIp` L50 in `bad_properties_sg_ingress`
  > Only one of ['CidrIp', 'CidrIpv6', 'SourcePrefixListId', 'SourceSecurityGroupId', 'SourceSecurityGroupName'] is a required property
- **F3014** (cfn-lint: E3014) `myInstance2` → `Properties.BlockDeviceMappings.Fn::If.2.0.Fn::If.1.VirtualName` L48 in `good_core_conditions`
  > Only one of ['VirtualName', 'Ebs', 'NoDevice'] is a required property
- **F3014** (cfn-lint: E3014) `myInstance2` → `Properties.BlockDeviceMappings.Fn::If.2.0.Fn::If.1.Ebs` L49 in `good_core_conditions`
  > Only one of ['VirtualName', 'Ebs', 'NoDevice'] is a required property

### E1021 — 8 missed — Base64 validation of parameters

- **E1021** `myInstance` → `Properties.UserData.Fn::Base64` L11 in `bad_functions_base64`
  > ['Random String'] is not of type 'string'
- **E1021** `myInstance` → `Properties.UserData.Fn::Base64.Fn::Join` L12 in `bad_functions_join`
  > expected maximum item count: 2, found: 3
- **E1021** `myInstance` → `Properties.UserData.Fn::Base64.Fn::Join.1` L14 in `bad_functions_join`
  > 'Test function' is not of type 'array'
- **E1021** `myInstance2` → `Properties.UserData.Fn::Base64` L21 in `bad_functions_join`
  > Exception '0' raised while validating 'fn_join'
- **E1021** `myInstance2` → `Properties.UserData.Fn::Base64.Fn::Join` L22 in `bad_functions_join`
  > {'Ref': 'myInstance'} is not of type 'array'
- **E1021** `LaunchConfiguration` → `Properties.UserData.Fn::Base64.Fn::Sub` L61 in `good_functions_sub`
  > {'Fn::Transform': {'Name': 'DynamicUserData'}} is not of type 'array', 'string'
- **E1021** `LaunchConfiguration` → `Properties.UserData.Fn::Base64.Fn::Sub` L24 in `good_parameters_not_used_parameters`
  > {'Fn::Transform': {'Name': 'DynamicUserData'}} is not of type 'array', 'string'
- **E1021** `LaunchConfiguration` → `Properties.UserData.Fn::Base64.Fn::Sub` L27 in `good_parameters_used_transforms`
  > {'Fn::Transform': {'Name': 'DynamicUserData'}} is not of type 'array', 'string'

### E1017 — 7 missed — Select validation of parameters

- **E1017** `mySubnet2` → `Properties.AvailabilityZone.Fn::Select.1.Fn::GetAZs` L27 in `bad_functions_getaz`
  > 'us-east-1a' is not one of ['', 'af-south-1', 'ap-east-1', 'ap-east-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-south-1', 'ap-south-2', 'ap-southeast-1', 'ap-southeast-2', 'ap-southe
- **E1017** `mySubnet3` → `Properties.AvailabilityZone.Fn::Select.1.Fn::GetAZs.Fn::GetAtt.1` L36 in `bad_functions_getaz`
  > 'AvailbilityZone' is not one of ['AssignIpv6AddressOnCreation', 'AvailabilityZone', 'AvailabilityZoneId', 'BlockPublicAccessStates.InternetGatewayBlockMode', 'CidrBlock', 'EnableDns64', 'EnableLniAtDe
- **E1017** `myInstance` → `Properties.AvailabilityZone.Fn::Select.0` L11 in `bad_functions_select`
  > 'a' is not of type 'integer'
- **E1017** `myInstance1` → `Properties.AvailabilityZone.Fn::Select` L19 in `bad_functions_select`
  > expected maximum item count: 2, found: 3
- **E1017** `myInstance1` → `Properties.AvailabilityZone.Fn::Select.1` L21 in `bad_functions_select`
  > 'Value1' is not of type 'array'
- **E1017** `myInstance2` → `Properties.AvailabilityZone.Fn::Select.1` L30 in `bad_functions_select`
  > {'Fn::Join': [',', ['a', 'b']]} is not of type 'array'
- **E1017** `myInstance3` → `Properties.AvailabilityZone.Fn::Select` L36 in `bad_functions_select`
  > 'foo' is not of type 'array'

### F3016 — 7 missed — Check the configuration of a resources UpdatePolicy

- **F3016** (cfn-lint: E3016) `MyModule` → `Resources.MyModule.UpdatePolicy` L5 in `bad_modules_bad_has_update_policy`
  > False schema does not allow {'EnableVersionUpgrade': False}
- **F3016** (cfn-lint: E3035) `PolicyList` → `Resources.PolicyList.DeletionPolicy` L16 in `bad_resources_deletionpolicy`
  > ['Snapshot', 'Retain'] is not of type 'string'
- **F3016** (cfn-lint: E3035) `PolicyList` → `Resources.PolicyList.DeletionPolicy` L16 in `bad_resources_deletionpolicy`
  > ['Snapshot', 'Retain'] is not one of ['Delete', 'Retain', 'RetainExceptOnCreate', 'Snapshot']
- **F3016** (cfn-lint: E3035) `UnsupportedIntrinsic` → `Resources.UnsupportedIntrinsic.DeletionPolicy` L32 in `bad_resources_deletionpolicy`
  > {'Fn::Cidr': ['192.168.0.0/24', 6, 5]} is not of type 'string'
- **F3016** (cfn-lint: E3035) `UnsupportedIntrinsic` → `Resources.UnsupportedIntrinsic.DeletionPolicy` L32 in `bad_resources_deletionpolicy`
  > {'Fn::Cidr': ['192.168.0.0/24', 6, 5]} is not one of ['Delete', 'Retain', 'RetainExceptOnCreate']
- **F3016** (cfn-lint: E3035) `InvalidMapping` → `Resources.InvalidMapping.DeletionPolicy` L43 in `bad_resources_deletionpolicy`
  > {'A': 'a1', 'B': ['b1', 'b2']} is not of type 'string'
- **F3016** (cfn-lint: E3035) `InvalidMapping` → `Resources.InvalidMapping.DeletionPolicy` L43 in `bad_resources_deletionpolicy`
  > {'A': 'a1', 'B': ['b1', 'b2']} is not one of ['Delete', 'Retain', 'RetainExceptOnCreate', 'Snapshot']

### E3530 — 6 missed — Validate IAM trust polices

- **E3530** `TestRole` → `Properties.AssumeRolePolicyDocument.Statement.0.Principal.AWS.0` L17 in `good_functions_sub_needed_custom_excludes`
  > 'arn:aws:iam::${self:custom.config.masterAccount}:user/${self:custom.config.deploymentUser}' is not valid under any of the given schemas
- **E3530** `TestRole` → `Properties.AssumeRolePolicyDocument.Statement.0.Principal.AWS.0` L17 in `good_functions_sub_needed_custom_excludes`
  > '*' was expected
- **E3530** `TestRole` → `Properties.AssumeRolePolicyDocument.Statement.0.Principal.AWS.0` L17 in `good_functions_sub_needed_custom_excludes`
  > 'arn:aws:iam::${self:custom.config.masterAccount}:user/${self:custom.config.deploymentUser}' does not match '^\\d{12}$'
- **E3530** `TestRole` → `Properties.AssumeRolePolicyDocument.Statement.0.Principal.AWS.0` L17 in `good_functions_sub_needed_custom_excludes`
  > 'arn:aws:iam::${self:custom.config.masterAccount}:user/${self:custom.config.deploymentUser}' does not match '^arn:(aws|aws-cn|aws-us-gov):iam::\\d{12}:(?:root|user|group|role)'
- **E3530** `TestRole` → `Properties.AssumeRolePolicyDocument.Statement.0.Principal.AWS.0` L17 in `good_functions_sub_needed_custom_excludes`
  > 'arn:aws:iam::${self:custom.config.masterAccount}:user/${self:custom.config.deploymentUser}' does not match '^arn:(aws|aws-cn|aws-us-gov):sts::\\d{12}:assumed-role'
- **E3530** `TestRole` → `Properties.AssumeRolePolicyDocument.Statement.0.Principal.AWS.0` L17 in `good_functions_sub_needed_custom_excludes`
  > 'arn:aws:iam::${self:custom.config.masterAccount}:user/${self:custom.config.deploymentUser}' does not match '^arn:(aws|aws-cn|aws-us-gov):iam::cloudfront:user/.+$'

### W1036 — 6 missed — Validate the values that come from a Fn::GetAZs function

- **W1036** `lambdaMap1` → `Properties.SecurityGroupIngress.Fn::GetAZs` L198 in `bad_generic`
  > 'us-east-1a' is not of type 'object' when 'Fn::GetAZs' is resolved
- **W1036** `lambdaMap1` → `Properties.SecurityGroupIngress.Fn::GetAZs` L198 in `bad_generic`
  > 'us-east-1b' is not of type 'object' when 'Fn::GetAZs' is resolved
- **W1036** `lambdaMap1` → `Properties.SecurityGroupIngress.Fn::GetAZs` L198 in `bad_generic`
  > 'us-east-1c' is not of type 'object' when 'Fn::GetAZs' is resolved
- **W1036** `lambdaMap1` → `Properties.SecurityGroupIngress.Fn::GetAZs` L198 in `bad_generic`
  > 'us-east-1d' is not of type 'object' when 'Fn::GetAZs' is resolved
- **W1036** `lambdaMap1` → `Properties.SecurityGroupIngress.Fn::GetAZs` L198 in `bad_generic`
  > 'us-east-1e' is not of type 'object' when 'Fn::GetAZs' is resolved
- **W1036** `lambdaMap1` → `Properties.SecurityGroupIngress.Fn::GetAZs` L198 in `bad_generic`
  > 'us-east-1f' is not of type 'object' when 'Fn::GetAZs' is resolved

### F0018 — 6 missed — Check UpdateReplacePolicy values for Resources

- **F0018** (cfn-lint: E3036) `PolicyList` → `Resources.PolicyList.UpdateReplacePolicy` L16 in `bad_resources_updatereplacepolicy`
  > ['Snapshot', 'Retain'] is not of type 'string'
- **F0018** (cfn-lint: E3036) `PolicyList` → `Resources.PolicyList.UpdateReplacePolicy` L16 in `bad_resources_updatereplacepolicy`
  > ['Snapshot', 'Retain'] is not one of ['Delete', 'Retain', 'Snapshot']
- **F0018** (cfn-lint: E3036) `UnsupportedIntrinsic` → `Resources.UnsupportedIntrinsic.UpdateReplacePolicy` L32 in `bad_resources_updatereplacepolicy`
  > {'Fn::Cidr': ['192.168.0.0/24', 6, 5]} is not of type 'string'
- **F0018** (cfn-lint: E3036) `UnsupportedIntrinsic` → `Resources.UnsupportedIntrinsic.UpdateReplacePolicy` L32 in `bad_resources_updatereplacepolicy`
  > {'Fn::Cidr': ['192.168.0.0/24', 6, 5]} is not one of ['Delete', 'Retain']
- **F0018** (cfn-lint: E3036) `InvalidMapping` → `Resources.InvalidMapping.UpdateReplacePolicy` L43 in `bad_resources_updatereplacepolicy`
  > {'A': 'a1', 'B': ['b1', 'b2']} is not of type 'string'
- **F0018** (cfn-lint: E3036) `InvalidMapping` → `Resources.InvalidMapping.UpdateReplacePolicy` L43 in `bad_resources_updatereplacepolicy`
  > {'A': 'a1', 'B': ['b1', 'b2']} is not one of ['Delete', 'Retain', 'Snapshot']

### E8001 — 5 missed — Conditions have appropriate properties

- **E8001** → `Conditions.BadCondition` L41 in `bad_conditions`
  > 'String' is not of type 'boolean'
- **E8001** → `Conditions.TooManyConditions` L43 in `bad_conditions`
  > {'Fn::Equals': [{'Ref': 'EnvType'}, 'prod'], 'Fn::Not': {'Fn::Equals': [{'Ref': 'EnvType'}, 'prod']}} is not of type 'boolean'
- **E8001** → `Conditions.HasParam` L47 in `bad_conditions`
  > {'Fn::Of': [{'Fn::Not': [{'Fn::Equals': [{'Ref': 'EnvType'}, '']}]}, {'Fn::Not': [{'Fn::Equals': [{'Ref': 'EnableGeoBlocking'}, '']}]}]} is not of type 'boolean'
- **E8001** → `Conditions.NullCondition` L51 in `bad_conditions`
  > None is not of type 'boolean'
- **E8001** → `Conditions` L6 in `bad_core_conditions_list`
  > [{'isProduction': {'Fn::Equals': [{'Ref': 'myEnvironment'}, 'prod']}}] is not of type 'object'

### E3001 — 5 missed — Basic CloudFormation Resource Check

- **E3001** `CloudFrontDistribution` → `Resources.CloudFrontDistribution.Condition` L84 in `bad_conditions`
  > False is not of type 'string'
- **E3001** `myBucketFirstAndLastFail` → `Resources.myBucketFirstAndLastFail.BadProperty` L32 in `bad_core_directives`
  > Additional properties are not allowed ('BadProperty' was unexpected)
- **E3001** `myBucketFirstAndLastPass` → `Resources.myBucketFirstAndLastPass.BadProperty` L19 in `bad_core_mandatory_checks`
  > Additional properties are not allowed ('BadProperty' was unexpected)
- **E3001** `myBucketFirstAndLastFail` → `Resources.myBucketFirstAndLastFail.BadProperty` L27 in `bad_core_mandatory_checks`
  > Additional properties are not allowed ('BadProperty' was unexpected)
- **E3001** `BadType` → `Resources.BadType.Type` L156 in `bad_resources_primary_identifiers`
  > {'Ref': 'AWS::Region'} is not of type 'string'

### E3022 — 5 missed — Resource SubnetRouteTableAssociation Properties

- **E3022** `PublicSubnetRouteTableAssociation1` → `Properties.SubnetId` L27 in `bad_properties_rt_association`
  > SubnetId in PublicSubnetRouteTableAssociation1 is also associated with PrivateSubnetRouteTableAssociation1
- **E3022** `PrivateSubnetRouteTableAssociation1` → `Properties.SubnetId` L35 in `bad_properties_rt_association`
  > SubnetId in PrivateSubnetRouteTableAssociation1 is also associated with PublicSubnetRouteTableAssociation1
- **E3022** `AuxiliaryPublicSubnetRouteTableAssociation1` → `Properties.SubnetId` L44 in `bad_properties_rt_association`
  > SubnetId in AuxiliaryPublicSubnetRouteTableAssociation1 is also associated with PublicSubnetRouteTableAssociation1, PrivateSubnetRouteTableAssociation1
- **E3022** `ProxySubnetRouteTableAssociation` → `Properties.SubnetId` L52 in `bad_properties_rt_association`
  > SubnetId in ProxySubnetRouteTableAssociation is also associated with PublicSubnetRouteTableAssociation1, PrivateSubnetRouteTableAssociation1
- **E3022** `AuxilliaryCustomSubnetRouteTableAssociation` → `Properties.SubnetId` L74 in `bad_properties_rt_association`
  > SubnetId in AuxilliaryCustomSubnetRouteTableAssociation is also associated with CustomSubnetRouteTableAssociation

### E3023 — 5 missed — Validate Route53 RecordSets

- **E3023** `MyCNAMERecordSetConditions` → `Properties.ResourceRecords` L90 in `bad_route53`
  > expected maximum item count: 1, found: 2
- **E3023** `MyRecordSetGroup` → `Properties.RecordSets.6.ResourceRecords.0` L164 in `bad_route53`
  > 'No valid domain name' is not valid under any of the given schemas
- **E3023** `MyRecordSetGroup` → `Properties.RecordSets.6.ResourceRecords.0` L164 in `bad_route53`
  > 'No valid domain name' does not match '^[a-zA-Z0-9\\!"\\#\\$\\%\\&\\\'\\(\\)\\*\\+\\,-\\/\\:\\;\\<\\=\\>\\?\\@\\[\\\\\\]\\^\\_\\`\\{\\|\\}\\~\\.]+$'
- **E3023** `MyRecordSetGroup` → `Properties.RecordSets.6.ResourceRecords.0` L164 in `bad_route53`
  > 'No valid domain name' does not match '^.*\\.acm-validations\\.aws\\.?$'
- **E3023** `MyRecordSetGroup` → `Properties.RecordSets.7.ResourceRecords.1` L170 in `bad_route53`
  > '65536 mx2.example.com' does not match '^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{1-3}|65[0-4][0-9]{1-2}|655[0-2][0-9]|6553[0-5])\\s[a-zA-Z0-9\\!"\\#\\$\\%\\&\\\'\\(\\)\\*\\+\\,-\\/\\:\\;\\<\\=\\>\\?\\@\

### I3011 — 4 missed — Check stateful resources have a set UpdateReplacePolicy/DeletionPolicy

- **I3011** `App1` → `Resources.App1` L3 in `good_transform_applications_location`
  > 'DeletionPolicy' is a required property (The default action when replacing/removing a resource is to delete it. Set explicit values for stateful resource)
- **I3011** `App1` → `Resources.App1` L3 in `good_transform_applications_location`
  > 'UpdateReplacePolicy' is a required property (The default action when replacing/removing a resource is to delete it. Set explicit values for stateful resource)
- **I3011** `App2` → `Resources.App2` L7 in `good_transform_applications_location`
  > 'DeletionPolicy' is a required property (The default action when replacing/removing a resource is to delete it. Set explicit values for stateful resource)
- **I3011** `App2` → `Resources.App2` L7 in `good_transform_applications_location`
  > 'UpdateReplacePolicy' is a required property (The default action when replacing/removing a resource is to delete it. Set explicit values for stateful resource)

### F0000 — 4 missed — Parsing error found when parsing the template

- **F0000** (cfn-lint: E0000) L18 in `bad_core_parse_invalid_map`
  > Unhashable type "{'Fn::ImportValue': 'Fn::Sub'}" (line 18)
- **F0000** (cfn-lint: E0000) L5 in `bad_duplicate`
  > Duplicate found 'MySNSTopic' (line 5)
- **F0000** (cfn-lint: E0000) L17 in `bad_duplicate`
  > Duplicate found 'MySNSTopic' (line 17)
- **F0000** (cfn-lint: E0000) L23 in `bad_duplicate`
  > Duplicate found 'MySNSTopic' (line 23)

### E2001 — 4 missed — Parameters have appropriate properties

- **E2001** → `Parameters.allowedValuesAListofBadTypes.AllowedValues.0` L10-11 in `bad_parameters_configuration`
  > {'key': 'value'} is not of type 'string'
- **E2001** → `Parameters.maxLengthIsNotString.MaxLength` L16 in `bad_parameters_configuration`
  > 'MaxLength' is not one of ['AllowedValues', 'ConstraintDescription', 'Default', 'Description', 'MaxValue', 'MinValue', 'NoEcho', 'Type']
- **E2001** → `Parameters.myInvalidParameter.NotType` L27 in `bad_parameters_configuration`
  > Additional properties are not allowed ('NotType' was unexpected)
- **E2001** → `Parameters.NullParamType` L35 in `bad_parameters_configuration`
  > 'Type' is a required property

### W8001 — 3 missed — Check if Conditions are Used

- **W8001** → `Conditions.IsParamBEnabled` L44 in `good_parameters_used_transform_language_extension`
  > Condition IsParamBEnabled not used
- **W8001** → `Conditions.IsParamCEnabled` L44 in `good_parameters_used_transform_language_extension`
  > Condition IsParamCEnabled not used
- **W8001** → `Conditions.IsParamDEnabled` L44 in `good_parameters_used_transform_language_extension`
  > Condition IsParamDEnabled not used

### F0013 — 3 missed — Check Fn::If structure for validity

- **F0013** (cfn-lint: E1028) `EC2Instance` → `Properties.Tags.1.Fn::If.0` L61 in `bad_conditions`
  > 'isProd' is not one of ['CreateProdResources', 'BadCondition', 'UnusedCondition', 'TooManyConditions', 'EnableGeoBlocking', 'HasParam', 'NullCondition']
- **F0013** (cfn-lint: E1028) `myInstance4` → `Properties.InstanceType.Fn::If` L67 in `bad_core_conditions`
  > {'Fn::If': ['isPrimary', 't3.2xlarge', 't3.xlarge']} is not of type 'array'
- **F0013** (cfn-lint: E1028) `AMIIDLookup` → `Properties.Role.Fn::If` L100 in `bad_core_conditions`
  > expected minimum item count: 3, found: 2

### E1032 — 3 missed — Validates ForEach functions

- **E1032** `Fn::ForEach::Buckets` → `Resources.Fn::ForEach::Buckets` L11 in `bad_functions_foreach_no_transform`
  > Missing Transform: Declare the AWS::LanguageExtensions Transform globally to enable use of the intrinsic function Fn::ForEach at Resources/Fn::ForEach::Buckets
- **E1032** → `Outputs.Fn::ForEach::BucketOutputs` L33 in `bad_functions_foreach_no_transform`
  > Missing Transform: Declare the AWS::LanguageExtensions Transform globally to enable use of the intrinsic function Fn::ForEach at Outputs/Fn::ForEach::BucketOutputs
- **E1032** → `Outputs.Fn::ForEach::BucketOutputs.2.Fn::ForEach::GetAttLoop` L36 in `bad_functions_foreach_no_transform`
  > Missing Transform: Declare the AWS::LanguageExtensions Transform globally to enable use of the intrinsic function Fn::ForEach at Outputs/Fn::ForEach::BucketOutputs/2/Fn::ForEach::GetAttLoop

### F1018 — 3 missed — Sub validation of parameters

- **F1018** (cfn-lint: E1019) `MyEC2Instance` → `Properties.UserData.Fn::Sub` L46 in `bad_functions_ref`
  > 'Package' is not one of ['myVpcId', 'mySecurityGroupVpc1', 'mySecurityGroupVpc2', 'MyEC2Instance', 'AnotherInstance', 'AWS::AccountId', 'AWS::NoValue', 'AWS::NotificationARNs', 'AWS::Partition', 'AWS:
- **F1018** (cfn-lint: E1019) `MyEC2Instance` → `Properties.UserData.Fn::Sub` L21 in `bad_refs`
  > 'Package' is not one of ['MyEC2Instance', 'AnotherInstance', 'AWS::AccountId', 'AWS::NoValue', 'AWS::NotificationARNs', 'AWS::Partition', 'AWS::Region', 'AWS::StackId', 'AWS::StackName', 'AWS::URLSuff
- **F1018** (cfn-lint: E1019) `myInstanceSub` → `Properties.UserData.Fn::Sub` L218 in `bad_resources_circular_dependency`
  > {'Test': 'bad configuration'} is not of type 'array', 'string'

### E7001 — 3 missed — Mappings are appropriately configured

- **E7001** → `Mappings.Bad.Name` L3 in `bad_mappings_name`
  > 'Bad.Name' does not match any of the regexes: '^[a-zA-Z0-9]+$'
- **E7001** → `Mappings.myMap.us-east-1.32` L7 in `good_functions_findinmap`
  > 32 does not match any of the regexes: '^[a-zA-Z0-9]+$'
- **E7001** → `Mappings.myMap.us-east-1.64` L7 in `good_functions_findinmap`
  > 64 does not match any of the regexes: '^[a-zA-Z0-9]+$'

### E5001 — 3 missed — Check that Modules resources are valid

- **E5001** `MyModule` → `Resources.MyModule.CreationPolicy` L6 in `bad_modules_bad_has_create_policy`
  > CreationPolicy is not permitted within Modules
- **E5001** `MyModule` → `Resources.MyModule.UpdatePolicy` L5 in `bad_modules_bad_has_update_policy`
  > UpdatePolicy is not permitted within Modules
- **E5001** `MyModule` → `Resources.MyModule.Metadata.AWS::CloudFormation::Module.{'something': 'true'}` L7 in `bad_modules_bad_uses_module_metadata`
  > The Metadata key AWS::CloudFormation::Module is reserved

### F2015 — 3 missed — Default value is within parameter constraints

- **F2015** (cfn-lint: E2015) → `Parameters.CDLAllowedPattern.Default` L42 in `bad_parameters_default`
  > Default should be allowed by AllowedPattern
- **F2015** (cfn-lint: E2015) → `Parameters.CDLAllowedValues.Default` L47 in `bad_parameters_default`
  > Default should be a value within AllowedValues
- **F2015** (cfn-lint: E2015) → `Parameters.CDLAllowedValuesWithSpaces.Default` L56 in `bad_parameters_default`
  > Default should be a value within AllowedValues

### E3048 — 3 missed — Validate ECS Fargate tasks have required properties and values

- **E3048** `taskdefinition` → `Properties` L222 in `bad_resources_circular_dependency`
  > 'NetworkMode' is a required property
- **E3048** `taskdefinition` → `Properties` L222 in `bad_resources_circular_dependency`
  > 'Cpu' is a required property
- **E3048** `taskdefinition` → `Properties` L222 in `bad_resources_circular_dependency`
  > 'Memory' is a required property

### E1005 — 3 missed — Validate Transform configuration

- **E1005** → `Transform` L2 in `bad_templates_base`
  > 'Name' is a required property
- **E1005** → `Transform.key` L3 in `bad_templates_base`
  > Additional properties are not allowed ('key' was unexpected)
- **E1005** → `Transform` L2 in `bad_templates_base_null`
  > None is not of type 'string', 'array', 'object'

### F3003 — 2 missed — Required Resource properties are missing

- **F3003** (cfn-lint: E3003) `myInstance2` → `Properties.BlockDeviceMappings.Fn::If.2.0.Fn::If.1` L46-48 in `bad_core_conditions`
  > 'DeviceName' is a required property
- **F3003** (cfn-lint: E3003) `AMIIDLookup` → `Properties` L101 in `good_core_conditions`
  > 'Role' is a required property

### F3012 — 2 missed — Check resource properties values

- **F3012** (cfn-lint: E3012) `IamRole2` → `Properties.Ref` L26 in `integration_ref-no-value`
  > {'Ref': 'AWS::NoValue'} is not of type object
- **F3012** (cfn-lint: E3012) `CloudFront1` → `Properties.Ref` L39 in `integration_ref-no-value`
  > {'Ref': 'AWS::NoValue'} is not of type object

### E1001 — 2 missed — Basic CloudFormation Template Configuration

- **E1001** → `Conditions.NullCondition` L51 in `bad_conditions`
  > None is not of type 'array', 'boolean', 'integer', 'number', 'object', 'string'
- **E1001** → `AWSTemplateFormatVersion` L1 in `bad_templates_base_null`
  > None is not of type 'string', 'date'

### E3024 — 2 missed — Validate tag configuration

- **E3024** `EC2Instance` → `Properties.Tags.1` L60-69 in `bad_conditions`
  > 'Key' is a required property
- **E3024** `EC2Instance` → `Properties.Tags.1.Fn::If.0` L61 in `bad_conditions`
  > 'isProd' is not one of ['CreateProdResources', 'BadCondition', 'UnusedCondition', 'TooManyConditions', 'EnableGeoBlocking', 'HasParam', 'NullCondition']

### F0014 — 2 missed — Check Fn::And structure for validity

- **F0014** (cfn-lint: E8004) → `Conditions.isPrimaryAndProduction.Fn::And.1.Condition` L11 in `bad_core_conditions_missing`
  > 'isPrimary' is not one of ['isProduction', 'isPrimaryAndProduction']
- **F0014** (cfn-lint: E8003) → `Conditions.primaryRegion.Fn::Equals.0` L4 in `bad_functions_import_value`
  > {'Fn::ImportValue': 'PrimaryRegion'} is not of type 'string'

### W3698 — 2 missed — VirtualName is ignored when Ebs is specified

- **W3698** `myInstance2` → `Properties.BlockDeviceMappings.Fn::If.2.0.Fn::If.1.VirtualName` L46 in `bad_core_conditions`
  > 'VirtualName' is ignored when 'Ebs' is specified
- **W3698** `myInstance2` → `Properties.BlockDeviceMappings.Fn::If.2.0.Fn::If.1.VirtualName` L48 in `good_core_conditions`
  > 'VirtualName' is ignored when 'Ebs' is specified

### F0002 — 2 missed — Error processing rule on the template

- **F0002** (cfn-lint: E0002) L1 in `bad_core_conditions_list`
  > Unknown exception while processing rule W8001: "'list_node' object has no attribute 'items'"
- **F0002** (cfn-lint: E0002) L1 in `bad_functions_foreach_no_transform`
  > Unknown exception while processing rule E1029: "'list_node' object has no attribute 'get'"

### E1011 — 2 missed — FindInMap validation of configuration

- **E1011** `myInstance` → `Properties.ImageId.Fn::FindInMap.2` L9 in `bad_functions_base64`
  > {'Fn::GetAtt': ['myInstance', 'AvailabilityZone']} is not of type 'string'
- **E1011** `lambdaMap2` → `Properties.SecurityGroupIngress.0` L206-207 in `bad_generic`
  > {'Fn::FindInMap': ['runtime', {'Ref': 'AWS::Region'}, 'production']} is not of type 'object'

### E1016 — 2 missed — ImportValue validation of parameters

- **E1016** `subnet` → `Properties.CidrBlock.Fn::ImportValue` L10 in `bad_functions_import_value`
  > {'Fn::ImportValue': 'CidrBlock'} is not of type 'string'
- **E1016** `subnet` → `Properties.VpcId.Fn::ImportValue` L13 in `bad_functions_import_value`
  > ['PrimaryRegion'] is not of type 'string'

### F1029 — 2 missed — Sub is required if a variable is used in a string

- **F1029** (cfn-lint: E1029) `TestBadStateMachine1` → `Properties.DefinitionString.Fn::Join.1.5` L46 in `bad_functions_sub_needed`
  > Found an embedded parameter "${definition_substitution_1}" outside of an "Fn::Sub" at Resources/TestBadStateMachine1/Properties/DefinitionString/Fn::Join/1/5
- **F1029** (cfn-lint: E1029) `TestBadStateMachine2` → `Properties.DefinitionString.Fn::Join.1.5` L67 in `bad_functions_sub_needed`
  > Found an embedded parameter "${definition_substitution_1}" outside of an "Fn::Sub" at Resources/TestBadStateMachine2/Properties/DefinitionString/Fn::Join/1/5

### I3510 — 2 missed — Validate statement resources match the actions

- **I3510** `myPolicy` → `Properties.PolicyDocument.Statement.1.Resource` L21 in `bad_functions_sub_needed`
  > action 'iam:GetLoginProfile' requires a resource of ['arn:${Partition}:iam::${Account}:user/.*']
- **I3510** `myPolicy` → `Properties.PolicyDocument.Statement.0.Resource` L25 in `bad_functions_sub_needed`
  > action 'iam:UploadSSHPublicKey' requires a resource of ['arn:${Partition}:iam::${Account}:user/.*']

### E3510 — 2 missed — Validate identity based IAM polices

- **E3510** `myPolicy` → `Properties.PolicyDocument.Statement.0.Resource` L25 in `bad_functions_sub_needed`
  > 'arn:aws:iam::${AWS::AccountId}:user/${aws:username}-${AMIId}' does not match '^(arn:(aws[A-Za-z\\-]*?|\\*):[^:]+:[^:]*(:(?:\\d{12}|\\*|aws)?:.+|)|\\*)$'
- **E3510** `myPolicy` → `Properties.PolicyDocument.Statement.1.NotResource` L29 in `bad_functions_sub_needed`
  > 'arn:aws:iam::${AWS::AccountId}:user/${aws:username}-${AMIId}' does not match '^(arn:(aws[A-Za-z\\-]*?|\\*):[^:]+:[^:]*(:(?:\\d{12}|\\*|aws)?:.+|)|\\*)$'

### E3671 — 2 missed — Validate block device mapping configuration

- **E3671** `MyEC2Instance` → `Properties.BlockDeviceMappings.0.Ebs.Iops` L17 in `bad_properties_ebs`
  > 0 is less than the minimum of 100
- **E3671** `MyLaunchConfig` → `Properties.BlockDeviceMappings.0.Ebs.Iops` L50 in `bad_properties_ebs`
  > 10 is less than the minimum of 100

### F3031 — 2 missed — Check if property values adhere to a specific pattern

- **F3031** (cfn-lint: E3031) `mySecurityGroupNonVpc` → `Properties.GroupDescription` L23 in `bad_properties_sg_ingress`
  > 'Special charaters like ^ and " are not supported' does not match '^([a-z,A-Z,0-9,. _\\-:/()#,@[\\]+=&;\\{\\}!$*])*$'
- **F3031** (cfn-lint: E3031) `TestRole` → `Properties.RoleName` L10 in `good_functions_sub_needed_custom_excludes`
  > 'TestRole-${Stage}' does not match '^[\\w+=,.@-]+$'

### W3037 — 2 missed — Check IAM Permission configuration

- **W3037** `myRoleToWriteToS3` → `Properties.Policies.0.PolicyDocument.Statement.2.Action` L140 in `bad_resources_circular_dependency`
  > 'headbucket' is not one of ['abortmultipartupload', 'associateaccessgrantsidentitycenter', 'bypassgovernanceretention', 'createaccessgrant', 'createaccessgrantsinstance', 'createaccessgrantslocation',
- **W3037** `myRoleToWriteToS3` → `Properties.Policies.0.PolicyDocument.Statement.2.Action` L140 in `bad_resources_circular_dependency`
  > 'listobjects' is not one of ['abortmultipartupload', 'associateaccessgrantsidentitycenter', 'bypassgovernanceretention', 'createaccessgrant', 'createaccessgrantsinstance', 'createaccessgrantslocation'

### E3019 — 2 missed — Validate that all resources have unique primary identifiers

- **E3019** `Project1` → `Properties.Name` L168 in `bad_resources_primary_identifiers`
  > Primary identifiers {'Name': 'myProjectName'} should have unique values across the resources {'Project2', 'Project1'}
- **E3019** `Project2` → `Properties.Name` L188 in `bad_resources_primary_identifiers`
  > Primary identifiers {'Name': 'myProjectName'} should have unique values across the resources {'Project2', 'Project1'}

### E9004 — 1 missed — GetAtt validation of parameters

- **E9004** (cfn-lint: E1010) `LambdaFunctionTestNotDefinedFromParent` → `Properties.Environment.Variables.Fn::GetAtt` L23 in `good_custom_is-not-defined`
  > {'Fn::GetAtt': ['LambdaExecutionRole', 'Arn']} is not of type 'object'

### F1020 — 1 missed — Ref validation of value

- **F1020** (cfn-lint: E1020) → `Conditions.TagEnvironments.Fn::Not.0.Fn::Equals.1` L15 in `bad_conditions_equals`
  > {'Ref': 'Environments'} is not of type 'string'

### W1001 — 1 missed — Ref/GetAtt to resource that is available when conditions are applied

- **W1001** → `Outputs.lambdaArn.Value` L63 in `bad_functions_relationship_conditions`
  > GetAtt to resource 'LambdaExecutionRole' that may not be available when condition 'isPrimary' is False at Outputs/lambdaArn/Value

### W2001 — 1 missed — Check if Parameters are Used

- **W2001** → `Parameters.NullParamNoEcho` L55 in `bad_parameters_configuration`
  > Parameter NullParamNoEcho not used.

### E6001 — 1 missed — Check the properties of Outputs

- **E6001** → `Outputs.Fn::ForEach::BucketOutputs` L33 in `bad_functions_foreach_no_transform`
  > 'Fn::ForEach::BucketOutputs' does not match any of the regexes: '^[a-zA-Z0-9]+$'

### E3673 — 1 missed — Validate if an ImageId is required

- **E3673** `myEc2Instance4` → `Properties` L67 in `bad_generic`
  > 'ImageId' is a required property

### F6101 — 1 missed — Validate that outputs values are a string

- **F6101** (cfn-lint: E6101) → `Outputs.myErrorOutput.Value.Fn::GetAtt.1` L229 in `bad_generic`
  > 'DNE' is not one of ['Id', 'CanonicalHostedZoneName', 'CanonicalHostedZoneNameID', 'SourceSecurityGroup.GroupName', 'DNSName', 'SourceSecurityGroup.OwnerAlias'] in ['us-east-1']

### W3045 — 1 missed — Controlling access to an S3 bucket should be done with bucket policies

- **W3045** `S3BucketA` → `Properties.AccessControl` L17 in `good_functions_foreach`
  > 'AccessControl' is a legacy property. Consider using 'AWS::S3::BucketPolicy' instead

### W1034 — 1 missed — Validate the values that come from a Fn::FindInMap function

- **W1034** `mySubnet` → `Properties.CidrBlock.Fn::FindInMap` L20 in `bad_mappings_used`
  > {'Fn::FindInMap': ['AcceptanceSubnets', 'eu-west-1a', 'Management']} is not a 'ipv4-network' when 'Fn::FindInMap' is resolved

### W2002 — 1 missed — Parameter type is not officially supported by CloudFormation

- **W2002** → `Parameters.mySsmParam.Type` L30 in `bad_parameters_configuration`
  > 'AWS::SSM::Parameter::Value<Test>' is not an officially documented CloudFormation parameter type. While CloudFormation may accept this type, it will not validate the parameter value.

### W1054 — 1 missed — Pseudo-parameter string found without Ref

- **W1054** `MyHostedZone` → `Properties.VPCs.0.VPCRegion` L22 in `bad_route53`
  > 'AWS::Region' is a pseudo-parameter and should probably be used as 'Ref: AWS::Region' instead of a plain string

### E2529 — 1 missed — Check for SubscriptionFilters have beyond 2 attachments to a CloudWatch Log Group

- **E2529** `LogSubscriptionFunctionFunctionDLogGroup` → `Resources.LogSubscriptionFunctionFunctionDLogGroup` L14 in `bad_some_logs_stream_lambda`
  > You can only have 2 Subscription Filters per CloudWatch Log Group

### E0001 — 1 missed — Error found when transforming the template

- **E0001** L1 in `bad_transform_no_properties`
  > Error transforming template: Resource with id [MyApi] is invalid. Missing required property 'StageName'.

### E3045 — 1 missed — Validate AccessControl are set with OwnershipControls

- **E3045** `S3BucketA` → `Properties` L16 in `good_functions_foreach`
  > A bucket with 'AccessControl' set should also have at least one 'OwnershipControl' configured

## False Positives — 0 extra findings across 0 rules

These are diagnostics the engine reports but cfn-lint does not expect (potential bugs).

## Engine Extra — 2090 correct findings across 58 rules

These are correct diagnostics the engine reports that cfn-lint does not cover.

### I9001 — 1031 findings

- **I9001** `EC2Instance` (AWS::EC2::Instance) → `Properties.ImageId` L54 in `bad_conditions`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `MountPoint` (AWS::EC2::VolumeAttachment) → `Properties.Device` L70 in `bad_conditions`
  > Property 'Device' is create-only; updating it will cause resource replacement
- **I9001** `MountPoint` (AWS::EC2::VolumeAttachment) → `Properties.InstanceId` L70 in `bad_conditions`
  > Property 'InstanceId' is create-only; updating it will cause resource replacement
- **I9001** `MountPoint` (AWS::EC2::VolumeAttachment) → `Properties.VolumeId` L70 in `bad_conditions`
  > Property 'VolumeId' is create-only; updating it will cause resource replacement
- **I9001** `mySubnet` (AWS::EC2::Subnet) → `Properties.CidrBlock` L22 in `bad_core_conditions`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `mySubnet` (AWS::EC2::Subnet) → `Properties.VpcId` L22 in `bad_core_conditions`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `myInstance1` (AWS::EC2::Instance) → `Properties.ImageId` L28 in `bad_core_conditions`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `myInstance1` (AWS::EC2::Instance) → `Properties.SubnetId` L28 in `bad_core_conditions`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `myInstance2` (AWS::EC2::Instance) → `Properties.ImageId` L33 in `bad_core_conditions`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `myInstance4` (AWS::EC2::Instance) → `Properties.ImageId` L63 in `bad_core_conditions`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `LambdaExecutionRole` (AWS::IAM::Role) → `Properties.Path` L73 in `bad_core_conditions`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `InstanceProfile` (AWS::IAM::InstanceProfile) → `Properties.Path` L89 in `bad_core_conditions`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `myTable` (AWS::DynamoDB::Table) → `Properties.TableName` L13 in `bad_core_config_configure_e3012`
  > Property 'TableName' is create-only; updating it will cause resource replacement
- **I9001** `myTable` (AWS::DynamoDB::Table) → `Properties.TableName` L7 in `bad_formatters`
  > Property 'TableName' is create-only; updating it will cause resource replacement
- **I9001** `myInstance` (AWS::EC2::Instance) → `Properties.ImageId` L7 in `bad_functions_base64`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `mySubnet1` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L11 in `bad_functions_getaz`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `mySubnet1` (AWS::EC2::Subnet) → `Properties.CidrBlock` L11 in `bad_functions_getaz`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `mySubnet1` (AWS::EC2::Subnet) → `Properties.VpcId` L11 in `bad_functions_getaz`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `mySubnet2` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L20 in `bad_functions_getaz`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `mySubnet2` (AWS::EC2::Subnet) → `Properties.CidrBlock` L20 in `bad_functions_getaz`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `mySubnet2` (AWS::EC2::Subnet) → `Properties.VpcId` L20 in `bad_functions_getaz`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `mySubnet3` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L29 in `bad_functions_getaz`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `mySubnet3` (AWS::EC2::Subnet) → `Properties.CidrBlock` L29 in `bad_functions_getaz`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `mySubnet3` (AWS::EC2::Subnet) → `Properties.VpcId` L29 in `bad_functions_getaz`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `subnet` (AWS::EC2::Subnet) → `Properties.CidrBlock` L7 in `bad_functions_import_value`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `subnet` (AWS::EC2::Subnet) → `Properties.VpcId` L7 in `bad_functions_import_value`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `myInstance` (AWS::EC2::Instance) → `Properties.ImageId` L7 in `bad_functions_join`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `myInstance2` (AWS::EC2::Instance) → `Properties.ImageId` L17 in `bad_functions_join`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `mySecurityGroupVpc1` (AWS::EC2::SecurityGroup) → `Properties.GroupDescription` L9 in `bad_functions_ref`
  > Property 'GroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `mySecurityGroupVpc1` (AWS::EC2::SecurityGroup) → `Properties.VpcId` L9 in `bad_functions_ref`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `mySecurityGroupVpc2` (AWS::EC2::SecurityGroup) → `Properties.GroupDescription` L21 in `bad_functions_ref`
  > Property 'GroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `mySecurityGroupVpc2` (AWS::EC2::SecurityGroup) → `Properties.VpcId` L21 in `bad_functions_ref`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `MyEC2Instance` (AWS::EC2::Instance) → `Properties.ImageId` L30 in `bad_functions_ref`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `MyEC2Instance` (AWS::EC2::Instance) → `Properties.KeyName` L30 in `bad_functions_ref`
  > Property 'KeyName' is create-only; updating it will cause resource replacement
- **I9001** `MyEC2Instance` (AWS::EC2::Instance) → `Properties.NetworkInterfaces` L30 in `bad_functions_ref`
  > Property 'NetworkInterfaces' is create-only; updating it will cause resource replacement
- **I9001** `AnotherInstance` (AWS::EC2::Instance) → `Properties.ImageId` L49 in `bad_functions_ref`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `AnotherInstance` (AWS::EC2::Instance) → `Properties.KeyName` L49 in `bad_functions_ref`
  > Property 'KeyName' is create-only; updating it will cause resource replacement
- **I9001** `AnotherInstance` (AWS::EC2::Instance) → `Properties.NetworkInterfaces` L49 in `bad_functions_ref`
  > Property 'NetworkInterfaces' is create-only; updating it will cause resource replacement
- **I9001** `LambdaExecutionRole` (AWS::IAM::Role) → `Properties.Path` L12 in `bad_functions_relationship_conditions`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `InstanceProfile` (AWS::IAM::InstanceProfile) → `Properties.Path` L28 in `bad_functions_relationship_conditions`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `myInstance` (AWS::EC2::Instance) → `Properties.AvailabilityZone` L7 in `bad_functions_select`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `myInstance` (AWS::EC2::Instance) → `Properties.ImageId` L7 in `bad_functions_select`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `myInstance1` (AWS::EC2::Instance) → `Properties.AvailabilityZone` L15 in `bad_functions_select`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `myInstance1` (AWS::EC2::Instance) → `Properties.ImageId` L15 in `bad_functions_select`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `myInstance2` (AWS::EC2::Instance) → `Properties.AvailabilityZone` L24 in `bad_functions_select`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `myInstance2` (AWS::EC2::Instance) → `Properties.ImageId` L24 in `bad_functions_select`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `myInstance3` (AWS::EC2::Instance) → `Properties.AvailabilityZone` L32 in `bad_functions_select`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `myInstance3` (AWS::EC2::Instance) → `Properties.ImageId` L32 in `bad_functions_select`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `myInstance` (AWS::EC2::Instance) → `Properties.ImageId` L9 in `bad_functions_sub_needed`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `mySnsTopic` (AWS::SNS::Topic) → `Properties.TopicName` L31 in `bad_functions_sub_needed`
  > Property 'TopicName' is create-only; updating it will cause resource replacement
- **I9001** `MyEC2Instance` (AWS::EC2::Instance) → `Properties.ImageId` L41 in `bad_generic`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `MyEC2Instance` (AWS::EC2::Instance) → `Properties.KeyName` L41 in `bad_generic`
  > Property 'KeyName' is create-only; updating it will cause resource replacement
- **I9001** `MyEC2Instance` (AWS::EC2::Instance) → `Properties.NetworkInterfaces` L41 in `bad_generic`
  > Property 'NetworkInterfaces' is create-only; updating it will cause resource replacement
- **I9001** `MyEC2Instance3` (AWS::EC2::Instance) → `Properties.ImageId` L61 in `bad_generic`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `RootRole` (AWS::IAM::Role) → `Properties.Path` L70 in `bad_generic`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `RootInstanceProfile` (AWS::IAM::InstanceProfile) → `Properties.Path` L103 in `bad_generic`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `SecurityGroup` (AWS::EC2::SecurityGroupIngress) → `Properties.FromPort` L137 in `bad_generic`
  > Property 'FromPort' is create-only; updating it will cause resource replacement
- **I9001** `myAcl` (AWS::WAFRegional::WebACL) → `Properties.Name` L141 in `bad_generic`
  > Property 'Name' is create-only; updating it will cause resource replacement
- **I9001** `lambdaMap1` (AWS::EC2::SecurityGroup) → `Properties.GroupDescription` L194 in `bad_generic`
  > Property 'GroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `lambdaMap2` (AWS::EC2::SecurityGroup) → `Properties.GroupDescription` L202 in `bad_generic`
  > Property 'GroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `PermitAllInbound` (AWS::EC2::NetworkAclEntry) → `Properties.NetworkAclId` L208 in `bad_generic`
  > Property 'NetworkAclId' is create-only; updating it will cause resource replacement
- **I9001** `PermitAllInbound` (AWS::EC2::NetworkAclEntry) → `Properties.RuleNumber` L208 in `bad_generic`
  > Property 'RuleNumber' is create-only; updating it will cause resource replacement
- **I9001** `MyEc2BlockDevice` (AWS::EC2::Instance) → `Properties.ImageId` L217 in `bad_generic`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `MyEc2BlockDevice` (AWS::EC2::Instance) → `Properties.KeyName` L217 in `bad_generic`
  > Property 'KeyName' is create-only; updating it will cause resource replacement
- **I9001** `MyEc2BlockDevice` (AWS::EC2::Instance) → `Properties.NetworkInterfaces` L217 in `bad_generic`
  > Property 'NetworkInterfaces' is create-only; updating it will cause resource replacement
- **I9001** `SampleBadBucketPolicy` (AWS::S3::BucketPolicy) → `Properties.Bucket` L13 in `bad_hard_coded_arn_properties`
  > Property 'Bucket' is create-only; updating it will cause resource replacement
- **I9001** `SampleRole` (AWS::IAM::Role) → `Properties.Path` L25 in `bad_hard_coded_arn_properties`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `RDSOptionGroup` (AWS::RDS::OptionGroup) → `Properties.EngineName` L4 in `bad_issues`
  > Property 'EngineName' is create-only; updating it will cause resource replacement
- **I9001** `RDSOptionGroup` (AWS::RDS::OptionGroup) → `Properties.MajorEngineVersion` L4 in `bad_issues`
  > Property 'MajorEngineVersion' is create-only; updating it will cause resource replacement
- **I9001** `RDSOptionGroup` (AWS::RDS::OptionGroup) → `Properties.OptionGroupDescription` L4 in `bad_issues`
  > Property 'OptionGroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `mySubnet` (AWS::EC2::Subnet) → `Properties.CidrBlock` L16 in `bad_mappings_used`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `mySubnet` (AWS::EC2::Subnet) → `Properties.VpcId` L16 in `bad_mappings_used`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `Instance` (AWS::EC2::Instance) → `Properties.ImageId` L5 in `bad_previous_generation_instances`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `CacheCluster` (AWS::ElastiCache::CacheCluster) → `Properties.Engine` L14 in `bad_previous_generation_instances`
  > Property 'Engine' is create-only; updating it will cause resource replacement
- **I9001** `Host` (AWS::EC2::Host) → `Properties.InstanceType` L25 in `bad_previous_generation_instances`
  > Property 'InstanceType' is create-only; updating it will cause resource replacement
- **I9001** `MyEC2Instance` (AWS::EC2::Instance) → `Properties.ImageId` L7 in `bad_properties_ebs`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `MyEC2Instance` (AWS::EC2::Instance) → `Properties.KeyName` L7 in `bad_properties_ebs`
  > Property 'KeyName' is create-only; updating it will cause resource replacement
- **I9001** `MyEC2Instance` (AWS::EC2::Instance) → `Properties.NetworkInterfaces` L7 in `bad_properties_ebs`
  > Property 'NetworkInterfaces' is create-only; updating it will cause resource replacement
- **I9001** `MyEC2Instance3` (AWS::EC2::Instance) → `Properties.ImageId` L30 in `bad_properties_ebs`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `MyLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.BlockDeviceMappings` L41 in `bad_properties_ebs`
  > Property 'BlockDeviceMappings' is create-only; updating it will cause resource replacement
- **I9001** `MyLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.ImageId` L41 in `bad_properties_ebs`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `MyLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.InstanceType` L41 in `bad_properties_ebs`
  > Property 'InstanceType' is create-only; updating it will cause resource replacement
- **I9001** `MyDB` (AWS::RDS::DBInstance) → `Properties.MasterUsername` L17 in `bad_properties_password`
  > Property 'MasterUsername' is create-only; updating it will cause resource replacement
- **I9001** `MyNewDB` (AWS::RDS::DBInstance) → `Properties.MasterUsername` L26 in `bad_properties_password`
  > Property 'MasterUsername' is create-only; updating it will cause resource replacement
- **I9001** `myThirdDb` (AWS::RDS::DBInstance) → `Properties.MasterUsername` L35 in `bad_properties_password`
  > Property 'MasterUsername' is create-only; updating it will cause resource replacement
- **I9001** `PublicSubnetRouteTableAssociation1` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L23 in `bad_properties_rt_association`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `PublicSubnetRouteTableAssociation1` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L23 in `bad_properties_rt_association`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnetRouteTableAssociation1` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L31 in `bad_properties_rt_association`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnetRouteTableAssociation1` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L31 in `bad_properties_rt_association`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `AuxiliaryPublicSubnetRouteTableAssociation1` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L39 in `bad_properties_rt_association`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `AuxiliaryPublicSubnetRouteTableAssociation1` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L39 in `bad_properties_rt_association`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `ProxySubnetRouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L48 in `bad_properties_rt_association`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `ProxySubnetRouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L48 in `bad_properties_rt_association`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `CustomResource` (AWS::CloudFormation::CustomResource) → `Properties.ServiceToken` L56 in `bad_properties_rt_association`
  > Property 'ServiceToken' is create-only; updating it will cause resource replacement
- **I9001** `CustomSubnetRouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L61 in `bad_properties_rt_association`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `CustomSubnetRouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L61 in `bad_properties_rt_association`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `AuxilliaryCustomSubnetRouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L69 in `bad_properties_rt_association`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `AuxilliaryCustomSubnetRouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L69 in `bad_properties_rt_association`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `mySecurityGroupNonVpc` (AWS::EC2::SecurityGroup) → `Properties.GroupDescription` L21 in `bad_properties_sg_ingress`
  > Property 'GroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `mySecurityGroupVpc` (AWS::EC2::SecurityGroup) → `Properties.GroupDescription` L29 in `bad_properties_sg_ingress`
  > Property 'GroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `mySecurityGroupVpc` (AWS::EC2::SecurityGroup) → `Properties.VpcId` L29 in `bad_properties_sg_ingress`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `SecurityGroupRuleSSM` (AWS::EC2::SecurityGroupIngress) → `Properties.CidrIp` L52 in `bad_properties_sg_ingress`
  > Property 'CidrIp' is create-only; updating it will cause resource replacement
- **I9001** `SecurityGroupRuleSSM` (AWS::EC2::SecurityGroupIngress) → `Properties.FromPort` L52 in `bad_properties_sg_ingress`
  > Property 'FromPort' is create-only; updating it will cause resource replacement
- **I9001** `SecurityGroupRuleSSM` (AWS::EC2::SecurityGroupIngress) → `Properties.GroupId` L52 in `bad_properties_sg_ingress`
  > Property 'GroupId' is create-only; updating it will cause resource replacement
- **I9001** `SecurityGroupRuleSSM` (AWS::EC2::SecurityGroupIngress) → `Properties.IpProtocol` L52 in `bad_properties_sg_ingress`
  > Property 'IpProtocol' is create-only; updating it will cause resource replacement
- **I9001** `SecurityGroupRuleSSM` (AWS::EC2::SecurityGroupIngress) → `Properties.ToPort` L52 in `bad_properties_sg_ingress`
  > Property 'ToPort' is create-only; updating it will cause resource replacement
- **I9001** `mySecurityGroupIngress` (AWS::EC2::SecurityGroupIngress) → `Properties.GroupId` L60 in `bad_properties_sg_ingress`
  > Property 'GroupId' is create-only; updating it will cause resource replacement
- **I9001** `mySecurityGroupIngress` (AWS::EC2::SecurityGroupIngress) → `Properties.IpProtocol` L60 in `bad_properties_sg_ingress`
  > Property 'IpProtocol' is create-only; updating it will cause resource replacement
- **I9001** `mySecurityGroupIngress` (AWS::EC2::SecurityGroupIngress) → `Properties.SourceSecurityGroupId` L60 in `bad_properties_sg_ingress`
  > Property 'SourceSecurityGroupId' is create-only; updating it will cause resource replacement
- **I9001** `mySecurityGroupIngress2` (AWS::EC2::SecurityGroupIngress) → `Properties.GroupId` L66 in `bad_properties_sg_ingress`
  > Property 'GroupId' is create-only; updating it will cause resource replacement
- **I9001** `mySecurityGroupIngress2` (AWS::EC2::SecurityGroupIngress) → `Properties.IpProtocol` L66 in `bad_properties_sg_ingress`
  > Property 'IpProtocol' is create-only; updating it will cause resource replacement
- **I9001** `mySecurityGroupIngress2` (AWS::EC2::SecurityGroupIngress) → `Properties.SourceSecurityGroupId` L66 in `bad_properties_sg_ingress`
  > Property 'SourceSecurityGroupId' is create-only; updating it will cause resource replacement
- **I9001** `mySecurityGroupIngressExclusive` (AWS::EC2::SecurityGroupIngress) → `Properties.GroupId` L72 in `bad_properties_sg_ingress`
  > Property 'GroupId' is create-only; updating it will cause resource replacement
- **I9001** `mySecurityGroupIngressExclusive` (AWS::EC2::SecurityGroupIngress) → `Properties.GroupName` L72 in `bad_properties_sg_ingress`
  > Property 'GroupName' is create-only; updating it will cause resource replacement
- **I9001** `myInstance` (AWS::EC2::Instance) → `Properties.ImageId` L77 in `bad_properties_sg_ingress`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `MyEC2Instance` (AWS::EC2::Instance) → `Properties.ImageId` L5 in `bad_refs`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `MyEC2Instance` (AWS::EC2::Instance) → `Properties.KeyName` L5 in `bad_refs`
  > Property 'KeyName' is create-only; updating it will cause resource replacement
- **I9001** `MyEC2Instance` (AWS::EC2::Instance) → `Properties.NetworkInterfaces` L5 in `bad_refs`
  > Property 'NetworkInterfaces' is create-only; updating it will cause resource replacement
- **I9001** `AnotherInstance` (AWS::EC2::Instance) → `Properties.ImageId` L24 in `bad_refs`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `AnotherInstance` (AWS::EC2::Instance) → `Properties.KeyName` L24 in `bad_refs`
  > Property 'KeyName' is create-only; updating it will cause resource replacement
- **I9001** `AnotherInstance` (AWS::EC2::Instance) → `Properties.NetworkInterfaces` L24 in `bad_refs`
  > Property 'NetworkInterfaces' is create-only; updating it will cause resource replacement
- **I9001** `mySecurityGroupVpc1` (AWS::EC2::SecurityGroup) → `Properties.GroupDescription` L24 in `bad_resources_circular_dependency`
  > Property 'GroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `mySecurityGroupVpc1` (AWS::EC2::SecurityGroup) → `Properties.VpcId` L24 in `bad_resources_circular_dependency`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `mySecurityGroupVpc2` (AWS::EC2::SecurityGroup) → `Properties.GroupDescription` L34 in `bad_resources_circular_dependency`
  > Property 'GroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `mySecurityGroupVpc2` (AWS::EC2::SecurityGroup) → `Properties.VpcId` L34 in `bad_resources_circular_dependency`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `mySecurityGroupVpc3` (AWS::EC2::SecurityGroup) → `Properties.GroupDescription` L42 in `bad_resources_circular_dependency`
  > Property 'GroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `mySecurityGroupVpc3` (AWS::EC2::SecurityGroup) → `Properties.VpcId` L42 in `bad_resources_circular_dependency`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `myInstance` (AWS::EC2::Instance) → `Properties.ImageId` L50 in `bad_resources_circular_dependency`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `myInstance` (AWS::EC2::Instance) → `Properties.NetworkInterfaces` L50 in `bad_resources_circular_dependency`
  > Property 'NetworkInterfaces' is create-only; updating it will cause resource replacement
- **I9001** `myBucket` (AWS::S3::Bucket) → `Properties.BucketName` L63 in `bad_resources_circular_dependency`
  > Property 'BucketName' is create-only; updating it will cause resource replacement
- **I9001** `myBucketPolicy` (AWS::S3::BucketPolicy) → `Properties.Bucket` L73 in `bad_resources_circular_dependency`
  > Property 'Bucket' is create-only; updating it will cause resource replacement
- **I9001** `myRoleToWriteToS3` (AWS::IAM::Role) → `Properties.Path` L97 in `bad_resources_circular_dependency`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `myRoleToWriteToS3` (AWS::IAM::Role) → `Properties.RoleName` L97 in `bad_resources_circular_dependency`
  > Property 'RoleName' is create-only; updating it will cause resource replacement
- **I9001** `myInstanceProfile` (AWS::IAM::InstanceProfile) → `Properties.InstanceProfileName` L146 in `bad_resources_circular_dependency`
  > Property 'InstanceProfileName' is create-only; updating it will cause resource replacement
- **I9001** `myInstanceProfile` (AWS::IAM::InstanceProfile) → `Properties.Path` L146 in `bad_resources_circular_dependency`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `myInstanceSub` (AWS::EC2::Instance) → `Properties.ImageId` L214 in `bad_resources_circular_dependency`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `taskdefinition` (AWS::ECS::TaskDefinition) → `Properties.ContainerDefinitions` L221 in `bad_resources_circular_dependency`
  > Property 'ContainerDefinitions' is create-only; updating it will cause resource replacement
- **I9001** `taskdefinition` (AWS::ECS::TaskDefinition) → `Properties.RequiresCompatibilities` L221 in `bad_resources_circular_dependency`
  > Property 'RequiresCompatibilities' is create-only; updating it will cause resource replacement
- **I9001** `taskdefinition` (AWS::ECS::TaskDefinition) → `Properties.Volumes` L221 in `bad_resources_circular_dependency`
  > Property 'Volumes' is create-only; updating it will cause resource replacement
- **I9001** `MyIAMUser` (AWS::IAM::User) → `Properties.UserName` L25 in `bad_resources_deletionpolicy`
  > Property 'UserName' is create-only; updating it will cause resource replacement
- **I9001** `my.Instance` (AWS::EC2::Instance) → `Properties.ImageId` L4 in `bad_resources_name`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `my_Instance` (AWS::EC2::Instance) → `Properties.ImageId` L8 in `bad_resources_name`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `RootRole` (AWS::IAM::Role) → `Properties.Path` L6 in `bad_resources_primary_identifiers`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `RootRole` (AWS::IAM::Role) → `Properties.RoleName` L6 in `bad_resources_primary_identifiers`
  > Property 'RoleName' is create-only; updating it will cause resource replacement
- **I9001** `RootRole2` (AWS::IAM::Role) → `Properties.Path` L28 in `bad_resources_primary_identifiers`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `RootRole2` (AWS::IAM::Role) → `Properties.RoleName` L28 in `bad_resources_primary_identifiers`
  > Property 'RoleName' is create-only; updating it will cause resource replacement
- **I9001** `RootRole3` (AWS::IAM::Role) → `Properties.Path` L50 in `bad_resources_primary_identifiers`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `RootRole3` (AWS::IAM::Role) → `Properties.RoleName` L50 in `bad_resources_primary_identifiers`
  > Property 'RoleName' is create-only; updating it will cause resource replacement
- **I9001** `RootRole4` (AWS::IAM::Role) → `Properties.Path` L73 in `bad_resources_primary_identifiers`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `RootRole4` (AWS::IAM::Role) → `Properties.RoleName` L73 in `bad_resources_primary_identifiers`
  > Property 'RoleName' is create-only; updating it will cause resource replacement
- **I9001** `RootRole5` (AWS::IAM::Role) → `Properties.Path` L97 in `bad_resources_primary_identifiers`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `RootRole5` (AWS::IAM::Role) → `Properties.RoleName` L97 in `bad_resources_primary_identifiers`
  > Property 'RoleName' is create-only; updating it will cause resource replacement
- **I9001** `RootRole6` (AWS::IAM::Role) → `Properties.Path` L119 in `bad_resources_primary_identifiers`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `RootRole6` (AWS::IAM::Role) → `Properties.RoleName` L119 in `bad_resources_primary_identifiers`
  > Property 'RoleName' is create-only; updating it will cause resource replacement
- **I9001** `Bucket2` (AWS::S3::Bucket) → `Properties.BucketName` L148 in `bad_resources_primary_identifiers`
  > Property 'BucketName' is create-only; updating it will cause resource replacement
- **I9001** `Project1` (AWS::CodeBuild::Project) → `Properties.Name` L166 in `bad_resources_primary_identifiers`
  > Property 'Name' is create-only; updating it will cause resource replacement
- **I9001** `Project2` (AWS::CodeBuild::Project) → `Properties.Name` L186 in `bad_resources_primary_identifiers`
  > Property 'Name' is create-only; updating it will cause resource replacement
- **I9001** `MyIAMUser` (AWS::IAM::User) → `Properties.UserName` L25 in `bad_resources_updatereplacepolicy`
  > Property 'UserName' is create-only; updating it will cause resource replacement
- **I9001** `MyHostedZone` (AWS::Route53::HostedZone) → `Properties.Name` L17 in `bad_route53`
  > Property 'Name' is create-only; updating it will cause resource replacement
- **I9001** `MyTXTRecordSet` (AWS::Route53::RecordSet) → `Properties.HostedZoneId` L24 in `bad_route53`
  > Property 'HostedZoneId' is create-only; updating it will cause resource replacement
- **I9001** `MyTXTRecordSet` (AWS::Route53::RecordSet) → `Properties.Name` L24 in `bad_route53`
  > Property 'Name' is create-only; updating it will cause resource replacement
- **I9001** `MyARecordSet` (AWS::Route53::RecordSet) → `Properties.HostedZoneId` L37 in `bad_route53`
  > Property 'HostedZoneId' is create-only; updating it will cause resource replacement
- **I9001** `MyARecordSet` (AWS::Route53::RecordSet) → `Properties.Name` L37 in `bad_route53`
  > Property 'Name' is create-only; updating it will cause resource replacement
- **I9001** `MyAAAARecordSet` (AWS::Route53::RecordSet) → `Properties.HostedZoneId` L47 in `bad_route53`
  > Property 'HostedZoneId' is create-only; updating it will cause resource replacement
- **I9001** `MyAAAARecordSet` (AWS::Route53::RecordSet) → `Properties.Name` L47 in `bad_route53`
  > Property 'Name' is create-only; updating it will cause resource replacement
- **I9001** `MyCAARecordSet` (AWS::Route53::RecordSet) → `Properties.HostedZoneId` L61 in `bad_route53`
  > Property 'HostedZoneId' is create-only; updating it will cause resource replacement
- **I9001** `MyCAARecordSet` (AWS::Route53::RecordSet) → `Properties.Name` L61 in `bad_route53`
  > Property 'Name' is create-only; updating it will cause resource replacement
- **I9001** `MyCNAMERecordSet` (AWS::Route53::RecordSet) → `Properties.HostedZoneId` L72 in `bad_route53`
  > Property 'HostedZoneId' is create-only; updating it will cause resource replacement
- **I9001** `MyCNAMERecordSet` (AWS::Route53::RecordSet) → `Properties.Name` L72 in `bad_route53`
  > Property 'Name' is create-only; updating it will cause resource replacement
- **I9001** `MyCNAMERecordSetConditions` (AWS::Route53::RecordSet) → `Properties.HostedZoneId` L83 in `bad_route53`
  > Property 'HostedZoneId' is create-only; updating it will cause resource replacement
- **I9001** `MyCNAMERecordSetConditions` (AWS::Route53::RecordSet) → `Properties.Name` L83 in `bad_route53`
  > Property 'Name' is create-only; updating it will cause resource replacement
- **I9001** `MyMXRecordSet` (AWS::Route53::RecordSet) → `Properties.HostedZoneId` L97 in `bad_route53`
  > Property 'HostedZoneId' is create-only; updating it will cause resource replacement
- **I9001** `MyMXRecordSet` (AWS::Route53::RecordSet) → `Properties.Name` L97 in `bad_route53`
  > Property 'Name' is create-only; updating it will cause resource replacement
- **I9001** `MyAliasRecordSet` (AWS::Route53::RecordSet) → `Properties.HostedZoneId` L107 in `bad_route53`
  > Property 'HostedZoneId' is create-only; updating it will cause resource replacement
- **I9001** `MyAliasRecordSet` (AWS::Route53::RecordSet) → `Properties.Name` L107 in `bad_route53`
  > Property 'Name' is create-only; updating it will cause resource replacement
- **I9001** `MyRecordSetGroup` (AWS::Route53::RecordSetGroup) → `Properties.HostedZoneId` L119 in `bad_route53`
  > Property 'HostedZoneId' is create-only; updating it will cause resource replacement
- **I9001** `PoorlyConfiguredRoute53` (AWS::Route53::RecordSetGroup) → `Properties.HostedZoneId` L172 in `bad_route53`
  > Property 'HostedZoneId' is create-only; updating it will cause resource replacement
- **I9001** `FunctionALogGroup` (AWS::Logs::LogGroup) → `Properties.LogGroupName` L23 in `bad_some_logs_stream_lambda`
  > Property 'LogGroupName' is create-only; updating it will cause resource replacement
- **I9001** `FunctionBLogGroup` (AWS::Logs::LogGroup) → `Properties.LogGroupName` L35 in `bad_some_logs_stream_lambda`
  > Property 'LogGroupName' is create-only; updating it will cause resource replacement
- **I9001** `FunctionCLogGroup` (AWS::Logs::LogGroup) → `Properties.LogGroupName` L46 in `bad_some_logs_stream_lambda`
  > Property 'LogGroupName' is create-only; updating it will cause resource replacement
- **I9001** `LogSubscriptionFunctionLogGroup` (AWS::Logs::LogGroup) → `Properties.LogGroupName` L79 in `bad_some_logs_stream_lambda`
  > Property 'LogGroupName' is create-only; updating it will cause resource replacement
- **I9001** `myInstance` (AWS::EC2::Instance) → `Properties.ImageId` L26 in `good_conditions`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `mySubnet` (AWS::EC2::Subnet) → `Properties.CidrBlock` L22 in `good_core_conditions`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `mySubnet` (AWS::EC2::Subnet) → `Properties.VpcId` L22 in `good_core_conditions`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `myInstance1` (AWS::EC2::Instance) → `Properties.ImageId` L28 in `good_core_conditions`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `myInstance1` (AWS::EC2::Instance) → `Properties.SubnetId` L28 in `good_core_conditions`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `myInstance2` (AWS::EC2::Instance) → `Properties.ImageId` L33 in `good_core_conditions`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `myInstance4` (AWS::EC2::Instance) → `Properties.ImageId` L65 in `good_core_conditions`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `LambdaExecutionRole` (AWS::IAM::Role) → `Properties.Path` L77 in `good_core_conditions`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `InstanceProfile` (AWS::IAM::InstanceProfile) → `Properties.Path` L93 in `good_core_conditions`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `myTable` (AWS::DynamoDB::Table) → `Properties.TableName` L7 in `good_core_config_default_e3012`
  > Property 'TableName' is create-only; updating it will cause resource replacement
- **I9001** `LambdaExecutionRole` (AWS::IAM::Role) → `Properties.Path` L9 in `good_custom_is-defined`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `LambdaExecutionRole` (AWS::IAM::Role) → `Properties.Path` L6 in `good_custom_is-not-defined`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `LambdaExecutionRole` (AWS::IAM::Role) → `Properties.Path` L7 in `good_custom_numeric-inequalities-large`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `LambdaExecutionRole` (AWS::IAM::Role) → `Properties.Path` L7 in `good_custom_numeric-inequalities-small`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `myInstance1` (AWS::EC2::Instance) → `Properties.ImageId` L12 in `good_functions_findinmap`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `myInstance2` (AWS::EC2::Instance) → `Properties.ImageId` L16 in `good_functions_findinmap`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `myInstance3` (AWS::EC2::Instance) → `Properties.ImageId` L24 in `good_functions_findinmap`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `Cluster0` (AWS::ECS::Cluster) → `Properties.ClusterName` L12 in `good_functions_findinmap_default_value`
  > Property 'ClusterName' is create-only; updating it will cause resource replacement
- **I9001** `Cluster1` (AWS::ECS::Cluster) → `Properties.ClusterName` L20 in `good_functions_findinmap_default_value`
  > Property 'ClusterName' is create-only; updating it will cause resource replacement
- **I9001** `Cluster2` (AWS::ECS::Cluster) → `Properties.ClusterName` L28 in `good_functions_findinmap_default_value`
  > Property 'ClusterName' is create-only; updating it will cause resource replacement
- **I9001** `Cluster3` (AWS::ECS::Cluster) → `Properties.ClusterName` L36 in `good_functions_findinmap_default_value`
  > Property 'ClusterName' is create-only; updating it will cause resource replacement
- **I9001** `Mesh0` (AWS::AppMesh::Mesh) → `Properties.MeshName` L44 in `good_functions_findinmap_default_value`
  > Property 'MeshName' is create-only; updating it will cause resource replacement
- **I9001** `Mesh1` (AWS::AppMesh::Mesh) → `Properties.MeshName` L60 in `good_functions_findinmap_default_value`
  > Property 'MeshName' is create-only; updating it will cause resource replacement
- **I9001** `Mesh2` (AWS::AppMesh::Mesh) → `Properties.MeshName` L71 in `good_functions_findinmap_default_value`
  > Property 'MeshName' is create-only; updating it will cause resource replacement
- **I9001** `Mesh3` (AWS::AppMesh::Mesh) → `Properties.MeshName` L82 in `good_functions_findinmap_default_value`
  > Property 'MeshName' is create-only; updating it will cause resource replacement
- **I9001** `Mesh4` (AWS::AppMesh::Mesh) → `Properties.MeshName` L94 in `good_functions_findinmap_default_value`
  > Property 'MeshName' is create-only; updating it will cause resource replacement
- **I9001** `Mesh` (AWS::AppMesh::Mesh) → `Properties.MeshName` L21 in `good_functions_findinmap_enhanced`
  > Property 'MeshName' is create-only; updating it will cause resource replacement
- **I9001** `Mesh2` (AWS::AppMesh::Mesh) → `Properties.MeshName` L34 in `good_functions_findinmap_enhanced`
  > Property 'MeshName' is create-only; updating it will cause resource replacement
- **I9001** `Cluster` (AWS::ECS::Cluster) → `Properties.ClusterName` L47 in `good_functions_findinmap_enhanced`
  > Property 'ClusterName' is create-only; updating it will cause resource replacement
- **I9001** `Queue` (AWS::SQS::Queue) → `Properties.QueueName` L60 in `good_functions_findinmap_enhanced`
  > Property 'QueueName' is create-only; updating it will cause resource replacement
- **I9001** `Cluster2` (AWS::ECS::Cluster) → `Properties.ClusterName` L79 in `good_functions_findinmap_enhanced`
  > Property 'ClusterName' is create-only; updating it will cause resource replacement
- **I9001** `Cluster3` (AWS::ECS::Cluster) → `Properties.ClusterName` L101 in `good_functions_findinmap_enhanced`
  > Property 'ClusterName' is create-only; updating it will cause resource replacement
- **I9001** `LambdaExecutionRole` (AWS::IAM::Role) → `Properties.Path` L12 in `good_functions_relationship_conditions`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `InstanceProfile` (AWS::IAM::InstanceProfile) → `Properties.Path` L28 in `good_functions_relationship_conditions`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `ConfigEnvironment` (AWS::AppConfig::Environment) → `Properties.ApplicationId` L28 in `good_functions_relationship_conditions_sam`
  > Property 'ApplicationId' is create-only; updating it will cause resource replacement
- **I9001** `myInstance` (AWS::EC2::Instance) → `Properties.ImageId` L20 in `good_functions_sub`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `myAlb` (AWS::ElasticLoadBalancingV2::LoadBalancer) → `Properties.Name` L50 in `good_functions_sub`
  > Property 'Name' is create-only; updating it will cause resource replacement
- **I9001** `LaunchConfiguration` (AWS::AutoScaling::LaunchConfiguration) → `Properties.ImageId` L55 in `good_functions_sub`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `LaunchConfiguration` (AWS::AutoScaling::LaunchConfiguration) → `Properties.InstanceType` L55 in `good_functions_sub`
  > Property 'InstanceType' is create-only; updating it will cause resource replacement
- **I9001** `LaunchConfiguration` (AWS::AutoScaling::LaunchConfiguration) → `Properties.UserData` L55 in `good_functions_sub`
  > Property 'UserData' is create-only; updating it will cause resource replacement
- **I9001** `myVPc2` (AWS::EC2::VPC) → `Properties.CidrBlock` L70 in `good_functions_sub`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `GreetingRequest` (AWS::ApiGateway::Method) → `Properties.HttpMethod` L87 in `good_functions_sub_needed`
  > Property 'HttpMethod' is create-only; updating it will cause resource replacement
- **I9001** `GreetingRequest` (AWS::ApiGateway::Method) → `Properties.ResourceId` L87 in `good_functions_sub_needed`
  > Property 'ResourceId' is create-only; updating it will cause resource replacement
- **I9001** `GreetingRequest` (AWS::ApiGateway::Method) → `Properties.RestApiId` L87 in `good_functions_sub_needed`
  > Property 'RestApiId' is create-only; updating it will cause resource replacement
- **I9001** `IOTPolicies` (AWS::IoT::Policy) → `Properties.PolicyName` L119 in `good_functions_sub_needed`
  > Property 'PolicyName' is create-only; updating it will cause resource replacement
- **I9001** `TestRole` (AWS::IAM::Role) → `Properties.RoleName` L8 in `good_functions_sub_needed_custom_excludes`
  > Property 'RoleName' is create-only; updating it will cause resource replacement
- **I9001** `RootRole` (AWS::IAM::Role) → `Properties.Path` L34 in `good_generic`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `RootInstanceProfile` (AWS::IAM::InstanceProfile) → `Properties.Path` L67 in `good_generic`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `MyEC2Instance` (AWS::EC2::Instance) → `Properties.ImageId` L73 in `good_generic`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `MyEC2Instance` (AWS::EC2::Instance) → `Properties.KeyName` L73 in `good_generic`
  > Property 'KeyName' is create-only; updating it will cause resource replacement
- **I9001** `MyEC2Instance` (AWS::EC2::Instance) → `Properties.NetworkInterfaces` L73 in `good_generic`
  > Property 'NetworkInterfaces' is create-only; updating it will cause resource replacement
- **I9001** `MyEC2Instance1` (AWS::EC2::Instance) → `Properties.ImageId` L93 in `good_generic`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `MyEC2Instance1` (AWS::EC2::Instance) → `Properties.KeyName` L93 in `good_generic`
  > Property 'KeyName' is create-only; updating it will cause resource replacement
- **I9001** `MyEC2Instance1` (AWS::EC2::Instance) → `Properties.NetworkInterfaces` L93 in `good_generic`
  > Property 'NetworkInterfaces' is create-only; updating it will cause resource replacement
- **I9001** `mySubnet` (AWS::EC2::Subnet) → `Properties.CidrBlock` L19 in `good_mappings_used`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `mySubnet` (AWS::EC2::Subnet) → `Properties.VpcId` L19 in `good_mappings_used`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rParameterGroup` (AWS::RDS::DBParameterGroup) → `Properties.Description` L57 in `good_no_value`
  > Property 'Description' is create-only; updating it will cause resource replacement
- **I9001** `rParameterGroup` (AWS::RDS::DBParameterGroup) → `Properties.Family` L57 in `good_no_value`
  > Property 'Family' is create-only; updating it will cause resource replacement
- **I9001** `rDBServerInstance` (AWS::RDS::DBInstance) → `Properties.DBSubnetGroupName` L124 in `good_no_value`
  > Property 'DBSubnetGroupName' is create-only; updating it will cause resource replacement
- **I9001** `rDBServerInstance` (AWS::RDS::DBInstance) → `Properties.MasterUsername` L124 in `good_no_value`
  > Property 'MasterUsername' is create-only; updating it will cause resource replacement
- **I9001** `rDBServerInstance` (AWS::RDS::DBInstance) → `Properties.StorageEncrypted` L124 in `good_no_value`
  > Property 'StorageEncrypted' is create-only; updating it will cause resource replacement
- **I9001** `myS3Bucket` (AWS::S3::Bucket) → `Properties.BucketName` L7 in `good_override_complete`
  > Property 'BucketName' is create-only; updating it will cause resource replacement
- **I9001** `untaggedInstance` (AWS::EC2::Instance) → `Properties.ImageId` L11 in `good_override_complete`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `VPC` (AWS::EC2::VPC) → `Properties.CidrBlock` L15 in `good_override_complete`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `myS3Bucket` (AWS::S3::Bucket) → `Properties.BucketName` L7 in `good_override_required`
  > Property 'BucketName' is create-only; updating it will cause resource replacement
- **I9001** `LaunchConfiguration` (AWS::AutoScaling::LaunchConfiguration) → `Properties.ImageId` L18 in `good_parameters_not_used_parameters`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `LaunchConfiguration` (AWS::AutoScaling::LaunchConfiguration) → `Properties.InstanceType` L18 in `good_parameters_not_used_parameters`
  > Property 'InstanceType' is create-only; updating it will cause resource replacement
- **I9001** `LaunchConfiguration` (AWS::AutoScaling::LaunchConfiguration) → `Properties.UserData` L18 in `good_parameters_not_used_parameters`
  > Property 'UserData' is create-only; updating it will cause resource replacement
- **I9001** `LaunchConfiguration` (AWS::AutoScaling::LaunchConfiguration) → `Properties.ImageId` L21 in `good_parameters_used_transforms`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `LaunchConfiguration` (AWS::AutoScaling::LaunchConfiguration) → `Properties.InstanceType` L21 in `good_parameters_used_transforms`
  > Property 'InstanceType' is create-only; updating it will cause resource replacement
- **I9001** `LaunchConfiguration` (AWS::AutoScaling::LaunchConfiguration) → `Properties.UserData` L21 in `good_parameters_used_transforms`
  > Property 'UserData' is create-only; updating it will cause resource replacement
- **I9001** `myVpc1` (AWS::EC2::VPC) → `Properties.CidrBlock` L30 in `good_properties_ec2_vpc`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `myVpc2` (AWS::EC2::VPC) → `Properties.CidrBlock` L35 in `good_properties_ec2_vpc`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `myVpc3` (AWS::EC2::VPC) → `Properties.CidrBlock` L40 in `good_properties_ec2_vpc`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `myVpc4` (AWS::EC2::VPC) → `Properties.CidrBlock` L45 in `good_properties_ec2_vpc`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `myVpc5` (AWS::EC2::VPC) → `Properties.CidrBlock` L50 in `good_properties_ec2_vpc`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `mySubnet21` (AWS::EC2::Subnet) → `Properties.CidrBlock` L55 in `good_properties_ec2_vpc`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `mySubnet21` (AWS::EC2::Subnet) → `Properties.VpcId` L55 in `good_properties_ec2_vpc`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `mySubnet22` (AWS::EC2::Subnet) → `Properties.CidrBlock` L63 in `good_properties_ec2_vpc`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `mySubnet22` (AWS::EC2::Subnet) → `Properties.VpcId` L63 in `good_properties_ec2_vpc`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `AppSubnetPublicRouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L28 in `good_properties_rt_association`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `AppSubnetPublicRouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L28 in `good_properties_rt_association`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `AppSubnetPrivateRouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L37 in `good_properties_rt_association`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `AppSubnetPrivateRouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L37 in `good_properties_rt_association`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `ProxySubnetRouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L46 in `good_properties_rt_association`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `ProxySubnetRouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L46 in `good_properties_rt_association`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `PublicSubnetRouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L54 in `good_properties_rt_association`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `PublicSubnetRouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L54 in `good_properties_rt_association`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `CustomResource` (AWS::CloudFormation::CustomResource) → `Properties.ServiceToken` L62 in `good_properties_rt_association`
  > Property 'ServiceToken' is create-only; updating it will cause resource replacement
- **I9001** `CustomSubnetRouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L67 in `good_properties_rt_association`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `CustomSubnetRouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L67 in `good_properties_rt_association`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `TestPipeline` (AWS::CodePipeline::Pipeline) → `Properties.Name` L6 in `good_resources_codepipeline`
  > Property 'Name' is create-only; updating it will cause resource replacement
- **I9001** `myInstance` (AWS::EC2::Instance) → `Properties.ImageId` L4 in `good_resources_name`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `RootRole` (AWS::IAM::Role) → `Properties.Path` L6 in `good_resources_primary_identifiers`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `RootRole` (AWS::IAM::Role) → `Properties.RoleName` L6 in `good_resources_primary_identifiers`
  > Property 'RoleName' is create-only; updating it will cause resource replacement
- **I9001** `RootRole3` (AWS::IAM::Role) → `Properties.Path` L28 in `good_resources_primary_identifiers`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `RootRole3` (AWS::IAM::Role) → `Properties.RoleName` L28 in `good_resources_primary_identifiers`
  > Property 'RoleName' is create-only; updating it will cause resource replacement
- **I9001** `RootRole4` (AWS::IAM::Role) → `Properties.Path` L51 in `good_resources_primary_identifiers`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `RootRole4` (AWS::IAM::Role) → `Properties.RoleName` L51 in `good_resources_primary_identifiers`
  > Property 'RoleName' is create-only; updating it will cause resource replacement
- **I9001** `FunctionPermission1` (AWS::Lambda::Permission) → `Properties.Action` L89 in `good_resources_primary_identifiers`
  > Property 'Action' is create-only; updating it will cause resource replacement
- **I9001** `FunctionPermission1` (AWS::Lambda::Permission) → `Properties.FunctionName` L89 in `good_resources_primary_identifiers`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `FunctionPermission1` (AWS::Lambda::Permission) → `Properties.Principal` L89 in `good_resources_primary_identifiers`
  > Property 'Principal' is create-only; updating it will cause resource replacement
- **I9001** `FunctionPermission2` (AWS::Lambda::Permission) → `Properties.Action` L95 in `good_resources_primary_identifiers`
  > Property 'Action' is create-only; updating it will cause resource replacement
- **I9001** `FunctionPermission2` (AWS::Lambda::Permission) → `Properties.FunctionName` L95 in `good_resources_primary_identifiers`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `FunctionPermission2` (AWS::Lambda::Permission) → `Properties.Principal` L95 in `good_resources_primary_identifiers`
  > Property 'Principal' is create-only; updating it will cause resource replacement
- **I9001** `FunctionALogGroup` (AWS::Logs::LogGroup) → `Properties.LogGroupName` L23 in `good_some_logs_stream_lambda`
  > Property 'LogGroupName' is create-only; updating it will cause resource replacement
- **I9001** `FunctionBLogGroup` (AWS::Logs::LogGroup) → `Properties.LogGroupName` L35 in `good_some_logs_stream_lambda`
  > Property 'LogGroupName' is create-only; updating it will cause resource replacement
- **I9001** `FunctionCLogGroup` (AWS::Logs::LogGroup) → `Properties.LogGroupName` L46 in `good_some_logs_stream_lambda`
  > Property 'LogGroupName' is create-only; updating it will cause resource replacement
- **I9001** `LogSubscriptionFunctionLogGroup` (AWS::Logs::LogGroup) → `Properties.LogGroupName` L74 in `good_some_logs_stream_lambda`
  > Property 'LogGroupName' is create-only; updating it will cause resource replacement
- **I9001** `SecurityGroups` (AWS::EC2::SecurityGroup) → `Properties.GroupDescription` L85 in `good_transform_language_extension`
  > Property 'GroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `SecurityGroups` (AWS::EC2::SecurityGroup) → `Properties.VpcId` L85 in `good_transform_language_extension`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `MySubnet` (AWS::EC2::Subnet) → `Properties.AvailabilityZoneId` L91 in `good_transform_language_extension`
  > Property 'AvailabilityZoneId' is create-only; updating it will cause resource replacement
- **I9001** `MySubnet` (AWS::EC2::Subnet) → `Properties.CidrBlock` L91 in `good_transform_language_extension`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `MySubnet` (AWS::EC2::Subnet) → `Properties.VpcId` L91 in `good_transform_language_extension`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `Subnet` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L4 in `integration_availability-zones`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `Subnet` (AWS::EC2::Subnet) → `Properties.AvailabilityZoneId` L4 in `integration_availability-zones`
  > Property 'AvailabilityZoneId' is create-only; updating it will cause resource replacement
- **I9001** `Subnet` (AWS::EC2::Subnet) → `Properties.CidrBlock` L4 in `integration_availability-zones`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `Subnet` (AWS::EC2::Subnet) → `Properties.VpcId` L4 in `integration_availability-zones`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `Table1` (AWS::DynamoDB::Table) → `Properties.TableName` L8 in `integration_aws-dynamodb-table`
  > Property 'TableName' is create-only; updating it will cause resource replacement
- **I9001** `Table2` (AWS::DynamoDB::Table) → `Properties.TableName` L27 in `integration_aws-dynamodb-table`
  > Property 'TableName' is create-only; updating it will cause resource replacement
- **I9001** `Table3` (AWS::DynamoDB::Table) → `Properties.TableName` L46 in `integration_aws-dynamodb-table`
  > Property 'TableName' is create-only; updating it will cause resource replacement
- **I9001** `NetworkInterface` (AWS::EC2::NetworkInterface) → `Properties.SubnetId` L3 in `integration_aws-ec2-instance`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `Instance` (AWS::EC2::Instance) → `Properties.ImageId` L9 in `integration_aws-ec2-instance`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `Instance` (AWS::EC2::Instance) → `Properties.NetworkInterfaces` L9 in `integration_aws-ec2-instance`
  > Property 'NetworkInterfaces' is create-only; updating it will cause resource replacement
- **I9001** `LaunchTemplate` (AWS::EC2::LaunchTemplate) → `Properties.LaunchTemplateName` L3 in `integration_aws-ec2-launchtemplate`
  > Property 'LaunchTemplateName' is create-only; updating it will cause resource replacement
- **I9001** `NetworkInterface` (AWS::EC2::NetworkInterface) → `Properties.SubnetId` L8 in `integration_aws-ec2-networkinterface`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `Subnet1` (AWS::EC2::Subnet) → `Properties.CidrBlock` L6 in `integration_aws-ec2-subnet`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `Subnet1` (AWS::EC2::Subnet) → `Properties.Ipv4NetmaskLength` L6 in `integration_aws-ec2-subnet`
  > Property 'Ipv4NetmaskLength' is create-only; updating it will cause resource replacement
- **I9001** `Subnet1` (AWS::EC2::Subnet) → `Properties.VpcId` L6 in `integration_aws-ec2-subnet`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `Subnet2` (AWS::EC2::Subnet) → `Properties.VpcId` L12 in `integration_aws-ec2-subnet`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `Subnet3` (AWS::EC2::Subnet) → `Properties.Ipv4IpamPoolId` L16 in `integration_aws-ec2-subnet`
  > Property 'Ipv4IpamPoolId' is create-only; updating it will cause resource replacement
- **I9001** `Subnet3` (AWS::EC2::Subnet) → `Properties.VpcId` L16 in `integration_aws-ec2-subnet`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `Subnet4` (AWS::EC2::Subnet) → `Properties.CidrBlock` L21 in `integration_aws-ec2-subnet`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `Subnet4` (AWS::EC2::Subnet) → `Properties.VpcId` L21 in `integration_aws-ec2-subnet`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `Subnet5` (AWS::EC2::Subnet) → `Properties.CidrBlock` L27 in `integration_aws-ec2-subnet`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `Subnet5` (AWS::EC2::Subnet) → `Properties.Ipv4IpamPoolId` L27 in `integration_aws-ec2-subnet`
  > Property 'Ipv4IpamPoolId' is create-only; updating it will cause resource replacement
- **I9001** `Subnet5` (AWS::EC2::Subnet) → `Properties.Ipv4NetmaskLength` L27 in `integration_aws-ec2-subnet`
  > Property 'Ipv4NetmaskLength' is create-only; updating it will cause resource replacement
- **I9001** `Subnet5` (AWS::EC2::Subnet) → `Properties.VpcId` L27 in `integration_aws-ec2-subnet`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `TaskDef` (AWS::ECS::TaskDefinition) → `Properties.ContainerDefinitions` L5 in `integration_cfn-gather`
  > Property 'ContainerDefinitions' is create-only; updating it will cause resource replacement
- **I9001** `TaskDef` (AWS::ECS::TaskDefinition) → `Properties.NetworkMode` L5 in `integration_cfn-gather`
  > Property 'NetworkMode' is create-only; updating it will cause resource replacement
- **I9001** `TaskDef` (AWS::ECS::TaskDefinition) → `Properties.RequiresCompatibilities` L5 in `integration_cfn-gather`
  > Property 'RequiresCompatibilities' is create-only; updating it will cause resource replacement
- **I9001** `AwsvpcTaskDef` (AWS::ECS::TaskDefinition) → `Properties.ContainerDefinitions` L25 in `integration_cfn-gather`
  > Property 'ContainerDefinitions' is create-only; updating it will cause resource replacement
- **I9001** `AwsvpcTaskDef` (AWS::ECS::TaskDefinition) → `Properties.NetworkMode` L25 in `integration_cfn-gather`
  > Property 'NetworkMode' is create-only; updating it will cause resource replacement
- **I9001** `FifoQueue` (AWS::SQS::Queue) → `Properties.FifoQueue` L38 in `integration_cfn-gather`
  > Property 'FifoQueue' is create-only; updating it will cause resource replacement
- **I9001** `FifoQueue` (AWS::SQS::Queue) → `Properties.QueueName` L38 in `integration_cfn-gather`
  > Property 'QueueName' is create-only; updating it will cause resource replacement
- **I9001** `StandardDLQ` (AWS::SQS::Queue) → `Properties.FifoQueue` L46 in `integration_cfn-gather`
  > Property 'FifoQueue' is create-only; updating it will cause resource replacement
- **I9001** `CognitoAuthorizer` (AWS::ApiGateway::Authorizer) → `Properties.RestApiId` L55 in `integration_cfn-gather`
  > Property 'RestApiId' is create-only; updating it will cause resource replacement
- **I9001** `MethodBadAuth` (AWS::ApiGateway::Method) → `Properties.HttpMethod` L63 in `integration_cfn-gather`
  > Property 'HttpMethod' is create-only; updating it will cause resource replacement
- **I9001** `MethodBadAuth` (AWS::ApiGateway::Method) → `Properties.ResourceId` L63 in `integration_cfn-gather`
  > Property 'ResourceId' is create-only; updating it will cause resource replacement
- **I9001** `MethodBadAuth` (AWS::ApiGateway::Method) → `Properties.RestApiId` L63 in `integration_cfn-gather`
  > Property 'RestApiId' is create-only; updating it will cause resource replacement
- **I9001** `Deployment` (AWS::ApiGateway::Deployment) → `Properties.RestApiId` L76 in `integration_cfn-gather`
  > Property 'RestApiId' is create-only; updating it will cause resource replacement
- **I9001** `StageBadApi` (AWS::ApiGateway::Stage) → `Properties.RestApiId` L80 in `integration_cfn-gather`
  > Property 'RestApiId' is create-only; updating it will cause resource replacement
- **I9001** `StageBadApi` (AWS::ApiGateway::Stage) → `Properties.StageName` L80 in `integration_cfn-gather`
  > Property 'StageName' is create-only; updating it will cause resource replacement
- **I9001** `SqsFifoQueue` (AWS::SQS::Queue) → `Properties.FifoQueue` L87 in `integration_cfn-gather`
  > Property 'FifoQueue' is create-only; updating it will cause resource replacement
- **I9001** `SqsFifoQueue` (AWS::SQS::Queue) → `Properties.QueueName` L87 in `integration_cfn-gather`
  > Property 'QueueName' is create-only; updating it will cause resource replacement
- **I9001** `FifoProcessor` (AWS::Lambda::Function) → `Properties.FunctionName` L92 in `integration_cfn-gather`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `FifoMapping` (AWS::Lambda::EventSourceMapping) → `Properties.EventSourceArn` L103 in `integration_cfn-gather`
  > Property 'EventSourceArn' is create-only; updating it will cause resource replacement
- **I9001** `BadEngineInstance` (AWS::RDS::DBInstance) → `Properties.DBClusterIdentifier` L116 in `integration_cfn-gather`
  > Property 'DBClusterIdentifier' is create-only; updating it will cause resource replacement
- **I9001** `CustomResource` (AWS::CloudFormation::CustomResource) → `Properties.ServiceToken` L9 in `integration_custom-resources`
  > Property 'ServiceToken' is create-only; updating it will cause resource replacement
- **I9001** `Vpc` (AWS::EC2::VPC) → `Properties.CidrBlock` L22 in `integration_deployment-file-template`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `Subnet1` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L26 in `integration_deployment-file-template`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `Subnet1` (AWS::EC2::Subnet) → `Properties.CidrBlock` L26 in `integration_deployment-file-template`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `Subnet1` (AWS::EC2::Subnet) → `Properties.VpcId` L26 in `integration_deployment-file-template`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `MyInstance` (AWS::EC2::Instance) → `Properties.ImageId` L32 in `integration_deployment-file-template`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `MyInstance` (AWS::EC2::Instance) → `Properties.SubnetId` L32 in `integration_deployment-file-template`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `SESEventSourceMapping` (AWS::Lambda::EventSourceMapping) → `Properties.EventSourceArn` L5 in `integration_dynamic-references`
  > Property 'EventSourceArn' is create-only; updating it will cause resource replacement
- **I9001** `SESEventSourceMappingBadDynamicReference` (AWS::Lambda::EventSourceMapping) → `Properties.EventSourceArn` L12 in `integration_dynamic-references`
  > Property 'EventSourceArn' is create-only; updating it will cause resource replacement
- **I9001** `Broker` (AWS::AmazonMQ::Broker) → `Properties.BrokerName` L19 in `integration_dynamic-references`
  > Property 'BrokerName' is create-only; updating it will cause resource replacement
- **I9001** `Broker` (AWS::AmazonMQ::Broker) → `Properties.DeploymentMode` L19 in `integration_dynamic-references`
  > Property 'DeploymentMode' is create-only; updating it will cause resource replacement
- **I9001** `Broker` (AWS::AmazonMQ::Broker) → `Properties.EngineType` L19 in `integration_dynamic-references`
  > Property 'EngineType' is create-only; updating it will cause resource replacement
- **I9001** `Broker` (AWS::AmazonMQ::Broker) → `Properties.PubliclyAccessible` L19 in `integration_dynamic-references`
  > Property 'PubliclyAccessible' is create-only; updating it will cause resource replacement
- **I9001** `SESEventSourceMappingSpaces` (AWS::Lambda::EventSourceMapping) → `Properties.EventSourceArn` L33 in `integration_dynamic-references`
  > Property 'EventSourceArn' is create-only; updating it will cause resource replacement
- **I9001** `Vpc` (AWS::EC2::VPC) → `Properties.CidrBlock` L9 in `integration_formats`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `Subnet` (AWS::EC2::Subnet) → `Properties.CidrBlock` L14 in `integration_formats`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `Subnet` (AWS::EC2::Subnet) → `Properties.VpcId` L14 in `integration_formats`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `SecurityGroup` (AWS::EC2::SecurityGroup) → `Properties.GroupDescription` L20 in `integration_formats`
  > Property 'GroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `SecurityGroup` (AWS::EC2::SecurityGroup) → `Properties.VpcId` L20 in `integration_formats`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `Instance1` (AWS::EC2::Instance) → `Properties.ImageId` L26 in `integration_formats`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `Instance1` (AWS::EC2::Instance) → `Properties.NetworkInterfaces` L26 in `integration_formats`
  > Property 'NetworkInterfaces' is create-only; updating it will cause resource replacement
- **I9001** `CapacityReservation` (AWS::EC2::CapacityReservation) → `Properties.AvailabilityZone` L8 in `integration_getatt-types`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `CapacityReservation` (AWS::EC2::CapacityReservation) → `Properties.InstancePlatform` L8 in `integration_getatt-types`
  > Property 'InstancePlatform' is create-only; updating it will cause resource replacement
- **I9001** `CapacityReservation` (AWS::EC2::CapacityReservation) → `Properties.InstanceType` L8 in `integration_getatt-types`
  > Property 'InstanceType' is create-only; updating it will cause resource replacement
- **I9001** `TestTaskDefinitionWithGetAtt` (AWS::ECS::TaskDefinition) → `Properties.ContainerDefinitions` L55 in `integration_getatt-types`
  > Property 'ContainerDefinitions' is create-only; updating it will cause resource replacement
- **I9001** `TestTaskDefinitionWithGetAtt` (AWS::ECS::TaskDefinition) → `Properties.Cpu` L55 in `integration_getatt-types`
  > Property 'Cpu' is create-only; updating it will cause resource replacement
- **I9001** `TestTaskDefinitionWithGetAtt` (AWS::ECS::TaskDefinition) → `Properties.ExecutionRoleArn` L55 in `integration_getatt-types`
  > Property 'ExecutionRoleArn' is create-only; updating it will cause resource replacement
- **I9001** `TestTaskDefinitionWithGetAtt` (AWS::ECS::TaskDefinition) → `Properties.Memory` L55 in `integration_getatt-types`
  > Property 'Memory' is create-only; updating it will cause resource replacement
- **I9001** `TestTaskDefinitionWithGetAtt` (AWS::ECS::TaskDefinition) → `Properties.NetworkMode` L55 in `integration_getatt-types`
  > Property 'NetworkMode' is create-only; updating it will cause resource replacement
- **I9001** `TestTaskDefinitionWithGetAtt` (AWS::ECS::TaskDefinition) → `Properties.RequiresCompatibilities` L55 in `integration_getatt-types`
  > Property 'RequiresCompatibilities' is create-only; updating it will cause resource replacement
- **I9001** `TestTaskDefinitionWithGetAtt` (AWS::ECS::TaskDefinition) → `Properties.TaskRoleArn` L55 in `integration_getatt-types`
  > Property 'TaskRoleArn' is create-only; updating it will cause resource replacement
- **I9001** `Vpc` (AWS::EC2::VPC) → `Properties.CidrBlock` L33 in `integration_ref-types`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `Subnet1` (AWS::EC2::Subnet) → `Properties.CidrBlock` L37 in `integration_ref-types`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `Subnet1` (AWS::EC2::Subnet) → `Properties.VpcId` L37 in `integration_ref-types`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `Subnet2` (AWS::EC2::Subnet) → `Properties.CidrBlock` L42 in `integration_ref-types`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `Subnet2` (AWS::EC2::Subnet) → `Properties.VpcId` L42 in `integration_ref-types`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `SecurityGroup1` (AWS::EC2::SecurityGroup) → `Properties.GroupDescription` L47 in `integration_ref-types`
  > Property 'GroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `SecurityGroup1` (AWS::EC2::SecurityGroup) → `Properties.VpcId` L47 in `integration_ref-types`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `SecurityGroup2` (AWS::EC2::SecurityGroup) → `Properties.GroupDescription` L52 in `integration_ref-types`
  > Property 'GroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `LoadBalancer` (AWS::ElasticLoadBalancingV2::LoadBalancer) → `Properties.Scheme` L56 in `integration_ref-types`
  > Property 'Scheme' is create-only; updating it will cause resource replacement
- **I9001** `LoadBalancer` (AWS::ElasticLoadBalancingV2::LoadBalancer) → `Properties.Type` L56 in `integration_ref-types`
  > Property 'Type' is create-only; updating it will cause resource replacement
- **I9001** `TaskDefinitionWithRefToResource` (AWS::ECS::TaskDefinition) → `Properties.ContainerDefinitions` L70 in `integration_ref-types`
  > Property 'ContainerDefinitions' is create-only; updating it will cause resource replacement
- **I9001** `TaskDefinitionWithRefToResource` (AWS::ECS::TaskDefinition) → `Properties.Cpu` L70 in `integration_ref-types`
  > Property 'Cpu' is create-only; updating it will cause resource replacement
- **I9001** `TaskDefinitionWithRefToResource` (AWS::ECS::TaskDefinition) → `Properties.ExecutionRoleArn` L70 in `integration_ref-types`
  > Property 'ExecutionRoleArn' is create-only; updating it will cause resource replacement
- **I9001** `TaskDefinitionWithRefToResource` (AWS::ECS::TaskDefinition) → `Properties.Memory` L70 in `integration_ref-types`
  > Property 'Memory' is create-only; updating it will cause resource replacement
- **I9001** `TaskDefinitionWithRefToResource` (AWS::ECS::TaskDefinition) → `Properties.NetworkMode` L70 in `integration_ref-types`
  > Property 'NetworkMode' is create-only; updating it will cause resource replacement
- **I9001** `TaskDefinitionWithRefToResource` (AWS::ECS::TaskDefinition) → `Properties.RequiresCompatibilities` L70 in `integration_ref-types`
  > Property 'RequiresCompatibilities' is create-only; updating it will cause resource replacement
- **I9001** `TaskDefinitionWithRefToResource` (AWS::ECS::TaskDefinition) → `Properties.TaskRoleArn` L70 in `integration_ref-types`
  > Property 'TaskRoleArn' is create-only; updating it will cause resource replacement
- **I9001** `TaskDefinitionWithRefToParameter` (AWS::ECS::TaskDefinition) → `Properties.ContainerDefinitions` L91 in `integration_ref-types`
  > Property 'ContainerDefinitions' is create-only; updating it will cause resource replacement
- **I9001** `TaskDefinitionWithRefToParameter` (AWS::ECS::TaskDefinition) → `Properties.Cpu` L91 in `integration_ref-types`
  > Property 'Cpu' is create-only; updating it will cause resource replacement
- **I9001** `TaskDefinitionWithRefToParameter` (AWS::ECS::TaskDefinition) → `Properties.ExecutionRoleArn` L91 in `integration_ref-types`
  > Property 'ExecutionRoleArn' is create-only; updating it will cause resource replacement
- **I9001** `TaskDefinitionWithRefToParameter` (AWS::ECS::TaskDefinition) → `Properties.Memory` L91 in `integration_ref-types`
  > Property 'Memory' is create-only; updating it will cause resource replacement
- **I9001** `TaskDefinitionWithRefToParameter` (AWS::ECS::TaskDefinition) → `Properties.NetworkMode` L91 in `integration_ref-types`
  > Property 'NetworkMode' is create-only; updating it will cause resource replacement
- **I9001** `TaskDefinitionWithRefToParameter` (AWS::ECS::TaskDefinition) → `Properties.RequiresCompatibilities` L91 in `integration_ref-types`
  > Property 'RequiresCompatibilities' is create-only; updating it will cause resource replacement
- **I9001** `TaskDefinitionWithRefToParameter` (AWS::ECS::TaskDefinition) → `Properties.TaskRoleArn` L91 in `integration_ref-types`
  > Property 'TaskRoleArn' is create-only; updating it will cause resource replacement
- **I9001** `LaunchConfiguration` (AWS::AutoScaling::LaunchConfiguration) → `Properties.AssociatePublicIpAddress` L112 in `integration_ref-types`
  > Property 'AssociatePublicIpAddress' is create-only; updating it will cause resource replacement
- **I9001** `LaunchConfiguration` (AWS::AutoScaling::LaunchConfiguration) → `Properties.ImageId` L112 in `integration_ref-types`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `LaunchConfiguration` (AWS::AutoScaling::LaunchConfiguration) → `Properties.InstanceType` L112 in `integration_ref-types`
  > Property 'InstanceType' is create-only; updating it will cause resource replacement
- **I9001** `LaunchConfiguration` (AWS::AutoScaling::LaunchConfiguration) → `Properties.SecurityGroups` L112 in `integration_ref-types`
  > Property 'SecurityGroups' is create-only; updating it will cause resource replacement
- **I9001** `MyInstance` (AWS::EC2::Instance) → `Properties.ImageId` L10 in `integration_resources-cloudformation-init`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `DeniedPolicies` (AWS::IAM::ManagedPolicy) → `Properties.Description` L116 in `issues_sam_w_conditions`
  > Property 'Description' is create-only; updating it will cause resource replacement
- **I9001** `DeniedPolicies` (AWS::IAM::ManagedPolicy) → `Properties.ManagedPolicyName` L116 in `issues_sam_w_conditions`
  > Property 'ManagedPolicyName' is create-only; updating it will cause resource replacement
- **I9001** `DeniedPolicies` (AWS::IAM::ManagedPolicy) → `Properties.Path` L116 in `issues_sam_w_conditions`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `LogMonitoringPolicy` (AWS::IAM::ManagedPolicy) → `Properties.Description` L131 in `issues_sam_w_conditions`
  > Property 'Description' is create-only; updating it will cause resource replacement
- **I9001** `LogMonitoringPolicy` (AWS::IAM::ManagedPolicy) → `Properties.ManagedPolicyName` L131 in `issues_sam_w_conditions`
  > Property 'ManagedPolicyName' is create-only; updating it will cause resource replacement
- **I9001** `LogMonitoringPolicy` (AWS::IAM::ManagedPolicy) → `Properties.Path` L131 in `issues_sam_w_conditions`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `TenantInfoReadPolicy` (AWS::IAM::ManagedPolicy) → `Properties.Description` L152 in `issues_sam_w_conditions`
  > Property 'Description' is create-only; updating it will cause resource replacement
- **I9001** `VmdEventsQueue` (AWS::SQS::Queue) → `Properties.FifoQueue` L204 in `issues_sam_w_conditions`
  > Property 'FifoQueue' is create-only; updating it will cause resource replacement
- **I9001** `VmdEventsQueue` (AWS::SQS::Queue) → `Properties.QueueName` L204 in `issues_sam_w_conditions`
  > Property 'QueueName' is create-only; updating it will cause resource replacement
- **I9001** `VmdEventsDeadLetterQueue` (AWS::SQS::Queue) → `Properties.FifoQueue` L215 in `issues_sam_w_conditions`
  > Property 'FifoQueue' is create-only; updating it will cause resource replacement
- **I9001** `VmdEventsDeadLetterQueue` (AWS::SQS::Queue) → `Properties.QueueName` L215 in `issues_sam_w_conditions`
  > Property 'QueueName' is create-only; updating it will cause resource replacement
- **I9001** `VmdEventsSubscription` (AWS::SNS::Subscription) → `Properties.Endpoint` L262 in `issues_sam_w_conditions`
  > Property 'Endpoint' is create-only; updating it will cause resource replacement
- **I9001** `VmdEventsSubscription` (AWS::SNS::Subscription) → `Properties.Protocol` L262 in `issues_sam_w_conditions`
  > Property 'Protocol' is create-only; updating it will cause resource replacement
- **I9001** `VmdEventsSubscription` (AWS::SNS::Subscription) → `Properties.TopicArn` L262 in `issues_sam_w_conditions`
  > Property 'TopicArn' is create-only; updating it will cause resource replacement
- **I9001** `DmdEventsQueue` (AWS::SQS::Queue) → `Properties.FifoQueue` L329 in `issues_sam_w_conditions`
  > Property 'FifoQueue' is create-only; updating it will cause resource replacement
- **I9001** `DmdEventsQueue` (AWS::SQS::Queue) → `Properties.QueueName` L329 in `issues_sam_w_conditions`
  > Property 'QueueName' is create-only; updating it will cause resource replacement
- **I9001** `DmdEventsDeadLetterQueue` (AWS::SQS::Queue) → `Properties.FifoQueue` L340 in `issues_sam_w_conditions`
  > Property 'FifoQueue' is create-only; updating it will cause resource replacement
- **I9001** `DmdEventsDeadLetterQueue` (AWS::SQS::Queue) → `Properties.QueueName` L340 in `issues_sam_w_conditions`
  > Property 'QueueName' is create-only; updating it will cause resource replacement
- **I9001** `DmdEventsSubscription` (AWS::SNS::Subscription) → `Properties.Endpoint` L387 in `issues_sam_w_conditions`
  > Property 'Endpoint' is create-only; updating it will cause resource replacement
- **I9001** `DmdEventsSubscription` (AWS::SNS::Subscription) → `Properties.Protocol` L387 in `issues_sam_w_conditions`
  > Property 'Protocol' is create-only; updating it will cause resource replacement
- **I9001** `DmdEventsSubscription` (AWS::SNS::Subscription) → `Properties.TopicArn` L387 in `issues_sam_w_conditions`
  > Property 'TopicArn' is create-only; updating it will cause resource replacement
- **I9001** `PollerFunctionIamRole` (AWS::IAM::Role) → `Properties.Path` L16 in `public_lambda-poller`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `PollerEventRuleIamRole` (AWS::IAM::Role) → `Properties.Path` L161 in `public_lambda-poller`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `PollerFunctionEventInvokePermission` (AWS::Lambda::Permission) → `Properties.Action` L195 in `public_lambda-poller`
  > Property 'Action' is create-only; updating it will cause resource replacement
- **I9001** `PollerFunctionEventInvokePermission` (AWS::Lambda::Permission) → `Properties.FunctionName` L195 in `public_lambda-poller`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `PollerFunctionEventInvokePermission` (AWS::Lambda::Permission) → `Properties.Principal` L195 in `public_lambda-poller`
  > Property 'Principal' is create-only; updating it will cause resource replacement
- **I9001** `PollerFunctionEventInvokePermission` (AWS::Lambda::Permission) → `Properties.SourceArn` L195 in `public_lambda-poller`
  > Property 'SourceArn' is create-only; updating it will cause resource replacement
- **I9001** `DBCluster` (AWS::RDS::DBCluster) → `Properties.DatabaseName` L19 in `public_rds-cluster`
  > Property 'DatabaseName' is create-only; updating it will cause resource replacement
- **I9001** `DBCluster` (AWS::RDS::DBCluster) → `Properties.EngineMode` L19 in `public_rds-cluster`
  > Property 'EngineMode' is create-only; updating it will cause resource replacement
- **I9001** `WatchmakerInstance` (AWS::EC2::Instance) → `Properties.ImageId` L566 in `public_watchmaker`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `WatchmakerInstance` (AWS::EC2::Instance) → `Properties.KeyName` L566 in `public_watchmaker`
  > Property 'KeyName' is create-only; updating it will cause resource replacement
- **I9001** `WatchmakerInstance` (AWS::EC2::Instance) → `Properties.NetworkInterfaces` L566 in `public_watchmaker`
  > Property 'NetworkInterfaces' is create-only; updating it will cause resource replacement
- **I9001** `WatchmakerInstanceLogGroup` (AWS::Logs::LogGroup) → `Properties.LogGroupName` L1687 in `public_watchmaker`
  > Property 'LogGroupName' is create-only; updating it will cause resource replacement
- **I9001** `FunctiontForEvaluateCisBenchmarkingPreconditions` (AWS::Lambda::Function) → `Properties.FunctionName` L120 in `quickstart_cis_benchmark`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `ConfigRuleForIamPasswordPolicy` (AWS::Config::ConfigRule) → `Properties.ConfigRuleName` L199 in `quickstart_cis_benchmark`
  > Property 'ConfigRuleName' is create-only; updating it will cause resource replacement
- **I9001** `FunctionForEvaluateRootAccountRule` (AWS::Lambda::Function) → `Properties.FunctionName` L225 in `quickstart_cis_benchmark`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `EvaluateRootAccountFunctionPermission` (AWS::Lambda::Permission) → `Properties.Action` L313 in `quickstart_cis_benchmark`
  > Property 'Action' is create-only; updating it will cause resource replacement
- **I9001** `EvaluateRootAccountFunctionPermission` (AWS::Lambda::Permission) → `Properties.FunctionName` L313 in `quickstart_cis_benchmark`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `EvaluateRootAccountFunctionPermission` (AWS::Lambda::Permission) → `Properties.Principal` L313 in `quickstart_cis_benchmark`
  > Property 'Principal' is create-only; updating it will cause resource replacement
- **I9001** `ConfigRuleForEvaluateRootAccount` (AWS::Config::ConfigRule) → `Properties.ConfigRuleName` L322 in `quickstart_cis_benchmark`
  > Property 'ConfigRuleName' is create-only; updating it will cause resource replacement
- **I9001** `ConfigRuleForRequiredTags` (AWS::Config::ConfigRule) → `Properties.ConfigRuleName` L339 in `quickstart_cis_benchmark`
  > Property 'ConfigRuleName' is create-only; updating it will cause resource replacement
- **I9001** `ConfigRuleForEncryptedVolumes` (AWS::Config::ConfigRule) → `Properties.ConfigRuleName` L370 in `quickstart_cis_benchmark`
  > Property 'ConfigRuleName' is create-only; updating it will cause resource replacement
- **I9001** `ConfigRuleForRestrictedSsh` (AWS::Config::ConfigRule) → `Properties.ConfigRuleName` L386 in `quickstart_cis_benchmark`
  > Property 'ConfigRuleName' is create-only; updating it will cause resource replacement
- **I9001** `ConfigRuleForUnrestrictedPorts` (AWS::Config::ConfigRule) → `Properties.ConfigRuleName` L402 in `quickstart_cis_benchmark`
  > Property 'ConfigRuleName' is create-only; updating it will cause resource replacement
- **I9001** `FunctionForVpcFlowLogRule` (AWS::Lambda::Function) → `Properties.FunctionName` L420 in `quickstart_cis_benchmark`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `ConfigPermissionToCallVpcFlowLogLambda` (AWS::Lambda::Permission) → `Properties.Action` L485 in `quickstart_cis_benchmark`
  > Property 'Action' is create-only; updating it will cause resource replacement
- **I9001** `ConfigPermissionToCallVpcFlowLogLambda` (AWS::Lambda::Permission) → `Properties.FunctionName` L485 in `quickstart_cis_benchmark`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `ConfigPermissionToCallVpcFlowLogLambda` (AWS::Lambda::Permission) → `Properties.Principal` L485 in `quickstart_cis_benchmark`
  > Property 'Principal' is create-only; updating it will cause resource replacement
- **I9001** `FunctionForVpcDefaultSecurityGroupsRule` (AWS::Lambda::Function) → `Properties.FunctionName` L496 in `quickstart_cis_benchmark`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `ConfigPermissionToCallVpcDefaultSecurityGroupsLambda` (AWS::Lambda::Permission) → `Properties.Action` L555 in `quickstart_cis_benchmark`
  > Property 'Action' is create-only; updating it will cause resource replacement
- **I9001** `ConfigPermissionToCallVpcDefaultSecurityGroupsLambda` (AWS::Lambda::Permission) → `Properties.FunctionName` L555 in `quickstart_cis_benchmark`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `ConfigPermissionToCallVpcDefaultSecurityGroupsLambda` (AWS::Lambda::Permission) → `Properties.Principal` L555 in `quickstart_cis_benchmark`
  > Property 'Principal' is create-only; updating it will cause resource replacement
- **I9001** `ConfigRuleForVpcDefaultSecurityGroupss` (AWS::Config::ConfigRule) → `Properties.ConfigRuleName` L563 in `quickstart_cis_benchmark`
  > Property 'ConfigRuleName' is create-only; updating it will cause resource replacement
- **I9001** `ConfigRuleForVpcFlowLogs` (AWS::Config::ConfigRule) → `Properties.ConfigRuleName` L583 in `quickstart_cis_benchmark`
  > Property 'ConfigRuleName' is create-only; updating it will cause resource replacement
- **I9001** `FunctionForRoleForMfaOnUsersRule` (AWS::Lambda::Function) → `Properties.FunctionName` L605 in `quickstart_cis_benchmark`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `ConfigPermissionToCallMfaForUsersLambda` (AWS::Lambda::Permission) → `Properties.Action` L670 in `quickstart_cis_benchmark`
  > Property 'Action' is create-only; updating it will cause resource replacement
- **I9001** `ConfigPermissionToCallMfaForUsersLambda` (AWS::Lambda::Permission) → `Properties.FunctionName` L670 in `quickstart_cis_benchmark`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `ConfigPermissionToCallMfaForUsersLambda` (AWS::Lambda::Permission) → `Properties.Principal` L670 in `quickstart_cis_benchmark`
  > Property 'Principal' is create-only; updating it will cause resource replacement
- **I9001** `ConfigRuleForMfaForUsers` (AWS::Config::ConfigRule) → `Properties.ConfigRuleName` L678 in `quickstart_cis_benchmark`
  > Property 'ConfigRuleName' is create-only; updating it will cause resource replacement
- **I9001** `FunctionForEvaluatePolicyPermissionsRule` (AWS::Lambda::Function) → `Properties.FunctionName` L698 in `quickstart_cis_benchmark`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `ConfigPermissionToCallEvaluatePolicyPermissionsLambda` (AWS::Lambda::Permission) → `Properties.Action` L764 in `quickstart_cis_benchmark`
  > Property 'Action' is create-only; updating it will cause resource replacement
- **I9001** `ConfigPermissionToCallEvaluatePolicyPermissionsLambda` (AWS::Lambda::Permission) → `Properties.FunctionName` L764 in `quickstart_cis_benchmark`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `ConfigPermissionToCallEvaluatePolicyPermissionsLambda` (AWS::Lambda::Permission) → `Properties.Principal` L764 in `quickstart_cis_benchmark`
  > Property 'Principal' is create-only; updating it will cause resource replacement
- **I9001** `ConfigRuleForEvaluatePolicyPermissions` (AWS::Config::ConfigRule) → `Properties.ConfigRuleName` L772 in `quickstart_cis_benchmark`
  > Property 'ConfigRuleName' is create-only; updating it will cause resource replacement
- **I9001** `FunctionForEvaluateUserPolicyAssociationRule` (AWS::Lambda::Function) → `Properties.FunctionName` L794 in `quickstart_cis_benchmark`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `ConfigPermissionToCallEvaluateUserPolicyAssociationLambda` (AWS::Lambda::Permission) → `Properties.Action` L854 in `quickstart_cis_benchmark`
  > Property 'Action' is create-only; updating it will cause resource replacement
- **I9001** `ConfigPermissionToCallEvaluateUserPolicyAssociationLambda` (AWS::Lambda::Permission) → `Properties.FunctionName` L854 in `quickstart_cis_benchmark`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `ConfigPermissionToCallEvaluateUserPolicyAssociationLambda` (AWS::Lambda::Permission) → `Properties.Principal` L854 in `quickstart_cis_benchmark`
  > Property 'Principal' is create-only; updating it will cause resource replacement
- **I9001** `ConfigRuleForEvaluateUserPolicyAssociations` (AWS::Config::ConfigRule) → `Properties.ConfigRuleName` L862 in `quickstart_cis_benchmark`
  > Property 'ConfigRuleName' is create-only; updating it will cause resource replacement
- **I9001** `FunctionForEvaluateCloudTrailRule` (AWS::Lambda::Function) → `Properties.FunctionName` L885 in `quickstart_cis_benchmark`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `ConfigPermissionToCallEvaluateCloudTrailLambda` (AWS::Lambda::Permission) → `Properties.Action` L970 in `quickstart_cis_benchmark`
  > Property 'Action' is create-only; updating it will cause resource replacement
- **I9001** `ConfigPermissionToCallEvaluateCloudTrailLambda` (AWS::Lambda::Permission) → `Properties.FunctionName` L970 in `quickstart_cis_benchmark`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `ConfigPermissionToCallEvaluateCloudTrailLambda` (AWS::Lambda::Permission) → `Properties.Principal` L970 in `quickstart_cis_benchmark`
  > Property 'Principal' is create-only; updating it will cause resource replacement
- **I9001** `ConfigRuleForEvaluateCloudTrail` (AWS::Config::ConfigRule) → `Properties.ConfigRuleName` L978 in `quickstart_cis_benchmark`
  > Property 'ConfigRuleName' is create-only; updating it will cause resource replacement
- **I9001** `FunctionForEvaluateCloudTrailBucketRule` (AWS::Lambda::Function) → `Properties.FunctionName` L998 in `quickstart_cis_benchmark`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `ConfigPermissionToCallEvaluateCloudTrailBucketLambda` (AWS::Lambda::Permission) → `Properties.Action` L1086 in `quickstart_cis_benchmark`
  > Property 'Action' is create-only; updating it will cause resource replacement
- **I9001** `ConfigPermissionToCallEvaluateCloudTrailBucketLambda` (AWS::Lambda::Permission) → `Properties.FunctionName` L1086 in `quickstart_cis_benchmark`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `ConfigPermissionToCallEvaluateCloudTrailBucketLambda` (AWS::Lambda::Permission) → `Properties.Principal` L1086 in `quickstart_cis_benchmark`
  > Property 'Principal' is create-only; updating it will cause resource replacement
- **I9001** `ConfigRuleForEvaluateCloudTrailBucket` (AWS::Config::ConfigRule) → `Properties.ConfigRuleName` L1094 in `quickstart_cis_benchmark`
  > Property 'ConfigRuleName' is create-only; updating it will cause resource replacement
- **I9001** `FunctionForEvaluateCloudTrailLogIntegrityRule` (AWS::Lambda::Function) → `Properties.FunctionName` L1114 in `quickstart_cis_benchmark`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `ConfigPermissionToCallEvaluateCloudTrailLogIntegrityLambda` (AWS::Lambda::Permission) → `Properties.Action` L1182 in `quickstart_cis_benchmark`
  > Property 'Action' is create-only; updating it will cause resource replacement
- **I9001** `ConfigPermissionToCallEvaluateCloudTrailLogIntegrityLambda` (AWS::Lambda::Permission) → `Properties.FunctionName` L1182 in `quickstart_cis_benchmark`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `ConfigPermissionToCallEvaluateCloudTrailLogIntegrityLambda` (AWS::Lambda::Permission) → `Properties.Principal` L1182 in `quickstart_cis_benchmark`
  > Property 'Principal' is create-only; updating it will cause resource replacement
- **I9001** `ConfigRuleForEvaluateCloudTrailLogIntegrity` (AWS::Config::ConfigRule) → `Properties.ConfigRuleName` L1191 in `quickstart_cis_benchmark`
  > Property 'ConfigRuleName' is create-only; updating it will cause resource replacement
- **I9001** `FunctionForInstanceRoleUseRule` (AWS::Lambda::Function) → `Properties.FunctionName` L1211 in `quickstart_cis_benchmark`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `ConfigPermissionToCallInstanceRoleUseLambda` (AWS::Lambda::Permission) → `Properties.Action` L1264 in `quickstart_cis_benchmark`
  > Property 'Action' is create-only; updating it will cause resource replacement
- **I9001** `ConfigPermissionToCallInstanceRoleUseLambda` (AWS::Lambda::Permission) → `Properties.FunctionName` L1264 in `quickstart_cis_benchmark`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `ConfigPermissionToCallInstanceRoleUseLambda` (AWS::Lambda::Permission) → `Properties.Principal` L1264 in `quickstart_cis_benchmark`
  > Property 'Principal' is create-only; updating it will cause resource replacement
- **I9001** `ConfigRuleForInstanceRoleUses` (AWS::Config::ConfigRule) → `Properties.ConfigRuleName` L1273 in `quickstart_cis_benchmark`
  > Property 'ConfigRuleName' is create-only; updating it will cause resource replacement
- **I9001** `FunctionForEvaluateKeyRotationRule` (AWS::Lambda::Function) → `Properties.FunctionName` L1296 in `quickstart_cis_benchmark`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `ConfigPermissionToCallEvaluateKeyRotationLambda` (AWS::Lambda::Permission) → `Properties.Action` L1361 in `quickstart_cis_benchmark`
  > Property 'Action' is create-only; updating it will cause resource replacement
- **I9001** `ConfigPermissionToCallEvaluateKeyRotationLambda` (AWS::Lambda::Permission) → `Properties.FunctionName` L1361 in `quickstart_cis_benchmark`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `ConfigPermissionToCallEvaluateKeyRotationLambda` (AWS::Lambda::Permission) → `Properties.Principal` L1361 in `quickstart_cis_benchmark`
  > Property 'Principal' is create-only; updating it will cause resource replacement
- **I9001** `ConfigRuleForEvaluateKeyRotations` (AWS::Config::ConfigRule) → `Properties.ConfigRuleName` L1370 in `quickstart_cis_benchmark`
  > Property 'ConfigRuleName' is create-only; updating it will cause resource replacement
- **I9001** `FunctionForEvaluateConfigInAllRegionsRule` (AWS::Lambda::Function) → `Properties.FunctionName` L1393 in `quickstart_cis_benchmark`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `EvaluateConfigInAllRegionsFunctionPermission` (AWS::Lambda::Permission) → `Properties.Action` L1469 in `quickstart_cis_benchmark`
  > Property 'Action' is create-only; updating it will cause resource replacement
- **I9001** `EvaluateConfigInAllRegionsFunctionPermission` (AWS::Lambda::Permission) → `Properties.FunctionName` L1469 in `quickstart_cis_benchmark`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `EvaluateConfigInAllRegionsFunctionPermission` (AWS::Lambda::Permission) → `Properties.Principal` L1469 in `quickstart_cis_benchmark`
  > Property 'Principal' is create-only; updating it will cause resource replacement
- **I9001** `ConfigRuleForEvaluateConfigInAllRegions` (AWS::Config::ConfigRule) → `Properties.ConfigRuleName` L1477 in `quickstart_cis_benchmark`
  > Property 'ConfigRuleName' is create-only; updating it will cause resource replacement
- **I9001** `FunctionForVpcPeeringRouteTablesRule` (AWS::Lambda::Function) → `Properties.FunctionName` L1498 in `quickstart_cis_benchmark`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `ConfigPermissionToCallVpcPeeringRouteTablesLambda` (AWS::Lambda::Permission) → `Properties.Action` L1554 in `quickstart_cis_benchmark`
  > Property 'Action' is create-only; updating it will cause resource replacement
- **I9001** `ConfigPermissionToCallVpcPeeringRouteTablesLambda` (AWS::Lambda::Permission) → `Properties.FunctionName` L1554 in `quickstart_cis_benchmark`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `ConfigPermissionToCallVpcPeeringRouteTablesLambda` (AWS::Lambda::Permission) → `Properties.Principal` L1554 in `quickstart_cis_benchmark`
  > Property 'Principal' is create-only; updating it will cause resource replacement
- **I9001** `ConfigRuleForVpcPeeringRouteTabless` (AWS::Config::ConfigRule) → `Properties.ConfigRuleName` L1562 in `quickstart_cis_benchmark`
  > Property 'ConfigRuleName' is create-only; updating it will cause resource replacement
- **I9001** `SnsTopicForCloudWatchEvents` (AWS::SNS::Topic) → `Properties.TopicName` L1586 in `quickstart_cis_benchmark`
  > Property 'TopicName' is create-only; updating it will cause resource replacement
- **I9001** `GetCloudTrailCloudWatchLog` (AWS::Lambda::Function) → `Properties.FunctionName` L1600 in `quickstart_cis_benchmark`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `UnauthorizedAttemptsCloudWatchFilter` (AWS::Logs::MetricFilter) → `Properties.LogGroupName` L1646 in `quickstart_cis_benchmark`
  > Property 'LogGroupName' is create-only; updating it will cause resource replacement
- **I9001** `UnauthorizedAttemptCloudWatchAlarm` (AWS::CloudWatch::Alarm) → `Properties.AlarmName` L1660 in `quickstart_cis_benchmark`
  > Property 'AlarmName' is create-only; updating it will cause resource replacement
- **I9001** `IAMRootActivityCloudWatchMetric` (AWS::Logs::MetricFilter) → `Properties.LogGroupName` L1680 in `quickstart_cis_benchmark`
  > Property 'LogGroupName' is create-only; updating it will cause resource replacement
- **I9001** `IAMRootActivityCloudWatchAlarm` (AWS::CloudWatch::Alarm) → `Properties.AlarmName` L1698 in `quickstart_cis_benchmark`
  > Property 'AlarmName' is create-only; updating it will cause resource replacement
- **I9001** `ConsoleSigninWithoutMfaCloudWatchMetric` (AWS::Logs::MetricFilter) → `Properties.LogGroupName` L1717 in `quickstart_cis_benchmark`
  > Property 'LogGroupName' is create-only; updating it will cause resource replacement
- **I9001** `ConsoleSigninWithoutMFACloudWatchAlarm` (AWS::CloudWatch::Alarm) → `Properties.AlarmName` L1736 in `quickstart_cis_benchmark`
  > Property 'AlarmName' is create-only; updating it will cause resource replacement
- **I9001** `ConsoleLoginFailureCloudWatchMetric` (AWS::Logs::MetricFilter) → `Properties.LogGroupName` L1755 in `quickstart_cis_benchmark`
  > Property 'LogGroupName' is create-only; updating it will cause resource replacement
- **I9001** `ConsoleLoginFailureCloudWatchAlarm` (AWS::CloudWatch::Alarm) → `Properties.AlarmName` L1773 in `quickstart_cis_benchmark`
  > Property 'AlarmName' is create-only; updating it will cause resource replacement
- **I9001** `KMSCustomerKeyDeletionCloudWatchMetric` (AWS::Logs::MetricFilter) → `Properties.LogGroupName` L1792 in `quickstart_cis_benchmark`
  > Property 'LogGroupName' is create-only; updating it will cause resource replacement
- **I9001** `KMSCustomerKeyDeletionCloudWatchAlarm` (AWS::CloudWatch::Alarm) → `Properties.AlarmName` L1810 in `quickstart_cis_benchmark`
  > Property 'AlarmName' is create-only; updating it will cause resource replacement
- **I9001** `FunctionToFormatCloudWatchEvent` (AWS::Lambda::Function) → `Properties.FunctionName` L1855 in `quickstart_cis_benchmark`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `LambdaPermissionForCloudTrailCloudWatchEventRules` (AWS::Lambda::Permission) → `Properties.Action` L1893 in `quickstart_cis_benchmark`
  > Property 'Action' is create-only; updating it will cause resource replacement
- **I9001** `LambdaPermissionForCloudTrailCloudWatchEventRules` (AWS::Lambda::Permission) → `Properties.FunctionName` L1893 in `quickstart_cis_benchmark`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `LambdaPermissionForCloudTrailCloudWatchEventRules` (AWS::Lambda::Permission) → `Properties.Principal` L1893 in `quickstart_cis_benchmark`
  > Property 'Principal' is create-only; updating it will cause resource replacement
- **I9001** `DetectS3BucketPolicyChanges` (AWS::Events::Rule) → `Properties.Name` L1905 in `quickstart_cis_benchmark`
  > Property 'Name' is create-only; updating it will cause resource replacement
- **I9001** `DetectConfigChanges` (AWS::Events::Rule) → `Properties.Name` L1935 in `quickstart_cis_benchmark`
  > Property 'Name' is create-only; updating it will cause resource replacement
- **I9001** `KmsKeyUseCloudWatchEventRule` (AWS::Events::Rule) → `Properties.Name` L1961 in `quickstart_cis_benchmark`
  > Property 'Name' is create-only; updating it will cause resource replacement
- **I9001** `CloudTrailCloudWatchEventRule` (AWS::Events::Rule) → `Properties.Name` L1983 in `quickstart_cis_benchmark`
  > Property 'Name' is create-only; updating it will cause resource replacement
- **I9001** `IamPolicyChangesCloudWatchEventRule` (AWS::Events::Rule) → `Properties.Name` L2006 in `quickstart_cis_benchmark`
  > Property 'Name' is create-only; updating it will cause resource replacement
- **I9001** `BillingChangeCloudWatchEventRule` (AWS::Events::Rule) → `Properties.Name` L2044 in `quickstart_cis_benchmark`
  > Property 'Name' is create-only; updating it will cause resource replacement
- **I9001** `Ec2TerminationCloudWatchEventRule` (AWS::Events::Rule) → `Properties.Name` L2068 in `quickstart_cis_benchmark`
  > Property 'Name' is create-only; updating it will cause resource replacement
- **I9001** `SecurityGroupChangesCloudWatchEventRule` (AWS::Events::Rule) → `Properties.Name` L2090 in `quickstart_cis_benchmark`
  > Property 'Name' is create-only; updating it will cause resource replacement
- **I9001** `NetworkAclChangesCloudWatchEventRule` (AWS::Events::Rule) → `Properties.Name` L2118 in `quickstart_cis_benchmark`
  > Property 'Name' is create-only; updating it will cause resource replacement
- **I9001** `NetworkChangeCloudWatchEventRule` (AWS::Events::Rule) → `Properties.Name` L2149 in `quickstart_cis_benchmark`
  > Property 'Name' is create-only; updating it will cause resource replacement
- **I9001** `BillingChangesCloudWatchFilter` (AWS::Logs::MetricFilter) → `Properties.LogGroupName` L2182 in `quickstart_cis_benchmark`
  > Property 'LogGroupName' is create-only; updating it will cause resource replacement
- **I9001** `BillingChangesCloudWatchAlarm` (AWS::CloudWatch::Alarm) → `Properties.AlarmName` L2200 in `quickstart_cis_benchmark`
  > Property 'AlarmName' is create-only; updating it will cause resource replacement
- **I9001** `FunctionToDisableUnusedCredentials` (AWS::Lambda::Function) → `Properties.FunctionName` L2252 in `quickstart_cis_benchmark`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `LambdaPermissionForDisableUnusedCredentials` (AWS::Lambda::Permission) → `Properties.Action` L2338 in `quickstart_cis_benchmark`
  > Property 'Action' is create-only; updating it will cause resource replacement
- **I9001** `LambdaPermissionForDisableUnusedCredentials` (AWS::Lambda::Permission) → `Properties.FunctionName` L2338 in `quickstart_cis_benchmark`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `LambdaPermissionForDisableUnusedCredentials` (AWS::Lambda::Permission) → `Properties.Principal` L2338 in `quickstart_cis_benchmark`
  > Property 'Principal' is create-only; updating it will cause resource replacement
- **I9001** `ScheduledRuleForDisableUnusedCredentials` (AWS::Events::Rule) → `Properties.Name` L2347 in `quickstart_cis_benchmark`
  > Property 'Name' is create-only; updating it will cause resource replacement
- **I9001** `rConfigRuleForSSH` (AWS::Config::ConfigRule) → `Properties.ConfigRuleName` L45 in `quickstart_config-rules`
  > Property 'ConfigRuleName' is create-only; updating it will cause resource replacement
- **I9001** `rConfigRuleForRequiredTags` (AWS::Config::ConfigRule) → `Properties.ConfigRuleName` L59 in `quickstart_config-rules`
  > Property 'ConfigRuleName' is create-only; updating it will cause resource replacement
- **I9001** `rConfigRuleForUnrestrictedPorts` (AWS::Config::ConfigRule) → `Properties.ConfigRuleName` L79 in `quickstart_config-rules`
  > Property 'ConfigRuleName' is create-only; updating it will cause resource replacement
- **I9001** `rConfigRulesLambdaRole` (AWS::IAM::Role) → `Properties.Path` L97 in `quickstart_config-rules`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `rConfigRulesLambdaProfile` (AWS::IAM::InstanceProfile) → `Properties.Path` L130 in `quickstart_config-rules`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `rConfigRuleForAMICompliance` (AWS::Config::ConfigRule) → `Properties.ConfigRuleName` L201 in `quickstart_config-rules`
  > Property 'ConfigRuleName' is create-only; updating it will cause resource replacement
- **I9001** `rConfigPermissionToCallLambdaAMICompliance` (AWS::Lambda::Permission) → `Properties.Action` L226 in `quickstart_config-rules`
  > Property 'Action' is create-only; updating it will cause resource replacement
- **I9001** `rConfigPermissionToCallLambdaAMICompliance` (AWS::Lambda::Permission) → `Properties.FunctionName` L226 in `quickstart_config-rules`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `rConfigPermissionToCallLambdaAMICompliance` (AWS::Lambda::Permission) → `Properties.Principal` L226 in `quickstart_config-rules`
  > Property 'Principal' is create-only; updating it will cause resource replacement
- **I9001** `rConfigRuleForCloudTrail` (AWS::Config::ConfigRule) → `Properties.ConfigRuleName` L298 in `quickstart_config-rules`
  > Property 'ConfigRuleName' is create-only; updating it will cause resource replacement
- **I9001** `rConfigPermissionToCallLambdaCloudTrail` (AWS::Lambda::Permission) → `Properties.Action` L319 in `quickstart_config-rules`
  > Property 'Action' is create-only; updating it will cause resource replacement
- **I9001** `rConfigPermissionToCallLambdaCloudTrail` (AWS::Lambda::Permission) → `Properties.FunctionName` L319 in `quickstart_config-rules`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `rConfigPermissionToCallLambdaCloudTrail` (AWS::Lambda::Permission) → `Properties.Principal` L319 in `quickstart_config-rules`
  > Property 'Principal' is create-only; updating it will cause resource replacement
- **I9001** `rSysAdminProfile` (AWS::IAM::InstanceProfile) → `Properties.Path` L43 in `quickstart_iam`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `rIAMAdminProfile` (AWS::IAM::InstanceProfile) → `Properties.Path` L137 in `quickstart_iam`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `rInstanceOpsProfile` (AWS::IAM::InstanceProfile) → `Properties.Path` L209 in `quickstart_iam`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `rReadOnlyAdminProfile` (AWS::IAM::InstanceProfile) → `Properties.Path` L322 in `quickstart_iam`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `rNatInstanceEni` (AWS::EC2::NetworkInterface) → `Properties.SubnetId` L75 in `quickstart_nat-instance`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `rNatInstance` (AWS::EC2::Instance) → `Properties.ImageId` L93 in `quickstart_nat-instance`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `rNatInstance` (AWS::EC2::Instance) → `Properties.KeyName` L93 in `quickstart_nat-instance`
  > Property 'KeyName' is create-only; updating it will cause resource replacement
- **I9001** `rNatInstance` (AWS::EC2::Instance) → `Properties.NetworkInterfaces` L93 in `quickstart_nat-instance`
  > Property 'NetworkInterfaces' is create-only; updating it will cause resource replacement
- **I9001** `AssociateEipNat` (AWS::EC2::EIPAssociation) → `Properties.AllocationId` L140 in `quickstart_nat-instance`
  > Property 'AllocationId' is create-only; updating it will cause resource replacement
- **I9001** `AssociateEipNat` (AWS::EC2::EIPAssociation) → `Properties.NetworkInterfaceId` L140 in `quickstart_nat-instance`
  > Property 'NetworkInterfaceId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteProdPrivateNatInstance` (AWS::EC2::Route) → `Properties.DestinationCidrBlock` L154 in `quickstart_nat-instance`
  > Property 'DestinationCidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `rRouteProdPrivateNatInstance` (AWS::EC2::Route) → `Properties.RouteTableId` L154 in `quickstart_nat-instance`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `rAutoScalingConfigApp` (AWS::AutoScaling::LaunchConfiguration) → `Properties.ImageId` L219 in `quickstart_nist_application`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `rAutoScalingConfigApp` (AWS::AutoScaling::LaunchConfiguration) → `Properties.InstanceType` L219 in `quickstart_nist_application`
  > Property 'InstanceType' is create-only; updating it will cause resource replacement
- **I9001** `rAutoScalingConfigApp` (AWS::AutoScaling::LaunchConfiguration) → `Properties.KeyName` L219 in `quickstart_nist_application`
  > Property 'KeyName' is create-only; updating it will cause resource replacement
- **I9001** `rAutoScalingConfigApp` (AWS::AutoScaling::LaunchConfiguration) → `Properties.SecurityGroups` L219 in `quickstart_nist_application`
  > Property 'SecurityGroups' is create-only; updating it will cause resource replacement
- **I9001** `rAutoScalingConfigApp` (AWS::AutoScaling::LaunchConfiguration) → `Properties.UserData` L219 in `quickstart_nist_application`
  > Property 'UserData' is create-only; updating it will cause resource replacement
- **I9001** `rAutoScalingConfigWeb` (AWS::AutoScaling::LaunchConfiguration) → `Properties.AssociatePublicIpAddress` L417 in `quickstart_nist_application`
  > Property 'AssociatePublicIpAddress' is create-only; updating it will cause resource replacement
- **I9001** `rAutoScalingConfigWeb` (AWS::AutoScaling::LaunchConfiguration) → `Properties.ImageId` L417 in `quickstart_nist_application`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `rAutoScalingConfigWeb` (AWS::AutoScaling::LaunchConfiguration) → `Properties.InstanceType` L417 in `quickstart_nist_application`
  > Property 'InstanceType' is create-only; updating it will cause resource replacement
- **I9001** `rAutoScalingConfigWeb` (AWS::AutoScaling::LaunchConfiguration) → `Properties.KeyName` L417 in `quickstart_nist_application`
  > Property 'KeyName' is create-only; updating it will cause resource replacement
- **I9001** `rAutoScalingConfigWeb` (AWS::AutoScaling::LaunchConfiguration) → `Properties.SecurityGroups` L417 in `quickstart_nist_application`
  > Property 'SecurityGroups' is create-only; updating it will cause resource replacement
- **I9001** `rAutoScalingConfigWeb` (AWS::AutoScaling::LaunchConfiguration) → `Properties.UserData` L417 in `quickstart_nist_application`
  > Property 'UserData' is create-only; updating it will cause resource replacement
- **I9001** `rAutoScalingDownApp` (AWS::AutoScaling::ScalingPolicy) → `Properties.AutoScalingGroupName` L561 in `quickstart_nist_application`
  > Property 'AutoScalingGroupName' is create-only; updating it will cause resource replacement
- **I9001** `rAutoScalingDownWeb` (AWS::AutoScaling::ScalingPolicy) → `Properties.AutoScalingGroupName` L569 in `quickstart_nist_application`
  > Property 'AutoScalingGroupName' is create-only; updating it will cause resource replacement
- **I9001** `rAutoScalingUpApp` (AWS::AutoScaling::ScalingPolicy) → `Properties.AutoScalingGroupName` L629 in `quickstart_nist_application`
  > Property 'AutoScalingGroupName' is create-only; updating it will cause resource replacement
- **I9001** `rAutoScalingUpWeb` (AWS::AutoScaling::ScalingPolicy) → `Properties.AutoScalingGroupName` L637 in `quickstart_nist_application`
  > Property 'AutoScalingGroupName' is create-only; updating it will cause resource replacement
- **I9001** `rELBApp` (AWS::ElasticLoadBalancing::LoadBalancer) → `Properties.Scheme` L723 in `quickstart_nist_application`
  > Property 'Scheme' is create-only; updating it will cause resource replacement
- **I9001** `rPostProcInstance` (AWS::EC2::Instance) → `Properties.ImageId` L794 in `quickstart_nist_application`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `rPostProcInstance` (AWS::EC2::Instance) → `Properties.SubnetId` L794 in `quickstart_nist_application`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `rPostProcInstanceProfile` (AWS::IAM::InstanceProfile) → `Properties.Path` L954 in `quickstart_nist_application`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `rPostProcInstanceRole` (AWS::IAM::Role) → `Properties.Path` L960 in `quickstart_nist_application`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `rRDSInstanceMySQL` (AWS::RDS::DBInstance) → `Properties.DBName` L1003 in `quickstart_nist_application`
  > Property 'DBName' is create-only; updating it will cause resource replacement
- **I9001** `rRDSInstanceMySQL` (AWS::RDS::DBInstance) → `Properties.DBSubnetGroupName` L1003 in `quickstart_nist_application`
  > Property 'DBSubnetGroupName' is create-only; updating it will cause resource replacement
- **I9001** `rRDSInstanceMySQL` (AWS::RDS::DBInstance) → `Properties.MasterUsername` L1003 in `quickstart_nist_application`
  > Property 'MasterUsername' is create-only; updating it will cause resource replacement
- **I9001** `rRDSInstanceMySQL` (AWS::RDS::DBInstance) → `Properties.StorageEncrypted` L1003 in `quickstart_nist_application`
  > Property 'StorageEncrypted' is create-only; updating it will cause resource replacement
- **I9001** `rS3AccessLogsPolicy` (AWS::S3::BucketPolicy) → `Properties.Bucket` L1027 in `quickstart_nist_application`
  > Property 'Bucket' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupApp` (AWS::EC2::SecurityGroup) → `Properties.GroupDescription` L1066 in `quickstart_nist_application`
  > Property 'GroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupApp` (AWS::EC2::SecurityGroup) → `Properties.VpcId` L1066 in `quickstart_nist_application`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupAppInstance` (AWS::EC2::SecurityGroup) → `Properties.GroupDescription` L1093 in `quickstart_nist_application`
  > Property 'GroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupAppInstance` (AWS::EC2::SecurityGroup) → `Properties.VpcId` L1093 in `quickstart_nist_application`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupRDS` (AWS::EC2::SecurityGroup) → `Properties.GroupDescription` L1121 in `quickstart_nist_application`
  > Property 'GroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupRDS` (AWS::EC2::SecurityGroup) → `Properties.VpcId` L1121 in `quickstart_nist_application`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupWeb` (AWS::EC2::SecurityGroup) → `Properties.GroupDescription` L1139 in `quickstart_nist_application`
  > Property 'GroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupWeb` (AWS::EC2::SecurityGroup) → `Properties.VpcId` L1139 in `quickstart_nist_application`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupWebInstance` (AWS::EC2::SecurityGroup) → `Properties.GroupDescription` L1150 in `quickstart_nist_application`
  > Property 'GroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupWebInstance` (AWS::EC2::SecurityGroup) → `Properties.VpcId` L1150 in `quickstart_nist_application`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rWebContentS3Policy` (AWS::S3::BucketPolicy) → `Properties.Bucket` L1197 in `quickstart_nist_application`
  > Property 'Bucket' is create-only; updating it will cause resource replacement
- **I9001** `rConfigPermissionToCallLambdaAMICompliance` (AWS::Lambda::Permission) → `Properties.Action` L163 in `quickstart_nist_config_rules`
  > Property 'Action' is create-only; updating it will cause resource replacement
- **I9001** `rConfigPermissionToCallLambdaAMICompliance` (AWS::Lambda::Permission) → `Properties.FunctionName` L163 in `quickstart_nist_config_rules`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `rConfigPermissionToCallLambdaAMICompliance` (AWS::Lambda::Permission) → `Properties.Principal` L163 in `quickstart_nist_config_rules`
  > Property 'Principal' is create-only; updating it will cause resource replacement
- **I9001** `rConfigPermissionToCallLambdaCloudTrail` (AWS::Lambda::Permission) → `Properties.Action` L173 in `quickstart_nist_config_rules`
  > Property 'Action' is create-only; updating it will cause resource replacement
- **I9001** `rConfigPermissionToCallLambdaCloudTrail` (AWS::Lambda::Permission) → `Properties.FunctionName` L173 in `quickstart_nist_config_rules`
  > Property 'FunctionName' is create-only; updating it will cause resource replacement
- **I9001** `rConfigPermissionToCallLambdaCloudTrail` (AWS::Lambda::Permission) → `Properties.Principal` L173 in `quickstart_nist_config_rules`
  > Property 'Principal' is create-only; updating it will cause resource replacement
- **I9001** `rConfigRuleForAMICompliance` (AWS::Config::ConfigRule) → `Properties.ConfigRuleName` L182 in `quickstart_nist_config_rules`
  > Property 'ConfigRuleName' is create-only; updating it will cause resource replacement
- **I9001** `rConfigRuleForCloudTrail` (AWS::Config::ConfigRule) → `Properties.ConfigRuleName` L203 in `quickstart_nist_config_rules`
  > Property 'ConfigRuleName' is create-only; updating it will cause resource replacement
- **I9001** `rConfigRuleForRequiredTags` (AWS::Config::ConfigRule) → `Properties.ConfigRuleName` L221 in `quickstart_nist_config_rules`
  > Property 'ConfigRuleName' is create-only; updating it will cause resource replacement
- **I9001** `rConfigRuleForSSH` (AWS::Config::ConfigRule) → `Properties.ConfigRuleName` L237 in `quickstart_nist_config_rules`
  > Property 'ConfigRuleName' is create-only; updating it will cause resource replacement
- **I9001** `rConfigRuleForUnrestrictedPorts` (AWS::Config::ConfigRule) → `Properties.ConfigRuleName` L249 in `quickstart_nist_config_rules`
  > Property 'ConfigRuleName' is create-only; updating it will cause resource replacement
- **I9001** `rConfigRulesLambdaProfile` (AWS::IAM::InstanceProfile) → `Properties.Path` L276 in `quickstart_nist_config_rules`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `rConfigRulesLambdaRole` (AWS::IAM::Role) → `Properties.Path` L282 in `quickstart_nist_config_rules`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `rIAMAdminProfile` (AWS::IAM::InstanceProfile) → `Properties.Path` L57 in `quickstart_nist_iam`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `rInstanceOpsProfile` (AWS::IAM::InstanceProfile) → `Properties.Path` L137 in `quickstart_nist_iam`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `rReadOnlyAdminProfile` (AWS::IAM::InstanceProfile) → `Properties.Path` L236 in `quickstart_nist_iam`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `rSysAdminProfile` (AWS::IAM::InstanceProfile) → `Properties.Path` L312 in `quickstart_nist_iam`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `rArchiveLogsBucketPolicy` (AWS::S3::BucketPolicy) → `Properties.Bucket` L61 in `quickstart_nist_logging`
  > Property 'Bucket' is create-only; updating it will cause resource replacement
- **I9001** `rCloudTrailChange` (AWS::Logs::MetricFilter) → `Properties.LogGroupName` L131 in `quickstart_nist_logging`
  > Property 'LogGroupName' is create-only; updating it will cause resource replacement
- **I9001** `rCloudTrailChangeAlarm` (AWS::CloudWatch::Alarm) → `Properties.AlarmName` L143 in `quickstart_nist_logging`
  > Property 'AlarmName' is create-only; updating it will cause resource replacement
- **I9001** `rCloudTrailProfile` (AWS::IAM::InstanceProfile) → `Properties.Path` L180 in `quickstart_nist_logging`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `rCloudTrailRole` (AWS::IAM::Role) → `Properties.Path` L187 in `quickstart_nist_logging`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `rCloudTrailS3Policy` (AWS::S3::BucketPolicy) → `Properties.Bucket` L232 in `quickstart_nist_logging`
  > Property 'Bucket' is create-only; updating it will cause resource replacement
- **I9001** `rCloudWatchLogsRole` (AWS::IAM::Role) → `Properties.Path` L325 in `quickstart_nist_logging`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `rIAMCreateAccessKey` (AWS::Logs::MetricFilter) → `Properties.LogGroupName` L380 in `quickstart_nist_logging`
  > Property 'LogGroupName' is create-only; updating it will cause resource replacement
- **I9001** `rIAMCreateAccessKeyAlarm` (AWS::CloudWatch::Alarm) → `Properties.AlarmName` L391 in `quickstart_nist_logging`
  > Property 'AlarmName' is create-only; updating it will cause resource replacement
- **I9001** `rIAMPolicyChangesAlarm` (AWS::CloudWatch::Alarm) → `Properties.AlarmName` L407 in `quickstart_nist_logging`
  > Property 'AlarmName' is create-only; updating it will cause resource replacement
- **I9001** `rIAMPolicyChangesMetricFilter` (AWS::Logs::MetricFilter) → `Properties.LogGroupName` L422 in `quickstart_nist_logging`
  > Property 'LogGroupName' is create-only; updating it will cause resource replacement
- **I9001** `rIAMRootActivity` (AWS::Logs::MetricFilter) → `Properties.LogGroupName` L432 in `quickstart_nist_logging`
  > Property 'LogGroupName' is create-only; updating it will cause resource replacement
- **I9001** `rNetworkAclChangesAlarm` (AWS::CloudWatch::Alarm) → `Properties.AlarmName` L443 in `quickstart_nist_logging`
  > Property 'AlarmName' is create-only; updating it will cause resource replacement
- **I9001** `rNetworkAclChangesMetricFilter` (AWS::Logs::MetricFilter) → `Properties.LogGroupName` L458 in `quickstart_nist_logging`
  > Property 'LogGroupName' is create-only; updating it will cause resource replacement
- **I9001** `rRootActivityAlarm` (AWS::CloudWatch::Alarm) → `Properties.AlarmName` L471 in `quickstart_nist_logging`
  > Property 'AlarmName' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupChangesAlarm` (AWS::CloudWatch::Alarm) → `Properties.AlarmName` L493 in `quickstart_nist_logging`
  > Property 'AlarmName' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupChangesMetricFilter` (AWS::Logs::MetricFilter) → `Properties.LogGroupName` L509 in `quickstart_nist_logging`
  > Property 'LogGroupName' is create-only; updating it will cause resource replacement
- **I9001** `rUnauthorizedAttemptAlarm` (AWS::CloudWatch::Alarm) → `Properties.AlarmName` L522 in `quickstart_nist_logging`
  > Property 'AlarmName' is create-only; updating it will cause resource replacement
- **I9001** `rUnauthorizedAttempts` (AWS::Logs::MetricFilter) → `Properties.LogGroupName` L537 in `quickstart_nist_logging`
  > Property 'LogGroupName' is create-only; updating it will cause resource replacement
- **I9001** `AssociaterEIPProdBastion` (AWS::EC2::EIPAssociation) → `Properties.AllocationId` L303 in `quickstart_nist_vpc_management`
  > Property 'AllocationId' is create-only; updating it will cause resource replacement
- **I9001** `AssociaterEIPProdBastion` (AWS::EC2::EIPAssociation) → `Properties.NetworkInterfaceId` L303 in `quickstart_nist_vpc_management`
  > Property 'NetworkInterfaceId' is create-only; updating it will cause resource replacement
- **I9001** `rDHCPOptionsAssocMgmt` (AWS::EC2::VPCDHCPOptionsAssociation) → `Properties.DhcpOptionsId` L313 in `quickstart_nist_vpc_management`
  > Property 'DhcpOptionsId' is create-only; updating it will cause resource replacement
- **I9001** `rDHCPOptionsAssocMgmt` (AWS::EC2::VPCDHCPOptionsAssociation) → `Properties.VpcId` L313 in `quickstart_nist_vpc_management`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rDHCPoptions` (AWS::EC2::DHCPOptions) → `Properties.DomainName` L320 in `quickstart_nist_vpc_management`
  > Property 'DomainName' is create-only; updating it will cause resource replacement
- **I9001** `rDHCPoptions` (AWS::EC2::DHCPOptions) → `Properties.DomainNameServers` L320 in `quickstart_nist_vpc_management`
  > Property 'DomainNameServers' is create-only; updating it will cause resource replacement
- **I9001** `rENIProductionBastion` (AWS::EC2::NetworkInterface) → `Properties.SubnetId` L405 in `quickstart_nist_vpc_management`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `rGWAttachmentMgmtIGW` (AWS::EC2::VPCGatewayAttachment) → `Properties.VpcId` L417 in `quickstart_nist_vpc_management`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rManagementDMZSubnetA` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L431 in `quickstart_nist_vpc_management`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `rManagementDMZSubnetA` (AWS::EC2::Subnet) → `Properties.CidrBlock` L431 in `quickstart_nist_vpc_management`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `rManagementDMZSubnetA` (AWS::EC2::Subnet) → `Properties.VpcId` L431 in `quickstart_nist_vpc_management`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rManagementDMZSubnetB` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L443 in `quickstart_nist_vpc_management`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `rManagementDMZSubnetB` (AWS::EC2::Subnet) → `Properties.CidrBlock` L443 in `quickstart_nist_vpc_management`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `rManagementDMZSubnetB` (AWS::EC2::Subnet) → `Properties.VpcId` L443 in `quickstart_nist_vpc_management`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rManagementPrivateSubnetA` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L455 in `quickstart_nist_vpc_management`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `rManagementPrivateSubnetA` (AWS::EC2::Subnet) → `Properties.CidrBlock` L455 in `quickstart_nist_vpc_management`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `rManagementPrivateSubnetA` (AWS::EC2::Subnet) → `Properties.VpcId` L455 in `quickstart_nist_vpc_management`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rManagementPrivateSubnetB` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L467 in `quickstart_nist_vpc_management`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `rManagementPrivateSubnetB` (AWS::EC2::Subnet) → `Properties.CidrBlock` L467 in `quickstart_nist_vpc_management`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `rManagementPrivateSubnetB` (AWS::EC2::Subnet) → `Properties.VpcId` L467 in `quickstart_nist_vpc_management`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rMgmtBastionInstance` (AWS::EC2::Instance) → `Properties.ImageId` L479 in `quickstart_nist_vpc_management`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `rMgmtBastionInstance` (AWS::EC2::Instance) → `Properties.KeyName` L479 in `quickstart_nist_vpc_management`
  > Property 'KeyName' is create-only; updating it will cause resource replacement
- **I9001** `rMgmtBastionInstance` (AWS::EC2::Instance) → `Properties.NetworkInterfaces` L479 in `quickstart_nist_vpc_management`
  > Property 'NetworkInterfaces' is create-only; updating it will cause resource replacement
- **I9001** `rNATGateway` (AWS::EC2::NatGateway) → `Properties.AllocationId` L546 in `quickstart_nist_vpc_management`
  > Property 'AllocationId' is create-only; updating it will cause resource replacement
- **I9001** `rNATGateway` (AWS::EC2::NatGateway) → `Properties.SubnetId` L546 in `quickstart_nist_vpc_management`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `rPeeringConnectionProduction` (AWS::EC2::VPCPeeringConnection) → `Properties.PeerVpcId` L586 in `quickstart_nist_vpc_management`
  > Property 'PeerVpcId' is create-only; updating it will cause resource replacement
- **I9001** `rPeeringConnectionProduction` (AWS::EC2::VPCPeeringConnection) → `Properties.VpcId` L586 in `quickstart_nist_vpc_management`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteAssocMgmtDMZA` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L597 in `quickstart_nist_vpc_management`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteAssocMgmtDMZA` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L597 in `quickstart_nist_vpc_management`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteAssocMgmtPrivA` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L604 in `quickstart_nist_vpc_management`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteAssocMgmtPrivA` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L604 in `quickstart_nist_vpc_management`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteAssocMgmtPrivB` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L611 in `quickstart_nist_vpc_management`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteAssocMgmtPrivB` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L611 in `quickstart_nist_vpc_management`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteMgmtIGW` (AWS::EC2::Route) → `Properties.DestinationCidrBlock` L618 in `quickstart_nist_vpc_management`
  > Property 'DestinationCidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `rRouteMgmtIGW` (AWS::EC2::Route) → `Properties.RouteTableId` L618 in `quickstart_nist_vpc_management`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteMgmtProdDMZ` (AWS::EC2::Route) → `Properties.DestinationCidrBlock` L626 in `quickstart_nist_vpc_management`
  > Property 'DestinationCidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `rRouteMgmtProdDMZ` (AWS::EC2::Route) → `Properties.RouteTableId` L626 in `quickstart_nist_vpc_management`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteMgmtProdPrivate` (AWS::EC2::Route) → `Properties.DestinationCidrBlock` L636 in `quickstart_nist_vpc_management`
  > Property 'DestinationCidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `rRouteMgmtProdPrivate` (AWS::EC2::Route) → `Properties.RouteTableId` L636 in `quickstart_nist_vpc_management`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteProdMgmt` (AWS::EC2::Route) → `Properties.DestinationCidrBlock` L646 in `quickstart_nist_vpc_management`
  > Property 'DestinationCidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `rRouteProdMgmt` (AWS::EC2::Route) → `Properties.RouteTableId` L646 in `quickstart_nist_vpc_management`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteProdMgmtPublic` (AWS::EC2::Route) → `Properties.DestinationCidrBlock` L656 in `quickstart_nist_vpc_management`
  > Property 'DestinationCidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `rRouteProdMgmtPublic` (AWS::EC2::Route) → `Properties.RouteTableId` L656 in `quickstart_nist_vpc_management`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteTableMgmtDMZ` (AWS::EC2::RouteTable) → `Properties.VpcId` L666 in `quickstart_nist_vpc_management`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteTableMgmtPrivate` (AWS::EC2::RouteTable) → `Properties.VpcId` L674 in `quickstart_nist_vpc_management`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupBastion` (AWS::EC2::SecurityGroup) → `Properties.GroupDescription` L682 in `quickstart_nist_vpc_management`
  > Property 'GroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupBastion` (AWS::EC2::SecurityGroup) → `Properties.VpcId` L682 in `quickstart_nist_vpc_management`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupPeered` (AWS::EC2::SecurityGroup) → `Properties.GroupDescription` L702 in `quickstart_nist_vpc_management`
  > Property 'GroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupPeered` (AWS::EC2::SecurityGroup) → `Properties.VpcId` L702 in `quickstart_nist_vpc_management`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupSSHFromMgmt` (AWS::EC2::SecurityGroup) → `Properties.GroupDescription` L716 in `quickstart_nist_vpc_management`
  > Property 'GroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupSSHFromMgmt` (AWS::EC2::SecurityGroup) → `Properties.VpcId` L716 in `quickstart_nist_vpc_management`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupVpcNat` (AWS::EC2::SecurityGroup) → `Properties.GroupDescription` L731 in `quickstart_nist_vpc_management`
  > Property 'GroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupVpcNat` (AWS::EC2::SecurityGroup) → `Properties.VpcId` L731 in `quickstart_nist_vpc_management`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rVPCManagement` (AWS::EC2::VPC) → `Properties.CidrBlock` L751 in `quickstart_nist_vpc_management`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `rrRouteAssocMgmtDMZB` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L763 in `quickstart_nist_vpc_management`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `rrRouteAssocMgmtDMZB` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L763 in `quickstart_nist_vpc_management`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `rAppPrivateSubnetA` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L179 in `quickstart_nist_vpc_production`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `rAppPrivateSubnetA` (AWS::EC2::Subnet) → `Properties.CidrBlock` L179 in `quickstart_nist_vpc_production`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `rAppPrivateSubnetA` (AWS::EC2::Subnet) → `Properties.VpcId` L179 in `quickstart_nist_vpc_production`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rAppPrivateSubnetAssociationA` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L194 in `quickstart_nist_vpc_production`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `rAppPrivateSubnetAssociationA` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L194 in `quickstart_nist_vpc_production`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `rAppPrivateSubnetAssociationB` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L201 in `quickstart_nist_vpc_production`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `rAppPrivateSubnetAssociationB` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L201 in `quickstart_nist_vpc_production`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `rAppPrivateSubnetB` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L208 in `quickstart_nist_vpc_production`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `rAppPrivateSubnetB` (AWS::EC2::Subnet) → `Properties.CidrBlock` L208 in `quickstart_nist_vpc_production`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `rAppPrivateSubnetB` (AWS::EC2::Subnet) → `Properties.VpcId` L208 in `quickstart_nist_vpc_production`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rDBPrivateSubnetA` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L223 in `quickstart_nist_vpc_production`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `rDBPrivateSubnetA` (AWS::EC2::Subnet) → `Properties.CidrBlock` L223 in `quickstart_nist_vpc_production`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `rDBPrivateSubnetA` (AWS::EC2::Subnet) → `Properties.VpcId` L223 in `quickstart_nist_vpc_production`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rDBPrivateSubnetB` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L238 in `quickstart_nist_vpc_production`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `rDBPrivateSubnetB` (AWS::EC2::Subnet) → `Properties.CidrBlock` L238 in `quickstart_nist_vpc_production`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `rDBPrivateSubnetB` (AWS::EC2::Subnet) → `Properties.VpcId` L238 in `quickstart_nist_vpc_production`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rDHCPOptionsAssocProd` (AWS::EC2::VPCDHCPOptionsAssociation) → `Properties.DhcpOptionsId` L253 in `quickstart_nist_vpc_production`
  > Property 'DhcpOptionsId' is create-only; updating it will cause resource replacement
- **I9001** `rDHCPOptionsAssocProd` (AWS::EC2::VPCDHCPOptionsAssociation) → `Properties.VpcId` L253 in `quickstart_nist_vpc_production`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rDHCPoptions` (AWS::EC2::DHCPOptions) → `Properties.DomainName` L260 in `quickstart_nist_vpc_production`
  > Property 'DomainName' is create-only; updating it will cause resource replacement
- **I9001** `rDHCPoptions` (AWS::EC2::DHCPOptions) → `Properties.DomainNameServers` L260 in `quickstart_nist_vpc_production`
  > Property 'DomainNameServers' is create-only; updating it will cause resource replacement
- **I9001** `rDMZSubnetA` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L273 in `quickstart_nist_vpc_production`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `rDMZSubnetA` (AWS::EC2::Subnet) → `Properties.CidrBlock` L273 in `quickstart_nist_vpc_production`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `rDMZSubnetA` (AWS::EC2::Subnet) → `Properties.VpcId` L273 in `quickstart_nist_vpc_production`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rDMZSubnetB` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L288 in `quickstart_nist_vpc_production`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `rDMZSubnetB` (AWS::EC2::Subnet) → `Properties.CidrBlock` L288 in `quickstart_nist_vpc_production`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `rDMZSubnetB` (AWS::EC2::Subnet) → `Properties.VpcId` L288 in `quickstart_nist_vpc_production`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rGWAttachmentProdIGW` (AWS::EC2::VPCGatewayAttachment) → `Properties.VpcId` L308 in `quickstart_nist_vpc_production`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rNACLAssocAppPrivSubnetA` (AWS::EC2::SubnetNetworkAclAssociation) → `Properties.NetworkAclId` L325 in `quickstart_nist_vpc_production`
  > Property 'NetworkAclId' is create-only; updating it will cause resource replacement
- **I9001** `rNACLAssocAppPrivSubnetA` (AWS::EC2::SubnetNetworkAclAssociation) → `Properties.SubnetId` L325 in `quickstart_nist_vpc_production`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `rNACLAssocAppPrivSubnetB` (AWS::EC2::SubnetNetworkAclAssociation) → `Properties.NetworkAclId` L332 in `quickstart_nist_vpc_production`
  > Property 'NetworkAclId' is create-only; updating it will cause resource replacement
- **I9001** `rNACLAssocAppPrivSubnetB` (AWS::EC2::SubnetNetworkAclAssociation) → `Properties.SubnetId` L332 in `quickstart_nist_vpc_production`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `rNACLAssocDBPrivSubnetA` (AWS::EC2::SubnetNetworkAclAssociation) → `Properties.NetworkAclId` L339 in `quickstart_nist_vpc_production`
  > Property 'NetworkAclId' is create-only; updating it will cause resource replacement
- **I9001** `rNACLAssocDBPrivSubnetA` (AWS::EC2::SubnetNetworkAclAssociation) → `Properties.SubnetId` L339 in `quickstart_nist_vpc_production`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `rNACLAssocDBPrivSubnetB` (AWS::EC2::SubnetNetworkAclAssociation) → `Properties.NetworkAclId` L346 in `quickstart_nist_vpc_production`
  > Property 'NetworkAclId' is create-only; updating it will cause resource replacement
- **I9001** `rNACLAssocDBPrivSubnetB` (AWS::EC2::SubnetNetworkAclAssociation) → `Properties.SubnetId` L346 in `quickstart_nist_vpc_production`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `rNACLAssocDMZPubSubnetA` (AWS::EC2::SubnetNetworkAclAssociation) → `Properties.NetworkAclId` L353 in `quickstart_nist_vpc_production`
  > Property 'NetworkAclId' is create-only; updating it will cause resource replacement
- **I9001** `rNACLAssocDMZPubSubnetA` (AWS::EC2::SubnetNetworkAclAssociation) → `Properties.SubnetId` L353 in `quickstart_nist_vpc_production`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `rNACLAssocDMZPubSubnetB` (AWS::EC2::SubnetNetworkAclAssociation) → `Properties.NetworkAclId` L360 in `quickstart_nist_vpc_production`
  > Property 'NetworkAclId' is create-only; updating it will cause resource replacement
- **I9001** `rNACLAssocDMZPubSubnetB` (AWS::EC2::SubnetNetworkAclAssociation) → `Properties.SubnetId` L360 in `quickstart_nist_vpc_production`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `rNACLPrivate` (AWS::EC2::NetworkAcl) → `Properties.VpcId` L367 in `quickstart_nist_vpc_production`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rNACLPublic` (AWS::EC2::NetworkAcl) → `Properties.VpcId` L372 in `quickstart_nist_vpc_production`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rNACLRuleAllowALLEgressPublic` (AWS::EC2::NetworkAclEntry) → `Properties.Egress` L377 in `quickstart_nist_vpc_production`
  > Property 'Egress' is create-only; updating it will cause resource replacement
- **I9001** `rNACLRuleAllowALLEgressPublic` (AWS::EC2::NetworkAclEntry) → `Properties.NetworkAclId` L377 in `quickstart_nist_vpc_production`
  > Property 'NetworkAclId' is create-only; updating it will cause resource replacement
- **I9001** `rNACLRuleAllowALLEgressPublic` (AWS::EC2::NetworkAclEntry) → `Properties.RuleNumber` L377 in `quickstart_nist_vpc_production`
  > Property 'RuleNumber' is create-only; updating it will cause resource replacement
- **I9001** `rNACLRuleAllowALLfromPrivEgress` (AWS::EC2::NetworkAclEntry) → `Properties.Egress` L390 in `quickstart_nist_vpc_production`
  > Property 'Egress' is create-only; updating it will cause resource replacement
- **I9001** `rNACLRuleAllowALLfromPrivEgress` (AWS::EC2::NetworkAclEntry) → `Properties.NetworkAclId` L390 in `quickstart_nist_vpc_production`
  > Property 'NetworkAclId' is create-only; updating it will cause resource replacement
- **I9001** `rNACLRuleAllowALLfromPrivEgress` (AWS::EC2::NetworkAclEntry) → `Properties.RuleNumber` L390 in `quickstart_nist_vpc_production`
  > Property 'RuleNumber' is create-only; updating it will cause resource replacement
- **I9001** `rNACLRuleAllowAllReturnTCP` (AWS::EC2::NetworkAclEntry) → `Properties.NetworkAclId` L403 in `quickstart_nist_vpc_production`
  > Property 'NetworkAclId' is create-only; updating it will cause resource replacement
- **I9001** `rNACLRuleAllowAllReturnTCP` (AWS::EC2::NetworkAclEntry) → `Properties.RuleNumber` L403 in `quickstart_nist_vpc_production`
  > Property 'RuleNumber' is create-only; updating it will cause resource replacement
- **I9001** `rNACLRuleAllowAllTCPInternal` (AWS::EC2::NetworkAclEntry) → `Properties.NetworkAclId` L415 in `quickstart_nist_vpc_production`
  > Property 'NetworkAclId' is create-only; updating it will cause resource replacement
- **I9001** `rNACLRuleAllowAllTCPInternal` (AWS::EC2::NetworkAclEntry) → `Properties.RuleNumber` L415 in `quickstart_nist_vpc_production`
  > Property 'RuleNumber' is create-only; updating it will cause resource replacement
- **I9001** `rNACLRuleAllowAllTCPInternalEgress` (AWS::EC2::NetworkAclEntry) → `Properties.Egress` L428 in `quickstart_nist_vpc_production`
  > Property 'Egress' is create-only; updating it will cause resource replacement
- **I9001** `rNACLRuleAllowAllTCPInternalEgress` (AWS::EC2::NetworkAclEntry) → `Properties.NetworkAclId` L428 in `quickstart_nist_vpc_production`
  > Property 'NetworkAclId' is create-only; updating it will cause resource replacement
- **I9001** `rNACLRuleAllowAllTCPInternalEgress` (AWS::EC2::NetworkAclEntry) → `Properties.RuleNumber` L428 in `quickstart_nist_vpc_production`
  > Property 'RuleNumber' is create-only; updating it will cause resource replacement
- **I9001** `rNACLRuleAllowBastionSSHAccess` (AWS::EC2::NetworkAclEntry) → `Properties.NetworkAclId` L441 in `quickstart_nist_vpc_production`
  > Property 'NetworkAclId' is create-only; updating it will cause resource replacement
- **I9001** `rNACLRuleAllowBastionSSHAccess` (AWS::EC2::NetworkAclEntry) → `Properties.RuleNumber` L441 in `quickstart_nist_vpc_production`
  > Property 'RuleNumber' is create-only; updating it will cause resource replacement
- **I9001** `rNACLRuleAllowEgressReturnTCP` (AWS::EC2::NetworkAclEntry) → `Properties.Egress` L453 in `quickstart_nist_vpc_production`
  > Property 'Egress' is create-only; updating it will cause resource replacement
- **I9001** `rNACLRuleAllowEgressReturnTCP` (AWS::EC2::NetworkAclEntry) → `Properties.NetworkAclId` L453 in `quickstart_nist_vpc_production`
  > Property 'NetworkAclId' is create-only; updating it will cause resource replacement
- **I9001** `rNACLRuleAllowEgressReturnTCP` (AWS::EC2::NetworkAclEntry) → `Properties.RuleNumber` L453 in `quickstart_nist_vpc_production`
  > Property 'RuleNumber' is create-only; updating it will cause resource replacement
- **I9001** `rNACLRuleAllowHTTPSPublic` (AWS::EC2::NetworkAclEntry) → `Properties.NetworkAclId` L466 in `quickstart_nist_vpc_production`
  > Property 'NetworkAclId' is create-only; updating it will cause resource replacement
- **I9001** `rNACLRuleAllowHTTPSPublic` (AWS::EC2::NetworkAclEntry) → `Properties.RuleNumber` L466 in `quickstart_nist_vpc_production`
  > Property 'RuleNumber' is create-only; updating it will cause resource replacement
- **I9001** `rNACLRuleAllowHTTPfromProd` (AWS::EC2::NetworkAclEntry) → `Properties.NetworkAclId` L478 in `quickstart_nist_vpc_production`
  > Property 'NetworkAclId' is create-only; updating it will cause resource replacement
- **I9001** `rNACLRuleAllowHTTPfromProd` (AWS::EC2::NetworkAclEntry) → `Properties.RuleNumber` L478 in `quickstart_nist_vpc_production`
  > Property 'RuleNumber' is create-only; updating it will cause resource replacement
- **I9001** `rNACLRuleAllowMgmtAccessSSHtoPrivate` (AWS::EC2::NetworkAclEntry) → `Properties.NetworkAclId` L491 in `quickstart_nist_vpc_production`
  > Property 'NetworkAclId' is create-only; updating it will cause resource replacement
- **I9001** `rNACLRuleAllowMgmtAccessSSHtoPrivate` (AWS::EC2::NetworkAclEntry) → `Properties.RuleNumber` L491 in `quickstart_nist_vpc_production`
  > Property 'RuleNumber' is create-only; updating it will cause resource replacement
- **I9001** `rNACLRuleAllowReturnTCPPriv` (AWS::EC2::NetworkAclEntry) → `Properties.NetworkAclId` L504 in `quickstart_nist_vpc_production`
  > Property 'NetworkAclId' is create-only; updating it will cause resource replacement
- **I9001** `rNACLRuleAllowReturnTCPPriv` (AWS::EC2::NetworkAclEntry) → `Properties.RuleNumber` L504 in `quickstart_nist_vpc_production`
  > Property 'RuleNumber' is create-only; updating it will cause resource replacement
- **I9001** `rNATGateway` (AWS::EC2::NatGateway) → `Properties.AllocationId` L516 in `quickstart_nist_vpc_production`
  > Property 'AllocationId' is create-only; updating it will cause resource replacement
- **I9001** `rNATGateway` (AWS::EC2::NatGateway) → `Properties.SubnetId` L516 in `quickstart_nist_vpc_production`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteAssocDBPrivateA` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L556 in `quickstart_nist_vpc_production`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteAssocDBPrivateA` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L556 in `quickstart_nist_vpc_production`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteAssocDBPrivateB` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L563 in `quickstart_nist_vpc_production`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteAssocDBPrivateB` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L563 in `quickstart_nist_vpc_production`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteAssocProdDMZA` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L570 in `quickstart_nist_vpc_production`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteAssocProdDMZA` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L570 in `quickstart_nist_vpc_production`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteAssocProdDMZB` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L577 in `quickstart_nist_vpc_production`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteAssocProdDMZB` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L577 in `quickstart_nist_vpc_production`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteProdIGW` (AWS::EC2::Route) → `Properties.DestinationCidrBlock` L584 in `quickstart_nist_vpc_production`
  > Property 'DestinationCidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `rRouteProdIGW` (AWS::EC2::Route) → `Properties.RouteTableId` L584 in `quickstart_nist_vpc_production`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteProdPrivateNatGateway` (AWS::EC2::Route) → `Properties.DestinationCidrBlock` L593 in `quickstart_nist_vpc_production`
  > Property 'DestinationCidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `rRouteProdPrivateNatGateway` (AWS::EC2::Route) → `Properties.RouteTableId` L593 in `quickstart_nist_vpc_production`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteTableMain` (AWS::EC2::RouteTable) → `Properties.VpcId` L602 in `quickstart_nist_vpc_production`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteTableProdPrivate` (AWS::EC2::RouteTable) → `Properties.VpcId` L610 in `quickstart_nist_vpc_production`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupMgmtBastion` (AWS::EC2::SecurityGroup) → `Properties.GroupDescription` L618 in `quickstart_nist_vpc_production`
  > Property 'GroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupMgmtBastion` (AWS::EC2::SecurityGroup) → `Properties.VpcId` L618 in `quickstart_nist_vpc_production`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupSSHFromProd` (AWS::EC2::SecurityGroup) → `Properties.GroupDescription` L636 in `quickstart_nist_vpc_production`
  > Property 'GroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupSSHFromProd` (AWS::EC2::SecurityGroup) → `Properties.VpcId` L636 in `quickstart_nist_vpc_production`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupVpcNat` (AWS::EC2::SecurityGroup) → `Properties.GroupDescription` L654 in `quickstart_nist_vpc_production`
  > Property 'GroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupVpcNat` (AWS::EC2::SecurityGroup) → `Properties.VpcId` L654 in `quickstart_nist_vpc_production`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rVPCProduction` (AWS::EC2::VPC) → `Properties.CidrBlock` L677 in `quickstart_nist_vpc_production`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `AnsibleConfigServer` (AWS::EC2::Instance) → `Properties.ImageId` L280 in `quickstart_openshift`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `AnsibleConfigServer` (AWS::EC2::Instance) → `Properties.KeyName` L280 in `quickstart_openshift`
  > Property 'KeyName' is create-only; updating it will cause resource replacement
- **I9001** `AnsibleConfigServer` (AWS::EC2::Instance) → `Properties.NetworkInterfaces` L280 in `quickstart_openshift`
  > Property 'NetworkInterfaces' is create-only; updating it will cause resource replacement
- **I9001** `LambdaExecutionRole` (AWS::IAM::Role) → `Properties.Path` L814 in `quickstart_openshift`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `OpenShiftEtcdLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.BlockDeviceMappings` L861 in `quickstart_openshift`
  > Property 'BlockDeviceMappings' is create-only; updating it will cause resource replacement
- **I9001** `OpenShiftEtcdLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.IamInstanceProfile` L861 in `quickstart_openshift`
  > Property 'IamInstanceProfile' is create-only; updating it will cause resource replacement
- **I9001** `OpenShiftEtcdLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.ImageId` L861 in `quickstart_openshift`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `OpenShiftEtcdLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.InstanceMonitoring` L861 in `quickstart_openshift`
  > Property 'InstanceMonitoring' is create-only; updating it will cause resource replacement
- **I9001** `OpenShiftEtcdLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.InstanceType` L861 in `quickstart_openshift`
  > Property 'InstanceType' is create-only; updating it will cause resource replacement
- **I9001** `OpenShiftEtcdLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.KeyName` L861 in `quickstart_openshift`
  > Property 'KeyName' is create-only; updating it will cause resource replacement
- **I9001** `OpenShiftEtcdLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.SecurityGroups` L861 in `quickstart_openshift`
  > Property 'SecurityGroups' is create-only; updating it will cause resource replacement
- **I9001** `OpenShiftEtcdLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.UserData` L861 in `quickstart_openshift`
  > Property 'UserData' is create-only; updating it will cause resource replacement
- **I9001** `OpenShiftInternalSecurityGroup` (AWS::EC2::SecurityGroup) → `Properties.GroupDescription` L1055 in `quickstart_openshift`
  > Property 'GroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `OpenShiftInternalSecurityGroup` (AWS::EC2::SecurityGroup) → `Properties.VpcId` L1055 in `quickstart_openshift`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `OpenShiftMasterASLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.BlockDeviceMappings` L1085 in `quickstart_openshift`
  > Property 'BlockDeviceMappings' is create-only; updating it will cause resource replacement
- **I9001** `OpenShiftMasterASLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.IamInstanceProfile` L1085 in `quickstart_openshift`
  > Property 'IamInstanceProfile' is create-only; updating it will cause resource replacement
- **I9001** `OpenShiftMasterASLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.ImageId` L1085 in `quickstart_openshift`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `OpenShiftMasterASLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.InstanceMonitoring` L1085 in `quickstart_openshift`
  > Property 'InstanceMonitoring' is create-only; updating it will cause resource replacement
- **I9001** `OpenShiftMasterASLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.InstanceType` L1085 in `quickstart_openshift`
  > Property 'InstanceType' is create-only; updating it will cause resource replacement
- **I9001** `OpenShiftMasterASLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.KeyName` L1085 in `quickstart_openshift`
  > Property 'KeyName' is create-only; updating it will cause resource replacement
- **I9001** `OpenShiftMasterASLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.SecurityGroups` L1085 in `quickstart_openshift`
  > Property 'SecurityGroups' is create-only; updating it will cause resource replacement
- **I9001** `OpenShiftMasterASLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.UserData` L1085 in `quickstart_openshift`
  > Property 'UserData' is create-only; updating it will cause resource replacement
- **I9001** `OpenShiftMasterInternalELB` (AWS::ElasticLoadBalancing::LoadBalancer) → `Properties.Scheme` L1317 in `quickstart_openshift`
  > Property 'Scheme' is create-only; updating it will cause resource replacement
- **I9001** `OpenShiftNodeInternalELB` (AWS::ElasticLoadBalancing::LoadBalancer) → `Properties.Scheme` L1370 in `quickstart_openshift`
  > Property 'Scheme' is create-only; updating it will cause resource replacement
- **I9001** `OpenShiftNodeSecurityGroup` (AWS::EC2::SecurityGroup) → `Properties.GroupDescription` L1395 in `quickstart_openshift`
  > Property 'GroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `OpenShiftNodeSecurityGroup` (AWS::EC2::SecurityGroup) → `Properties.VpcId` L1395 in `quickstart_openshift`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `OpenShiftNodesLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.BlockDeviceMappings` L1415 in `quickstart_openshift`
  > Property 'BlockDeviceMappings' is create-only; updating it will cause resource replacement
- **I9001** `OpenShiftNodesLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.IamInstanceProfile` L1415 in `quickstart_openshift`
  > Property 'IamInstanceProfile' is create-only; updating it will cause resource replacement
- **I9001** `OpenShiftNodesLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.ImageId` L1415 in `quickstart_openshift`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `OpenShiftNodesLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.InstanceMonitoring` L1415 in `quickstart_openshift`
  > Property 'InstanceMonitoring' is create-only; updating it will cause resource replacement
- **I9001** `OpenShiftNodesLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.InstanceType` L1415 in `quickstart_openshift`
  > Property 'InstanceType' is create-only; updating it will cause resource replacement
- **I9001** `OpenShiftNodesLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.KeyName` L1415 in `quickstart_openshift`
  > Property 'KeyName' is create-only; updating it will cause resource replacement
- **I9001** `OpenShiftNodesLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.SecurityGroups` L1415 in `quickstart_openshift`
  > Property 'SecurityGroups' is create-only; updating it will cause resource replacement
- **I9001** `OpenShiftNodesLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.UserData` L1415 in `quickstart_openshift`
  > Property 'UserData' is create-only; updating it will cause resource replacement
- **I9001** `OpenShiftSecurityGroup` (AWS::EC2::SecurityGroup) → `Properties.GroupDescription` L1637 in `quickstart_openshift`
  > Property 'GroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `OpenShiftSecurityGroup` (AWS::EC2::SecurityGroup) → `Properties.VpcId` L1637 in `quickstart_openshift`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `SetupRole` (AWS::IAM::Role) → `Properties.Path` L1657 in `quickstart_openshift`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `SetupRoleProfile` (AWS::IAM::InstanceProfile) → `Properties.Path` L1688 in `quickstart_openshift`
  > Property 'Path' is create-only; updating it will cause resource replacement
- **I9001** `rParameterGroup` (AWS::RDS::DBParameterGroup) → `Properties.Description` L57 in `quickstart_test`
  > Property 'Description' is create-only; updating it will cause resource replacement
- **I9001** `rParameterGroup` (AWS::RDS::DBParameterGroup) → `Properties.Family` L57 in `quickstart_test`
  > Property 'Family' is create-only; updating it will cause resource replacement
- **I9001** `rDBServerInstance` (AWS::RDS::DBInstance) → `Properties.DBSubnetGroupName` L124 in `quickstart_test`
  > Property 'DBSubnetGroupName' is create-only; updating it will cause resource replacement
- **I9001** `rDBServerInstance` (AWS::RDS::DBInstance) → `Properties.MasterUsername` L124 in `quickstart_test`
  > Property 'MasterUsername' is create-only; updating it will cause resource replacement
- **I9001** `rDBServerInstance` (AWS::RDS::DBInstance) → `Properties.StorageEncrypted` L124 in `quickstart_test`
  > Property 'StorageEncrypted' is create-only; updating it will cause resource replacement
- **I9001** `DHCPOptions` (AWS::EC2::DHCPOptions) → `Properties.DomainName` L481 in `quickstart_vpc`
  > Property 'DomainName' is create-only; updating it will cause resource replacement
- **I9001** `DHCPOptions` (AWS::EC2::DHCPOptions) → `Properties.DomainNameServers` L481 in `quickstart_vpc`
  > Property 'DomainNameServers' is create-only; updating it will cause resource replacement
- **I9001** `VPC` (AWS::EC2::VPC) → `Properties.CidrBlock` L506 in `quickstart_vpc`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `VPCDHCPOptionsAssociation` (AWS::EC2::VPCDHCPOptionsAssociation) → `Properties.DhcpOptionsId` L527 in `quickstart_vpc`
  > Property 'DhcpOptionsId' is create-only; updating it will cause resource replacement
- **I9001** `VPCDHCPOptionsAssociation` (AWS::EC2::VPCDHCPOptionsAssociation) → `Properties.VpcId` L527 in `quickstart_vpc`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `VPCGatewayAttachment` (AWS::EC2::VPCGatewayAttachment) → `Properties.VpcId` L555 in `quickstart_vpc`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet1A` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L566 in `quickstart_vpc`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet1A` (AWS::EC2::Subnet) → `Properties.CidrBlock` L566 in `quickstart_vpc`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet1A` (AWS::EC2::Subnet) → `Properties.VpcId` L566 in `quickstart_vpc`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet1B` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L596 in `quickstart_vpc`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet1B` (AWS::EC2::Subnet) → `Properties.CidrBlock` L596 in `quickstart_vpc`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet1B` (AWS::EC2::Subnet) → `Properties.VpcId` L596 in `quickstart_vpc`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet2A` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L626 in `quickstart_vpc`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet2A` (AWS::EC2::Subnet) → `Properties.CidrBlock` L626 in `quickstart_vpc`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet2A` (AWS::EC2::Subnet) → `Properties.VpcId` L626 in `quickstart_vpc`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet2B` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L656 in `quickstart_vpc`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet2B` (AWS::EC2::Subnet) → `Properties.CidrBlock` L656 in `quickstart_vpc`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet2B` (AWS::EC2::Subnet) → `Properties.VpcId` L656 in `quickstart_vpc`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet3A` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L686 in `quickstart_vpc`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet3A` (AWS::EC2::Subnet) → `Properties.CidrBlock` L686 in `quickstart_vpc`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet3A` (AWS::EC2::Subnet) → `Properties.VpcId` L686 in `quickstart_vpc`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet3B` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L716 in `quickstart_vpc`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet3B` (AWS::EC2::Subnet) → `Properties.CidrBlock` L716 in `quickstart_vpc`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet3B` (AWS::EC2::Subnet) → `Properties.VpcId` L716 in `quickstart_vpc`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet4A` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L746 in `quickstart_vpc`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet4A` (AWS::EC2::Subnet) → `Properties.CidrBlock` L746 in `quickstart_vpc`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet4A` (AWS::EC2::Subnet) → `Properties.VpcId` L746 in `quickstart_vpc`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet4B` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L776 in `quickstart_vpc`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet4B` (AWS::EC2::Subnet) → `Properties.CidrBlock` L776 in `quickstart_vpc`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet4B` (AWS::EC2::Subnet) → `Properties.VpcId` L776 in `quickstart_vpc`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `PublicSubnet1` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L806 in `quickstart_vpc`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `PublicSubnet1` (AWS::EC2::Subnet) → `Properties.CidrBlock` L806 in `quickstart_vpc`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `PublicSubnet1` (AWS::EC2::Subnet) → `Properties.VpcId` L806 in `quickstart_vpc`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `PublicSubnet2` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L836 in `quickstart_vpc`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `PublicSubnet2` (AWS::EC2::Subnet) → `Properties.CidrBlock` L836 in `quickstart_vpc`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `PublicSubnet2` (AWS::EC2::Subnet) → `Properties.VpcId` L836 in `quickstart_vpc`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `PublicSubnet3` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L866 in `quickstart_vpc`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `PublicSubnet3` (AWS::EC2::Subnet) → `Properties.CidrBlock` L866 in `quickstart_vpc`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `PublicSubnet3` (AWS::EC2::Subnet) → `Properties.VpcId` L866 in `quickstart_vpc`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `PublicSubnet4` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L897 in `quickstart_vpc`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `PublicSubnet4` (AWS::EC2::Subnet) → `Properties.CidrBlock` L897 in `quickstart_vpc`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `PublicSubnet4` (AWS::EC2::Subnet) → `Properties.VpcId` L897 in `quickstart_vpc`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet1ARouteTable` (AWS::EC2::RouteTable) → `Properties.VpcId` L928 in `quickstart_vpc`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet1ARoute` (AWS::EC2::Route) → `Properties.DestinationCidrBlock` L947 in `quickstart_vpc`
  > Property 'DestinationCidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet1ARoute` (AWS::EC2::Route) → `Properties.RouteTableId` L947 in `quickstart_vpc`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet1ARouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L979 in `quickstart_vpc`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet1ARouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L979 in `quickstart_vpc`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet2ARouteTable` (AWS::EC2::RouteTable) → `Properties.VpcId` L991 in `quickstart_vpc`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet2ARoute` (AWS::EC2::Route) → `Properties.DestinationCidrBlock` L1010 in `quickstart_vpc`
  > Property 'DestinationCidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet2ARoute` (AWS::EC2::Route) → `Properties.RouteTableId` L1010 in `quickstart_vpc`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet2ARouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L1042 in `quickstart_vpc`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet2ARouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L1042 in `quickstart_vpc`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet3ARouteTable` (AWS::EC2::RouteTable) → `Properties.VpcId` L1054 in `quickstart_vpc`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet3ARoute` (AWS::EC2::Route) → `Properties.DestinationCidrBlock` L1073 in `quickstart_vpc`
  > Property 'DestinationCidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet3ARoute` (AWS::EC2::Route) → `Properties.RouteTableId` L1073 in `quickstart_vpc`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet3ARouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L1105 in `quickstart_vpc`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet3ARouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L1105 in `quickstart_vpc`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet4ARouteTable` (AWS::EC2::RouteTable) → `Properties.VpcId` L1117 in `quickstart_vpc`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet4ARoute` (AWS::EC2::Route) → `Properties.DestinationCidrBlock` L1136 in `quickstart_vpc`
  > Property 'DestinationCidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet4ARoute` (AWS::EC2::Route) → `Properties.RouteTableId` L1136 in `quickstart_vpc`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet4ARouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L1168 in `quickstart_vpc`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet4ARouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L1168 in `quickstart_vpc`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet1BRouteTable` (AWS::EC2::RouteTable) → `Properties.VpcId` L1180 in `quickstart_vpc`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet1BRoute` (AWS::EC2::Route) → `Properties.DestinationCidrBlock` L1199 in `quickstart_vpc`
  > Property 'DestinationCidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet1BRoute` (AWS::EC2::Route) → `Properties.RouteTableId` L1199 in `quickstart_vpc`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet1BRouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L1231 in `quickstart_vpc`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet1BRouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L1231 in `quickstart_vpc`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet1BNetworkAcl` (AWS::EC2::NetworkAcl) → `Properties.VpcId` L1243 in `quickstart_vpc`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet1BNetworkAclEntryInbound` (AWS::EC2::NetworkAclEntry) → `Properties.Egress` L1262 in `quickstart_vpc`
  > Property 'Egress' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet1BNetworkAclEntryInbound` (AWS::EC2::NetworkAclEntry) → `Properties.NetworkAclId` L1262 in `quickstart_vpc`
  > Property 'NetworkAclId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet1BNetworkAclEntryInbound` (AWS::EC2::NetworkAclEntry) → `Properties.RuleNumber` L1262 in `quickstart_vpc`
  > Property 'RuleNumber' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet1BNetworkAclEntryOutbound` (AWS::EC2::NetworkAclEntry) → `Properties.Egress` L1276 in `quickstart_vpc`
  > Property 'Egress' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet1BNetworkAclEntryOutbound` (AWS::EC2::NetworkAclEntry) → `Properties.NetworkAclId` L1276 in `quickstart_vpc`
  > Property 'NetworkAclId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet1BNetworkAclEntryOutbound` (AWS::EC2::NetworkAclEntry) → `Properties.RuleNumber` L1276 in `quickstart_vpc`
  > Property 'RuleNumber' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet1BNetworkAclAssociation` (AWS::EC2::SubnetNetworkAclAssociation) → `Properties.NetworkAclId` L1290 in `quickstart_vpc`
  > Property 'NetworkAclId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet1BNetworkAclAssociation` (AWS::EC2::SubnetNetworkAclAssociation) → `Properties.SubnetId` L1290 in `quickstart_vpc`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet2BRouteTable` (AWS::EC2::RouteTable) → `Properties.VpcId` L1302 in `quickstart_vpc`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet2BRoute` (AWS::EC2::Route) → `Properties.DestinationCidrBlock` L1321 in `quickstart_vpc`
  > Property 'DestinationCidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet2BRoute` (AWS::EC2::Route) → `Properties.RouteTableId` L1321 in `quickstart_vpc`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet2BRouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L1353 in `quickstart_vpc`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet2BRouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L1353 in `quickstart_vpc`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet2BNetworkAcl` (AWS::EC2::NetworkAcl) → `Properties.VpcId` L1365 in `quickstart_vpc`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet2BNetworkAclEntryInbound` (AWS::EC2::NetworkAclEntry) → `Properties.Egress` L1384 in `quickstart_vpc`
  > Property 'Egress' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet2BNetworkAclEntryInbound` (AWS::EC2::NetworkAclEntry) → `Properties.NetworkAclId` L1384 in `quickstart_vpc`
  > Property 'NetworkAclId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet2BNetworkAclEntryInbound` (AWS::EC2::NetworkAclEntry) → `Properties.RuleNumber` L1384 in `quickstart_vpc`
  > Property 'RuleNumber' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet2BNetworkAclEntryOutbound` (AWS::EC2::NetworkAclEntry) → `Properties.Egress` L1398 in `quickstart_vpc`
  > Property 'Egress' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet2BNetworkAclEntryOutbound` (AWS::EC2::NetworkAclEntry) → `Properties.NetworkAclId` L1398 in `quickstart_vpc`
  > Property 'NetworkAclId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet2BNetworkAclEntryOutbound` (AWS::EC2::NetworkAclEntry) → `Properties.RuleNumber` L1398 in `quickstart_vpc`
  > Property 'RuleNumber' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet2BNetworkAclAssociation` (AWS::EC2::SubnetNetworkAclAssociation) → `Properties.NetworkAclId` L1412 in `quickstart_vpc`
  > Property 'NetworkAclId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet2BNetworkAclAssociation` (AWS::EC2::SubnetNetworkAclAssociation) → `Properties.SubnetId` L1412 in `quickstart_vpc`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet3BRouteTable` (AWS::EC2::RouteTable) → `Properties.VpcId` L1424 in `quickstart_vpc`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet3BRoute` (AWS::EC2::Route) → `Properties.DestinationCidrBlock` L1443 in `quickstart_vpc`
  > Property 'DestinationCidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet3BRoute` (AWS::EC2::Route) → `Properties.RouteTableId` L1443 in `quickstart_vpc`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet3BRouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L1475 in `quickstart_vpc`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet3BRouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L1475 in `quickstart_vpc`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet3BNetworkAcl` (AWS::EC2::NetworkAcl) → `Properties.VpcId` L1487 in `quickstart_vpc`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet3BNetworkAclEntryInbound` (AWS::EC2::NetworkAclEntry) → `Properties.Egress` L1506 in `quickstart_vpc`
  > Property 'Egress' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet3BNetworkAclEntryInbound` (AWS::EC2::NetworkAclEntry) → `Properties.NetworkAclId` L1506 in `quickstart_vpc`
  > Property 'NetworkAclId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet3BNetworkAclEntryInbound` (AWS::EC2::NetworkAclEntry) → `Properties.RuleNumber` L1506 in `quickstart_vpc`
  > Property 'RuleNumber' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet3BNetworkAclEntryOutbound` (AWS::EC2::NetworkAclEntry) → `Properties.Egress` L1520 in `quickstart_vpc`
  > Property 'Egress' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet3BNetworkAclEntryOutbound` (AWS::EC2::NetworkAclEntry) → `Properties.NetworkAclId` L1520 in `quickstart_vpc`
  > Property 'NetworkAclId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet3BNetworkAclEntryOutbound` (AWS::EC2::NetworkAclEntry) → `Properties.RuleNumber` L1520 in `quickstart_vpc`
  > Property 'RuleNumber' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet3BNetworkAclAssociation` (AWS::EC2::SubnetNetworkAclAssociation) → `Properties.NetworkAclId` L1534 in `quickstart_vpc`
  > Property 'NetworkAclId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet3BNetworkAclAssociation` (AWS::EC2::SubnetNetworkAclAssociation) → `Properties.SubnetId` L1534 in `quickstart_vpc`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet4BRouteTable` (AWS::EC2::RouteTable) → `Properties.VpcId` L1546 in `quickstart_vpc`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet4BRoute` (AWS::EC2::Route) → `Properties.DestinationCidrBlock` L1565 in `quickstart_vpc`
  > Property 'DestinationCidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet4BRoute` (AWS::EC2::Route) → `Properties.RouteTableId` L1565 in `quickstart_vpc`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet4BRouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L1597 in `quickstart_vpc`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet4BRouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L1597 in `quickstart_vpc`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet4BNetworkAcl` (AWS::EC2::NetworkAcl) → `Properties.VpcId` L1609 in `quickstart_vpc`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet4BNetworkAclEntryInbound` (AWS::EC2::NetworkAclEntry) → `Properties.Egress` L1628 in `quickstart_vpc`
  > Property 'Egress' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet4BNetworkAclEntryInbound` (AWS::EC2::NetworkAclEntry) → `Properties.NetworkAclId` L1628 in `quickstart_vpc`
  > Property 'NetworkAclId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet4BNetworkAclEntryInbound` (AWS::EC2::NetworkAclEntry) → `Properties.RuleNumber` L1628 in `quickstart_vpc`
  > Property 'RuleNumber' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet4BNetworkAclEntryOutbound` (AWS::EC2::NetworkAclEntry) → `Properties.Egress` L1642 in `quickstart_vpc`
  > Property 'Egress' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet4BNetworkAclEntryOutbound` (AWS::EC2::NetworkAclEntry) → `Properties.NetworkAclId` L1642 in `quickstart_vpc`
  > Property 'NetworkAclId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet4BNetworkAclEntryOutbound` (AWS::EC2::NetworkAclEntry) → `Properties.RuleNumber` L1642 in `quickstart_vpc`
  > Property 'RuleNumber' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet4BNetworkAclAssociation` (AWS::EC2::SubnetNetworkAclAssociation) → `Properties.NetworkAclId` L1656 in `quickstart_vpc`
  > Property 'NetworkAclId' is create-only; updating it will cause resource replacement
- **I9001** `PrivateSubnet4BNetworkAclAssociation` (AWS::EC2::SubnetNetworkAclAssociation) → `Properties.SubnetId` L1656 in `quickstart_vpc`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `PublicSubnetRouteTable` (AWS::EC2::RouteTable) → `Properties.VpcId` L1668 in `quickstart_vpc`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `PublicSubnetRoute` (AWS::EC2::Route) → `Properties.DestinationCidrBlock` L1686 in `quickstart_vpc`
  > Property 'DestinationCidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `PublicSubnetRoute` (AWS::EC2::Route) → `Properties.RouteTableId` L1686 in `quickstart_vpc`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `PublicSubnet1RouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L1699 in `quickstart_vpc`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `PublicSubnet1RouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L1699 in `quickstart_vpc`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `PublicSubnet2RouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L1710 in `quickstart_vpc`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `PublicSubnet2RouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L1710 in `quickstart_vpc`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `PublicSubnet3RouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L1721 in `quickstart_vpc`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `PublicSubnet3RouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L1721 in `quickstart_vpc`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `PublicSubnet4RouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L1733 in `quickstart_vpc`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `PublicSubnet4RouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L1733 in `quickstart_vpc`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `NATGateway1` (AWS::EC2::NatGateway) → `Properties.AllocationId` L1821 in `quickstart_vpc`
  > Property 'AllocationId' is create-only; updating it will cause resource replacement
- **I9001** `NATGateway1` (AWS::EC2::NatGateway) → `Properties.SubnetId` L1821 in `quickstart_vpc`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `NATGateway2` (AWS::EC2::NatGateway) → `Properties.AllocationId` L1837 in `quickstart_vpc`
  > Property 'AllocationId' is create-only; updating it will cause resource replacement
- **I9001** `NATGateway2` (AWS::EC2::NatGateway) → `Properties.SubnetId` L1837 in `quickstart_vpc`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `NATGateway3` (AWS::EC2::NatGateway) → `Properties.AllocationId` L1853 in `quickstart_vpc`
  > Property 'AllocationId' is create-only; updating it will cause resource replacement
- **I9001** `NATGateway3` (AWS::EC2::NatGateway) → `Properties.SubnetId` L1853 in `quickstart_vpc`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `NATGateway4` (AWS::EC2::NatGateway) → `Properties.AllocationId` L1869 in `quickstart_vpc`
  > Property 'AllocationId' is create-only; updating it will cause resource replacement
- **I9001** `NATGateway4` (AWS::EC2::NatGateway) → `Properties.SubnetId` L1869 in `quickstart_vpc`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `NATInstance1` (AWS::EC2::Instance) → `Properties.ImageId` L1885 in `quickstart_vpc`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `NATInstance1` (AWS::EC2::Instance) → `Properties.KeyName` L1885 in `quickstart_vpc`
  > Property 'KeyName' is create-only; updating it will cause resource replacement
- **I9001** `NATInstance1` (AWS::EC2::Instance) → `Properties.NetworkInterfaces` L1885 in `quickstart_vpc`
  > Property 'NetworkInterfaces' is create-only; updating it will cause resource replacement
- **I9001** `NATInstance2` (AWS::EC2::Instance) → `Properties.ImageId` L1937 in `quickstart_vpc`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `NATInstance2` (AWS::EC2::Instance) → `Properties.KeyName` L1937 in `quickstart_vpc`
  > Property 'KeyName' is create-only; updating it will cause resource replacement
- **I9001** `NATInstance2` (AWS::EC2::Instance) → `Properties.NetworkInterfaces` L1937 in `quickstart_vpc`
  > Property 'NetworkInterfaces' is create-only; updating it will cause resource replacement
- **I9001** `NATInstance3` (AWS::EC2::Instance) → `Properties.ImageId` L1989 in `quickstart_vpc`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `NATInstance3` (AWS::EC2::Instance) → `Properties.KeyName` L1989 in `quickstart_vpc`
  > Property 'KeyName' is create-only; updating it will cause resource replacement
- **I9001** `NATInstance3` (AWS::EC2::Instance) → `Properties.NetworkInterfaces` L1989 in `quickstart_vpc`
  > Property 'NetworkInterfaces' is create-only; updating it will cause resource replacement
- **I9001** `NATInstance4` (AWS::EC2::Instance) → `Properties.ImageId` L2041 in `quickstart_vpc`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `NATInstance4` (AWS::EC2::Instance) → `Properties.KeyName` L2041 in `quickstart_vpc`
  > Property 'KeyName' is create-only; updating it will cause resource replacement
- **I9001** `NATInstance4` (AWS::EC2::Instance) → `Properties.NetworkInterfaces` L2041 in `quickstart_vpc`
  > Property 'NetworkInterfaces' is create-only; updating it will cause resource replacement
- **I9001** `NATInstanceSecurityGroup` (AWS::EC2::SecurityGroup) → `Properties.GroupDescription` L2093 in `quickstart_vpc`
  > Property 'GroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `NATInstanceSecurityGroup` (AWS::EC2::SecurityGroup) → `Properties.VpcId` L2093 in `quickstart_vpc`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `S3VPCEndpoint` (AWS::EC2::VPCEndpoint) → `Properties.ServiceName` L2113 in `quickstart_vpc`
  > Property 'ServiceName' is create-only; updating it will cause resource replacement
- **I9001** `S3VPCEndpoint` (AWS::EC2::VPCEndpoint) → `Properties.VpcId` L2113 in `quickstart_vpc`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rVPCManagement` (AWS::EC2::VPC) → `Properties.CidrBlock` L339 in `quickstart_vpc-management`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `rGWAttachmentMgmtIGW` (AWS::EC2::VPCGatewayAttachment) → `Properties.VpcId` L365 in `quickstart_vpc-management`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupPeered` (AWS::EC2::SecurityGroup) → `Properties.GroupDescription` L418 in `quickstart_vpc-management`
  > Property 'GroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupPeered` (AWS::EC2::SecurityGroup) → `Properties.VpcId` L418 in `quickstart_vpc-management`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupVpcNat` (AWS::EC2::SecurityGroup) → `Properties.GroupDescription` L437 in `quickstart_vpc-management`
  > Property 'GroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupVpcNat` (AWS::EC2::SecurityGroup) → `Properties.VpcId` L437 in `quickstart_vpc-management`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rManagementDMZSubnetA` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L465 in `quickstart_vpc-management`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `rManagementDMZSubnetA` (AWS::EC2::Subnet) → `Properties.CidrBlock` L465 in `quickstart_vpc-management`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `rManagementDMZSubnetA` (AWS::EC2::Subnet) → `Properties.VpcId` L465 in `quickstart_vpc-management`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rManagementDMZSubnetB` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L483 in `quickstart_vpc-management`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `rManagementDMZSubnetB` (AWS::EC2::Subnet) → `Properties.CidrBlock` L483 in `quickstart_vpc-management`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `rManagementDMZSubnetB` (AWS::EC2::Subnet) → `Properties.VpcId` L483 in `quickstart_vpc-management`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rManagementPrivateSubnetA` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L501 in `quickstart_vpc-management`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `rManagementPrivateSubnetA` (AWS::EC2::Subnet) → `Properties.CidrBlock` L501 in `quickstart_vpc-management`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `rManagementPrivateSubnetA` (AWS::EC2::Subnet) → `Properties.VpcId` L501 in `quickstart_vpc-management`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rManagementPrivateSubnetB` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L519 in `quickstart_vpc-management`
  > Property 'AvailabilityZone' is create-only; updating it will cause resource replacement
- **I9001** `rManagementPrivateSubnetB` (AWS::EC2::Subnet) → `Properties.CidrBlock` L519 in `quickstart_vpc-management`
  > Property 'CidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `rManagementPrivateSubnetB` (AWS::EC2::Subnet) → `Properties.VpcId` L519 in `quickstart_vpc-management`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rDHCPoptions` (AWS::EC2::DHCPOptions) → `Properties.DomainName` L538 in `quickstart_vpc-management`
  > Property 'DomainName' is create-only; updating it will cause resource replacement
- **I9001** `rDHCPoptions` (AWS::EC2::DHCPOptions) → `Properties.DomainNameServers` L538 in `quickstart_vpc-management`
  > Property 'DomainNameServers' is create-only; updating it will cause resource replacement
- **I9001** `rRouteTableMgmtPrivate` (AWS::EC2::RouteTable) → `Properties.VpcId` L555 in `quickstart_vpc-management`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteTableMgmtDMZ` (AWS::EC2::RouteTable) → `Properties.VpcId` L567 in `quickstart_vpc-management`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteMgmtIGW` (AWS::EC2::Route) → `Properties.DestinationCidrBlock` L579 in `quickstart_vpc-management`
  > Property 'DestinationCidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `rRouteMgmtIGW` (AWS::EC2::Route) → `Properties.RouteTableId` L579 in `quickstart_vpc-management`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteAssocMgmtDMZA` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L591 in `quickstart_vpc-management`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteAssocMgmtDMZA` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L591 in `quickstart_vpc-management`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `rrRouteAssocMgmtDMZB` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L602 in `quickstart_vpc-management`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `rrRouteAssocMgmtDMZB` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L602 in `quickstart_vpc-management`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteAssocMgmtPrivA` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L613 in `quickstart_vpc-management`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteAssocMgmtPrivA` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L613 in `quickstart_vpc-management`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteAssocMgmtPrivB` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.RouteTableId` L624 in `quickstart_vpc-management`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteAssocMgmtPrivB` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L624 in `quickstart_vpc-management`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `rMgmtBastionInstance` (AWS::EC2::Instance) → `Properties.ImageId` L635 in `quickstart_vpc-management`
  > Property 'ImageId' is create-only; updating it will cause resource replacement
- **I9001** `rMgmtBastionInstance` (AWS::EC2::Instance) → `Properties.KeyName` L635 in `quickstart_vpc-management`
  > Property 'KeyName' is create-only; updating it will cause resource replacement
- **I9001** `rMgmtBastionInstance` (AWS::EC2::Instance) → `Properties.NetworkInterfaces` L635 in `quickstart_vpc-management`
  > Property 'NetworkInterfaces' is create-only; updating it will cause resource replacement
- **I9001** `AssociaterEIPProdBastion` (AWS::EC2::EIPAssociation) → `Properties.AllocationId` L727 in `quickstart_vpc-management`
  > Property 'AllocationId' is create-only; updating it will cause resource replacement
- **I9001** `AssociaterEIPProdBastion` (AWS::EC2::EIPAssociation) → `Properties.NetworkInterfaceId` L727 in `quickstart_vpc-management`
  > Property 'NetworkInterfaceId' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupSSHFromMgmt` (AWS::EC2::SecurityGroup) → `Properties.GroupDescription` L742 in `quickstart_vpc-management`
  > Property 'GroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupSSHFromMgmt` (AWS::EC2::SecurityGroup) → `Properties.VpcId` L742 in `quickstart_vpc-management`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rNATGateway` (AWS::EC2::NatGateway) → `Properties.AllocationId` L771 in `quickstart_vpc-management`
  > Property 'AllocationId' is create-only; updating it will cause resource replacement
- **I9001** `rNATGateway` (AWS::EC2::NatGateway) → `Properties.SubnetId` L771 in `quickstart_vpc-management`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `rENIProductionBastion` (AWS::EC2::NetworkInterface) → `Properties.SubnetId` L784 in `quickstart_vpc-management`
  > Property 'SubnetId' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupBastion` (AWS::EC2::SecurityGroup) → `Properties.GroupDescription` L801 in `quickstart_vpc-management`
  > Property 'GroupDescription' is create-only; updating it will cause resource replacement
- **I9001** `rSecurityGroupBastion` (AWS::EC2::SecurityGroup) → `Properties.VpcId` L801 in `quickstart_vpc-management`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rDHCPOptionsAssocMgmt` (AWS::EC2::VPCDHCPOptionsAssociation) → `Properties.DhcpOptionsId` L828 in `quickstart_vpc-management`
  > Property 'DhcpOptionsId' is create-only; updating it will cause resource replacement
- **I9001** `rDHCPOptionsAssocMgmt` (AWS::EC2::VPCDHCPOptionsAssociation) → `Properties.VpcId` L828 in `quickstart_vpc-management`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rPeeringConnectionProduction` (AWS::EC2::VPCPeeringConnection) → `Properties.PeerVpcId` L839 in `quickstart_vpc-management`
  > Property 'PeerVpcId' is create-only; updating it will cause resource replacement
- **I9001** `rPeeringConnectionProduction` (AWS::EC2::VPCPeeringConnection) → `Properties.VpcId` L839 in `quickstart_vpc-management`
  > Property 'VpcId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteMgmtProdPrivate` (AWS::EC2::Route) → `Properties.DestinationCidrBlock` L855 in `quickstart_vpc-management`
  > Property 'DestinationCidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `rRouteMgmtProdPrivate` (AWS::EC2::Route) → `Properties.RouteTableId` L855 in `quickstart_vpc-management`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteProdMgmt` (AWS::EC2::Route) → `Properties.DestinationCidrBlock` L870 in `quickstart_vpc-management`
  > Property 'DestinationCidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `rRouteProdMgmt` (AWS::EC2::Route) → `Properties.RouteTableId` L870 in `quickstart_vpc-management`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteProdMgmtPublic` (AWS::EC2::Route) → `Properties.DestinationCidrBlock` L885 in `quickstart_vpc-management`
  > Property 'DestinationCidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `rRouteProdMgmtPublic` (AWS::EC2::Route) → `Properties.RouteTableId` L885 in `quickstart_vpc-management`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement
- **I9001** `rRouteMgmtProdDMZ` (AWS::EC2::Route) → `Properties.DestinationCidrBlock` L900 in `quickstart_vpc-management`
  > Property 'DestinationCidrBlock' is create-only; updating it will cause resource replacement
- **I9001** `rRouteMgmtProdDMZ` (AWS::EC2::Route) → `Properties.RouteTableId` L900 in `quickstart_vpc-management`
  > Property 'RouteTableId' is create-only; updating it will cause resource replacement

### I9040 — 453 findings

- **I9040** `NewVolume` (AWS::EC2::Volume) → `Properties.Tags` L77 in `bad_conditions`
  > Resource 'NewVolume' of type 'AWS::EC2::Volume' supports Tags but none are configured
- **I9040** `CloudFrontDistribution` (AWS::CloudFront::Distribution) → `Properties.Tags` L83 in `bad_conditions`
  > Resource 'CloudFrontDistribution' of type 'AWS::CloudFront::Distribution' supports Tags but none are configured
- **I9040** `mySubnet` (AWS::EC2::Subnet) → `Properties.Tags` L22 in `bad_core_conditions`
  > Resource 'mySubnet' of type 'AWS::EC2::Subnet' supports Tags but none are configured
- **I9040** `myInstance1` (AWS::EC2::Instance) → `Properties.Tags` L28 in `bad_core_conditions`
  > Resource 'myInstance1' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `myInstance2` (AWS::EC2::Instance) → `Properties.Tags` L33 in `bad_core_conditions`
  > Resource 'myInstance2' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `myInstance3` (AWS::EC2::Instance) → `Properties.Tags` L50 in `bad_core_conditions`
  > Resource 'myInstance3' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `myInstance4` (AWS::EC2::Instance) → `Properties.Tags` L63 in `bad_core_conditions`
  > Resource 'myInstance4' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `LambdaExecutionRole` (AWS::IAM::Role) → `Properties.Tags` L73 in `bad_core_conditions`
  > Resource 'LambdaExecutionRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `AMIIDLookup` (AWS::Lambda::Function) → `Properties.Tags` L96 in `bad_core_conditions`
  > Resource 'AMIIDLookup' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `myTable` (AWS::DynamoDB::Table) → `Properties.Tags` L13 in `bad_core_config_configure_e3012`
  > Resource 'myTable' of type 'AWS::DynamoDB::Table' supports Tags but none are configured
- **I9040** `myBucketPass` (AWS::S3::Bucket) → `Properties.Tags` L6 in `bad_core_directives`
  > Resource 'myBucketPass' of type 'AWS::S3::Bucket' supports Tags but none are configured
- **I9040** `myBucketFail` (AWS::S3::Bucket) → `Properties.Tags` L15 in `bad_core_directives`
  > Resource 'myBucketFail' of type 'AWS::S3::Bucket' supports Tags but none are configured
- **I9040** `myBucketFirstAndLastPass` (AWS::S3::Bucket) → `Properties.Tags` L19 in `bad_core_directives`
  > Resource 'myBucketFirstAndLastPass' of type 'AWS::S3::Bucket' supports Tags but none are configured
- **I9040** `myBucketFirstAndLastFail` (AWS::S3::Bucket) → `Properties.Tags` L32 in `bad_core_directives`
  > Resource 'myBucketFirstAndLastFail' of type 'AWS::S3::Bucket' supports Tags but none are configured
- **I9040** `myBucketPass` (AWS::S3::Bucket) → `Properties.Tags` L6 in `bad_core_mandatory_checks`
  > Resource 'myBucketPass' of type 'AWS::S3::Bucket' supports Tags but none are configured
- **I9040** `myBucketFail` (AWS::S3::Bucket) → `Properties.Tags` L15 in `bad_core_mandatory_checks`
  > Resource 'myBucketFail' of type 'AWS::S3::Bucket' supports Tags but none are configured
- **I9040** `myBucketFirstAndLastPass` (AWS::S3::Bucket) → `Properties.Tags` L19 in `bad_core_mandatory_checks`
  > Resource 'myBucketFirstAndLastPass' of type 'AWS::S3::Bucket' supports Tags but none are configured
- **I9040** `myBucketFirstAndLastFail` (AWS::S3::Bucket) → `Properties.Tags` L27 in `bad_core_mandatory_checks`
  > Resource 'myBucketFirstAndLastFail' of type 'AWS::S3::Bucket' supports Tags but none are configured
- **I9040** `myS3Bucket` (AWS::S3::Bucket) → `Properties.Tags` L8 in `bad_duplicate`
  > Resource 'myS3Bucket' of type 'AWS::S3::Bucket' supports Tags but none are configured
- **I9040** `mySnsTopic` (AWS::SNS::Topic) → `Properties.Tags` L14 in `bad_duplicate`
  > Resource 'mySnsTopic' of type 'AWS::SNS::Topic' supports Tags but none are configured
- **I9040** `myTable` (AWS::DynamoDB::Table) → `Properties.Tags` L7 in `bad_formatters`
  > Resource 'myTable' of type 'AWS::DynamoDB::Table' supports Tags but none are configured
- **I9040** `myInstance` (AWS::EC2::Instance) → `Properties.Tags` L7 in `bad_functions_base64`
  > Resource 'myInstance' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `mySubnet1` (AWS::EC2::Subnet) → `Properties.Tags` L11 in `bad_functions_getaz`
  > Resource 'mySubnet1' of type 'AWS::EC2::Subnet' supports Tags but none are configured
- **I9040** `mySubnet2` (AWS::EC2::Subnet) → `Properties.Tags` L20 in `bad_functions_getaz`
  > Resource 'mySubnet2' of type 'AWS::EC2::Subnet' supports Tags but none are configured
- **I9040** `mySubnet3` (AWS::EC2::Subnet) → `Properties.Tags` L29 in `bad_functions_getaz`
  > Resource 'mySubnet3' of type 'AWS::EC2::Subnet' supports Tags but none are configured
- **I9040** `subnet` (AWS::EC2::Subnet) → `Properties.Tags` L7 in `bad_functions_import_value`
  > Resource 'subnet' of type 'AWS::EC2::Subnet' supports Tags but none are configured
- **I9040** `myInstance` (AWS::EC2::Instance) → `Properties.Tags` L7 in `bad_functions_join`
  > Resource 'myInstance' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `myInstance2` (AWS::EC2::Instance) → `Properties.Tags` L17 in `bad_functions_join`
  > Resource 'myInstance2' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `mySecurityGroupVpc1` (AWS::EC2::SecurityGroup) → `Properties.Tags` L9 in `bad_functions_ref`
  > Resource 'mySecurityGroupVpc1' of type 'AWS::EC2::SecurityGroup' supports Tags but none are configured
- **I9040** `mySecurityGroupVpc2` (AWS::EC2::SecurityGroup) → `Properties.Tags` L21 in `bad_functions_ref`
  > Resource 'mySecurityGroupVpc2' of type 'AWS::EC2::SecurityGroup' supports Tags but none are configured
- **I9040** `MyEC2Instance` (AWS::EC2::Instance) → `Properties.Tags` L30 in `bad_functions_ref`
  > Resource 'MyEC2Instance' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `AnotherInstance` (AWS::EC2::Instance) → `Properties.Tags` L49 in `bad_functions_ref`
  > Resource 'AnotherInstance' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `LambdaExecutionRole` (AWS::IAM::Role) → `Properties.Tags` L12 in `bad_functions_relationship_conditions`
  > Resource 'LambdaExecutionRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `AMIIDLookup` (AWS::Lambda::Function) → `Properties.Tags` L34 in `bad_functions_relationship_conditions`
  > Resource 'AMIIDLookup' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `SubCondRefParam` (AWS::SSM::Parameter) → `Properties.Tags` L50 in `bad_functions_relationship_conditions`
  > Resource 'SubCondRefParam' of type 'AWS::SSM::Parameter' supports Tags but none are configured
- **I9040** `SubCondGetAttParam` (AWS::SSM::Parameter) → `Properties.Tags` L56 in `bad_functions_relationship_conditions`
  > Resource 'SubCondGetAttParam' of type 'AWS::SSM::Parameter' supports Tags but none are configured
- **I9040** `myInstance` (AWS::EC2::Instance) → `Properties.Tags` L7 in `bad_functions_select`
  > Resource 'myInstance' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `myInstance1` (AWS::EC2::Instance) → `Properties.Tags` L15 in `bad_functions_select`
  > Resource 'myInstance1' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `myInstance2` (AWS::EC2::Instance) → `Properties.Tags` L24 in `bad_functions_select`
  > Resource 'myInstance2' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `myInstance3` (AWS::EC2::Instance) → `Properties.Tags` L32 in `bad_functions_select`
  > Resource 'myInstance3' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `myInstance` (AWS::EC2::Instance) → `Properties.Tags` L9 in `bad_functions_sub_needed`
  > Resource 'myInstance' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `mySnsTopic` (AWS::SNS::Topic) → `Properties.Tags` L31 in `bad_functions_sub_needed`
  > Resource 'mySnsTopic' of type 'AWS::SNS::Topic' supports Tags but none are configured
- **I9040** `TestBadStateMachine1` (AWS::StepFunctions::StateMachine) → `Properties.Tags` L36 in `bad_functions_sub_needed`
  > Resource 'TestBadStateMachine1' of type 'AWS::StepFunctions::StateMachine' supports Tags but none are configured
- **I9040** `TestBadStateMachine2` (AWS::StepFunctions::StateMachine) → `Properties.Tags` L57 in `bad_functions_sub_needed`
  > Resource 'TestBadStateMachine2' of type 'AWS::StepFunctions::StateMachine' supports Tags but none are configured
- **I9040** `myIamProfile` (AWS::IAM::Role) → `Properties.Tags` L26 in `bad_generic`
  > Resource 'myIamProfile' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `myIamProfile2` (AWS::IAM::Role) → `Properties.Tags` L28 in `bad_generic`
  > Resource 'myIamProfile2' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `myIamProfile3` (AWS::IAM::Role) → `Properties.Tags` L31 in `bad_generic`
  > Resource 'myIamProfile3' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `MyEC2Instance` (AWS::EC2::Instance) → `Properties.Tags` L41 in `bad_generic`
  > Resource 'MyEC2Instance' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `MyEC2Instance3` (AWS::EC2::Instance) → `Properties.Tags` L61 in `bad_generic`
  > Resource 'MyEC2Instance3' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `myEc2Instance4` (AWS::EC2::Instance) → `Properties.Tags` L66 in `bad_generic`
  > Resource 'myEc2Instance4' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `RootRole` (AWS::IAM::Role) → `Properties.Tags` L70 in `bad_generic`
  > Resource 'RootRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `ElasticLoadBalancer` (AWS::ElasticLoadBalancing::LoadBalancer) → `Properties.Tags` L111 in `bad_generic`
  > Resource 'ElasticLoadBalancer' of type 'AWS::ElasticLoadBalancing::LoadBalancer' supports Tags but none are configured
- **I9040** `myLambdaTwo` (AWS::Lambda::Function) → `Properties.Tags` L145 in `bad_generic`
  > Resource 'myLambdaTwo' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `conditionLoadBalancer` (AWS::ElasticLoadBalancing::LoadBalancer) → `Properties.Tags` L149 in `bad_generic`
  > Resource 'conditionLoadBalancer' of type 'AWS::ElasticLoadBalancing::LoadBalancer' supports Tags but none are configured
- **I9040** `lambdaMap1` (AWS::EC2::SecurityGroup) → `Properties.Tags` L194 in `bad_generic`
  > Resource 'lambdaMap1' of type 'AWS::EC2::SecurityGroup' supports Tags but none are configured
- **I9040** `lambdaMap2` (AWS::EC2::SecurityGroup) → `Properties.Tags` L202 in `bad_generic`
  > Resource 'lambdaMap2' of type 'AWS::EC2::SecurityGroup' supports Tags but none are configured
- **I9040** `MyEc2BlockDevice` (AWS::EC2::Instance) → `Properties.Tags` L217 in `bad_generic`
  > Resource 'MyEc2BlockDevice' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `S3BadBucket` (AWS::S3::Bucket) → `Properties.Tags` L4 in `bad_hard_coded_arn_properties`
  > Resource 'S3BadBucket' of type 'AWS::S3::Bucket' supports Tags but none are configured
- **I9040** `SampleRole` (AWS::IAM::Role) → `Properties.Tags` L25 in `bad_hard_coded_arn_properties`
  > Resource 'SampleRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `RDSOptionGroup` (AWS::RDS::OptionGroup) → `Properties.Tags` L4 in `bad_issues`
  > Resource 'RDSOptionGroup' of type 'AWS::RDS::OptionGroup' supports Tags but none are configured
- **I9040** `mySubnet` (AWS::EC2::Subnet) → `Properties.Tags` L16 in `bad_mappings_used`
  > Resource 'mySubnet' of type 'AWS::EC2::Subnet' supports Tags but none are configured
- **I9040** `SNSTopicWithSecretNameInRef` (AWS::SNS::Topic) → `Properties.Tags` L9 in `bad_noecho`
  > Resource 'SNSTopicWithSecretNameInRef' of type 'AWS::SNS::Topic' supports Tags but none are configured
- **I9040** `SNSTopicWithSecretNameInSub` (AWS::SNS::Topic) → `Properties.Tags` L15 in `bad_noecho`
  > Resource 'SNSTopicWithSecretNameInSub' of type 'AWS::SNS::Topic' supports Tags but none are configured
- **I9040** `IamPipeline` (AWS::CloudFormation::Stack) → `Properties.Tags` L61 in `bad_parameters_configuration`
  > Resource 'IamPipeline' of type 'AWS::CloudFormation::Stack' supports Tags but none are configured
- **I9040** `Domain` (AWS::Elasticsearch::Domain) → `Properties.Tags` L3 in `bad_previous_generation_instances`
  > Resource 'Domain' of type 'AWS::Elasticsearch::Domain' supports Tags but none are configured
- **I9040** `Instance` (AWS::EC2::Instance) → `Properties.Tags` L5 in `bad_previous_generation_instances`
  > Resource 'Instance' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `DBInstance` (AWS::RDS::DBInstance) → `Properties.Tags` L10 in `bad_previous_generation_instances`
  > Resource 'DBInstance' of type 'AWS::RDS::DBInstance' supports Tags but none are configured
- **I9040** `CacheCluster` (AWS::ElastiCache::CacheCluster) → `Properties.Tags` L14 in `bad_previous_generation_instances`
  > Resource 'CacheCluster' of type 'AWS::ElastiCache::CacheCluster' supports Tags but none are configured
- **I9040** `Domain2` (AWS::Elasticsearch::Domain) → `Properties.Tags` L20 in `bad_previous_generation_instances`
  > Resource 'Domain2' of type 'AWS::Elasticsearch::Domain' supports Tags but none are configured
- **I9040** `Host` (AWS::EC2::Host) → `Properties.Tags` L25 in `bad_previous_generation_instances`
  > Resource 'Host' of type 'AWS::EC2::Host' supports Tags but none are configured
- **I9040** `MyEC2Instance` (AWS::EC2::Instance) → `Properties.Tags` L7 in `bad_properties_ebs`
  > Resource 'MyEC2Instance' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `MyEC2Instance3` (AWS::EC2::Instance) → `Properties.Tags` L30 in `bad_properties_ebs`
  > Resource 'MyEC2Instance3' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `MyDB` (AWS::RDS::DBInstance) → `Properties.Tags` L17 in `bad_properties_password`
  > Resource 'MyDB' of type 'AWS::RDS::DBInstance' supports Tags but none are configured
- **I9040** `MyNewDB` (AWS::RDS::DBInstance) → `Properties.Tags` L26 in `bad_properties_password`
  > Resource 'MyNewDB' of type 'AWS::RDS::DBInstance' supports Tags but none are configured
- **I9040** `myThirdDb` (AWS::RDS::DBInstance) → `Properties.Tags` L35 in `bad_properties_password`
  > Resource 'myThirdDb' of type 'AWS::RDS::DBInstance' supports Tags but none are configured
- **I9040** `mySecurityGroupNonVpc` (AWS::EC2::SecurityGroup) → `Properties.Tags` L21 in `bad_properties_sg_ingress`
  > Resource 'mySecurityGroupNonVpc' of type 'AWS::EC2::SecurityGroup' supports Tags but none are configured
- **I9040** `mySecurityGroupVpc` (AWS::EC2::SecurityGroup) → `Properties.Tags` L29 in `bad_properties_sg_ingress`
  > Resource 'mySecurityGroupVpc' of type 'AWS::EC2::SecurityGroup' supports Tags but none are configured
- **I9040** `myInstance` (AWS::EC2::Instance) → `Properties.Tags` L77 in `bad_properties_sg_ingress`
  > Resource 'myInstance' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `MyEC2Instance` (AWS::EC2::Instance) → `Properties.Tags` L5 in `bad_refs`
  > Resource 'MyEC2Instance' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `AnotherInstance` (AWS::EC2::Instance) → `Properties.Tags` L24 in `bad_refs`
  > Resource 'AnotherInstance' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `mySecurityGroupVpc1` (AWS::EC2::SecurityGroup) → `Properties.Tags` L24 in `bad_resources_circular_dependency`
  > Resource 'mySecurityGroupVpc1' of type 'AWS::EC2::SecurityGroup' supports Tags but none are configured
- **I9040** `mySecurityGroupVpc2` (AWS::EC2::SecurityGroup) → `Properties.Tags` L34 in `bad_resources_circular_dependency`
  > Resource 'mySecurityGroupVpc2' of type 'AWS::EC2::SecurityGroup' supports Tags but none are configured
- **I9040** `mySecurityGroupVpc3` (AWS::EC2::SecurityGroup) → `Properties.Tags` L42 in `bad_resources_circular_dependency`
  > Resource 'mySecurityGroupVpc3' of type 'AWS::EC2::SecurityGroup' supports Tags but none are configured
- **I9040** `myInstance` (AWS::EC2::Instance) → `Properties.Tags` L50 in `bad_resources_circular_dependency`
  > Resource 'myInstance' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `myBucket` (AWS::S3::Bucket) → `Properties.Tags` L63 in `bad_resources_circular_dependency`
  > Resource 'myBucket' of type 'AWS::S3::Bucket' supports Tags but none are configured
- **I9040** `myRoleToWriteToS3` (AWS::IAM::Role) → `Properties.Tags` L97 in `bad_resources_circular_dependency`
  > Resource 'myRoleToWriteToS3' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `myKms` (AWS::KMS::Key) → `Properties.Tags` L154 in `bad_resources_circular_dependency`
  > Resource 'myKms' of type 'AWS::KMS::Key' supports Tags but none are configured
- **I9040** `myInstanceSub` (AWS::EC2::Instance) → `Properties.Tags` L214 in `bad_resources_circular_dependency`
  > Resource 'myInstanceSub' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `taskdefinition` (AWS::ECS::TaskDefinition) → `Properties.Tags` L221 in `bad_resources_circular_dependency`
  > Resource 'taskdefinition' of type 'AWS::ECS::TaskDefinition' supports Tags but none are configured
- **I9040** `Resource` (AWS::SNS::Topic) → `Properties.Tags` L3 in `bad_resources_circular_dependency_2`
  > Resource 'Resource' of type 'AWS::SNS::Topic' supports Tags but none are configured
- **I9040** `Resource2` (AWS::SNS::Topic) → `Properties.Tags` L8 in `bad_resources_circular_dependency_2`
  > Resource 'Resource2' of type 'AWS::SNS::Topic' supports Tags but none are configured
- **I9040** `Resource3` (AWS::SNS::Topic) → `Properties.Tags` L13 in `bad_resources_circular_dependency_2`
  > Resource 'Resource3' of type 'AWS::SNS::Topic' supports Tags but none are configured
- **I9040** `Resource4` (AWS::SNS::Topic) → `Properties.Tags` L18 in `bad_resources_circular_dependency_2`
  > Resource 'Resource4' of type 'AWS::SNS::Topic' supports Tags but none are configured
- **I9040** `Resource5` (AWS::SNS::Topic) → `Properties.Tags` L23 in `bad_resources_circular_dependency_2`
  > Resource 'Resource5' of type 'AWS::SNS::Topic' supports Tags but none are configured
- **I9040** `Resource6` (AWS::SNS::Topic) → `Properties.Tags` L28 in `bad_resources_circular_dependency_2`
  > Resource 'Resource6' of type 'AWS::SNS::Topic' supports Tags but none are configured
- **I9040** `Resource7` (AWS::SNS::Topic) → `Properties.Tags` L33 in `bad_resources_circular_dependency_2`
  > Resource 'Resource7' of type 'AWS::SNS::Topic' supports Tags but none are configured
- **I9040** `Resource8` (AWS::SNS::Topic) → `Properties.Tags` L38 in `bad_resources_circular_dependency_2`
  > Resource 'Resource8' of type 'AWS::SNS::Topic' supports Tags but none are configured
- **I9040** `Resource9` (AWS::SNS::Topic) → `Properties.Tags` L43 in `bad_resources_circular_dependency_2`
  > Resource 'Resource9' of type 'AWS::SNS::Topic' supports Tags but none are configured
- **I9040** `Resource` (AWS::SNS::Topic) → `Properties.Tags` L5 in `bad_resources_circular_dependency_dependson`
  > Resource 'Resource' of type 'AWS::SNS::Topic' supports Tags but none are configured
- **I9040** `Resource2` (AWS::SNS::Topic) → `Properties.Tags` L8 in `bad_resources_circular_dependency_dependson`
  > Resource 'Resource2' of type 'AWS::SNS::Topic' supports Tags but none are configured
- **I9040** `CloudFrontDistribution` (AWS::CloudFront::Distribution) → `Properties.Tags` L4 in `bad_resources_cloudfront_invalid_aliases`
  > Resource 'CloudFrontDistribution' of type 'AWS::CloudFront::Distribution' supports Tags but none are configured
- **I9040** `PolicyList` (AWS::RDS::DBInstance) → `Properties.Tags` L11 in `bad_resources_deletionpolicy`
  > Resource 'PolicyList' of type 'AWS::RDS::DBInstance' supports Tags but none are configured
- **I9040** `MadeUpPolicy` (AWS::RDS::DBInstance) → `Properties.Tags` L18 in `bad_resources_deletionpolicy`
  > Resource 'MadeUpPolicy' of type 'AWS::RDS::DBInstance' supports Tags but none are configured
- **I9040** `MyIAMUser` (AWS::IAM::User) → `Properties.Tags` L25 in `bad_resources_deletionpolicy`
  > Resource 'MyIAMUser' of type 'AWS::IAM::User' supports Tags but none are configured
- **I9040** `InvalidMapping` (AWS::RDS::DBInstance) → `Properties.Tags` L38 in `bad_resources_deletionpolicy`
  > Resource 'InvalidMapping' of type 'AWS::RDS::DBInstance' supports Tags but none are configured
- **I9040** `my.Instance` (AWS::EC2::Instance) → `Properties.Tags` L4 in `bad_resources_name`
  > Resource 'my.Instance' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `my_Instance` (AWS::EC2::Instance) → `Properties.Tags` L8 in `bad_resources_name`
  > Resource 'my_Instance' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `RootRole` (AWS::IAM::Role) → `Properties.Tags` L6 in `bad_resources_primary_identifiers`
  > Resource 'RootRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `RootRole2` (AWS::IAM::Role) → `Properties.Tags` L28 in `bad_resources_primary_identifiers`
  > Resource 'RootRole2' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `RootRole3` (AWS::IAM::Role) → `Properties.Tags` L50 in `bad_resources_primary_identifiers`
  > Resource 'RootRole3' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `RootRole4` (AWS::IAM::Role) → `Properties.Tags` L73 in `bad_resources_primary_identifiers`
  > Resource 'RootRole4' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `RootRole5` (AWS::IAM::Role) → `Properties.Tags` L97 in `bad_resources_primary_identifiers`
  > Resource 'RootRole5' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `RootRole6` (AWS::IAM::Role) → `Properties.Tags` L119 in `bad_resources_primary_identifiers`
  > Resource 'RootRole6' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `Bucket1` (AWS::S3::Bucket) → `Properties.Tags` L141 in `bad_resources_primary_identifiers`
  > Resource 'Bucket1' of type 'AWS::S3::Bucket' supports Tags but none are configured
- **I9040** `Bucket2` (AWS::S3::Bucket) → `Properties.Tags` L148 in `bad_resources_primary_identifiers`
  > Resource 'Bucket2' of type 'AWS::S3::Bucket' supports Tags but none are configured
- **I9040** `Project1` (AWS::CodeBuild::Project) → `Properties.Tags` L166 in `bad_resources_primary_identifiers`
  > Resource 'Project1' of type 'AWS::CodeBuild::Project' supports Tags but none are configured
- **I9040** `Project2` (AWS::CodeBuild::Project) → `Properties.Tags` L186 in `bad_resources_primary_identifiers`
  > Resource 'Project2' of type 'AWS::CodeBuild::Project' supports Tags but none are configured
- **I9040** `Name` (AWS::SNS::Topic) → `Properties.Tags` L6 in `bad_resources_uniqueNames`
  > Resource 'Name' of type 'AWS::SNS::Topic' supports Tags but none are configured
- **I9040** `PolicyList` (AWS::RDS::DBInstance) → `Properties.Tags` L11 in `bad_resources_updatereplacepolicy`
  > Resource 'PolicyList' of type 'AWS::RDS::DBInstance' supports Tags but none are configured
- **I9040** `MadeUpPolicy` (AWS::RDS::DBInstance) → `Properties.Tags` L18 in `bad_resources_updatereplacepolicy`
  > Resource 'MadeUpPolicy' of type 'AWS::RDS::DBInstance' supports Tags but none are configured
- **I9040** `MyIAMUser` (AWS::IAM::User) → `Properties.Tags` L25 in `bad_resources_updatereplacepolicy`
  > Resource 'MyIAMUser' of type 'AWS::IAM::User' supports Tags but none are configured
- **I9040** `InvalidMapping` (AWS::RDS::DBInstance) → `Properties.Tags` L38 in `bad_resources_updatereplacepolicy`
  > Resource 'InvalidMapping' of type 'AWS::RDS::DBInstance' supports Tags but none are configured
- **I9040** `FunctionA` (AWS::Serverless::Function) → `Properties.Tags` L17 in `bad_some_logs_stream_lambda`
  > Resource 'FunctionA' of type 'AWS::Serverless::Function' supports Tags but none are configured
- **I9040** `FunctionALogGroup` (AWS::Logs::LogGroup) → `Properties.Tags` L23 in `bad_some_logs_stream_lambda`
  > Resource 'FunctionALogGroup' of type 'AWS::Logs::LogGroup' supports Tags but none are configured
- **I9040** `FunctionB` (AWS::Serverless::Function) → `Properties.Tags` L29 in `bad_some_logs_stream_lambda`
  > Resource 'FunctionB' of type 'AWS::Serverless::Function' supports Tags but none are configured
- **I9040** `FunctionBLogGroup` (AWS::Logs::LogGroup) → `Properties.Tags` L35 in `bad_some_logs_stream_lambda`
  > Resource 'FunctionBLogGroup' of type 'AWS::Logs::LogGroup' supports Tags but none are configured
- **I9040** `FunctionC` (AWS::Serverless::Function) → `Properties.Tags` L40 in `bad_some_logs_stream_lambda`
  > Resource 'FunctionC' of type 'AWS::Serverless::Function' supports Tags but none are configured
- **I9040** `FunctionCLogGroup` (AWS::Logs::LogGroup) → `Properties.Tags` L46 in `bad_some_logs_stream_lambda`
  > Resource 'FunctionCLogGroup' of type 'AWS::Logs::LogGroup' supports Tags but none are configured
- **I9040** `LogSubscriptionFunction` (AWS::Serverless::Function) → `Properties.Tags` L52 in `bad_some_logs_stream_lambda`
  > Resource 'LogSubscriptionFunction' of type 'AWS::Serverless::Function' supports Tags but none are configured
- **I9040** `LogSubscriptionFunctionLogGroup` (AWS::Logs::LogGroup) → `Properties.Tags` L79 in `bad_some_logs_stream_lambda`
  > Resource 'LogSubscriptionFunctionLogGroup' of type 'AWS::Logs::LogGroup' supports Tags but none are configured
- **I9040** `MyApi` (AWS::Serverless::Api) → `Properties.Tags` L8 in `bad_transform_no_properties`
  > Resource 'MyApi' of type 'AWS::Serverless::Api' supports Tags but none are configured
- **I9040** `CloudFrontDistribution` (AWS::CloudFront::Distribution) → `Properties.Tags` L40 in `good_conditions`
  > Resource 'CloudFrontDistribution' of type 'AWS::CloudFront::Distribution' supports Tags but none are configured
- **I9040** `mySubnet` (AWS::EC2::Subnet) → `Properties.Tags` L22 in `good_core_conditions`
  > Resource 'mySubnet' of type 'AWS::EC2::Subnet' supports Tags but none are configured
- **I9040** `myInstance1` (AWS::EC2::Instance) → `Properties.Tags` L28 in `good_core_conditions`
  > Resource 'myInstance1' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `myInstance2` (AWS::EC2::Instance) → `Properties.Tags` L33 in `good_core_conditions`
  > Resource 'myInstance2' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `myInstance3` (AWS::EC2::Instance) → `Properties.Tags` L52 in `good_core_conditions`
  > Resource 'myInstance3' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `myInstance4` (AWS::EC2::Instance) → `Properties.Tags` L65 in `good_core_conditions`
  > Resource 'myInstance4' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `LambdaExecutionRole` (AWS::IAM::Role) → `Properties.Tags` L77 in `good_core_conditions`
  > Resource 'LambdaExecutionRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `AMIIDLookup` (AWS::Lambda::Function) → `Properties.Tags` L100 in `good_core_conditions`
  > Resource 'AMIIDLookup' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `myTable` (AWS::DynamoDB::Table) → `Properties.Tags` L7 in `good_core_config_default_e3012`
  > Resource 'myTable' of type 'AWS::DynamoDB::Table' supports Tags but none are configured
- **I9040** `MyKey` (AWS::KMS::Key) → `Properties.Tags` L5 in `good_core_directives`
  > Resource 'MyKey' of type 'AWS::KMS::Key' supports Tags but none are configured
- **I9040** `LambdaExecutionRole` (AWS::IAM::Role) → `Properties.Tags` L9 in `good_custom_is-defined`
  > Resource 'LambdaExecutionRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `LambdaFunctionTestDefinedArray` (AWS::Lambda::Function) → `Properties.Tags` L23 in `good_custom_is-defined`
  > Resource 'LambdaFunctionTestDefinedArray' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `LambdaFunctionTestDefinedEmpty` (AWS::Lambda::Function) → `Properties.Tags` L35 in `good_custom_is-defined`
  > Resource 'LambdaFunctionTestDefinedEmpty' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `LambdaFunctionTestDefinedGetAttr` (AWS::Lambda::Function) → `Properties.Tags` L45 in `good_custom_is-defined`
  > Resource 'LambdaFunctionTestDefinedGetAttr' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `LambdaFunctionTestDefinedObject` (AWS::Lambda::Function) → `Properties.Tags` L55 in `good_custom_is-defined`
  > Resource 'LambdaFunctionTestDefinedObject' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `LambdaFunctionTestDefinedRef` (AWS::Lambda::Function) → `Properties.Tags` L66 in `good_custom_is-defined`
  > Resource 'LambdaFunctionTestDefinedRef' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `LambdaFunctionTestDefinedValue` (AWS::Lambda::Function) → `Properties.Tags` L76 in `good_custom_is-defined`
  > Resource 'LambdaFunctionTestDefinedValue' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `LambdaExecutionRole` (AWS::IAM::Role) → `Properties.Tags` L6 in `good_custom_is-not-defined`
  > Resource 'LambdaExecutionRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `LambdaFunctionTestNotDefinedFromParent` (AWS::Lambda::Function) → `Properties.Tags` L20 in `good_custom_is-not-defined`
  > Resource 'LambdaFunctionTestNotDefinedFromParent' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `LambdaFunctionTestNotDefinedFromProperties` (AWS::Lambda::Function) → `Properties.Tags` L29 in `good_custom_is-not-defined`
  > Resource 'LambdaFunctionTestNotDefinedFromProperties' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `LambdaFunctionTestNotDefinedRefAWSNoValue` (AWS::Lambda::Function) → `Properties.Tags` L36 in `good_custom_is-not-defined`
  > Resource 'LambdaFunctionTestNotDefinedRefAWSNoValue' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `LambdaFunctionTestNotDefinedWithSiblings` (AWS::Lambda::Function) → `Properties.Tags` L46 in `good_custom_is-not-defined`
  > Resource 'LambdaFunctionTestNotDefinedWithSiblings' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `LambdaExecutionRole` (AWS::IAM::Role) → `Properties.Tags` L7 in `good_custom_numeric-inequalities-large`
  > Resource 'LambdaExecutionRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `TimeoutInNumericsFunction` (AWS::Lambda::Function) → `Properties.Tags` L22 in `good_custom_numeric-inequalities-large`
  > Resource 'TimeoutInNumericsFunction' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `TimeoutInStringFunction` (AWS::Lambda::Function) → `Properties.Tags` L30 in `good_custom_numeric-inequalities-large`
  > Resource 'TimeoutInStringFunction' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `LambdaExecutionRole` (AWS::IAM::Role) → `Properties.Tags` L7 in `good_custom_numeric-inequalities-small`
  > Resource 'LambdaExecutionRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `TimeoutInNumericsFunction` (AWS::Lambda::Function) → `Properties.Tags` L22 in `good_custom_numeric-inequalities-small`
  > Resource 'TimeoutInNumericsFunction' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `TimeoutInStringFunction` (AWS::Lambda::Function) → `Properties.Tags` L30 in `good_custom_numeric-inequalities-small`
  > Resource 'TimeoutInStringFunction' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `myInstance1` (AWS::EC2::Instance) → `Properties.Tags` L12 in `good_functions_findinmap`
  > Resource 'myInstance1' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `myInstance2` (AWS::EC2::Instance) → `Properties.Tags` L16 in `good_functions_findinmap`
  > Resource 'myInstance2' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `myInstance3` (AWS::EC2::Instance) → `Properties.Tags` L24 in `good_functions_findinmap`
  > Resource 'myInstance3' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `Cluster0` (AWS::ECS::Cluster) → `Properties.Tags` L12 in `good_functions_findinmap_default_value`
  > Resource 'Cluster0' of type 'AWS::ECS::Cluster' supports Tags but none are configured
- **I9040** `Cluster1` (AWS::ECS::Cluster) → `Properties.Tags` L20 in `good_functions_findinmap_default_value`
  > Resource 'Cluster1' of type 'AWS::ECS::Cluster' supports Tags but none are configured
- **I9040** `Cluster2` (AWS::ECS::Cluster) → `Properties.Tags` L28 in `good_functions_findinmap_default_value`
  > Resource 'Cluster2' of type 'AWS::ECS::Cluster' supports Tags but none are configured
- **I9040** `Cluster3` (AWS::ECS::Cluster) → `Properties.Tags` L36 in `good_functions_findinmap_default_value`
  > Resource 'Cluster3' of type 'AWS::ECS::Cluster' supports Tags but none are configured
- **I9040** `Mesh0` (AWS::AppMesh::Mesh) → `Properties.Tags` L44 in `good_functions_findinmap_default_value`
  > Resource 'Mesh0' of type 'AWS::AppMesh::Mesh' supports Tags but none are configured
- **I9040** `Mesh1` (AWS::AppMesh::Mesh) → `Properties.Tags` L60 in `good_functions_findinmap_default_value`
  > Resource 'Mesh1' of type 'AWS::AppMesh::Mesh' supports Tags but none are configured
- **I9040** `Mesh2` (AWS::AppMesh::Mesh) → `Properties.Tags` L71 in `good_functions_findinmap_default_value`
  > Resource 'Mesh2' of type 'AWS::AppMesh::Mesh' supports Tags but none are configured
- **I9040** `Mesh3` (AWS::AppMesh::Mesh) → `Properties.Tags` L82 in `good_functions_findinmap_default_value`
  > Resource 'Mesh3' of type 'AWS::AppMesh::Mesh' supports Tags but none are configured
- **I9040** `Mesh4` (AWS::AppMesh::Mesh) → `Properties.Tags` L94 in `good_functions_findinmap_default_value`
  > Resource 'Mesh4' of type 'AWS::AppMesh::Mesh' supports Tags but none are configured
- **I9040** `Mesh` (AWS::AppMesh::Mesh) → `Properties.Tags` L21 in `good_functions_findinmap_enhanced`
  > Resource 'Mesh' of type 'AWS::AppMesh::Mesh' supports Tags but none are configured
- **I9040** `Mesh2` (AWS::AppMesh::Mesh) → `Properties.Tags` L34 in `good_functions_findinmap_enhanced`
  > Resource 'Mesh2' of type 'AWS::AppMesh::Mesh' supports Tags but none are configured
- **I9040** `Cluster` (AWS::ECS::Cluster) → `Properties.Tags` L47 in `good_functions_findinmap_enhanced`
  > Resource 'Cluster' of type 'AWS::ECS::Cluster' supports Tags but none are configured
- **I9040** `Queue` (AWS::SQS::Queue) → `Properties.Tags` L60 in `good_functions_findinmap_enhanced`
  > Resource 'Queue' of type 'AWS::SQS::Queue' supports Tags but none are configured
- **I9040** `Cluster2` (AWS::ECS::Cluster) → `Properties.Tags` L79 in `good_functions_findinmap_enhanced`
  > Resource 'Cluster2' of type 'AWS::ECS::Cluster' supports Tags but none are configured
- **I9040** `Cluster3` (AWS::ECS::Cluster) → `Properties.Tags` L101 in `good_functions_findinmap_enhanced`
  > Resource 'Cluster3' of type 'AWS::ECS::Cluster' supports Tags but none are configured
- **I9040** `LambdaExecutionRole` (AWS::IAM::Role) → `Properties.Tags` L12 in `good_functions_relationship_conditions`
  > Resource 'LambdaExecutionRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `AMIIDLookup` (AWS::Lambda::Function) → `Properties.Tags` L35 in `good_functions_relationship_conditions`
  > Resource 'AMIIDLookup' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `ConfigApplication` (AWS::AppConfig::Application) → `Properties.Tags` L24 in `good_functions_relationship_conditions_sam`
  > Resource 'ConfigApplication' of type 'AWS::AppConfig::Application' supports Tags but none are configured
- **I9040** `ConfigEnvironment` (AWS::AppConfig::Environment) → `Properties.Tags` L28 in `good_functions_relationship_conditions_sam`
  > Resource 'ConfigEnvironment' of type 'AWS::AppConfig::Environment' supports Tags but none are configured
- **I9040** `FunctionC` (AWS::Serverless::Function) → `Properties.Tags` L34 in `good_functions_relationship_conditions_sam`
  > Resource 'FunctionC' of type 'AWS::Serverless::Function' supports Tags but none are configured
- **I9040** `myInstance` (AWS::EC2::Instance) → `Properties.Tags` L20 in `good_functions_sub`
  > Resource 'myInstance' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `mySubStack` (AWS::CloudFormation::Stack) → `Properties.Tags` L42 in `good_functions_sub`
  > Resource 'mySubStack' of type 'AWS::CloudFormation::Stack' supports Tags but none are configured
- **I9040** `myAlb` (AWS::ElasticLoadBalancingV2::LoadBalancer) → `Properties.Tags` L50 in `good_functions_sub`
  > Resource 'myAlb' of type 'AWS::ElasticLoadBalancingV2::LoadBalancer' supports Tags but none are configured
- **I9040** `MyStack` (AWS::CloudFormation::Stack) → `Properties.Tags` L65 in `good_functions_sub`
  > Resource 'MyStack' of type 'AWS::CloudFormation::Stack' supports Tags but none are configured
- **I9040** `myVPc2` (AWS::EC2::VPC) → `Properties.Tags` L70 in `good_functions_sub`
  > Resource 'myVPc2' of type 'AWS::EC2::VPC' supports Tags but none are configured
- **I9040** `Key` (AWS::ApiGateway::ApiKey) → `Properties.Tags` L83 in `good_functions_sub_needed`
  > Resource 'Key' of type 'AWS::ApiGateway::ApiKey' supports Tags but none are configured
- **I9040** `IOTPolicies` (AWS::IoT::Policy) → `Properties.Tags` L119 in `good_functions_sub_needed`
  > Resource 'IOTPolicies' of type 'AWS::IoT::Policy' supports Tags but none are configured
- **I9040** `TestGoodStateMachine1` (AWS::StepFunctions::StateMachine) → `Properties.Tags` L138 in `good_functions_sub_needed`
  > Resource 'TestGoodStateMachine1' of type 'AWS::StepFunctions::StateMachine' supports Tags but none are configured
- **I9040** `TestRole` (AWS::IAM::Role) → `Properties.Tags` L8 in `good_functions_sub_needed_custom_excludes`
  > Resource 'TestRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `RootRole` (AWS::IAM::Role) → `Properties.Tags` L34 in `good_generic`
  > Resource 'RootRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `MyEC2Instance` (AWS::EC2::Instance) → `Properties.Tags` L73 in `good_generic`
  > Resource 'MyEC2Instance' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `mySnsTopic` (AWS::SNS::Topic) → `Properties.Tags` L91 in `good_generic`
  > Resource 'mySnsTopic' of type 'AWS::SNS::Topic' supports Tags but none are configured
- **I9040** `MyEC2Instance1` (AWS::EC2::Instance) → `Properties.Tags` L93 in `good_generic`
  > Resource 'MyEC2Instance1' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `ElasticIP` (AWS::EC2::EIP) → `Properties.Tags` L118 in `good_generic`
  > Resource 'ElasticIP' of type 'AWS::EC2::EIP' supports Tags but none are configured
- **I9040** `ElasticLoadBalancer` (AWS::ElasticLoadBalancing::LoadBalancer) → `Properties.Tags` L122 in `good_generic`
  > Resource 'ElasticLoadBalancer' of type 'AWS::ElasticLoadBalancing::LoadBalancer' supports Tags but none are configured
- **I9040** `IamPipeline` (AWS::CloudFormation::Stack) → `Properties.Tags` L141 in `good_generic`
  > Resource 'IamPipeline' of type 'AWS::CloudFormation::Stack' supports Tags but none are configured
- **I9040** `LambdaFunction` (AWS::Lambda::Function) → `Properties.Tags` L161 in `good_generic`
  > Resource 'LambdaFunction' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `mySubnet` (AWS::EC2::Subnet) → `Properties.Tags` L19 in `good_mappings_used`
  > Resource 'mySubnet' of type 'AWS::EC2::Subnet' supports Tags but none are configured
- **I9040** `IamPipeline` (AWS::CloudFormation::Stack) → `Properties.Tags` L6 in `good_minimal`
  > Resource 'IamPipeline' of type 'AWS::CloudFormation::Stack' supports Tags but none are configured
- **I9040** `OtherResource` (AWS::S3::Bucket) → `Properties.Tags` L9 in `good_modules_minimal`
  > Resource 'OtherResource' of type 'AWS::S3::Bucket' supports Tags but none are configured
- **I9040** `rDBMonitoringRole` (AWS::IAM::Role) → `Properties.Tags` L94 in `good_no_value`
  > Resource 'rDBMonitoringRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `myS3Bucket` (AWS::S3::Bucket) → `Properties.Tags` L7 in `good_override_complete`
  > Resource 'myS3Bucket' of type 'AWS::S3::Bucket' supports Tags but none are configured
- **I9040** `untaggedInstance` (AWS::EC2::Instance) → `Properties.Tags` L11 in `good_override_complete`
  > Resource 'untaggedInstance' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `VPC` (AWS::EC2::VPC) → `Properties.Tags` L15 in `good_override_complete`
  > Resource 'VPC' of type 'AWS::EC2::VPC' supports Tags but none are configured
- **I9040** `myS3Bucket` (AWS::S3::Bucket) → `Properties.Tags` L7 in `good_override_required`
  > Resource 'myS3Bucket' of type 'AWS::S3::Bucket' supports Tags but none are configured
- **I9040** `SomeLambda` (AWS::Serverless::Function) → `Properties.Tags` L9 in `good_parameters_not_used_parameters`
  > Resource 'SomeLambda' of type 'AWS::Serverless::Function' supports Tags but none are configured
- **I9040** `MyAPI` (AWS::Serverless::Api) → `Properties.Tags` L14 in `good_parameters_used_transform_removed`
  > Resource 'MyAPI' of type 'AWS::Serverless::Api' supports Tags but none are configured
- **I9040** `SomeLambda` (AWS::Serverless::Function) → `Properties.Tags` L15 in `good_parameters_used_transforms`
  > Resource 'SomeLambda' of type 'AWS::Serverless::Function' supports Tags but none are configured
- **I9040** `myVpc1` (AWS::EC2::VPC) → `Properties.Tags` L30 in `good_properties_ec2_vpc`
  > Resource 'myVpc1' of type 'AWS::EC2::VPC' supports Tags but none are configured
- **I9040** `myVpc2` (AWS::EC2::VPC) → `Properties.Tags` L35 in `good_properties_ec2_vpc`
  > Resource 'myVpc2' of type 'AWS::EC2::VPC' supports Tags but none are configured
- **I9040** `myVpc3` (AWS::EC2::VPC) → `Properties.Tags` L40 in `good_properties_ec2_vpc`
  > Resource 'myVpc3' of type 'AWS::EC2::VPC' supports Tags but none are configured
- **I9040** `myVpc4` (AWS::EC2::VPC) → `Properties.Tags` L45 in `good_properties_ec2_vpc`
  > Resource 'myVpc4' of type 'AWS::EC2::VPC' supports Tags but none are configured
- **I9040** `myVpc5` (AWS::EC2::VPC) → `Properties.Tags` L50 in `good_properties_ec2_vpc`
  > Resource 'myVpc5' of type 'AWS::EC2::VPC' supports Tags but none are configured
- **I9040** `mySubnet21` (AWS::EC2::Subnet) → `Properties.Tags` L55 in `good_properties_ec2_vpc`
  > Resource 'mySubnet21' of type 'AWS::EC2::Subnet' supports Tags but none are configured
- **I9040** `mySubnet22` (AWS::EC2::Subnet) → `Properties.Tags` L63 in `good_properties_ec2_vpc`
  > Resource 'mySubnet22' of type 'AWS::EC2::Subnet' supports Tags but none are configured
- **I9040** `TestPipeline` (AWS::CodePipeline::Pipeline) → `Properties.Tags` L6 in `good_resources_codepipeline`
  > Resource 'TestPipeline' of type 'AWS::CodePipeline::Pipeline' supports Tags but none are configured
- **I9040** `PolicyList` (AWS::RDS::DBInstance) → `Properties.Tags` L27 in `good_resources_deletionpolicy`
  > Resource 'PolicyList' of type 'AWS::RDS::DBInstance' supports Tags but none are configured
- **I9040** `myInstance` (AWS::EC2::Instance) → `Properties.Tags` L4 in `good_resources_name`
  > Resource 'myInstance' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `RootRole` (AWS::IAM::Role) → `Properties.Tags` L6 in `good_resources_primary_identifiers`
  > Resource 'RootRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `RootRole3` (AWS::IAM::Role) → `Properties.Tags` L28 in `good_resources_primary_identifiers`
  > Resource 'RootRole3' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `RootRole4` (AWS::IAM::Role) → `Properties.Tags` L51 in `good_resources_primary_identifiers`
  > Resource 'RootRole4' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `Bucket1` (AWS::S3::Bucket) → `Properties.Tags` L75 in `good_resources_primary_identifiers`
  > Resource 'Bucket1' of type 'AWS::S3::Bucket' supports Tags but none are configured
- **I9040** `Bucket2` (AWS::S3::Bucket) → `Properties.Tags` L82 in `good_resources_primary_identifiers`
  > Resource 'Bucket2' of type 'AWS::S3::Bucket' supports Tags but none are configured
- **I9040** `PolicyList` (AWS::RDS::DBInstance) → `Properties.Tags` L27 in `good_resources_updatereplacepolicy`
  > Resource 'PolicyList' of type 'AWS::RDS::DBInstance' supports Tags but none are configured
- **I9040** `FunctionA` (AWS::Serverless::Function) → `Properties.Tags` L17 in `good_some_logs_stream_lambda`
  > Resource 'FunctionA' of type 'AWS::Serverless::Function' supports Tags but none are configured
- **I9040** `FunctionALogGroup` (AWS::Logs::LogGroup) → `Properties.Tags` L23 in `good_some_logs_stream_lambda`
  > Resource 'FunctionALogGroup' of type 'AWS::Logs::LogGroup' supports Tags but none are configured
- **I9040** `FunctionB` (AWS::Serverless::Function) → `Properties.Tags` L29 in `good_some_logs_stream_lambda`
  > Resource 'FunctionB' of type 'AWS::Serverless::Function' supports Tags but none are configured
- **I9040** `FunctionBLogGroup` (AWS::Logs::LogGroup) → `Properties.Tags` L35 in `good_some_logs_stream_lambda`
  > Resource 'FunctionBLogGroup' of type 'AWS::Logs::LogGroup' supports Tags but none are configured
- **I9040** `FunctionC` (AWS::Serverless::Function) → `Properties.Tags` L40 in `good_some_logs_stream_lambda`
  > Resource 'FunctionC' of type 'AWS::Serverless::Function' supports Tags but none are configured
- **I9040** `FunctionCLogGroup` (AWS::Logs::LogGroup) → `Properties.Tags` L46 in `good_some_logs_stream_lambda`
  > Resource 'FunctionCLogGroup' of type 'AWS::Logs::LogGroup' supports Tags but none are configured
- **I9040** `LogSubscriptionFunction` (AWS::Serverless::Function) → `Properties.Tags` L52 in `good_some_logs_stream_lambda`
  > Resource 'LogSubscriptionFunction' of type 'AWS::Serverless::Function' supports Tags but none are configured
- **I9040** `LogSubscriptionFunctionLogGroup` (AWS::Logs::LogGroup) → `Properties.Tags` L74 in `good_some_logs_stream_lambda`
  > Resource 'LogSubscriptionFunctionLogGroup' of type 'AWS::Logs::LogGroup' supports Tags but none are configured
- **I9040** `MyServerlessFunctionLogicalID` (AWS::Serverless::Function) → `Properties.Tags` L6 in `good_transform`
  > Resource 'MyServerlessFunctionLogicalID' of type 'AWS::Serverless::Function' supports Tags but none are configured
- **I9040** `AppName` (AWS::Serverless::Application) → `Properties.Tags` L19 in `good_transform`
  > Resource 'AppName' of type 'AWS::Serverless::Application' supports Tags but none are configured
- **I9040** `App1` (AWS::Serverless::Application) → `Properties.Tags` L4 in `good_transform_applications_location`
  > Resource 'App1' of type 'AWS::Serverless::Application' supports Tags but none are configured
- **I9040** `App2` (AWS::Serverless::Application) → `Properties.Tags` L8 in `good_transform_applications_location`
  > Resource 'App2' of type 'AWS::Serverless::Application' supports Tags but none are configured
- **I9040** `SkillFunction` (AWS::Serverless::Function) → `Properties.Tags` L21 in `good_transform_auto_publish_alias`
  > Resource 'SkillFunction' of type 'AWS::Serverless::Function' supports Tags but none are configured
- **I9040** `SkillFunction2` (AWS::Serverless::Function) → `Properties.Tags` L30 in `good_transform_auto_publish_alias`
  > Resource 'SkillFunction2' of type 'AWS::Serverless::Function' supports Tags but none are configured
- **I9040** `LambdaFunction` (AWS::Serverless::Function) → `Properties.Tags` L11 in `good_transform_auto_publish_code_sha256`
  > Resource 'LambdaFunction' of type 'AWS::Serverless::Function' supports Tags but none are configured
- **I9040** `Function` (AWS::Serverless::Function) → `Properties.Tags` L17 in `good_transform_function_use_s3_uri`
  > Resource 'Function' of type 'AWS::Serverless::Function' supports Tags but none are configured
- **I9040** `HelloWorldFunction` (AWS::Serverless::Function) → `Properties.Tags` L5 in `good_transform_function_using_image`
  > Resource 'HelloWorldFunction' of type 'AWS::Serverless::Function' supports Tags but none are configured
- **I9040** `PolicyList` (AWS::RDS::DBInstance) → `Properties.Tags` L50 in `good_transform_language_extension`
  > Resource 'PolicyList' of type 'AWS::RDS::DBInstance' supports Tags but none are configured
- **I9040** `TestStateMachine` (AWS::Serverless::StateMachine) → `Properties.Tags` L62 in `good_transform_language_extension`
  > Resource 'TestStateMachine' of type 'AWS::Serverless::StateMachine' supports Tags but none are configured
- **I9040** `TestLambdaFunction` (AWS::Serverless::Function) → `Properties.Tags` L75 in `good_transform_language_extension`
  > Resource 'TestLambdaFunction' of type 'AWS::Serverless::Function' supports Tags but none are configured
- **I9040** `SecurityGroups` (AWS::EC2::SecurityGroup) → `Properties.Tags` L85 in `good_transform_language_extension`
  > Resource 'SecurityGroups' of type 'AWS::EC2::SecurityGroup' supports Tags but none are configured
- **I9040** `MySubnet` (AWS::EC2::Subnet) → `Properties.Tags` L91 in `good_transform_language_extension`
  > Resource 'MySubnet' of type 'AWS::EC2::Subnet' supports Tags but none are configured
- **I9040** `SkillFunction` (AWS::Serverless::Function) → `Properties.Tags` L16 in `good_transform_list_transform`
  > Resource 'SkillFunction' of type 'AWS::Serverless::Function' supports Tags but none are configured
- **I9040** `Function` (AWS::Serverless::Function) → `Properties.Tags` L15 in `good_transform_list_transform_many`
  > Resource 'Function' of type 'AWS::Serverless::Function' supports Tags but none are configured
- **I9040** `SkillFunction` (AWS::Lambda::Function) → `Properties.Tags` L8 in `good_transform_list_transform_not_sam`
  > Resource 'SkillFunction' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `myFunction` (AWS::Serverless::Function) → `Properties.Tags` L6 in `good_transform_serverless_api`
  > Resource 'myFunction' of type 'AWS::Serverless::Function' supports Tags but none are configured
- **I9040** `myApi` (AWS::Serverless::Api) → `Properties.Tags` L22 in `good_transform_serverless_api`
  > Resource 'myApi' of type 'AWS::Serverless::Api' supports Tags but none are configured
- **I9040** `myApi` (AWS::Serverless::Api) → `Properties.Tags` L6 in `good_transform_serverless_function`
  > Resource 'myApi' of type 'AWS::Serverless::Api' supports Tags but none are configured
- **I9040** `myFunction` (AWS::Serverless::Function) → `Properties.Tags` L10 in `good_transform_serverless_function`
  > Resource 'myFunction' of type 'AWS::Serverless::Function' supports Tags but none are configured
- **I9040** `myBucket` (AWS::S3::Bucket) → `Properties.Tags` L72 in `good_transform_serverless_function`
  > Resource 'myBucket' of type 'AWS::S3::Bucket' supports Tags but none are configured
- **I9040** `myFunction` (AWS::Serverless::Function) → `Properties.Tags` L11 in `good_transform_serverless_globals`
  > Resource 'myFunction' of type 'AWS::Serverless::Function' supports Tags but none are configured
- **I9040** `StateMachine` (AWS::Serverless::StateMachine) → `Properties.Tags` L4 in `good_transform_step_function_local_definition`
  > Resource 'StateMachine' of type 'AWS::Serverless::StateMachine' supports Tags but none are configured
- **I9040** `Subnet` (AWS::EC2::Subnet) → `Properties.Tags` L4 in `integration_availability-zones`
  > Resource 'Subnet' of type 'AWS::EC2::Subnet' supports Tags but none are configured
- **I9040** `KMS` (AWS::KMS::Key) → `Properties.Tags` L4 in `integration_aws-dynamodb-table`
  > Resource 'KMS' of type 'AWS::KMS::Key' supports Tags but none are configured
- **I9040** `Table1` (AWS::DynamoDB::Table) → `Properties.Tags` L8 in `integration_aws-dynamodb-table`
  > Resource 'Table1' of type 'AWS::DynamoDB::Table' supports Tags but none are configured
- **I9040** `Table2` (AWS::DynamoDB::Table) → `Properties.Tags` L27 in `integration_aws-dynamodb-table`
  > Resource 'Table2' of type 'AWS::DynamoDB::Table' supports Tags but none are configured
- **I9040** `Table3` (AWS::DynamoDB::Table) → `Properties.Tags` L46 in `integration_aws-dynamodb-table`
  > Resource 'Table3' of type 'AWS::DynamoDB::Table' supports Tags but none are configured
- **I9040** `NetworkInterface` (AWS::EC2::NetworkInterface) → `Properties.Tags` L3 in `integration_aws-ec2-instance`
  > Resource 'NetworkInterface' of type 'AWS::EC2::NetworkInterface' supports Tags but none are configured
- **I9040** `NetworkInterface` (AWS::EC2::NetworkInterface) → `Properties.Tags` L8 in `integration_aws-ec2-networkinterface`
  > Resource 'NetworkInterface' of type 'AWS::EC2::NetworkInterface' supports Tags but none are configured
- **I9040** `Subnet1` (AWS::EC2::Subnet) → `Properties.Tags` L6 in `integration_aws-ec2-subnet`
  > Resource 'Subnet1' of type 'AWS::EC2::Subnet' supports Tags but none are configured
- **I9040** `Subnet2` (AWS::EC2::Subnet) → `Properties.Tags` L12 in `integration_aws-ec2-subnet`
  > Resource 'Subnet2' of type 'AWS::EC2::Subnet' supports Tags but none are configured
- **I9040** `Subnet3` (AWS::EC2::Subnet) → `Properties.Tags` L16 in `integration_aws-ec2-subnet`
  > Resource 'Subnet3' of type 'AWS::EC2::Subnet' supports Tags but none are configured
- **I9040** `Subnet4` (AWS::EC2::Subnet) → `Properties.Tags` L21 in `integration_aws-ec2-subnet`
  > Resource 'Subnet4' of type 'AWS::EC2::Subnet' supports Tags but none are configured
- **I9040** `Subnet5` (AWS::EC2::Subnet) → `Properties.Tags` L27 in `integration_aws-ec2-subnet`
  > Resource 'Subnet5' of type 'AWS::EC2::Subnet' supports Tags but none are configured
- **I9040** `Function` (AWS::Lambda::Function) → `Properties.Tags` L3 in `integration_aws-lambda-function`
  > Resource 'Function' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `Role` (AWS::IAM::Role) → `Properties.Tags` L9 in `integration_aws-lambda-function`
  > Resource 'Role' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `TaskDef` (AWS::ECS::TaskDefinition) → `Properties.Tags` L5 in `integration_cfn-gather`
  > Resource 'TaskDef' of type 'AWS::ECS::TaskDefinition' supports Tags but none are configured
- **I9040** `FargateService` (AWS::ECS::Service) → `Properties.Tags` L15 in `integration_cfn-gather`
  > Resource 'FargateService' of type 'AWS::ECS::Service' supports Tags but none are configured
- **I9040** `AwsvpcTaskDef` (AWS::ECS::TaskDefinition) → `Properties.Tags` L25 in `integration_cfn-gather`
  > Resource 'AwsvpcTaskDef' of type 'AWS::ECS::TaskDefinition' supports Tags but none are configured
- **I9040** `ServiceNoNetConfig` (AWS::ECS::Service) → `Properties.Tags` L33 in `integration_cfn-gather`
  > Resource 'ServiceNoNetConfig' of type 'AWS::ECS::Service' supports Tags but none are configured
- **I9040** `FifoQueue` (AWS::SQS::Queue) → `Properties.Tags` L38 in `integration_cfn-gather`
  > Resource 'FifoQueue' of type 'AWS::SQS::Queue' supports Tags but none are configured
- **I9040** `StandardDLQ` (AWS::SQS::Queue) → `Properties.Tags` L46 in `integration_cfn-gather`
  > Resource 'StandardDLQ' of type 'AWS::SQS::Queue' supports Tags but none are configured
- **I9040** `RestApi` (AWS::ApiGateway::RestApi) → `Properties.Tags` L51 in `integration_cfn-gather`
  > Resource 'RestApi' of type 'AWS::ApiGateway::RestApi' supports Tags but none are configured
- **I9040** `RestApi2` (AWS::ApiGateway::RestApi) → `Properties.Tags` L72 in `integration_cfn-gather`
  > Resource 'RestApi2' of type 'AWS::ApiGateway::RestApi' supports Tags but none are configured
- **I9040** `StageBadApi` (AWS::ApiGateway::Stage) → `Properties.Tags` L80 in `integration_cfn-gather`
  > Resource 'StageBadApi' of type 'AWS::ApiGateway::Stage' supports Tags but none are configured
- **I9040** `SqsFifoQueue` (AWS::SQS::Queue) → `Properties.Tags` L87 in `integration_cfn-gather`
  > Resource 'SqsFifoQueue' of type 'AWS::SQS::Queue' supports Tags but none are configured
- **I9040** `FifoProcessor` (AWS::Lambda::Function) → `Properties.Tags` L92 in `integration_cfn-gather`
  > Resource 'FifoProcessor' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `FifoMapping` (AWS::Lambda::EventSourceMapping) → `Properties.Tags` L103 in `integration_cfn-gather`
  > Resource 'FifoMapping' of type 'AWS::Lambda::EventSourceMapping' supports Tags but none are configured
- **I9040** `AuroraCluster` (AWS::RDS::DBCluster) → `Properties.Tags` L110 in `integration_cfn-gather`
  > Resource 'AuroraCluster' of type 'AWS::RDS::DBCluster' supports Tags but none are configured
- **I9040** `BadEngineInstance` (AWS::RDS::DBInstance) → `Properties.Tags` L116 in `integration_cfn-gather`
  > Resource 'BadEngineInstance' of type 'AWS::RDS::DBInstance' supports Tags but none are configured
- **I9040** `KmsKey` (AWS::KMS::Key) → `Properties.Tags` L3 in `integration_custom-resources`
  > Resource 'KmsKey' of type 'AWS::KMS::Key' supports Tags but none are configured
- **I9040** `Vpc` (AWS::EC2::VPC) → `Properties.Tags` L22 in `integration_deployment-file-template`
  > Resource 'Vpc' of type 'AWS::EC2::VPC' supports Tags but none are configured
- **I9040** `Subnet1` (AWS::EC2::Subnet) → `Properties.Tags` L26 in `integration_deployment-file-template`
  > Resource 'Subnet1' of type 'AWS::EC2::Subnet' supports Tags but none are configured
- **I9040** `MyInstance` (AWS::EC2::Instance) → `Properties.Tags` L32 in `integration_deployment-file-template`
  > Resource 'MyInstance' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `SESEventSourceMapping` (AWS::Lambda::EventSourceMapping) → `Properties.Tags` L5 in `integration_dynamic-references`
  > Resource 'SESEventSourceMapping' of type 'AWS::Lambda::EventSourceMapping' supports Tags but none are configured
- **I9040** `SESEventSourceMappingBadDynamicReference` (AWS::Lambda::EventSourceMapping) → `Properties.Tags` L12 in `integration_dynamic-references`
  > Resource 'SESEventSourceMappingBadDynamicReference' of type 'AWS::Lambda::EventSourceMapping' supports Tags but none are configured
- **I9040** `Broker` (AWS::AmazonMQ::Broker) → `Properties.Tags` L19 in `integration_dynamic-references`
  > Resource 'Broker' of type 'AWS::AmazonMQ::Broker' supports Tags but none are configured
- **I9040** `SESEventSourceMappingSpaces` (AWS::Lambda::EventSourceMapping) → `Properties.Tags` L33 in `integration_dynamic-references`
  > Resource 'SESEventSourceMappingSpaces' of type 'AWS::Lambda::EventSourceMapping' supports Tags but none are configured
- **I9040** `Vpc` (AWS::EC2::VPC) → `Properties.Tags` L9 in `integration_formats`
  > Resource 'Vpc' of type 'AWS::EC2::VPC' supports Tags but none are configured
- **I9040** `Subnet` (AWS::EC2::Subnet) → `Properties.Tags` L14 in `integration_formats`
  > Resource 'Subnet' of type 'AWS::EC2::Subnet' supports Tags but none are configured
- **I9040** `SecurityGroup` (AWS::EC2::SecurityGroup) → `Properties.Tags` L20 in `integration_formats`
  > Resource 'SecurityGroup' of type 'AWS::EC2::SecurityGroup' supports Tags but none are configured
- **I9040** `Instance1` (AWS::EC2::Instance) → `Properties.Tags` L26 in `integration_formats`
  > Resource 'Instance1' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `SsmParameter` (AWS::SSM::Parameter) → `Properties.Tags` L15 in `integration_getatt-types`
  > Resource 'SsmParameter' of type 'AWS::SSM::Parameter' supports Tags but none are configured
- **I9040** `DocDBCluster` (AWS::DocDB::DBCluster) → `Properties.Tags` L20 in `integration_getatt-types`
  > Resource 'DocDBCluster' of type 'AWS::DocDB::DBCluster' supports Tags but none are configured
- **I9040** `TestCluster` (AWS::ECS::Cluster) → `Properties.Tags` L26 in `integration_getatt-types`
  > Resource 'TestCluster' of type 'AWS::ECS::Cluster' supports Tags but none are configured
- **I9040** `TestFargateExecutionRole` (AWS::IAM::Role) → `Properties.Tags` L28 in `integration_getatt-types`
  > Resource 'TestFargateExecutionRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `TestFargateTaskRole` (AWS::IAM::Role) → `Properties.Tags` L41 in `integration_getatt-types`
  > Resource 'TestFargateTaskRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `TestLogGroup` (AWS::Logs::LogGroup) → `Properties.Tags` L51 in `integration_getatt-types`
  > Resource 'TestLogGroup' of type 'AWS::Logs::LogGroup' supports Tags but none are configured
- **I9040** `TestTaskDefinitionWithGetAtt` (AWS::ECS::TaskDefinition) → `Properties.Tags` L55 in `integration_getatt-types`
  > Resource 'TestTaskDefinitionWithGetAtt' of type 'AWS::ECS::TaskDefinition' supports Tags but none are configured
- **I9040** `IamRole2` (AWS::IAM::Role) → `Properties.Tags` L25 in `integration_ref-no-value`
  > Resource 'IamRole2' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `CloudFront1` (AWS::CloudFront::Distribution) → `Properties.Tags` L38 in `integration_ref-no-value`
  > Resource 'CloudFront1' of type 'AWS::CloudFront::Distribution' supports Tags but none are configured
- **I9040** `CloudFront2` (AWS::CloudFront::Distribution) → `Properties.Tags` L41 in `integration_ref-no-value`
  > Resource 'CloudFront2' of type 'AWS::CloudFront::Distribution' supports Tags but none are configured
- **I9040** `Cluster` (AWS::ECS::Cluster) → `Properties.Tags` L8 in `integration_ref-types`
  > Resource 'Cluster' of type 'AWS::ECS::Cluster' supports Tags but none are configured
- **I9040** `FargateExecutionRole` (AWS::IAM::Role) → `Properties.Tags` L10 in `integration_ref-types`
  > Resource 'FargateExecutionRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `FargateTaskRole` (AWS::IAM::Role) → `Properties.Tags` L23 in `integration_ref-types`
  > Resource 'FargateTaskRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `Vpc` (AWS::EC2::VPC) → `Properties.Tags` L33 in `integration_ref-types`
  > Resource 'Vpc' of type 'AWS::EC2::VPC' supports Tags but none are configured
- **I9040** `Subnet1` (AWS::EC2::Subnet) → `Properties.Tags` L37 in `integration_ref-types`
  > Resource 'Subnet1' of type 'AWS::EC2::Subnet' supports Tags but none are configured
- **I9040** `Subnet2` (AWS::EC2::Subnet) → `Properties.Tags` L42 in `integration_ref-types`
  > Resource 'Subnet2' of type 'AWS::EC2::Subnet' supports Tags but none are configured
- **I9040** `SecurityGroup1` (AWS::EC2::SecurityGroup) → `Properties.Tags` L47 in `integration_ref-types`
  > Resource 'SecurityGroup1' of type 'AWS::EC2::SecurityGroup' supports Tags but none are configured
- **I9040** `SecurityGroup2` (AWS::EC2::SecurityGroup) → `Properties.Tags` L52 in `integration_ref-types`
  > Resource 'SecurityGroup2' of type 'AWS::EC2::SecurityGroup' supports Tags but none are configured
- **I9040** `LoadBalancer` (AWS::ElasticLoadBalancingV2::LoadBalancer) → `Properties.Tags` L56 in `integration_ref-types`
  > Resource 'LoadBalancer' of type 'AWS::ElasticLoadBalancingV2::LoadBalancer' supports Tags but none are configured
- **I9040** `LogGroup` (AWS::Logs::LogGroup) → `Properties.Tags` L66 in `integration_ref-types`
  > Resource 'LogGroup' of type 'AWS::Logs::LogGroup' supports Tags but none are configured
- **I9040** `TaskDefinitionWithRefToResource` (AWS::ECS::TaskDefinition) → `Properties.Tags` L70 in `integration_ref-types`
  > Resource 'TaskDefinitionWithRefToResource' of type 'AWS::ECS::TaskDefinition' supports Tags but none are configured
- **I9040** `TaskDefinitionWithRefToParameter` (AWS::ECS::TaskDefinition) → `Properties.Tags` L91 in `integration_ref-types`
  > Resource 'TaskDefinitionWithRefToParameter' of type 'AWS::ECS::TaskDefinition' supports Tags but none are configured
- **I9040** `MyInstance` (AWS::EC2::Instance) → `Properties.Tags` L10 in `integration_resources-cloudformation-init`
  > Resource 'MyInstance' of type 'AWS::EC2::Instance' supports Tags but none are configured
- **I9040** `VmdEventsLambda` (AWS::Serverless::Function) → `Properties.Tags` L169 in `issues_sam_w_conditions`
  > Resource 'VmdEventsLambda' of type 'AWS::Serverless::Function' supports Tags but none are configured
- **I9040** `VmdEventsQueue` (AWS::SQS::Queue) → `Properties.Tags` L204 in `issues_sam_w_conditions`
  > Resource 'VmdEventsQueue' of type 'AWS::SQS::Queue' supports Tags but none are configured
- **I9040** `VmdEventsLambdaErrorsGreaterThanZeroAlarm` (AWS::CloudWatch::Alarm) → `Properties.Tags` L272 in `issues_sam_w_conditions`
  > Resource 'VmdEventsLambdaErrorsGreaterThanZeroAlarm' of type 'AWS::CloudWatch::Alarm' supports Tags but none are configured
- **I9040** `DmdEventsLambda` (AWS::Serverless::Function) → `Properties.Tags` L294 in `issues_sam_w_conditions`
  > Resource 'DmdEventsLambda' of type 'AWS::Serverless::Function' supports Tags but none are configured
- **I9040** `DmdEventsQueue` (AWS::SQS::Queue) → `Properties.Tags` L329 in `issues_sam_w_conditions`
  > Resource 'DmdEventsQueue' of type 'AWS::SQS::Queue' supports Tags but none are configured
- **I9040** `DmdEventsLambdaErrorsGreaterThanZeroAlarm` (AWS::CloudWatch::Alarm) → `Properties.Tags` L397 in `issues_sam_w_conditions`
  > Resource 'DmdEventsLambdaErrorsGreaterThanZeroAlarm' of type 'AWS::CloudWatch::Alarm' supports Tags but none are configured
- **I9040** `PollerFunctionIamRole` (AWS::IAM::Role) → `Properties.Tags` L16 in `public_lambda-poller`
  > Resource 'PollerFunctionIamRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `PollerEventRuleIamRole` (AWS::IAM::Role) → `Properties.Tags` L161 in `public_lambda-poller`
  > Resource 'PollerEventRuleIamRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `PollerEventRule` (AWS::Events::Rule) → `Properties.Tags` L184 in `public_lambda-poller`
  > Resource 'PollerEventRule' of type 'AWS::Events::Rule' supports Tags but none are configured
- **I9040** `WatchmakerInstanceLogGroup` (AWS::Logs::LogGroup) → `Properties.Tags` L1687 in `public_watchmaker`
  > Resource 'WatchmakerInstanceLogGroup' of type 'AWS::Logs::LogGroup' supports Tags but none are configured
- **I9040** `MasterConfigRole` (AWS::IAM::Role) → `Properties.Tags` L77 in `quickstart_cis_benchmark`
  > Resource 'MasterConfigRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `FunctiontForEvaluateCisBenchmarkingPreconditions` (AWS::Lambda::Function) → `Properties.Tags` L120 in `quickstart_cis_benchmark`
  > Resource 'FunctiontForEvaluateCisBenchmarkingPreconditions' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `FunctionForEvaluateRootAccountRule` (AWS::Lambda::Function) → `Properties.Tags` L225 in `quickstart_cis_benchmark`
  > Resource 'FunctionForEvaluateRootAccountRule' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `FunctionForVpcFlowLogRule` (AWS::Lambda::Function) → `Properties.Tags` L420 in `quickstart_cis_benchmark`
  > Resource 'FunctionForVpcFlowLogRule' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `FunctionForVpcDefaultSecurityGroupsRule` (AWS::Lambda::Function) → `Properties.Tags` L496 in `quickstart_cis_benchmark`
  > Resource 'FunctionForVpcDefaultSecurityGroupsRule' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `FunctionForRoleForMfaOnUsersRule` (AWS::Lambda::Function) → `Properties.Tags` L605 in `quickstart_cis_benchmark`
  > Resource 'FunctionForRoleForMfaOnUsersRule' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `FunctionForEvaluatePolicyPermissionsRule` (AWS::Lambda::Function) → `Properties.Tags` L698 in `quickstart_cis_benchmark`
  > Resource 'FunctionForEvaluatePolicyPermissionsRule' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `FunctionForEvaluateUserPolicyAssociationRule` (AWS::Lambda::Function) → `Properties.Tags` L794 in `quickstart_cis_benchmark`
  > Resource 'FunctionForEvaluateUserPolicyAssociationRule' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `FunctionForEvaluateCloudTrailRule` (AWS::Lambda::Function) → `Properties.Tags` L885 in `quickstart_cis_benchmark`
  > Resource 'FunctionForEvaluateCloudTrailRule' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `FunctionForEvaluateCloudTrailBucketRule` (AWS::Lambda::Function) → `Properties.Tags` L998 in `quickstart_cis_benchmark`
  > Resource 'FunctionForEvaluateCloudTrailBucketRule' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `FunctionForEvaluateCloudTrailLogIntegrityRule` (AWS::Lambda::Function) → `Properties.Tags` L1114 in `quickstart_cis_benchmark`
  > Resource 'FunctionForEvaluateCloudTrailLogIntegrityRule' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `FunctionForInstanceRoleUseRule` (AWS::Lambda::Function) → `Properties.Tags` L1211 in `quickstart_cis_benchmark`
  > Resource 'FunctionForInstanceRoleUseRule' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `FunctionForEvaluateKeyRotationRule` (AWS::Lambda::Function) → `Properties.Tags` L1296 in `quickstart_cis_benchmark`
  > Resource 'FunctionForEvaluateKeyRotationRule' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `FunctionForEvaluateConfigInAllRegionsRule` (AWS::Lambda::Function) → `Properties.Tags` L1393 in `quickstart_cis_benchmark`
  > Resource 'FunctionForEvaluateConfigInAllRegionsRule' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `FunctionForVpcPeeringRouteTablesRule` (AWS::Lambda::Function) → `Properties.Tags` L1498 in `quickstart_cis_benchmark`
  > Resource 'FunctionForVpcPeeringRouteTablesRule' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `SnsTopicForCloudWatchEvents` (AWS::SNS::Topic) → `Properties.Tags` L1586 in `quickstart_cis_benchmark`
  > Resource 'SnsTopicForCloudWatchEvents' of type 'AWS::SNS::Topic' supports Tags but none are configured
- **I9040** `GetCloudTrailCloudWatchLog` (AWS::Lambda::Function) → `Properties.Tags` L1600 in `quickstart_cis_benchmark`
  > Resource 'GetCloudTrailCloudWatchLog' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `UnauthorizedAttemptCloudWatchAlarm` (AWS::CloudWatch::Alarm) → `Properties.Tags` L1660 in `quickstart_cis_benchmark`
  > Resource 'UnauthorizedAttemptCloudWatchAlarm' of type 'AWS::CloudWatch::Alarm' supports Tags but none are configured
- **I9040** `IAMRootActivityCloudWatchAlarm` (AWS::CloudWatch::Alarm) → `Properties.Tags` L1698 in `quickstart_cis_benchmark`
  > Resource 'IAMRootActivityCloudWatchAlarm' of type 'AWS::CloudWatch::Alarm' supports Tags but none are configured
- **I9040** `ConsoleSigninWithoutMFACloudWatchAlarm` (AWS::CloudWatch::Alarm) → `Properties.Tags` L1736 in `quickstart_cis_benchmark`
  > Resource 'ConsoleSigninWithoutMFACloudWatchAlarm' of type 'AWS::CloudWatch::Alarm' supports Tags but none are configured
- **I9040** `ConsoleLoginFailureCloudWatchAlarm` (AWS::CloudWatch::Alarm) → `Properties.Tags` L1773 in `quickstart_cis_benchmark`
  > Resource 'ConsoleLoginFailureCloudWatchAlarm' of type 'AWS::CloudWatch::Alarm' supports Tags but none are configured
- **I9040** `KMSCustomerKeyDeletionCloudWatchAlarm` (AWS::CloudWatch::Alarm) → `Properties.Tags` L1810 in `quickstart_cis_benchmark`
  > Resource 'KMSCustomerKeyDeletionCloudWatchAlarm' of type 'AWS::CloudWatch::Alarm' supports Tags but none are configured
- **I9040** `RoleForCloudWatchEvents` (AWS::IAM::Role) → `Properties.Tags` L1829 in `quickstart_cis_benchmark`
  > Resource 'RoleForCloudWatchEvents' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `FunctionToFormatCloudWatchEvent` (AWS::Lambda::Function) → `Properties.Tags` L1855 in `quickstart_cis_benchmark`
  > Resource 'FunctionToFormatCloudWatchEvent' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `DetectS3BucketPolicyChanges` (AWS::Events::Rule) → `Properties.Tags` L1905 in `quickstart_cis_benchmark`
  > Resource 'DetectS3BucketPolicyChanges' of type 'AWS::Events::Rule' supports Tags but none are configured
- **I9040** `DetectConfigChanges` (AWS::Events::Rule) → `Properties.Tags` L1935 in `quickstart_cis_benchmark`
  > Resource 'DetectConfigChanges' of type 'AWS::Events::Rule' supports Tags but none are configured
- **I9040** `KmsKeyUseCloudWatchEventRule` (AWS::Events::Rule) → `Properties.Tags` L1961 in `quickstart_cis_benchmark`
  > Resource 'KmsKeyUseCloudWatchEventRule' of type 'AWS::Events::Rule' supports Tags but none are configured
- **I9040** `CloudTrailCloudWatchEventRule` (AWS::Events::Rule) → `Properties.Tags` L1983 in `quickstart_cis_benchmark`
  > Resource 'CloudTrailCloudWatchEventRule' of type 'AWS::Events::Rule' supports Tags but none are configured
- **I9040** `IamPolicyChangesCloudWatchEventRule` (AWS::Events::Rule) → `Properties.Tags` L2006 in `quickstart_cis_benchmark`
  > Resource 'IamPolicyChangesCloudWatchEventRule' of type 'AWS::Events::Rule' supports Tags but none are configured
- **I9040** `BillingChangeCloudWatchEventRule` (AWS::Events::Rule) → `Properties.Tags` L2044 in `quickstart_cis_benchmark`
  > Resource 'BillingChangeCloudWatchEventRule' of type 'AWS::Events::Rule' supports Tags but none are configured
- **I9040** `Ec2TerminationCloudWatchEventRule` (AWS::Events::Rule) → `Properties.Tags` L2068 in `quickstart_cis_benchmark`
  > Resource 'Ec2TerminationCloudWatchEventRule' of type 'AWS::Events::Rule' supports Tags but none are configured
- **I9040** `SecurityGroupChangesCloudWatchEventRule` (AWS::Events::Rule) → `Properties.Tags` L2090 in `quickstart_cis_benchmark`
  > Resource 'SecurityGroupChangesCloudWatchEventRule' of type 'AWS::Events::Rule' supports Tags but none are configured
- **I9040** `NetworkAclChangesCloudWatchEventRule` (AWS::Events::Rule) → `Properties.Tags` L2118 in `quickstart_cis_benchmark`
  > Resource 'NetworkAclChangesCloudWatchEventRule' of type 'AWS::Events::Rule' supports Tags but none are configured
- **I9040** `NetworkChangeCloudWatchEventRule` (AWS::Events::Rule) → `Properties.Tags` L2149 in `quickstart_cis_benchmark`
  > Resource 'NetworkChangeCloudWatchEventRule' of type 'AWS::Events::Rule' supports Tags but none are configured
- **I9040** `BillingChangesCloudWatchAlarm` (AWS::CloudWatch::Alarm) → `Properties.Tags` L2200 in `quickstart_cis_benchmark`
  > Resource 'BillingChangesCloudWatchAlarm' of type 'AWS::CloudWatch::Alarm' supports Tags but none are configured
- **I9040** `RoleForDisableUnusedCredentialsFunction` (AWS::IAM::Role) → `Properties.Tags` L2219 in `quickstart_cis_benchmark`
  > Resource 'RoleForDisableUnusedCredentialsFunction' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `FunctionToDisableUnusedCredentials` (AWS::Lambda::Function) → `Properties.Tags` L2252 in `quickstart_cis_benchmark`
  > Resource 'FunctionToDisableUnusedCredentials' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `ScheduledRuleForDisableUnusedCredentials` (AWS::Events::Rule) → `Properties.Tags` L2347 in `quickstart_cis_benchmark`
  > Resource 'ScheduledRuleForDisableUnusedCredentials' of type 'AWS::Events::Rule' supports Tags but none are configured
- **I9040** `rConfigRulesLambdaRole` (AWS::IAM::Role) → `Properties.Tags` L97 in `quickstart_config-rules`
  > Resource 'rConfigRulesLambdaRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `rAMIComplianceFunction` (AWS::Lambda::Function) → `Properties.Tags` L139 in `quickstart_config-rules`
  > Resource 'rAMIComplianceFunction' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `rCloudTrailValidationFunction` (AWS::Lambda::Function) → `Properties.Tags` L237 in `quickstart_config-rules`
  > Resource 'rCloudTrailValidationFunction' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `rSysAdminRole` (AWS::IAM::Role) → `Properties.Tags` L22 in `quickstart_iam`
  > Resource 'rSysAdminRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `rIAMAdminRole` (AWS::IAM::Role) → `Properties.Tags` L117 in `quickstart_iam`
  > Resource 'rIAMAdminRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `rInstanceOpsRole` (AWS::IAM::Role) → `Properties.Tags` L189 in `quickstart_iam`
  > Resource 'rInstanceOpsRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `rReadOnlyAdminRole` (AWS::IAM::Role) → `Properties.Tags` L302 in `quickstart_iam`
  > Resource 'rReadOnlyAdminRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `rEipNat` (AWS::EC2::EIP) → `Properties.Tags` L69 in `quickstart_nat-instance`
  > Resource 'rEipNat' of type 'AWS::EC2::EIP' supports Tags but none are configured
- **I9040** `rCWAlarmHighCPUApp` (AWS::CloudWatch::Alarm) → `Properties.Tags` L645 in `quickstart_nist_application`
  > Resource 'rCWAlarmHighCPUApp' of type 'AWS::CloudWatch::Alarm' supports Tags but none are configured
- **I9040** `rCWAlarmHighCPUWeb` (AWS::CloudWatch::Alarm) → `Properties.Tags` L663 in `quickstart_nist_application`
  > Resource 'rCWAlarmHighCPUWeb' of type 'AWS::CloudWatch::Alarm' supports Tags but none are configured
- **I9040** `rCWAlarmLowCPUApp` (AWS::CloudWatch::Alarm) → `Properties.Tags` L681 in `quickstart_nist_application`
  > Resource 'rCWAlarmLowCPUApp' of type 'AWS::CloudWatch::Alarm' supports Tags but none are configured
- **I9040** `rCWAlarmLowCPUWeb` (AWS::CloudWatch::Alarm) → `Properties.Tags` L698 in `quickstart_nist_application`
  > Resource 'rCWAlarmLowCPUWeb' of type 'AWS::CloudWatch::Alarm' supports Tags but none are configured
- **I9040** `rDBSubnetGroup` (AWS::RDS::DBSubnetGroup) → `Properties.Tags` L716 in `quickstart_nist_application`
  > Resource 'rDBSubnetGroup' of type 'AWS::RDS::DBSubnetGroup' supports Tags but none are configured
- **I9040** `rPostProcInstanceRole` (AWS::IAM::Role) → `Properties.Tags` L960 in `quickstart_nist_application`
  > Resource 'rPostProcInstanceRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `rRDSInstanceMySQL` (AWS::RDS::DBInstance) → `Properties.Tags` L1003 in `quickstart_nist_application`
  > Resource 'rRDSInstanceMySQL' of type 'AWS::RDS::DBInstance' supports Tags but none are configured
- **I9040** `rS3ELBAccessLogs` (AWS::S3::Bucket) → `Properties.Tags` L1061 in `quickstart_nist_application`
  > Resource 'rS3ELBAccessLogs' of type 'AWS::S3::Bucket' supports Tags but none are configured
- **I9040** `rSecurityGroupWeb` (AWS::EC2::SecurityGroup) → `Properties.Tags` L1139 in `quickstart_nist_application`
  > Resource 'rSecurityGroupWeb' of type 'AWS::EC2::SecurityGroup' supports Tags but none are configured
- **I9040** `rWebContentBucket` (AWS::S3::Bucket) → `Properties.Tags` L1178 in `quickstart_nist_application`
  > Resource 'rWebContentBucket' of type 'AWS::S3::Bucket' supports Tags but none are configured
- **I9040** `rAMIComplianceFunction` (AWS::Lambda::Function) → `Properties.Tags` L34 in `quickstart_nist_config_rules`
  > Resource 'rAMIComplianceFunction' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `rCloudTrailValidationFunction` (AWS::Lambda::Function) → `Properties.Tags` L98 in `quickstart_nist_config_rules`
  > Resource 'rCloudTrailValidationFunction' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `rConfigRulesLambdaRole` (AWS::IAM::Role) → `Properties.Tags` L282 in `quickstart_nist_config_rules`
  > Resource 'rConfigRulesLambdaRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `ApplicationTemplate` (AWS::CloudFormation::Stack) → `Properties.Tags` L277 in `quickstart_nist_high_main`
  > Resource 'ApplicationTemplate' of type 'AWS::CloudFormation::Stack' supports Tags but none are configured
- **I9040** `ConfigRulesTemplate` (AWS::CloudFormation::Stack) → `Properties.Tags` L387 in `quickstart_nist_high_main`
  > Resource 'ConfigRulesTemplate' of type 'AWS::CloudFormation::Stack' supports Tags but none are configured
- **I9040** `IamTemplate` (AWS::CloudFormation::Stack) → `Properties.Tags` L411 in `quickstart_nist_high_main`
  > Resource 'IamTemplate' of type 'AWS::CloudFormation::Stack' supports Tags but none are configured
- **I9040** `LoggingTemplate` (AWS::CloudFormation::Stack) → `Properties.Tags` L424 in `quickstart_nist_high_main`
  > Resource 'LoggingTemplate' of type 'AWS::CloudFormation::Stack' supports Tags but none are configured
- **I9040** `ManagementVpcTemplate` (AWS::CloudFormation::Stack) → `Properties.Tags` L445 in `quickstart_nist_high_main`
  > Resource 'ManagementVpcTemplate' of type 'AWS::CloudFormation::Stack' supports Tags but none are configured
- **I9040** `ProductionVpcTemplate` (AWS::CloudFormation::Stack) → `Properties.Tags` L526 in `quickstart_nist_high_main`
  > Resource 'ProductionVpcTemplate' of type 'AWS::CloudFormation::Stack' supports Tags but none are configured
- **I9040** `rIAMAdminRole` (AWS::IAM::Role) → `Properties.Tags` L64 in `quickstart_nist_iam`
  > Resource 'rIAMAdminRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `rInstanceOpsRole` (AWS::IAM::Role) → `Properties.Tags` L144 in `quickstart_nist_iam`
  > Resource 'rInstanceOpsRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `rReadOnlyAdminRole` (AWS::IAM::Role) → `Properties.Tags` L243 in `quickstart_nist_iam`
  > Resource 'rReadOnlyAdminRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `rSysAdminRole` (AWS::IAM::Role) → `Properties.Tags` L319 in `quickstart_nist_iam`
  > Resource 'rSysAdminRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `rArchiveLogsBucket` (AWS::S3::Bucket) → `Properties.Tags` L42 in `quickstart_nist_logging`
  > Resource 'rArchiveLogsBucket' of type 'AWS::S3::Bucket' supports Tags but none are configured
- **I9040** `rCloudTrailBucket` (AWS::S3::Bucket) → `Properties.Tags` L120 in `quickstart_nist_logging`
  > Resource 'rCloudTrailBucket' of type 'AWS::S3::Bucket' supports Tags but none are configured
- **I9040** `rCloudTrailChangeAlarm` (AWS::CloudWatch::Alarm) → `Properties.Tags` L143 in `quickstart_nist_logging`
  > Resource 'rCloudTrailChangeAlarm' of type 'AWS::CloudWatch::Alarm' supports Tags but none are configured
- **I9040** `rCloudTrailLogGroup` (AWS::Logs::LogGroup) → `Properties.Tags` L159 in `quickstart_nist_logging`
  > Resource 'rCloudTrailLogGroup' of type 'AWS::Logs::LogGroup' supports Tags but none are configured
- **I9040** `rCloudTrailLoggingLocal` (AWS::CloudTrail::Trail) → `Properties.Tags` L163 in `quickstart_nist_logging`
  > Resource 'rCloudTrailLoggingLocal' of type 'AWS::CloudTrail::Trail' supports Tags but none are configured
- **I9040** `rCloudTrailRole` (AWS::IAM::Role) → `Properties.Tags` L187 in `quickstart_nist_logging`
  > Resource 'rCloudTrailRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `rCloudWatchLogsRole` (AWS::IAM::Role) → `Properties.Tags` L325 in `quickstart_nist_logging`
  > Resource 'rCloudWatchLogsRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `rIAMCreateAccessKeyAlarm` (AWS::CloudWatch::Alarm) → `Properties.Tags` L391 in `quickstart_nist_logging`
  > Resource 'rIAMCreateAccessKeyAlarm' of type 'AWS::CloudWatch::Alarm' supports Tags but none are configured
- **I9040** `rIAMPolicyChangesAlarm` (AWS::CloudWatch::Alarm) → `Properties.Tags` L407 in `quickstart_nist_logging`
  > Resource 'rIAMPolicyChangesAlarm' of type 'AWS::CloudWatch::Alarm' supports Tags but none are configured
- **I9040** `rNetworkAclChangesAlarm` (AWS::CloudWatch::Alarm) → `Properties.Tags` L443 in `quickstart_nist_logging`
  > Resource 'rNetworkAclChangesAlarm' of type 'AWS::CloudWatch::Alarm' supports Tags but none are configured
- **I9040** `rRootActivityAlarm` (AWS::CloudWatch::Alarm) → `Properties.Tags` L471 in `quickstart_nist_logging`
  > Resource 'rRootActivityAlarm' of type 'AWS::CloudWatch::Alarm' supports Tags but none are configured
- **I9040** `rSecurityAlarmTopic` (AWS::SNS::Topic) → `Properties.Tags` L486 in `quickstart_nist_logging`
  > Resource 'rSecurityAlarmTopic' of type 'AWS::SNS::Topic' supports Tags but none are configured
- **I9040** `rSecurityGroupChangesAlarm` (AWS::CloudWatch::Alarm) → `Properties.Tags` L493 in `quickstart_nist_logging`
  > Resource 'rSecurityGroupChangesAlarm' of type 'AWS::CloudWatch::Alarm' supports Tags but none are configured
- **I9040** `rUnauthorizedAttemptAlarm` (AWS::CloudWatch::Alarm) → `Properties.Tags` L522 in `quickstart_nist_logging`
  > Resource 'rUnauthorizedAttemptAlarm' of type 'AWS::CloudWatch::Alarm' supports Tags but none are configured
- **I9040** `rDeepSecurityInfrastructureTemplate` (AWS::CloudFormation::Stack) → `Properties.Tags` L333 in `quickstart_nist_vpc_management`
  > Resource 'rDeepSecurityInfrastructureTemplate' of type 'AWS::CloudFormation::Stack' supports Tags but none are configured
- **I9040** `rEIPProdBastion` (AWS::EC2::EIP) → `Properties.Tags` L394 in `quickstart_nist_vpc_management`
  > Resource 'rEIPProdBastion' of type 'AWS::EC2::EIP' supports Tags but none are configured
- **I9040** `rEIPProdNAT` (AWS::EC2::EIP) → `Properties.Tags` L399 in `quickstart_nist_vpc_management`
  > Resource 'rEIPProdNAT' of type 'AWS::EC2::EIP' supports Tags but none are configured
- **I9040** `rNATGateway` (AWS::EC2::NatGateway) → `Properties.Tags` L546 in `quickstart_nist_vpc_management`
  > Resource 'rNATGateway' of type 'AWS::EC2::NatGateway' supports Tags but none are configured
- **I9040** `rNatInstanceTemplate` (AWS::CloudFormation::Stack) → `Properties.Tags` L557 in `quickstart_nist_vpc_management`
  > Resource 'rNatInstanceTemplate' of type 'AWS::CloudFormation::Stack' supports Tags but none are configured
- **I9040** `rEIPProdNAT` (AWS::EC2::EIP) → `Properties.Tags` L303 in `quickstart_nist_vpc_production`
  > Resource 'rEIPProdNAT' of type 'AWS::EC2::EIP' supports Tags but none are configured
- **I9040** `rNACLPrivate` (AWS::EC2::NetworkAcl) → `Properties.Tags` L367 in `quickstart_nist_vpc_production`
  > Resource 'rNACLPrivate' of type 'AWS::EC2::NetworkAcl' supports Tags but none are configured
- **I9040** `rNACLPublic` (AWS::EC2::NetworkAcl) → `Properties.Tags` L372 in `quickstart_nist_vpc_production`
  > Resource 'rNACLPublic' of type 'AWS::EC2::NetworkAcl' supports Tags but none are configured
- **I9040** `rNATGateway` (AWS::EC2::NatGateway) → `Properties.Tags` L516 in `quickstart_nist_vpc_production`
  > Resource 'rNATGateway' of type 'AWS::EC2::NatGateway' supports Tags but none are configured
- **I9040** `rNatInstanceTemplate` (AWS::CloudFormation::Stack) → `Properties.Tags` L527 in `quickstart_nist_vpc_production`
  > Resource 'rNatInstanceTemplate' of type 'AWS::CloudFormation::Stack' supports Tags but none are configured
- **I9040** `ContainerAccessELB` (AWS::ElasticLoadBalancing::LoadBalancer) → `Properties.Tags` L747 in `quickstart_openshift`
  > Resource 'ContainerAccessELB' of type 'AWS::ElasticLoadBalancing::LoadBalancer' supports Tags but none are configured
- **I9040** `KeyGen` (AWS::Lambda::Function) → `Properties.Tags` L799 in `quickstart_openshift`
  > Resource 'KeyGen' of type 'AWS::Lambda::Function' supports Tags but none are configured
- **I9040** `LambdaExecutionRole` (AWS::IAM::Role) → `Properties.Tags` L814 in `quickstart_openshift`
  > Resource 'LambdaExecutionRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `OpenShiftInternalSecurityGroup` (AWS::EC2::SecurityGroup) → `Properties.Tags` L1055 in `quickstart_openshift`
  > Resource 'OpenShiftInternalSecurityGroup' of type 'AWS::EC2::SecurityGroup' supports Tags but none are configured
- **I9040** `OpenShiftMasterELB` (AWS::ElasticLoadBalancing::LoadBalancer) → `Properties.Tags` L1282 in `quickstart_openshift`
  > Resource 'OpenShiftMasterELB' of type 'AWS::ElasticLoadBalancing::LoadBalancer' supports Tags but none are configured
- **I9040** `OpenShiftMasterInternalELB` (AWS::ElasticLoadBalancing::LoadBalancer) → `Properties.Tags` L1317 in `quickstart_openshift`
  > Resource 'OpenShiftMasterInternalELB' of type 'AWS::ElasticLoadBalancing::LoadBalancer' supports Tags but none are configured
- **I9040** `OpenShiftNodeInternalELB` (AWS::ElasticLoadBalancing::LoadBalancer) → `Properties.Tags` L1370 in `quickstart_openshift`
  > Resource 'OpenShiftNodeInternalELB' of type 'AWS::ElasticLoadBalancing::LoadBalancer' supports Tags but none are configured
- **I9040** `OpenShiftNodeSecurityGroup` (AWS::EC2::SecurityGroup) → `Properties.Tags` L1395 in `quickstart_openshift`
  > Resource 'OpenShiftNodeSecurityGroup' of type 'AWS::EC2::SecurityGroup' supports Tags but none are configured
- **I9040** `OpenShiftSecurityGroup` (AWS::EC2::SecurityGroup) → `Properties.Tags` L1637 in `quickstart_openshift`
  > Resource 'OpenShiftSecurityGroup' of type 'AWS::EC2::SecurityGroup' supports Tags but none are configured
- **I9040** `SetupRole` (AWS::IAM::Role) → `Properties.Tags` L1657 in `quickstart_openshift`
  > Resource 'SetupRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `OpenShiftStack` (AWS::CloudFormation::Stack) → `Properties.Tags` L185 in `quickstart_openshift_master`
  > Resource 'OpenShiftStack' of type 'AWS::CloudFormation::Stack' supports Tags but none are configured
- **I9040** `VPCStack` (AWS::CloudFormation::Stack) → `Properties.Tags` L243 in `quickstart_openshift_master`
  > Resource 'VPCStack' of type 'AWS::CloudFormation::Stack' supports Tags but none are configured
- **I9040** `rDBMonitoringRole` (AWS::IAM::Role) → `Properties.Tags` L94 in `quickstart_test`
  > Resource 'rDBMonitoringRole' of type 'AWS::IAM::Role' supports Tags but none are configured
- **I9040** `DHCPOptions` (AWS::EC2::DHCPOptions) → `Properties.Tags` L481 in `quickstart_vpc`
  > Resource 'DHCPOptions' of type 'AWS::EC2::DHCPOptions' supports Tags but none are configured
- **I9040** `NAT1EIP` (AWS::EC2::EIP) → `Properties.Tags` L1745 in `quickstart_vpc`
  > Resource 'NAT1EIP' of type 'AWS::EC2::EIP' supports Tags but none are configured
- **I9040** `NAT2EIP` (AWS::EC2::EIP) → `Properties.Tags` L1764 in `quickstart_vpc`
  > Resource 'NAT2EIP' of type 'AWS::EC2::EIP' supports Tags but none are configured
- **I9040** `NAT3EIP` (AWS::EC2::EIP) → `Properties.Tags` L1783 in `quickstart_vpc`
  > Resource 'NAT3EIP' of type 'AWS::EC2::EIP' supports Tags but none are configured
- **I9040** `NAT4EIP` (AWS::EC2::EIP) → `Properties.Tags` L1802 in `quickstart_vpc`
  > Resource 'NAT4EIP' of type 'AWS::EC2::EIP' supports Tags but none are configured
- **I9040** `NATGateway1` (AWS::EC2::NatGateway) → `Properties.Tags` L1821 in `quickstart_vpc`
  > Resource 'NATGateway1' of type 'AWS::EC2::NatGateway' supports Tags but none are configured
- **I9040** `NATGateway2` (AWS::EC2::NatGateway) → `Properties.Tags` L1837 in `quickstart_vpc`
  > Resource 'NATGateway2' of type 'AWS::EC2::NatGateway' supports Tags but none are configured
- **I9040** `NATGateway3` (AWS::EC2::NatGateway) → `Properties.Tags` L1853 in `quickstart_vpc`
  > Resource 'NATGateway3' of type 'AWS::EC2::NatGateway' supports Tags but none are configured
- **I9040** `NATGateway4` (AWS::EC2::NatGateway) → `Properties.Tags` L1869 in `quickstart_vpc`
  > Resource 'NATGateway4' of type 'AWS::EC2::NatGateway' supports Tags but none are configured
- **I9040** `NATInstanceSecurityGroup` (AWS::EC2::SecurityGroup) → `Properties.Tags` L2093 in `quickstart_vpc`
  > Resource 'NATInstanceSecurityGroup' of type 'AWS::EC2::SecurityGroup' supports Tags but none are configured
- **I9040** `S3VPCEndpoint` (AWS::EC2::VPCEndpoint) → `Properties.Tags` L2113 in `quickstart_vpc`
  > Resource 'S3VPCEndpoint' of type 'AWS::EC2::VPCEndpoint' supports Tags but none are configured
- **I9040** `rNatInstanceTemplate` (AWS::CloudFormation::Stack) → `Properties.Tags` L377 in `quickstart_vpc-management`
  > Resource 'rNatInstanceTemplate' of type 'AWS::CloudFormation::Stack' supports Tags but none are configured
- **I9040** `rEIPProdBastion` (AWS::EC2::EIP) → `Properties.Tags` L720 in `quickstart_vpc-management`
  > Resource 'rEIPProdBastion' of type 'AWS::EC2::EIP' supports Tags but none are configured
- **I9040** `rEIPProdNAT` (AWS::EC2::EIP) → `Properties.Tags` L763 in `quickstart_vpc-management`
  > Resource 'rEIPProdNAT' of type 'AWS::EC2::EIP' supports Tags but none are configured
- **I9040** `rNATGateway` (AWS::EC2::NatGateway) → `Properties.Tags` L771 in `quickstart_vpc-management`
  > Resource 'rNATGateway' of type 'AWS::EC2::NatGateway' supports Tags but none are configured
- **I9040** `rDeepSecurityInfrastructureTemplate` (AWS::CloudFormation::Stack) → `Properties.Tags` L915 in `quickstart_vpc-management`
  > Resource 'rDeepSecurityInfrastructureTemplate' of type 'AWS::CloudFormation::Stack' supports Tags but none are configured

### W9003 — 175 findings

- **W9003** `myTable` (AWS::DynamoDB::Table) → `Properties.ProvisionedThroughput.WriteCapacityUnits` L7 in `bad_formatters`
  > '5' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `mySecurityGroupVpc1` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.0.IpProtocol` L9 in `bad_functions_ref`
  > 1 is not of type 'string' — automatically coerced (number → string)
- **W9003** `mySecurityGroupVpc1` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.1.IpProtocol` L9 in `bad_functions_ref`
  > 1 is not of type 'string' — automatically coerced (number → string)
- **W9003** `mySecurityGroupVpc2` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.0.IpProtocol` L21 in `bad_functions_ref`
  > 1 is not of type 'string' — automatically coerced (number → string)
- **W9003** `MyEC2Instance` (AWS::EC2::Instance) → `Properties.KeyName` L41 in `bad_generic`
  > 1 is not of type 'string' — automatically coerced (number → string)
- **W9003** `ElasticLoadBalancer` (AWS::ElasticLoadBalancing::LoadBalancer) → `Properties.HealthCheck.UnhealthyThreshold` L111 in `bad_generic`
  > 5 is not of type 'string' — automatically coerced (number → string)
- **W9003** `conditionLoadBalancer` (AWS::ElasticLoadBalancing::LoadBalancer) → `Properties.ConnectionDrainingPolicy.Enabled` L149 in `bad_generic`
  > 'true' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `conditionLoadBalancer` (AWS::ElasticLoadBalancing::LoadBalancer) → `Properties.ConnectionDrainingPolicy.Timeout` L149 in `bad_generic`
  > '60' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `conditionLoadBalancer` (AWS::ElasticLoadBalancing::LoadBalancer) → `Properties.Tags.{}.Value` L149 in `bad_generic`
  > true is not of type 'string' — automatically coerced (boolean → string)
- **W9003** `MyEC2Instance` (AWS::EC2::Instance) → `Properties.KeyName` L7 in `bad_properties_ebs`
  > 1 is not of type 'string' — automatically coerced (number → string)
- **W9003** `mySecurityGroupNonVpc` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.0.IpProtocol` L21 in `bad_properties_sg_ingress`
  > 1 is not of type 'string' — automatically coerced (number → string)
- **W9003** `mySecurityGroupVpc` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.0.IpProtocol` L29 in `bad_properties_sg_ingress`
  > 1 is not of type 'string' — automatically coerced (number → string)
- **W9003** `mySecurityGroupVpc` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.1.IpProtocol` L29 in `bad_properties_sg_ingress`
  > 1 is not of type 'string' — automatically coerced (number → string)
- **W9003** `mySecurityGroupVpc` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.3.IpProtocol` L29 in `bad_properties_sg_ingress`
  > 1 is not of type 'string' — automatically coerced (number → string)
- **W9003** `mySecurityGroupVpc` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.4.IpProtocol` L29 in `bad_properties_sg_ingress`
  > 1 is not of type 'string' — automatically coerced (number → string)
- **W9003** `mySecurityGroupIngress` (AWS::EC2::SecurityGroupIngress) → `Properties.IpProtocol` L60 in `bad_properties_sg_ingress`
  > 1 is not of type 'string' — automatically coerced (number → string)
- **W9003** `mySecurityGroupIngress2` (AWS::EC2::SecurityGroupIngress) → `Properties.IpProtocol` L66 in `bad_properties_sg_ingress`
  > 1 is not of type 'string' — automatically coerced (number → string)
- **W9003** `mySecurityGroupVpc1` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.0.IpProtocol` L24 in `bad_resources_circular_dependency`
  > 1 is not of type 'string' — automatically coerced (number → string)
- **W9003** `mySecurityGroupVpc1` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.1.IpProtocol` L24 in `bad_resources_circular_dependency`
  > 1 is not of type 'string' — automatically coerced (number → string)
- **W9003** `mySecurityGroupVpc2` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.0.IpProtocol` L34 in `bad_resources_circular_dependency`
  > 1 is not of type 'string' — automatically coerced (number → string)
- **W9003** `mySecurityGroupVpc3` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.0.IpProtocol` L42 in `bad_resources_circular_dependency`
  > 1 is not of type 'string' — automatically coerced (number → string)
- **W9003** `myInstance` (AWS::EC2::Instance) → `Properties.NetworkInterfaces.0.DeviceIndex` L50 in `bad_resources_circular_dependency`
  > 0 is not of type 'string' — automatically coerced (number → string)
- **W9003** `myTable` (AWS::DynamoDB::Table) → `Properties.ProvisionedThroughput.WriteCapacityUnits` L7 in `good_core_config_default_e3012`
  > '5' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `TimeoutInStringFunction` (AWS::Lambda::Function) → `Properties.Timeout` L30 in `good_custom_numeric-inequalities-large`
  > '100' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `TimeoutInStringFunction` (AWS::Lambda::Function) → `Properties.Timeout` L30 in `good_custom_numeric-inequalities-small`
  > '9' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rDBServerInstance` (AWS::RDS::DBInstance) → `Properties.Port` L124 in `good_no_value`
  > 1433.0 is not of type 'string' — automatically coerced (number → string)
- **W9003** `Instance1` (AWS::EC2::Instance) → `Properties.NetworkInterfaces.0.DeviceIndex` L26 in `integration_formats`
  > 0 is not of type 'string' — automatically coerced (number → string)
- **W9003** `Instance1` (AWS::EC2::Instance) → `Properties.NetworkInterfaces.1.DeviceIndex` L26 in `integration_formats`
  > 1 is not of type 'string' — automatically coerced (number → string)
- **W9003** `Instance1` (AWS::EC2::Instance) → `Properties.NetworkInterfaces.2.DeviceIndex` L26 in `integration_formats`
  > 2 is not of type 'string' — automatically coerced (number → string)
- **W9003** `UnauthorizedAttemptsCloudWatchFilter` (AWS::Logs::MetricFilter) → `Properties.MetricTransformations.0.MetricValue` L1646 in `quickstart_cis_benchmark`
  > 1 is not of type 'string' — automatically coerced (number → string)
- **W9003** `IAMRootActivityCloudWatchMetric` (AWS::Logs::MetricFilter) → `Properties.MetricTransformations.0.MetricValue` L1680 in `quickstart_cis_benchmark`
  > 1 is not of type 'string' — automatically coerced (number → string)
- **W9003** `ConsoleSigninWithoutMfaCloudWatchMetric` (AWS::Logs::MetricFilter) → `Properties.MetricTransformations.0.MetricValue` L1717 in `quickstart_cis_benchmark`
  > 1 is not of type 'string' — automatically coerced (number → string)
- **W9003** `ConsoleLoginFailureCloudWatchMetric` (AWS::Logs::MetricFilter) → `Properties.MetricTransformations.0.MetricValue` L1755 in `quickstart_cis_benchmark`
  > 1 is not of type 'string' — automatically coerced (number → string)
- **W9003** `KMSCustomerKeyDeletionCloudWatchMetric` (AWS::Logs::MetricFilter) → `Properties.MetricTransformations.0.MetricValue` L1792 in `quickstart_cis_benchmark`
  > 1 is not of type 'string' — automatically coerced (number → string)
- **W9003** `BillingChangesCloudWatchFilter` (AWS::Logs::MetricFilter) → `Properties.MetricTransformations.0.MetricValue` L2182 in `quickstart_cis_benchmark`
  > 1 is not of type 'string' — automatically coerced (number → string)
- **W9003** `rAMIComplianceFunction` (AWS::Lambda::Function) → `Properties.Timeout` L139 in `quickstart_config-rules`
  > '30' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rCloudTrailValidationFunction` (AWS::Lambda::Function) → `Properties.Timeout` L237 in `quickstart_config-rules`
  > '30' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rAutoScalingConfigWeb` (AWS::AutoScaling::LaunchConfiguration) → `Properties.AssociatePublicIpAddress` L417 in `quickstart_nist_application`
  > 'True' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `rAutoScalingDownApp` (AWS::AutoScaling::ScalingPolicy) → `Properties.ScalingAdjustment` L561 in `quickstart_nist_application`
  > '1' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rAutoScalingDownWeb` (AWS::AutoScaling::ScalingPolicy) → `Properties.ScalingAdjustment` L569 in `quickstart_nist_application`
  > '-1' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rAutoScalingGroupApp` (AWS::AutoScaling::AutoScalingGroup) → `Properties.HealthCheckGracePeriod` L577 in `quickstart_nist_application`
  > '300' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rAutoScalingGroupApp` (AWS::AutoScaling::AutoScalingGroup) → `Properties.Tags.0.PropagateAtLaunch` L577 in `quickstart_nist_application`
  > 'true' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `rAutoScalingGroupApp` (AWS::AutoScaling::AutoScalingGroup) → `Properties.Tags.1.PropagateAtLaunch` L577 in `quickstart_nist_application`
  > 'true' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `rAutoScalingGroupWeb` (AWS::AutoScaling::AutoScalingGroup) → `Properties.HealthCheckGracePeriod` L603 in `quickstart_nist_application`
  > '300' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rAutoScalingGroupWeb` (AWS::AutoScaling::AutoScalingGroup) → `Properties.Tags.0.PropagateAtLaunch` L603 in `quickstart_nist_application`
  > 'true' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `rAutoScalingGroupWeb` (AWS::AutoScaling::AutoScalingGroup) → `Properties.Tags.1.PropagateAtLaunch` L603 in `quickstart_nist_application`
  > 'true' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `rAutoScalingUpApp` (AWS::AutoScaling::ScalingPolicy) → `Properties.ScalingAdjustment` L629 in `quickstart_nist_application`
  > '-1' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rAutoScalingUpWeb` (AWS::AutoScaling::ScalingPolicy) → `Properties.ScalingAdjustment` L637 in `quickstart_nist_application`
  > '1' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rCWAlarmHighCPUApp` (AWS::CloudWatch::Alarm) → `Properties.EvaluationPeriods` L645 in `quickstart_nist_application`
  > '1' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rCWAlarmHighCPUApp` (AWS::CloudWatch::Alarm) → `Properties.Period` L645 in `quickstart_nist_application`
  > '60' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rCWAlarmHighCPUApp` (AWS::CloudWatch::Alarm) → `Properties.Threshold` L645 in `quickstart_nist_application`
  > '50' is not of type 'number' — automatically coerced (string → number)
- **W9003** `rCWAlarmHighCPUWeb` (AWS::CloudWatch::Alarm) → `Properties.EvaluationPeriods` L663 in `quickstart_nist_application`
  > '1' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rCWAlarmHighCPUWeb` (AWS::CloudWatch::Alarm) → `Properties.Period` L663 in `quickstart_nist_application`
  > '60' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rCWAlarmHighCPUWeb` (AWS::CloudWatch::Alarm) → `Properties.Threshold` L663 in `quickstart_nist_application`
  > '50' is not of type 'number' — automatically coerced (string → number)
- **W9003** `rCWAlarmLowCPUApp` (AWS::CloudWatch::Alarm) → `Properties.EvaluationPeriods` L681 in `quickstart_nist_application`
  > '1' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rCWAlarmLowCPUApp` (AWS::CloudWatch::Alarm) → `Properties.Period` L681 in `quickstart_nist_application`
  > '60' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rCWAlarmLowCPUApp` (AWS::CloudWatch::Alarm) → `Properties.Threshold` L681 in `quickstart_nist_application`
  > '10' is not of type 'number' — automatically coerced (string → number)
- **W9003** `rCWAlarmLowCPUWeb` (AWS::CloudWatch::Alarm) → `Properties.EvaluationPeriods` L698 in `quickstart_nist_application`
  > '1' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rCWAlarmLowCPUWeb` (AWS::CloudWatch::Alarm) → `Properties.Period` L698 in `quickstart_nist_application`
  > '60' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rCWAlarmLowCPUWeb` (AWS::CloudWatch::Alarm) → `Properties.Threshold` L698 in `quickstart_nist_application`
  > '10' is not of type 'number' — automatically coerced (string → number)
- **W9003** `rELBApp` (AWS::ElasticLoadBalancing::LoadBalancer) → `Properties.AccessLoggingPolicy.EmitInterval` L723 in `quickstart_nist_application`
  > '60' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rELBApp` (AWS::ElasticLoadBalancing::LoadBalancer) → `Properties.AccessLoggingPolicy.Enabled` L723 in `quickstart_nist_application`
  > 'true' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `rELBWeb` (AWS::ElasticLoadBalancing::LoadBalancer) → `Properties.AccessLoggingPolicy.EmitInterval` L759 in `quickstart_nist_application`
  > '60' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rELBWeb` (AWS::ElasticLoadBalancing::LoadBalancer) → `Properties.AccessLoggingPolicy.Enabled` L759 in `quickstart_nist_application`
  > 'true' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `rRDSInstanceMySQL` (AWS::RDS::DBInstance) → `Properties.MultiAZ` L1003 in `quickstart_nist_application`
  > 'true' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `rRDSInstanceMySQL` (AWS::RDS::DBInstance) → `Properties.StorageEncrypted` L1003 in `quickstart_nist_application`
  > 'true' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `rSecurityGroupApp` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupEgress.0.FromPort` L1066 in `quickstart_nist_application`
  > '443' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rSecurityGroupApp` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupEgress.0.ToPort` L1066 in `quickstart_nist_application`
  > '443' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rSecurityGroupApp` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupEgress.1.FromPort` L1066 in `quickstart_nist_application`
  > '80' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rSecurityGroupApp` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupEgress.1.ToPort` L1066 in `quickstart_nist_application`
  > '80' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rSecurityGroupApp` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.0.FromPort` L1066 in `quickstart_nist_application`
  > '443' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rSecurityGroupApp` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.0.ToPort` L1066 in `quickstart_nist_application`
  > '443' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rSecurityGroupAppInstance` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.0.FromPort` L1093 in `quickstart_nist_application`
  > '443' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rSecurityGroupAppInstance` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.0.ToPort` L1093 in `quickstart_nist_application`
  > '443' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rSecurityGroupAppInstance` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.1.FromPort` L1093 in `quickstart_nist_application`
  > '80' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rSecurityGroupAppInstance` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.1.ToPort` L1093 in `quickstart_nist_application`
  > '80' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rSecurityGroupAppInstance` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.2.FromPort` L1093 in `quickstart_nist_application`
  > '22' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rSecurityGroupAppInstance` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.2.ToPort` L1093 in `quickstart_nist_application`
  > '22' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rSecurityGroupRDS` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.0.FromPort` L1121 in `quickstart_nist_application`
  > '3306' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rSecurityGroupRDS` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.0.ToPort` L1121 in `quickstart_nist_application`
  > '3306' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rSecurityGroupWeb` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.0.FromPort` L1139 in `quickstart_nist_application`
  > '443' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rSecurityGroupWeb` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.0.ToPort` L1139 in `quickstart_nist_application`
  > '443' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rSecurityGroupWebInstance` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.0.FromPort` L1150 in `quickstart_nist_application`
  > '443' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rSecurityGroupWebInstance` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.0.ToPort` L1150 in `quickstart_nist_application`
  > '443' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rSecurityGroupWebInstance` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.1.FromPort` L1150 in `quickstart_nist_application`
  > '80' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rSecurityGroupWebInstance` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.1.ToPort` L1150 in `quickstart_nist_application`
  > '80' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rSecurityGroupWebInstance` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.2.FromPort` L1150 in `quickstart_nist_application`
  > '22' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rSecurityGroupWebInstance` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.2.ToPort` L1150 in `quickstart_nist_application`
  > '22' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rWebContentBucket` (AWS::S3::Bucket) → `Properties.LifecycleConfiguration.Rules.0.ExpirationInDays` L1178 in `quickstart_nist_application`
  > '2555' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rWebContentBucket` (AWS::S3::Bucket) → `Properties.LifecycleConfiguration.Rules.0.Transition.TransitionInDays` L1178 in `quickstart_nist_application`
  > '90' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `ApplicationTemplate` (AWS::CloudFormation::Stack) → `Properties.TimeoutInMinutes` L277 in `quickstart_nist_high_main`
  > '30' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `ConfigRulesTemplate` (AWS::CloudFormation::Stack) → `Properties.TimeoutInMinutes` L387 in `quickstart_nist_high_main`
  > '20' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `IamTemplate` (AWS::CloudFormation::Stack) → `Properties.TimeoutInMinutes` L411 in `quickstart_nist_high_main`
  > '20' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `LoggingTemplate` (AWS::CloudFormation::Stack) → `Properties.TimeoutInMinutes` L424 in `quickstart_nist_high_main`
  > '20' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `ManagementVpcTemplate` (AWS::CloudFormation::Stack) → `Properties.TimeoutInMinutes` L445 in `quickstart_nist_high_main`
  > '20' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `ProductionVpcTemplate` (AWS::CloudFormation::Stack) → `Properties.TimeoutInMinutes` L526 in `quickstart_nist_high_main`
  > '20' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `AnsibleConfigServer` (AWS::EC2::Instance) → `Properties.NetworkInterfaces.0.AssociatePublicIpAddress` L280 in `quickstart_openshift`
  > 'true' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `AnsibleConfigServer` (AWS::EC2::Instance) → `Properties.NetworkInterfaces.0.DeleteOnTermination` L280 in `quickstart_openshift`
  > 'true' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `KeyGen` (AWS::Lambda::Function) → `Properties.Timeout` L799 in `quickstart_openshift`
  > '5' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `OpenShiftEtcdASG` (AWS::AutoScaling::AutoScalingGroup) → `Properties.Tags.0.PropagateAtLaunch` L842 in `quickstart_openshift`
  > 'true' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `OpenShiftEtcdLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.BlockDeviceMappings.0.Ebs.VolumeSize` L861 in `quickstart_openshift`
  > '80' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `OpenShiftEtcdLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.InstanceMonitoring` L861 in `quickstart_openshift`
  > 'true' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `OpenShiftMasterASG` (AWS::AutoScaling::AutoScalingGroup) → `Properties.Tags.0.PropagateAtLaunch` L1064 in `quickstart_openshift`
  > 'true' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `OpenShiftMasterASLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.BlockDeviceMappings.0.Ebs.VolumeSize` L1085 in `quickstart_openshift`
  > '80' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `OpenShiftMasterASLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.InstanceMonitoring` L1085 in `quickstart_openshift`
  > 'true' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `OpenShiftNodeASG` (AWS::AutoScaling::AutoScalingGroup) → `Properties.DesiredCapacity` L1349 in `quickstart_openshift`
  > 3.0 is not of type 'string' — automatically coerced (number → string)
- **W9003** `OpenShiftNodeASG` (AWS::AutoScaling::AutoScalingGroup) → `Properties.MaxSize` L1349 in `quickstart_openshift`
  > 3.0 is not of type 'string' — automatically coerced (number → string)
- **W9003** `OpenShiftNodeASG` (AWS::AutoScaling::AutoScalingGroup) → `Properties.Tags.0.PropagateAtLaunch` L1349 in `quickstart_openshift`
  > 'true' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `OpenShiftNodeSecurityGroup` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.1.FromPort` L1395 in `quickstart_openshift`
  > '8080' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `OpenShiftNodeSecurityGroup` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.1.ToPort` L1395 in `quickstart_openshift`
  > '8080' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `OpenShiftNodeSecurityGroup` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.2.FromPort` L1395 in `quickstart_openshift`
  > '80' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `OpenShiftNodeSecurityGroup` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.2.ToPort` L1395 in `quickstart_openshift`
  > '80' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `OpenShiftNodesLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.BlockDeviceMappings.0.Ebs.VolumeSize` L1415 in `quickstart_openshift`
  > '80' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `OpenShiftNodesLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.BlockDeviceMappings.1.Ebs.VolumeSize` L1415 in `quickstart_openshift`
  > '110' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `OpenShiftNodesLaunchConfig` (AWS::AutoScaling::LaunchConfiguration) → `Properties.InstanceMonitoring` L1415 in `quickstart_openshift`
  > 'true' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `OpenShiftSecurityGroup` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.1.FromPort` L1637 in `quickstart_openshift`
  > '8443' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `OpenShiftSecurityGroup` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.1.ToPort` L1637 in `quickstart_openshift`
  > '8444' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `OpenShiftSecurityGroup` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.2.FromPort` L1637 in `quickstart_openshift`
  > '22' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `OpenShiftSecurityGroup` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.2.ToPort` L1637 in `quickstart_openshift`
  > '22' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rDBServerInstance` (AWS::RDS::DBInstance) → `Properties.Port` L124 in `quickstart_test`
  > 1433.0 is not of type 'string' — automatically coerced (number → string)
- **W9003** `VPC` (AWS::EC2::VPC) → `Properties.EnableDnsHostnames` L506 in `quickstart_vpc`
  > 'true' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `VPC` (AWS::EC2::VPC) → `Properties.EnableDnsSupport` L506 in `quickstart_vpc`
  > 'true' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `PrivateSubnet1BNetworkAclEntryInbound` (AWS::EC2::NetworkAclEntry) → `Properties.Egress` L1262 in `quickstart_vpc`
  > 'false' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `PrivateSubnet1BNetworkAclEntryInbound` (AWS::EC2::NetworkAclEntry) → `Properties.Protocol` L1262 in `quickstart_vpc`
  > '-1' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `PrivateSubnet1BNetworkAclEntryInbound` (AWS::EC2::NetworkAclEntry) → `Properties.RuleNumber` L1262 in `quickstart_vpc`
  > '100' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `PrivateSubnet1BNetworkAclEntryOutbound` (AWS::EC2::NetworkAclEntry) → `Properties.Egress` L1276 in `quickstart_vpc`
  > 'true' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `PrivateSubnet1BNetworkAclEntryOutbound` (AWS::EC2::NetworkAclEntry) → `Properties.Protocol` L1276 in `quickstart_vpc`
  > '-1' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `PrivateSubnet1BNetworkAclEntryOutbound` (AWS::EC2::NetworkAclEntry) → `Properties.RuleNumber` L1276 in `quickstart_vpc`
  > '100' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `PrivateSubnet2BNetworkAclEntryInbound` (AWS::EC2::NetworkAclEntry) → `Properties.Egress` L1384 in `quickstart_vpc`
  > 'false' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `PrivateSubnet2BNetworkAclEntryInbound` (AWS::EC2::NetworkAclEntry) → `Properties.Protocol` L1384 in `quickstart_vpc`
  > '-1' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `PrivateSubnet2BNetworkAclEntryInbound` (AWS::EC2::NetworkAclEntry) → `Properties.RuleNumber` L1384 in `quickstart_vpc`
  > '100' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `PrivateSubnet2BNetworkAclEntryOutbound` (AWS::EC2::NetworkAclEntry) → `Properties.Egress` L1398 in `quickstart_vpc`
  > 'true' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `PrivateSubnet2BNetworkAclEntryOutbound` (AWS::EC2::NetworkAclEntry) → `Properties.Protocol` L1398 in `quickstart_vpc`
  > '-1' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `PrivateSubnet2BNetworkAclEntryOutbound` (AWS::EC2::NetworkAclEntry) → `Properties.RuleNumber` L1398 in `quickstart_vpc`
  > '100' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `PrivateSubnet3BNetworkAclEntryInbound` (AWS::EC2::NetworkAclEntry) → `Properties.Egress` L1506 in `quickstart_vpc`
  > 'false' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `PrivateSubnet3BNetworkAclEntryInbound` (AWS::EC2::NetworkAclEntry) → `Properties.Protocol` L1506 in `quickstart_vpc`
  > '-1' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `PrivateSubnet3BNetworkAclEntryInbound` (AWS::EC2::NetworkAclEntry) → `Properties.RuleNumber` L1506 in `quickstart_vpc`
  > '100' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `PrivateSubnet3BNetworkAclEntryOutbound` (AWS::EC2::NetworkAclEntry) → `Properties.Egress` L1520 in `quickstart_vpc`
  > 'true' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `PrivateSubnet3BNetworkAclEntryOutbound` (AWS::EC2::NetworkAclEntry) → `Properties.Protocol` L1520 in `quickstart_vpc`
  > '-1' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `PrivateSubnet3BNetworkAclEntryOutbound` (AWS::EC2::NetworkAclEntry) → `Properties.RuleNumber` L1520 in `quickstart_vpc`
  > '100' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `PrivateSubnet4BNetworkAclEntryInbound` (AWS::EC2::NetworkAclEntry) → `Properties.Egress` L1628 in `quickstart_vpc`
  > 'false' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `PrivateSubnet4BNetworkAclEntryInbound` (AWS::EC2::NetworkAclEntry) → `Properties.Protocol` L1628 in `quickstart_vpc`
  > '-1' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `PrivateSubnet4BNetworkAclEntryInbound` (AWS::EC2::NetworkAclEntry) → `Properties.RuleNumber` L1628 in `quickstart_vpc`
  > '100' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `PrivateSubnet4BNetworkAclEntryOutbound` (AWS::EC2::NetworkAclEntry) → `Properties.Egress` L1642 in `quickstart_vpc`
  > 'true' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `PrivateSubnet4BNetworkAclEntryOutbound` (AWS::EC2::NetworkAclEntry) → `Properties.Protocol` L1642 in `quickstart_vpc`
  > '-1' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `PrivateSubnet4BNetworkAclEntryOutbound` (AWS::EC2::NetworkAclEntry) → `Properties.RuleNumber` L1642 in `quickstart_vpc`
  > '100' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `NATInstance1` (AWS::EC2::Instance) → `Properties.NetworkInterfaces.0.AssociatePublicIpAddress` L1885 in `quickstart_vpc`
  > 'true' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `NATInstance1` (AWS::EC2::Instance) → `Properties.NetworkInterfaces.0.DeleteOnTermination` L1885 in `quickstart_vpc`
  > 'true' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `NATInstance1` (AWS::EC2::Instance) → `Properties.SourceDestCheck` L1885 in `quickstart_vpc`
  > 'false' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `NATInstance2` (AWS::EC2::Instance) → `Properties.NetworkInterfaces.0.AssociatePublicIpAddress` L1937 in `quickstart_vpc`
  > 'true' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `NATInstance2` (AWS::EC2::Instance) → `Properties.NetworkInterfaces.0.DeleteOnTermination` L1937 in `quickstart_vpc`
  > 'true' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `NATInstance2` (AWS::EC2::Instance) → `Properties.SourceDestCheck` L1937 in `quickstart_vpc`
  > 'false' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `NATInstance3` (AWS::EC2::Instance) → `Properties.NetworkInterfaces.0.AssociatePublicIpAddress` L1989 in `quickstart_vpc`
  > 'true' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `NATInstance3` (AWS::EC2::Instance) → `Properties.NetworkInterfaces.0.DeleteOnTermination` L1989 in `quickstart_vpc`
  > 'true' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `NATInstance3` (AWS::EC2::Instance) → `Properties.SourceDestCheck` L1989 in `quickstart_vpc`
  > 'false' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `NATInstance4` (AWS::EC2::Instance) → `Properties.NetworkInterfaces.0.AssociatePublicIpAddress` L2041 in `quickstart_vpc`
  > 'true' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `NATInstance4` (AWS::EC2::Instance) → `Properties.NetworkInterfaces.0.DeleteOnTermination` L2041 in `quickstart_vpc`
  > 'true' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `NATInstance4` (AWS::EC2::Instance) → `Properties.SourceDestCheck` L2041 in `quickstart_vpc`
  > 'false' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `NATInstanceSecurityGroup` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.0.FromPort` L2093 in `quickstart_vpc`
  > '1' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `NATInstanceSecurityGroup` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.0.ToPort` L2093 in `quickstart_vpc`
  > '65535' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rVPCManagement` (AWS::EC2::VPC) → `Properties.EnableDnsHostnames` L339 in `quickstart_vpc-management`
  > 'true' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `rVPCManagement` (AWS::EC2::VPC) → `Properties.EnableDnsSupport` L339 in `quickstart_vpc-management`
  > 'true' is not of type 'boolean' — automatically coerced (string → boolean)
- **W9003** `rNatInstanceTemplate` (AWS::CloudFormation::Stack) → `Properties.TimeoutInMinutes` L377 in `quickstart_vpc-management`
  > '20' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rSecurityGroupPeered` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.0.FromPort` L418 in `quickstart_vpc-management`
  > '22' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rSecurityGroupPeered` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.0.ToPort` L418 in `quickstart_vpc-management`
  > '22' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rSecurityGroupVpcNat` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.0.FromPort` L437 in `quickstart_vpc-management`
  > '80' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rSecurityGroupVpcNat` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.0.ToPort` L437 in `quickstart_vpc-management`
  > '80' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rSecurityGroupVpcNat` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.1.FromPort` L437 in `quickstart_vpc-management`
  > '443' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rSecurityGroupVpcNat` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.1.ToPort` L437 in `quickstart_vpc-management`
  > '443' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rSecurityGroupSSHFromMgmt` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.0.FromPort` L742 in `quickstart_vpc-management`
  > '22' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rSecurityGroupSSHFromMgmt` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.0.ToPort` L742 in `quickstart_vpc-management`
  > '22' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rSecurityGroupBastion` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupEgress.0.FromPort` L801 in `quickstart_vpc-management`
  > '1' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rSecurityGroupBastion` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupEgress.0.ToPort` L801 in `quickstart_vpc-management`
  > '65535' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rSecurityGroupBastion` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.0.FromPort` L801 in `quickstart_vpc-management`
  > '22' is not of type 'integer' — automatically coerced (string → integer)
- **W9003** `rSecurityGroupBastion` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.0.ToPort` L801 in `quickstart_vpc-management`
  > '22' is not of type 'integer' — automatically coerced (string → integer)

### W1028 — 41 findings — Check Fn::If has a path that cannot be reached

- **W1028** `myInstance4` (AWS::EC2::Instance) → `Properties.InstanceType.Fn::If.Fn::If.2` L63 in `bad_core_conditions`
  > ['Fn::If', 2] is not reachable. When setting condition 'isPrimary' to False from current status True
- **W1028** `conditionLoadBalancer` (AWS::ElasticLoadBalancing::LoadBalancer) → `Properties.Fn::If.Fn::If.2` L149 in `bad_generic`
  > ['Fn::If', 2] is not reachable. When setting condition 'IsProduction' to False from current status True
- **W1028** `ProxySubnetRouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId.Fn::If.2` L48 in `bad_properties_rt_association`
  > ['Fn::If', 2] is not reachable. When setting condition 'isPublic' to False from current status True
- **W1028** `RootRole5` (AWS::IAM::Role) → `Properties.RoleName.Fn::If.2` L97 in `bad_resources_primary_identifiers`
  > ['Fn::If', 2] is not reachable. When setting condition 'IsUsEast1' to False from current status True
- **W1028** `RootRole6` (AWS::IAM::Role) → `Properties.RoleName.Fn::If.2` L119 in `bad_resources_primary_identifiers`
  > ['Fn::If', 2] is not reachable. When setting condition 'IsUsEast1' to False from current status True
- **W1028** `Bucket1` (AWS::S3::Bucket) → `Properties.Fn::If.Fn::If.2` L141 in `bad_resources_primary_identifiers`
  > ['Fn::If', 2] is not reachable. When setting condition 'IsUsEast1' to False from current status True
- **W1028** `Bucket2` (AWS::S3::Bucket) → `Properties.BucketName.Fn::If.2` L148 in `bad_resources_primary_identifiers`
  > ['Fn::If', 2] is not reachable. When setting condition 'IsUsEast1' to False from current status True
- **W1028** `MyCNAMERecordSetConditions` (AWS::Route53::RecordSet) → `Properties.ResourceRecords.Fn::If.2` L83 in `bad_route53`
  > ['Fn::If', 2] is not reachable. When setting condition 'isPrimaryRegion' to False from current status True
- **W1028** `CloudFrontDistribution` (AWS::CloudFront::Distribution) → `Properties.DistributionConfig.Restrictions.GeoRestriction.Fn::If.1.Locations.Fn::If.2` L40 in `good_conditions`
  > ['Fn::If', 2] is not reachable. When setting condition 'PrimaryRegion' to False. Where existing status for condition 'EnableGeoBlockingAlias' is True
- **W1028** `AMIIDLookup` (AWS::Lambda::Function) → `Properties.Role.Fn::If.2` L100 in `good_core_conditions`
  > ['Fn::If', 2] is not reachable. When setting condition 'isPrimary' to False from current status True
- **W1028** `ProxySubnetRouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId.Fn::If.2` L46 in `good_properties_rt_association`
  > ['Fn::If', 2] is not reachable. When setting condition 'isPublic' to False from current status True
- **W1028** `TestPipeline` (AWS::CodePipeline::Pipeline) → `Properties.Stages.2.Actions.0.Fn::If.2` L6 in `good_resources_codepipeline`
  > ['Fn::If', 2] is not reachable. When setting condition 'myCondition' to False from current status True
- **W1028** `Bucket1` (AWS::S3::Bucket) → `Properties.Fn::If.Fn::If.2` L75 in `good_resources_primary_identifiers`
  > ['Fn::If', 2] is not reachable. When setting condition 'IsUsEast1' to False from current status True
- **W1028** `IamRole1` (AWS::IAM::Role) → `Properties.Tags.0.Fn::If.2` L8 in `integration_ref-no-value`
  > ['Fn::If', 2] is not reachable. When setting condition 'IsUsEast1' to False from current status True
- **W1028** `IamRole3` (AWS::IAM::Role) → `Properties.Tags.Fn::If.2` L28 in `integration_ref-no-value`
  > ['Fn::If', 2] is not reachable. When setting condition 'IsUsEast1' to False from current status True
- **W1028** `CloudFront2` (AWS::CloudFront::Distribution) → `Properties.DistributionConfig.DefaultCacheBehavior.Fn::If.2` L41 in `integration_ref-no-value`
  > ['Fn::If', 2] is not reachable. When setting condition 'IsUsEast1' to False from current status True
- **W1028** `DHCPOptions` (AWS::EC2::DHCPOptions) → `Properties.DomainName.Fn::If.2` L481 in `quickstart_vpc`
  > ['Fn::If', 2] is not reachable. When setting condition 'NVirginiaRegionCondition' to False from current status True
- **W1028** `PrivateSubnet1ARoute` (AWS::EC2::Route) → `Properties.InstanceId.Fn::If.1` L947 in `quickstart_vpc`
  > ['Fn::If', 1] is not reachable. When setting condition 'NATInstanceCondition' to True
- **W1028** `PrivateSubnet1ARoute` (AWS::EC2::Route) → `Properties.NatGatewayId.Fn::If.2` L947 in `quickstart_vpc`
  > ['Fn::If', 2] is not reachable. When setting condition 'NATGatewayCondition' to False. Where existing status for condition 'PrivateSubnetsCondition' is True
- **W1028** `PrivateSubnet2ARoute` (AWS::EC2::Route) → `Properties.InstanceId.Fn::If.1` L1010 in `quickstart_vpc`
  > ['Fn::If', 1] is not reachable. When setting condition 'NATInstanceCondition' to True
- **W1028** `PrivateSubnet2ARoute` (AWS::EC2::Route) → `Properties.NatGatewayId.Fn::If.2` L1010 in `quickstart_vpc`
  > ['Fn::If', 2] is not reachable. When setting condition 'NATGatewayCondition' to False. Where existing status for condition 'PrivateSubnetsCondition' is True
- **W1028** `PrivateSubnet3ARoute` (AWS::EC2::Route) → `Properties.InstanceId.Fn::If.1` L1073 in `quickstart_vpc`
  > ['Fn::If', 1] is not reachable. When setting condition 'NATInstanceCondition' to True
- **W1028** `PrivateSubnet3ARoute` (AWS::EC2::Route) → `Properties.NatGatewayId.Fn::If.2` L1073 in `quickstart_vpc`
  > ['Fn::If', 2] is not reachable. When setting condition 'NATGatewayCondition' to False. Where existing status for condition 'PrivateSubnets&3AZCondition' is True
- **W1028** `PrivateSubnet4ARoute` (AWS::EC2::Route) → `Properties.InstanceId.Fn::If.1` L1136 in `quickstart_vpc`
  > ['Fn::If', 1] is not reachable. When setting condition 'NATInstanceCondition' to True
- **W1028** `PrivateSubnet4ARoute` (AWS::EC2::Route) → `Properties.NatGatewayId.Fn::If.2` L1136 in `quickstart_vpc`
  > ['Fn::If', 2] is not reachable. When setting condition 'NATGatewayCondition' to False. Where existing status for condition 'PrivateSubnets&4AZCondition' is True
- **W1028** `PrivateSubnet1BRoute` (AWS::EC2::Route) → `Properties.InstanceId.Fn::If.1` L1199 in `quickstart_vpc`
  > ['Fn::If', 1] is not reachable. When setting condition 'NATInstanceCondition' to True
- **W1028** `PrivateSubnet1BRoute` (AWS::EC2::Route) → `Properties.NatGatewayId.Fn::If.2` L1199 in `quickstart_vpc`
  > ['Fn::If', 2] is not reachable. When setting condition 'NATGatewayCondition' to False. Where existing status for condition 'AdditionalPrivateSubnetsCondition' is True
- **W1028** `PrivateSubnet2BRoute` (AWS::EC2::Route) → `Properties.InstanceId.Fn::If.1` L1321 in `quickstart_vpc`
  > ['Fn::If', 1] is not reachable. When setting condition 'NATInstanceCondition' to True
- **W1028** `PrivateSubnet2BRoute` (AWS::EC2::Route) → `Properties.NatGatewayId.Fn::If.2` L1321 in `quickstart_vpc`
  > ['Fn::If', 2] is not reachable. When setting condition 'NATGatewayCondition' to False. Where existing status for condition 'AdditionalPrivateSubnetsCondition' is True
- **W1028** `PrivateSubnet3BRoute` (AWS::EC2::Route) → `Properties.InstanceId.Fn::If.1` L1443 in `quickstart_vpc`
  > ['Fn::If', 1] is not reachable. When setting condition 'NATInstanceCondition' to True
- **W1028** `PrivateSubnet3BRoute` (AWS::EC2::Route) → `Properties.NatGatewayId.Fn::If.2` L1443 in `quickstart_vpc`
  > ['Fn::If', 2] is not reachable. When setting condition 'NATGatewayCondition' to False. Where existing status for condition 'AdditionalPrivateSubnets&3AZCondition' is True
- **W1028** `PrivateSubnet4BRoute` (AWS::EC2::Route) → `Properties.InstanceId.Fn::If.1` L1565 in `quickstart_vpc`
  > ['Fn::If', 1] is not reachable. When setting condition 'NATInstanceCondition' to True
- **W1028** `PrivateSubnet4BRoute` (AWS::EC2::Route) → `Properties.NatGatewayId.Fn::If.2` L1565 in `quickstart_vpc`
  > ['Fn::If', 2] is not reachable. When setting condition 'NATGatewayCondition' to False. Where existing status for condition 'AdditionalPrivateSubnets&4AZCondition' is True
- **W1028** `NAT1EIP` (AWS::EC2::EIP) → `Properties.InstanceId.Fn::If.1` L1745 in `quickstart_vpc`
  > ['Fn::If', 1] is not reachable. When setting condition 'NATInstanceCondition' to True
- **W1028** `NAT2EIP` (AWS::EC2::EIP) → `Properties.InstanceId.Fn::If.1` L1764 in `quickstart_vpc`
  > ['Fn::If', 1] is not reachable. When setting condition 'NATInstanceCondition' to True
- **W1028** `NAT3EIP` (AWS::EC2::EIP) → `Properties.InstanceId.Fn::If.1` L1783 in `quickstart_vpc`
  > ['Fn::If', 1] is not reachable. When setting condition 'NATInstanceCondition' to True
- **W1028** `NAT4EIP` (AWS::EC2::EIP) → `Properties.InstanceId.Fn::If.1` L1802 in `quickstart_vpc`
  > ['Fn::If', 1] is not reachable. When setting condition 'NATInstanceCondition' to True
- **W1028** `NATInstance1` (AWS::EC2::Instance) → `Properties.KeyName.Fn::If.1` L1885 in `quickstart_vpc`
  > ['Fn::If', 1] is not reachable. When setting condition 'NATInstanceCondition' to True
- **W1028** `NATInstance2` (AWS::EC2::Instance) → `Properties.KeyName.Fn::If.1` L1937 in `quickstart_vpc`
  > ['Fn::If', 1] is not reachable. When setting condition 'NATInstanceCondition' to True
- **W1028** `NATInstance3` (AWS::EC2::Instance) → `Properties.KeyName.Fn::If.1` L1989 in `quickstart_vpc`
  > ['Fn::If', 1] is not reachable. When setting condition 'NATInstanceCondition' to True
- **W1028** `NATInstance4` (AWS::EC2::Instance) → `Properties.KeyName.Fn::If.1` L2041 in `quickstart_vpc`
  > ['Fn::If', 1] is not reachable. When setting condition 'NATInstanceCondition' to True

### E1152 — 37 findings — Validate AMI id format

- **E1152** `myInstance1` (AWS::EC2::Instance) → `Properties.ImageId` L28 in `bad_core_conditions`
  > Value 'ami-123456' does not match AMI ID format (ami-xxxxxxxxx)
- **E1152** `myInstance2` (AWS::EC2::Instance) → `Properties.ImageId` L33 in `bad_core_conditions`
  > Value 'ami-123456' does not match AMI ID format (ami-xxxxxxxxx)
- **E1152** `myInstance3` (AWS::EC2::Instance) → `Properties.ImageId` L50 in `bad_core_conditions`
  > Value 'ami-1234567' does not match AMI ID format (ami-xxxxxxxxx)
- **E1152** `myInstance3` (AWS::EC2::Instance) → `Properties.ImageId` L50 in `bad_core_conditions`
  > Value 'ami-123abcd' does not match AMI ID format (ami-xxxxxxxxx)
- **E1152** `myInstance3` (AWS::EC2::Instance) → `Properties.ImageId` L50 in `bad_core_conditions`
  > Value 'ami-abcdefg' does not match AMI ID format (ami-xxxxxxxxx)
- **E1152** `myInstance4` (AWS::EC2::Instance) → `Properties.ImageId` L63 in `bad_core_conditions`
  > Value 'ami-123456' does not match AMI ID format (ami-xxxxxxxxx)
- **E1152** `myInstance4` (AWS::EC2::Instance) → `Properties.ImageId` L63 in `bad_core_conditions`
  > Value 'ami-abcdef' does not match AMI ID format (ami-xxxxxxxxx)
- **E1152** `myInstance` (AWS::EC2::Instance) → `Properties.ImageId` L7 in `bad_functions_join`
  > Value 'ami-1234' does not match AMI ID format (ami-xxxxxxxxx)
- **E1152** `myInstance2` (AWS::EC2::Instance) → `Properties.ImageId` L17 in `bad_functions_join`
  > Value 'ami-1234' does not match AMI ID format (ami-xxxxxxxxx)
- **E1152** `myInstance` (AWS::EC2::Instance) → `Properties.ImageId` L7 in `bad_functions_select`
  > Value 'String' does not match AMI ID format (ami-xxxxxxxxx)
- **E1152** `myInstance1` (AWS::EC2::Instance) → `Properties.ImageId` L15 in `bad_functions_select`
  > Value 'String' does not match AMI ID format (ami-xxxxxxxxx)
- **E1152** `myInstance2` (AWS::EC2::Instance) → `Properties.ImageId` L24 in `bad_functions_select`
  > Value 'String' does not match AMI ID format (ami-xxxxxxxxx)
- **E1152** `myInstance3` (AWS::EC2::Instance) → `Properties.ImageId` L32 in `bad_functions_select`
  > Value 'String' does not match AMI ID format (ami-xxxxxxxxx)
- **E1152** `Instance` (AWS::EC2::Instance) → `Properties.ImageId` L5 in `bad_previous_generation_instances`
  > Value 'ami-abc' does not match AMI ID format (ami-xxxxxxxxx)
- **E1152** `myInstance` (AWS::EC2::Instance) → `Properties.ImageId` L77 in `bad_properties_sg_ingress`
  > Value 'ami-123456' does not match AMI ID format (ami-xxxxxxxxx)
- **E1152** `myInstanceSub` (AWS::EC2::Instance) → `Properties.ImageId` L214 in `bad_resources_circular_dependency`
  > Value 'String' does not match AMI ID format (ami-xxxxxxxxx)
- **E1152** `my.Instance` (AWS::EC2::Instance) → `Properties.ImageId` L4 in `bad_resources_name`
  > 'ami-123456' does not match format 'AWS::EC2::Image.Id'
- **E1152** `my.Instance` (AWS::EC2::Instance) → `Properties.ImageId` L4 in `bad_resources_name`
  > Value 'ami-123456' does not match AMI ID format (ami-xxxxxxxxx)
- **E1152** `my_Instance` (AWS::EC2::Instance) → `Properties.ImageId` L8 in `bad_resources_name`
  > 'ami-123456' does not match format 'AWS::EC2::Image.Id'
- **E1152** `my_Instance` (AWS::EC2::Instance) → `Properties.ImageId` L8 in `bad_resources_name`
  > Value 'ami-123456' does not match AMI ID format (ami-xxxxxxxxx)
- **E1152** `myInstance` (AWS::EC2::Instance) → `Properties.ImageId` L26 in `good_conditions`
  > 'ami-abcdefgh' does not match format 'AWS::EC2::Image.Id'
- **E1152** `myInstance` (AWS::EC2::Instance) → `Properties.ImageId` L26 in `good_conditions`
  > Value 'ami-abcdefgh' does not match AMI ID format (ami-xxxxxxxxx)
- **E1152** `myInstance` (AWS::EC2::Instance) → `Properties.ImageId` L20 in `good_functions_sub`
  > Value 'String' does not match AMI ID format (ami-xxxxxxxxx)
- **E1152** `LaunchConfiguration` (AWS::AutoScaling::LaunchConfiguration) → `Properties.ImageId` L55 in `good_functions_sub`
  > Value 'ami-123456' does not match AMI ID format (ami-xxxxxxxxx)
- **E1152** `LaunchConfiguration` (AWS::AutoScaling::LaunchConfiguration) → `Properties.ImageId` L18 in `good_parameters_not_used_parameters`
  > Value 'ami-123456' does not match AMI ID format (ami-xxxxxxxxx)
- **E1152** `LaunchConfiguration` (AWS::AutoScaling::LaunchConfiguration) → `Properties.ImageId` L21 in `good_parameters_used_transforms`
  > Value 'ami-123456' does not match AMI ID format (ami-xxxxxxxxx)
- **E1152** `myInstance` (AWS::EC2::Instance) → `Properties.ImageId` L4 in `good_resources_name`
  > Value 'ami-123456' does not match AMI ID format (ami-xxxxxxxxx)
- **E1152** `Instance` (AWS::EC2::Instance) → `Properties.ImageId` L9 in `integration_aws-ec2-instance`
  > 'ami-abcdefgh' does not match format 'AWS::EC2::Image.Id'
- **E1152** `Instance` (AWS::EC2::Instance) → `Properties.ImageId` L9 in `integration_aws-ec2-instance`
  > Value 'ami-abcdefgh' does not match AMI ID format (ami-xxxxxxxxx)
- **E1152** `LaunchTemplate` (AWS::EC2::LaunchTemplate) → `Properties.LaunchTemplateData.ImageId` L3 in `integration_aws-ec2-launchtemplate`
  > 'ami-abcdefgh' does not match format 'AWS::EC2::Image.Id'
- **E1152** `LaunchTemplate` (AWS::EC2::LaunchTemplate) → `Properties.LaunchTemplateData.ImageId` L3 in `integration_aws-ec2-launchtemplate`
  > Value 'ami-abcdefgh' does not match AMI ID format (ami-xxxxxxxxx)
- **E1152** `rNatInstance` (AWS::EC2::Instance) → `Properties.ImageId` L93 in `quickstart_nat-instance`
  > Value '' does not match AMI ID format (ami-xxxxxxxxx)
- **E1152** `rAutoScalingConfigApp` (AWS::AutoScaling::LaunchConfiguration) → `Properties.ImageId` L219 in `quickstart_nist_application`
  > Value 'none' does not match AMI ID format (ami-xxxxxxxxx)
- **E1152** `rAutoScalingConfigWeb` (AWS::AutoScaling::LaunchConfiguration) → `Properties.ImageId` L417 in `quickstart_nist_application`
  > Value 'none' does not match AMI ID format (ami-xxxxxxxxx)
- **E1152** `rPostProcInstance` (AWS::EC2::Instance) → `Properties.ImageId` L794 in `quickstart_nist_application`
  > Value 'none' does not match AMI ID format (ami-xxxxxxxxx)
- **E1152** `rMgmtBastionInstance` (AWS::EC2::Instance) → `Properties.ImageId` L479 in `quickstart_nist_vpc_management`
  > Value '' does not match AMI ID format (ami-xxxxxxxxx)
- **E1152** `rMgmtBastionInstance` (AWS::EC2::Instance) → `Properties.ImageId` L635 in `quickstart_vpc-management`
  > Value '' does not match AMI ID format (ami-xxxxxxxxx)

### I3510 — 32 findings — Validate statement resources match the actions

- **I3510** `SampleBadIAMPolicy1` (AWS::IAM::ManagedPolicy) → `Properties.PolicyDocument` L40 in `bad_hard_coded_arn_properties`
  > Action 'sns:Publish' requires a resource matching 'arn:*:sns:*:*:.*' but none of the resources match
- **I3510** `SampleBadIAMPolicy2` (AWS::IAM::ManagedPolicy) → `Properties.PolicyDocument` L53 in `bad_hard_coded_arn_properties`
  > Action 'sns:Publish' requires a resource matching 'arn:*:sns:*:*:.*' but none of the resources match
- **I3510** `SampleBadIAMPolicy3` (AWS::IAM::ManagedPolicy) → `Properties.PolicyDocument` L68 in `bad_hard_coded_arn_properties`
  > Action 'sns:Publish' requires a resource matching 'arn:*:sns:*:*:.*' but none of the resources match
- **I3510** `myRoleToWriteToS3` (AWS::IAM::Role) → `Properties.Policies[0].PolicyDocument` L97 in `bad_resources_circular_dependency`
  > Action 's3:AbortMultipartUpload' requires a resource matching 'arn:*:s3:*:*:accesspoint/.*' but none of the resources match
- **I3510** `myRoleToWriteToS3` (AWS::IAM::Role) → `Properties.Policies[0].PolicyDocument` L97 in `bad_resources_circular_dependency`
  > Action 's3:GetBucketAcl' requires a resource matching 'arn:*:s3:*:*:accesspoint/.*' but none of the resources match
- **I3510** `myRoleToWriteToS3` (AWS::IAM::Role) → `Properties.Policies[0].PolicyDocument` L97 in `bad_resources_circular_dependency`
  > Action 's3:GetObject' requires a resource matching 'arn:*:s3:*:*:accesspoint/.*' but none of the resources match
- **I3510** `myRoleToWriteToS3` (AWS::IAM::Role) → `Properties.Policies[0].PolicyDocument` L97 in `bad_resources_circular_dependency`
  > Action 's3:GetObjectAcl' requires a resource matching 'arn:*:s3:*:*:accesspoint/.*' but none of the resources match
- **I3510** `myRoleToWriteToS3` (AWS::IAM::Role) → `Properties.Policies[0].PolicyDocument` L97 in `bad_resources_circular_dependency`
  > Action 's3:GetObjectVersion' requires a resource matching 'arn:*:s3:*:*:accesspoint/.*' but none of the resources match
- **I3510** `myRoleToWriteToS3` (AWS::IAM::Role) → `Properties.Policies[0].PolicyDocument` L97 in `bad_resources_circular_dependency`
  > Action 's3:ListBucket' requires a resource matching 'arn:*:s3:*:*:accesspoint/.*' but none of the resources match
- **I3510** `myRoleToWriteToS3` (AWS::IAM::Role) → `Properties.Policies[0].PolicyDocument` L97 in `bad_resources_circular_dependency`
  > Action 's3:PutObject' requires a resource matching 'arn:*:s3:*:*:accesspoint/.*' but none of the resources match
- **I3510** `myRoleToWriteToS3` (AWS::IAM::Role) → `Properties.Policies[0].PolicyDocument` L97 in `bad_resources_circular_dependency`
  > Action 's3:PutObjectTagging' requires a resource matching 'arn:*:s3:*:*:accesspoint/.*' but none of the resources match
- **I3510** `myRoleToWriteToS3` (AWS::IAM::Role) → `Properties.Policies[0].PolicyDocument` L97 in `bad_resources_circular_dependency`
  > Action 's3:PutObjectVersionTagging' requires a resource matching 'arn:*:s3:*:*:accesspoint/.*' but none of the resources match
- **I3510** `myPolicy2` (AWS::IAM::Policy) → `Properties.PolicyDocument` L29 in `good_functions_sub_needed`
  > Action 'redshift:JoinGroup' requires a resource matching 'arn:*:redshift:*:*:dbgroup:.*' but none of the resources match
- **I3510** `rDBMonitoringRole` (AWS::IAM::Role) → `Properties.Policies[0].PolicyDocument` L94 in `good_no_value`
  > Action 'logs:CreateLogGroup' requires a resource matching 'arn:*:logs:*:*:log-group:.*' but none of the resources match
- **I3510** `rDBMonitoringRole` (AWS::IAM::Role) → `Properties.Policies[0].PolicyDocument` L94 in `good_no_value`
  > Action 'logs:CreateLogStream' requires a resource matching 'arn:*:logs:*:*:log-group:.*' but none of the resources match
- **I3510** `rDBMonitoringRole` (AWS::IAM::Role) → `Properties.Policies[0].PolicyDocument` L94 in `good_no_value`
  > Action 'logs:DescribeLogStreams' requires a resource matching 'arn:*:logs:*:*:log-group:.*' but none of the resources match
- **I3510** `rDBMonitoringRole` (AWS::IAM::Role) → `Properties.Policies[0].PolicyDocument` L94 in `good_no_value`
  > Action 'logs:GetLogEvents' requires a resource matching 'arn:*:logs:*:*:log-group:.*' but none of the resources match
- **I3510** `rDBMonitoringRole` (AWS::IAM::Role) → `Properties.Policies[0].PolicyDocument` L94 in `good_no_value`
  > Action 'logs:PutLogEvents' requires a resource matching 'arn:*:logs:*:*:log-group:.*' but none of the resources match
- **I3510** `rDBMonitoringRole` (AWS::IAM::Role) → `Properties.Policies[0].PolicyDocument` L94 in `good_no_value`
  > Action 'logs:PutRetentionPolicy' requires a resource matching 'arn:*:logs:*:*:log-group:.*' but none of the resources match
- **I3510** `TenantInfoReadPolicy` (AWS::IAM::ManagedPolicy) → `Properties.PolicyDocument` L152 in `issues_sam_w_conditions`
  > Action 'secretsmanager:DescribeSecret' requires a resource matching 'arn:*:secretsmanager:*:*:secret:.*' but none of the resources match
- **I3510** `TenantInfoReadPolicy` (AWS::IAM::ManagedPolicy) → `Properties.PolicyDocument` L152 in `issues_sam_w_conditions`
  > Action 'secretsmanager:GetSecretValue' requires a resource matching 'arn:*:secretsmanager:*:*:secret:.*' but none of the resources match
- **I3510** `rPostProcInstanceRole` (AWS::IAM::Role) → `Properties.Policies[0].PolicyDocument` L960 in `quickstart_nist_application`
  > Action 'sns:Publish' requires a resource matching 'arn:*:sns:*:*:.*' but none of the resources match
- **I3510** `LambdaExecutionRole` (AWS::IAM::Role) → `Properties.Policies[0].PolicyDocument` L814 in `quickstart_openshift`
  > Action 'logs:CreateLogGroup' requires a resource matching 'arn:*:logs:*:*:log-group:.*' but none of the resources match
- **I3510** `LambdaExecutionRole` (AWS::IAM::Role) → `Properties.Policies[0].PolicyDocument` L814 in `quickstart_openshift`
  > Action 'logs:CreateLogStream' requires a resource matching 'arn:*:logs:*:*:log-group:.*' but none of the resources match
- **I3510** `LambdaExecutionRole` (AWS::IAM::Role) → `Properties.Policies[0].PolicyDocument` L814 in `quickstart_openshift`
  > Action 'logs:PutLogEvents' requires a resource matching 'arn:*:logs:*:*:log-group:.*' but none of the resources match
- **I3510** `SetupRole` (AWS::IAM::Role) → `Properties.Policies[0].PolicyDocument` L1657 in `quickstart_openshift`
  > Action 's3:GetObject' requires a resource matching 'arn:*:s3:*:*:accesspoint/.*' but none of the resources match
- **I3510** `rDBMonitoringRole` (AWS::IAM::Role) → `Properties.Policies[0].PolicyDocument` L94 in `quickstart_test`
  > Action 'logs:CreateLogGroup' requires a resource matching 'arn:*:logs:*:*:log-group:.*' but none of the resources match
- **I3510** `rDBMonitoringRole` (AWS::IAM::Role) → `Properties.Policies[0].PolicyDocument` L94 in `quickstart_test`
  > Action 'logs:CreateLogStream' requires a resource matching 'arn:*:logs:*:*:log-group:.*' but none of the resources match
- **I3510** `rDBMonitoringRole` (AWS::IAM::Role) → `Properties.Policies[0].PolicyDocument` L94 in `quickstart_test`
  > Action 'logs:DescribeLogStreams' requires a resource matching 'arn:*:logs:*:*:log-group:.*' but none of the resources match
- **I3510** `rDBMonitoringRole` (AWS::IAM::Role) → `Properties.Policies[0].PolicyDocument` L94 in `quickstart_test`
  > Action 'logs:GetLogEvents' requires a resource matching 'arn:*:logs:*:*:log-group:.*' but none of the resources match
- **I3510** `rDBMonitoringRole` (AWS::IAM::Role) → `Properties.Policies[0].PolicyDocument` L94 in `quickstart_test`
  > Action 'logs:PutLogEvents' requires a resource matching 'arn:*:logs:*:*:log-group:.*' but none of the resources match
- **I3510** `rDBMonitoringRole` (AWS::IAM::Role) → `Properties.Policies[0].PolicyDocument` L94 in `quickstart_test`
  > Action 'logs:PutRetentionPolicy' requires a resource matching 'arn:*:logs:*:*:log-group:.*' but none of the resources match

### F3012 — 27 findings — Check resource properties values

- **F3012** `myInstance4` (AWS::EC2::Instance) → `Properties.InstanceType` L63 in `bad_core_conditions`
  > {"Fn::If":"t3.2xlarge"} is not of type 'string'
- **F3012** `myInstance1` (AWS::EC2::Instance) → `Properties.AvailabilityZone` L15 in `bad_functions_select`
  > {"Fn::Select":[0,"Value1","value2"]} is not of type 'string'
- **F3012** `myInstance3` (AWS::EC2::Instance) → `Properties.AvailabilityZone` L32 in `bad_functions_select`
  > {"Fn::Select":"foo"} is not of type 'string'
- **F3012** `lambdaMap1` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.0` L194 in `bad_generic`
  > 'us-east-1a' is not of type 'object'
- **F3012** `lambdaMap1` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.1` L194 in `bad_generic`
  > 'us-east-1b' is not of type 'object'
- **F3012** `lambdaMap1` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.2` L194 in `bad_generic`
  > 'us-east-1c' is not of type 'object'
- **F3012** `lambdaMap1` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.3` L194 in `bad_generic`
  > 'us-east-1d' is not of type 'object'
- **F3012** `lambdaMap1` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.4` L194 in `bad_generic`
  > 'us-east-1e' is not of type 'object'
- **F3012** `lambdaMap1` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.5` L194 in `bad_generic`
  > 'us-east-1f' is not of type 'object'
- **F3012** `lambdaMap2` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress.0` L202 in `bad_generic`
  > [{"CidrIp":"0.0.0.0/0","IpProtocol":"tcp","ToPort":80,"FromPort":80}] is not of type 'object'
- **F3012** `myInstanceSub` (AWS::EC2::Instance) → `Properties.UserData` L214 in `bad_resources_circular_dependency`
  > {"Fn::Sub":{"Test":"bad configuration"}} is not of type 'string'
- **F3012** `LambdaFunctionTestDefinedArray` (AWS::Lambda::Function) → `Properties.Code` L23 in `good_custom_is-defined`
  > './' is not of type 'object'
- **F3012** `LambdaFunctionTestDefinedEmpty` (AWS::Lambda::Function) → `Properties.Code` L35 in `good_custom_is-defined`
  > './' is not of type 'object'
- **F3012** `LambdaFunctionTestDefinedGetAttr` (AWS::Lambda::Function) → `Properties.Code` L45 in `good_custom_is-defined`
  > './' is not of type 'object'
- **F3012** `LambdaFunctionTestDefinedObject` (AWS::Lambda::Function) → `Properties.Code` L55 in `good_custom_is-defined`
  > './' is not of type 'object'
- **F3012** `LambdaFunctionTestDefinedRef` (AWS::Lambda::Function) → `Properties.Code` L66 in `good_custom_is-defined`
  > './' is not of type 'object'
- **F3012** `LambdaFunctionTestDefinedValue` (AWS::Lambda::Function) → `Properties.Code` L76 in `good_custom_is-defined`
  > './' is not of type 'object'
- **F3012** `LambdaFunctionTestNotDefinedFromParent` (AWS::Lambda::Function) → `Properties.Code` L20 in `good_custom_is-not-defined`
  > './' is not of type 'object'
- **F3012** `LambdaFunctionTestNotDefinedFromParent` (AWS::Lambda::Function) → `Properties.Environment.Variables` L20 in `good_custom_is-not-defined`
  > GetAtt LambdaExecutionRole.Arn (AWS::IAM::Role) returns 'string', but property expects 'object'
- **F3012** `LambdaFunctionTestNotDefinedFromProperties` (AWS::Lambda::Function) → `Properties.Code` L29 in `good_custom_is-not-defined`
  > './' is not of type 'object'
- **F3012** `LambdaFunctionTestNotDefinedRefAWSNoValue` (AWS::Lambda::Function) → `Properties.Code` L36 in `good_custom_is-not-defined`
  > './' is not of type 'object'
- **F3012** `LambdaFunctionTestNotDefinedWithSiblings` (AWS::Lambda::Function) → `Properties.Code` L46 in `good_custom_is-not-defined`
  > './' is not of type 'object'
- **F3012** `TimeoutInNumericsFunction` (AWS::Lambda::Function) → `Properties.Code` L22 in `good_custom_numeric-inequalities-large`
  > './' is not of type 'object'
- **F3012** `TimeoutInStringFunction` (AWS::Lambda::Function) → `Properties.Code` L30 in `good_custom_numeric-inequalities-large`
  > './' is not of type 'object'
- **F3012** `TimeoutInNumericsFunction` (AWS::Lambda::Function) → `Properties.Code` L22 in `good_custom_numeric-inequalities-small`
  > './' is not of type 'object'
- **F3012** `TimeoutInStringFunction` (AWS::Lambda::Function) → `Properties.Code` L30 in `good_custom_numeric-inequalities-small`
  > './' is not of type 'object'
- **F3012** `Function` (AWS::Lambda::Function) → `Properties.Code` L3 in `integration_aws-lambda-function`
  > 's3://bucket/code.zip' is not of type 'object'

### W9010 — 21 findings

- **W9010** `EC2Instance` (AWS::EC2::Instance) → `Properties.ImageId` L54 in `bad_conditions`
  > Hardcoded AMI ID — use a parameter or mapping for portability
- **W9010** `MyEC2Instance` (AWS::EC2::Instance) → `Properties.ImageId` L30 in `bad_functions_ref`
  > Hardcoded AMI ID — use a parameter or mapping for portability
- **W9010** `AnotherInstance` (AWS::EC2::Instance) → `Properties.ImageId` L49 in `bad_functions_ref`
  > Hardcoded AMI ID — use a parameter or mapping for portability
- **W9010** `MyEC2Instance` (AWS::EC2::Instance) → `Properties.ImageId` L41 in `bad_generic`
  > Hardcoded AMI ID — use a parameter or mapping for portability
- **W9010** `MyEC2Instance3` (AWS::EC2::Instance) → `Properties.ImageId` L61 in `bad_generic`
  > Hardcoded AMI ID — use a parameter or mapping for portability
- **W9010** `MyEc2BlockDevice` (AWS::EC2::Instance) → `Properties.ImageId` L217 in `bad_generic`
  > Hardcoded AMI ID — use a parameter or mapping for portability
- **W9010** `MyEC2Instance` (AWS::EC2::Instance) → `Properties.ImageId` L7 in `bad_properties_ebs`
  > Hardcoded AMI ID — use a parameter or mapping for portability
- **W9010** `MyEC2Instance3` (AWS::EC2::Instance) → `Properties.ImageId` L30 in `bad_properties_ebs`
  > Hardcoded AMI ID — use a parameter or mapping for portability
- **W9010** `MyEC2Instance` (AWS::EC2::Instance) → `Properties.ImageId` L5 in `bad_refs`
  > Hardcoded AMI ID — use a parameter or mapping for portability
- **W9010** `AnotherInstance` (AWS::EC2::Instance) → `Properties.ImageId` L24 in `bad_refs`
  > Hardcoded AMI ID — use a parameter or mapping for portability
- **W9010** `myInstance` (AWS::EC2::Instance) → `Properties.ImageId` L26 in `good_conditions`
  > Hardcoded AMI ID — use a parameter or mapping for portability
- **W9010** `myInstance1` (AWS::EC2::Instance) → `Properties.ImageId` L28 in `good_core_conditions`
  > Hardcoded AMI ID — use a parameter or mapping for portability
- **W9010** `myInstance2` (AWS::EC2::Instance) → `Properties.ImageId` L33 in `good_core_conditions`
  > Hardcoded AMI ID — use a parameter or mapping for portability
- **W9010** `myInstance3` (AWS::EC2::Instance) → `Properties.ImageId` L52 in `good_core_conditions`
  > Hardcoded AMI ID — use a parameter or mapping for portability
- **W9010** `myInstance4` (AWS::EC2::Instance) → `Properties.ImageId` L65 in `good_core_conditions`
  > Hardcoded AMI ID — use a parameter or mapping for portability
- **W9010** `MyEC2Instance` (AWS::EC2::Instance) → `Properties.ImageId` L73 in `good_generic`
  > Hardcoded AMI ID — use a parameter or mapping for portability
- **W9010** `MyEC2Instance1` (AWS::EC2::Instance) → `Properties.ImageId` L93 in `good_generic`
  > Hardcoded AMI ID — use a parameter or mapping for portability
- **W9010** `untaggedInstance` (AWS::EC2::Instance) → `Properties.ImageId` L11 in `good_override_complete`
  > Hardcoded AMI ID — use a parameter or mapping for portability
- **W9010** `Instance1` (AWS::EC2::Instance) → `Properties.ImageId` L26 in `integration_formats`
  > Hardcoded AMI ID — use a parameter or mapping for portability
- **W9010** `MyInstance` (AWS::EC2::Instance) → `Properties.ImageId` L10 in `integration_resources-cloudformation-init`
  > Hardcoded AMI ID — use a parameter or mapping for portability
- **W9010** `AnsibleConfigServer` (AWS::EC2::Instance) → `Properties.ImageId` L280 in `quickstart_openshift`
  > Hardcoded AMI ID — use a parameter or mapping for portability

### W1030 — 21 findings — Validate the values that come from a Ref function

- **W1030** `PublicSubnetRouteTableAssociation1` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L23 in `bad_properties_rt_association`
  > {'Ref': 'PublicSubnet01'} is not a 'AWS::EC2::Subnet.Id' with pattern '^[\.\-_\/#A-Za-z0-9]{1,512}\Z' when 'Ref' is resolved
- **W1030** `PublicSubnetRouteTableAssociation1` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L23 in `bad_properties_rt_association`
  > {'Ref': 'PublicSubnet01'} is not a 'AWS::EC2::Subnet.Id' with pattern '^subnet-(([0-9A-Fa-f]{8})|([0-9A-Fa-f]{17}))$' when 'Ref' is resolved
- **W1030** `PrivateSubnetRouteTableAssociation1` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L31 in `bad_properties_rt_association`
  > {'Ref': 'PublicSubnet01'} is not a 'AWS::EC2::Subnet.Id' with pattern '^[\.\-_\/#A-Za-z0-9]{1,512}\Z' when 'Ref' is resolved
- **W1030** `PrivateSubnetRouteTableAssociation1` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L31 in `bad_properties_rt_association`
  > {'Ref': 'PublicSubnet01'} is not a 'AWS::EC2::Subnet.Id' with pattern '^subnet-(([0-9A-Fa-f]{8})|([0-9A-Fa-f]{17}))$' when 'Ref' is resolved
- **W1030** `AuxiliaryPublicSubnetRouteTableAssociation1` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L39 in `bad_properties_rt_association`
  > {'Ref': 'PublicSubnet01'} is not a 'AWS::EC2::Subnet.Id' with pattern '^[\.\-_\/#A-Za-z0-9]{1,512}\Z' when 'Ref' is resolved
- **W1030** `AuxiliaryPublicSubnetRouteTableAssociation1` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L39 in `bad_properties_rt_association`
  > {'Ref': 'PublicSubnet01'} is not a 'AWS::EC2::Subnet.Id' with pattern '^subnet-(([0-9A-Fa-f]{8})|([0-9A-Fa-f]{17}))$' when 'Ref' is resolved
- **W1030** `myInstance` (AWS::EC2::Instance) → `Properties.SecurityGroupIds.0` L77 in `bad_properties_sg_ingress`
  > {'Ref': 'mySecurityGroup'} is not a 'AWS::EC2::SecurityGroup.Id' with pattern '^sg-([a-fA-F0-9]{8}|[a-fA-F0-9]{17})$' when 'Ref' is resolved
- **W1030** `myLaunchTemplate` (AWS::EC2::LaunchTemplate) → `Properties.LaunchTemplateData.SecurityGroupIds.0` L83 in `bad_properties_sg_ingress`
  > {'Ref': 'mySecurity2Group'} is not a 'AWS::EC2::SecurityGroup.Id' with pattern '^sg-([a-fA-F0-9]{8}|[a-fA-F0-9]{17})$' when 'Ref' is resolved
- **W1030** `AppSubnetPublicRouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L28 in `good_properties_rt_association`
  > {'Ref': 'AppSubnet01'} is not a 'AWS::EC2::Subnet.Id' with pattern '^[\.\-_\/#A-Za-z0-9]{1,512}\Z' when 'Ref' is resolved
- **W1030** `AppSubnetPublicRouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L28 in `good_properties_rt_association`
  > {'Ref': 'AppSubnet01'} is not a 'AWS::EC2::Subnet.Id' with pattern '^subnet-(([0-9A-Fa-f]{8})|([0-9A-Fa-f]{17}))$' when 'Ref' is resolved
- **W1030** `AppSubnetPrivateRouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L37 in `good_properties_rt_association`
  > {'Ref': 'AppSubnet01'} is not a 'AWS::EC2::Subnet.Id' with pattern '^[\.\-_\/#A-Za-z0-9]{1,512}\Z' when 'Ref' is resolved
- **W1030** `AppSubnetPrivateRouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L37 in `good_properties_rt_association`
  > {'Ref': 'AppSubnet01'} is not a 'AWS::EC2::Subnet.Id' with pattern '^subnet-(([0-9A-Fa-f]{8})|([0-9A-Fa-f]{17}))$' when 'Ref' is resolved
- **W1030** `PublicSubnetRouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L54 in `good_properties_rt_association`
  > {'Ref': 'PublicSubnet01'} is not a 'AWS::EC2::Subnet.Id' with pattern '^[\.\-_\/#A-Za-z0-9]{1,512}\Z' when 'Ref' is resolved
- **W1030** `PublicSubnetRouteTableAssociation` (AWS::EC2::SubnetRouteTableAssociation) → `Properties.SubnetId` L54 in `good_properties_rt_association`
  > {'Ref': 'PublicSubnet01'} is not a 'AWS::EC2::Subnet.Id' with pattern '^subnet-(([0-9A-Fa-f]{8})|([0-9A-Fa-f]{17}))$' when 'Ref' is resolved
- **W1030** `rNatInstance` (AWS::EC2::Instance) → `Properties.KeyName` L93 in `quickstart_nat-instance`
  > {'Ref': 'pEC2KeyPair'} is shorter than 1 when 'Ref' is resolved
- **W1030** `rMgmtBastionInstance` (AWS::EC2::Instance) → `Properties.KeyName` L479 in `quickstart_nist_vpc_management`
  > {'Ref': 'pEC2KeyPairBastion'} is shorter than 1 when 'Ref' is resolved
- **W1030** `rPeeringConnectionProduction` (AWS::EC2::VPCPeeringConnection) → `Properties.PeerVpcId` L586 in `quickstart_nist_vpc_management`
  > {'Ref': 'pProductionVPC'} is not a 'AWS::EC2::VPC.Id' with pattern '^vpc-([a-fA-F0-9]{8}|[a-fA-F0-9]{17})$' when 'Ref' is resolved
- **W1030** → `Parameters.QSS3BucketName.Default` in `quickstart_openshift`
  > {'Ref': 'QSS3BucketName'} does not match '^(arn:(aws[A-Za-z\-]*?|\*):[^:]+:[^:]*(:(?:\d{12}|\*|aws)?:.+|)|\*)$' when 'Ref' is resolved
- **W1030** → `Parameters.QSS3KeyPrefix.Default` in `quickstart_openshift`
  > {'Ref': 'QSS3KeyPrefix'} does not match '^(arn:(aws[A-Za-z\-]*?|\*):[^:]+:[^:]*(:(?:\d{12}|\*|aws)?:.+|)|\*)$' when 'Ref' is resolved
- **W1030** `rMgmtBastionInstance` (AWS::EC2::Instance) → `Properties.KeyName` L635 in `quickstart_vpc-management`
  > {'Ref': 'pEC2KeyPairBastion'} is shorter than 1 when 'Ref' is resolved
- **W1030** `rPeeringConnectionProduction` (AWS::EC2::VPCPeeringConnection) → `Properties.PeerVpcId` L839 in `quickstart_vpc-management`
  > {'Ref': 'pProductionVPC'} is not a 'AWS::EC2::VPC.Id' with pattern '^vpc-([a-fA-F0-9]{8}|[a-fA-F0-9]{17})$' when 'Ref' is resolved

### W8001 — 18 findings — Check if Conditions are Used

- **W8001** L4 in `bad_conditions_and`
  > Condition 'TestAndToLittle' is not used by any resource or Fn::If
- **W8001** L4 in `bad_conditions_and`
  > Condition 'TestAndToMany' is not used by any resource or Fn::If
- **W8001** L13 in `bad_core_conditions`
  > Condition 'isProductionOrStaging' is not used by any resource or Fn::If
- **W8001** L7 in `bad_core_conditions_missing`
  > Condition 'isProduction' is not used by any resource or Fn::If
- **W8001** L13 in `good_core_conditions`
  > Condition 'isProductionOrStaging' is not used by any resource or Fn::If
- **W8001** L3 in `good_resources_deletionpolicy`
  > Condition 'IsUsEast1' is not used by any resource or Fn::If
- **W8001** L3 in `good_resources_updatereplacepolicy`
  > Condition 'IsUsEast1' is not used by any resource or Fn::If
- **W8001** L6 in `good_transform_language_extension`
  > Condition 'IsUsEast1' is not used by any resource or Fn::If
- **W8001** L3 in `public_watchmaker`
  > Condition 'SupportsNvme' is not used by any resource or Fn::If
- **W8001** L3 in `public_watchmaker`
  > Condition 'UseAdminGroups' is not used by any resource or Fn::If
- **W8001** L3 in `public_watchmaker`
  > Condition 'UseAdminUsers' is not used by any resource or Fn::If
- **W8001** L3 in `public_watchmaker`
  > Condition 'UseCfnUrl' is not used by any resource or Fn::If
- **W8001** L3 in `public_watchmaker`
  > Condition 'UseComputerName' is not used by any resource or Fn::If
- **W8001** L3 in `public_watchmaker`
  > Condition 'UseEnvironment' is not used by any resource or Fn::If
- **W8001** L3 in `public_watchmaker`
  > Condition 'UseOuPath' is not used by any resource or Fn::If
- **W8001** L3 in `public_watchmaker`
  > Condition 'UseWamConfig' is not used by any resource or Fn::If
- **W8001** L3 in `quickstart_nist_application`
  > Condition 'IsGovCloud' is not used by any resource or Fn::If
- **W8001** L3 in `quickstart_nist_logging`
  > Condition 'IsGovCloud' is not used by any resource or Fn::If

### F0001 — 15 findings

- **F0001** L12 in `bad_conditions_equals_not_useful`
  > Resources section must exist and be non-empty
- **F0001** L13 in `bad_core_conditions_missing`
  > Resources section must exist and be non-empty
- **F0001** L8 in `bad_core_config_parameters`
  > Resources section must exist and be non-empty
- **F0001** L11 in `bad_mappings_name`
  > Resources section must exist and be non-empty
- **F0001** L62 in `bad_parameters_default`
  > Resources section must exist and be non-empty
- **F0001** L5 in `bad_templates_base`
  > Resources section must exist and be non-empty
- **F0001** L3 in `bad_templates_base_date`
  > Resources section must exist and be non-empty
- **F0001** L12 in `good_core_config_cfn_lint`
  > Resources section must exist and be non-empty
- **F0001** L9 in `good_core_config_only_i1002`
  > Resources section must exist and be non-empty
- **F0001** L9 in `good_core_config_only_i1003`
  > Resources section must exist and be non-empty
- **F0001** L9 in `good_core_config_parameters`
  > Resources section must exist and be non-empty
- **F0001** L8 in `good_decode_parsing`
  > Resources section must exist and be non-empty
- **F0001** L11 in `good_mappings_name`
  > Resources section must exist and be non-empty
- **F0001** L82 in `good_parameters_default`
  > Resources section must exist and be non-empty
- **F0001** L22 in `integration_metdata`
  > Resources section must exist and be non-empty

### W2001 — 14 findings — Check if Parameters are Used

- **W2001** L4 in `bad_core_conditions_list`
  > Parameter 'myEnvironment' is not referenced anywhere in the template
- **W2001** L4 in `bad_functions_foreach_no_transform`
  > Parameter 'Environment' is not referenced anywhere in the template
- **W2001** L4 in `bad_parameters_default`
  > Parameter 'myMinLength' is not referenced anywhere in the template
- **W2001** L4 in `bad_parameters_default`
  > Parameter 'myMinValue' is not referenced anywhere in the template
- **W2001** L4 in `good_functions_foreach`
  > Parameter 'Environment' is not referenced anywhere in the template
- **W2001** L4 in `good_parameters_not_used_parameters`
  > Parameter 'Version' is not referenced anywhere in the template
- **W2001** L4 in `good_parameters_used_transform_language_extension`
  > Parameter 'ParamA' is not referenced anywhere in the template
- **W2001** L4 in `good_parameters_used_transform_language_extension`
  > Parameter 'ParamB' is not referenced anywhere in the template
- **W2001** L4 in `good_parameters_used_transform_language_extension`
  > Parameter 'ParamC' is not referenced anywhere in the template
- **W2001** L4 in `good_parameters_used_transform_language_extension`
  > Parameter 'ParamD' is not referenced anywhere in the template
- **W2001** L5 in `good_parameters_used_transform_removed`
  > Parameter 'AppStack' is not referenced anywhere in the template
- **W2001** L5 in `good_parameters_used_transform_removed`
  > Parameter 'CognitoStackName' is not referenced anywhere in the template
- **W2001** L5 in `good_parameters_used_transform_removed`
  > Parameter 'ECSStack' is not referenced anywhere in the template
- **W2001** L5 in `issues_sam_w_conditions`
  > Parameter 'Zone' is not referenced anywhere in the template

### W9008 — 14 findings

- **W9008** `DBInstance` (AWS::RDS::DBInstance) L10 in `bad_previous_generation_instances`
  > RDS instance should have StorageEncrypted set to true
- **W9008** `MyDB` (AWS::RDS::DBInstance) L17 in `bad_properties_password`
  > RDS instance should have StorageEncrypted set to true
- **W9008** `MyNewDB` (AWS::RDS::DBInstance) L26 in `bad_properties_password`
  > RDS instance should have StorageEncrypted set to true
- **W9008** `myThirdDb` (AWS::RDS::DBInstance) L35 in `bad_properties_password`
  > RDS instance should have StorageEncrypted set to true
- **W9008** `PolicyList` (AWS::RDS::DBInstance) L11 in `bad_resources_deletionpolicy`
  > RDS instance should have StorageEncrypted set to true
- **W9008** `MadeUpPolicy` (AWS::RDS::DBInstance) L18 in `bad_resources_deletionpolicy`
  > RDS instance should have StorageEncrypted set to true
- **W9008** `InvalidMapping` (AWS::RDS::DBInstance) L38 in `bad_resources_deletionpolicy`
  > RDS instance should have StorageEncrypted set to true
- **W9008** `PolicyList` (AWS::RDS::DBInstance) L11 in `bad_resources_updatereplacepolicy`
  > RDS instance should have StorageEncrypted set to true
- **W9008** `MadeUpPolicy` (AWS::RDS::DBInstance) L18 in `bad_resources_updatereplacepolicy`
  > RDS instance should have StorageEncrypted set to true
- **W9008** `InvalidMapping` (AWS::RDS::DBInstance) L38 in `bad_resources_updatereplacepolicy`
  > RDS instance should have StorageEncrypted set to true
- **W9008** `PolicyList` (AWS::RDS::DBInstance) L27 in `good_resources_deletionpolicy`
  > RDS instance should have StorageEncrypted set to true
- **W9008** `PolicyList` (AWS::RDS::DBInstance) L27 in `good_resources_updatereplacepolicy`
  > RDS instance should have StorageEncrypted set to true
- **W9008** `PolicyList` (AWS::RDS::DBInstance) L50 in `good_transform_language_extension`
  > RDS instance should have StorageEncrypted set to true
- **W9008** `BadEngineInstance` (AWS::RDS::DBInstance) L116 in `integration_cfn-gather`
  > RDS instance should have StorageEncrypted set to true

### I3042 — 13 findings — ARNs should use correctly placed Pseudo Parameters

- **I3042** `TestBadStateMachine1` (AWS::StepFunctions::StateMachine) L36 in `bad_functions_sub_needed`
  > Hardcoded partition 'aws' in ARN — use AWS::Partition pseudo-parameter for portability
- **I3042** `TestBadStateMachine2` (AWS::StepFunctions::StateMachine) L57 in `bad_functions_sub_needed`
  > Hardcoded partition 'aws' in ARN — use AWS::Partition pseudo-parameter for portability
- **I3042** `CustomResource` (AWS::CloudFormation::CustomResource) L56 in `bad_properties_rt_association`
  > Hardcoded partition 'aws' in ARN — use AWS::Partition pseudo-parameter for portability
- **I3042** `myKms` (AWS::KMS::Key) → `Properties.Properties.KeyPolicy.Statement.3.Principal.AWS` L154 in `bad_resources_circular_dependency`
  > ARN in Resource myKms contains hardcoded Partition in ARN or incorrectly placed Pseudo Parameters
- **I3042** `TestGoodStateMachine1` (AWS::StepFunctions::StateMachine) L138 in `good_functions_sub_needed`
  > Hardcoded partition 'aws' in ARN — use AWS::Partition pseudo-parameter for portability
- **I3042** `LambdaFunction` (AWS::Lambda::Function) L161 in `good_generic`
  > Hardcoded partition 'aws' in ARN — use AWS::Partition pseudo-parameter for portability
- **I3042** `rDBPassword` (Custom::Secret) L83 in `good_no_value`
  > Hardcoded partition 'aws' in ARN — use AWS::Partition pseudo-parameter for portability
- **I3042** `CustomResource` (AWS::CloudFormation::CustomResource) L62 in `good_properties_rt_association`
  > Hardcoded partition 'aws' in ARN — use AWS::Partition pseudo-parameter for portability
- **I3042** `TestPipeline` (AWS::CodePipeline::Pipeline) L6 in `good_resources_codepipeline`
  > Hardcoded partition 'aws' in ARN — use AWS::Partition pseudo-parameter for portability
- **I3042** `SkillFunction` (AWS::Lambda::Function) L8 in `good_transform_list_transform_not_sam`
  > Hardcoded partition 'aws' in ARN — use AWS::Partition pseudo-parameter for portability
- **I3042** `FifoProcessor` (AWS::Lambda::Function) → `Properties.Properties.Role` L92 in `integration_cfn-gather`
  > ARN in Resource FifoProcessor contains hardcoded Partition in ARN or incorrectly placed Pseudo Parameters
- **I3042** `GetRSA` (Custom::GenerateKeys) L774 in `quickstart_openshift`
  > Hardcoded partition 'aws' in ARN — use AWS::Partition pseudo-parameter for portability
- **I3042** `rDBPassword` (Custom::Secret) L83 in `quickstart_test`
  > Hardcoded partition 'aws' in ARN — use AWS::Partition pseudo-parameter for portability

### I3011 — 12 findings — Check stateful resources have a set UpdateReplacePolicy/DeletionPolicy

- **I3011** `MyCognitoUserPool` (AWS::Cognito::UserPool) L4 in `bad_resources_cognito_userpool_tag_is_list`
  > 'DeletionPolicy' is a required property (The default action when replacing/removing a resource is to delete it. Set explicit values for stateful resource)
- **I3011** `MyCognitoUserPool` (AWS::Cognito::UserPool) L4 in `bad_resources_cognito_userpool_tag_is_list`
  > 'UpdateReplacePolicy' is a required property (The default action when replacing/removing a resource is to delete it. Set explicit values for stateful resource)
- **I3011** `MyCognitoUserPool` (AWS::Cognito::UserPool) L4 in `good_resources_cognito_userpool_tag_is_string_map`
  > 'DeletionPolicy' is a required property (The default action when replacing/removing a resource is to delete it. Set explicit values for stateful resource)
- **I3011** `MyCognitoUserPool` (AWS::Cognito::UserPool) L4 in `good_resources_cognito_userpool_tag_is_string_map`
  > 'UpdateReplacePolicy' is a required property (The default action when replacing/removing a resource is to delete it. Set explicit values for stateful resource)
- **I3011** `VmdEventsQueue` (AWS::SQS::Queue) L204 in `issues_sam_w_conditions`
  > 'DeletionPolicy' is a required property (The default action when replacing/removing a resource is to delete it. Set explicit values for stateful resource)
- **I3011** `VmdEventsQueue` (AWS::SQS::Queue) L204 in `issues_sam_w_conditions`
  > 'UpdateReplacePolicy' is a required property (The default action when replacing/removing a resource is to delete it. Set explicit values for stateful resource)
- **I3011** `VmdEventsDeadLetterQueue` (AWS::SQS::Queue) L215 in `issues_sam_w_conditions`
  > 'DeletionPolicy' is a required property (The default action when replacing/removing a resource is to delete it. Set explicit values for stateful resource)
- **I3011** `VmdEventsDeadLetterQueue` (AWS::SQS::Queue) L215 in `issues_sam_w_conditions`
  > 'UpdateReplacePolicy' is a required property (The default action when replacing/removing a resource is to delete it. Set explicit values for stateful resource)
- **I3011** `DmdEventsQueue` (AWS::SQS::Queue) L329 in `issues_sam_w_conditions`
  > 'DeletionPolicy' is a required property (The default action when replacing/removing a resource is to delete it. Set explicit values for stateful resource)
- **I3011** `DmdEventsQueue` (AWS::SQS::Queue) L329 in `issues_sam_w_conditions`
  > 'UpdateReplacePolicy' is a required property (The default action when replacing/removing a resource is to delete it. Set explicit values for stateful resource)
- **I3011** `DmdEventsDeadLetterQueue` (AWS::SQS::Queue) L340 in `issues_sam_w_conditions`
  > 'DeletionPolicy' is a required property (The default action when replacing/removing a resource is to delete it. Set explicit values for stateful resource)
- **I3011** `DmdEventsDeadLetterQueue` (AWS::SQS::Queue) L340 in `issues_sam_w_conditions`
  > 'UpdateReplacePolicy' is a required property (The default action when replacing/removing a resource is to delete it. Set explicit values for stateful resource)

### W2508 — 12 findings

- **W2508** `rSecurityGroupBastion` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress` L682 in `quickstart_nist_vpc_management`
  > Security group allows 0.0.0.0/0 access to sensitive port 22 (range 22-22)
- **W2508** `rSecurityGroupPeered` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress` L702 in `quickstart_nist_vpc_management`
  > Security group allows 0.0.0.0/0 access to sensitive port 22 (range 22-22)
- **W2508** `rSecurityGroupMgmtBastion` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress` L618 in `quickstart_nist_vpc_production`
  > Security group allows 0.0.0.0/0 access to sensitive port 22 (range 22-22)
- **W2508** `OpenShiftInternalSecurityGroup` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress` L1055 in `quickstart_openshift`
  > Security group allows all traffic from 0.0.0.0/0 — sensitive port 1433 is exposed
- **W2508** `OpenShiftInternalSecurityGroup` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress` L1055 in `quickstart_openshift`
  > Security group allows all traffic from 0.0.0.0/0 — sensitive port 22 is exposed
- **W2508** `OpenShiftInternalSecurityGroup` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress` L1055 in `quickstart_openshift`
  > Security group allows all traffic from 0.0.0.0/0 — sensitive port 27017 is exposed
- **W2508** `OpenShiftInternalSecurityGroup` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress` L1055 in `quickstart_openshift`
  > Security group allows all traffic from 0.0.0.0/0 — sensitive port 3306 is exposed
- **W2508** `OpenShiftInternalSecurityGroup` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress` L1055 in `quickstart_openshift`
  > Security group allows all traffic from 0.0.0.0/0 — sensitive port 3389 is exposed
- **W2508** `OpenShiftInternalSecurityGroup` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress` L1055 in `quickstart_openshift`
  > Security group allows all traffic from 0.0.0.0/0 — sensitive port 5432 is exposed
- **W2508** `OpenShiftInternalSecurityGroup` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress` L1055 in `quickstart_openshift`
  > Security group allows all traffic from 0.0.0.0/0 — sensitive port 6379 is exposed
- **W2508** `rSecurityGroupPeered` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress` L418 in `quickstart_vpc-management`
  > Security group allows 0.0.0.0/0 access to sensitive port 22 (range 22-22)
- **W2508** `rSecurityGroupBastion` (AWS::EC2::SecurityGroup) → `Properties.SecurityGroupIngress` L801 in `quickstart_vpc-management`
  > Security group allows 0.0.0.0/0 access to sensitive port 22 (range 22-22)

### W2503 — 12 findings

- **W2503** `PrivateSubnet1ARoute` (AWS::EC2::Route) → `Properties.InstanceId.Fn::If.1` L947 in `quickstart_vpc`
  > Resource 'PrivateSubnet1ARoute' (condition 'PrivateSubnetsCondition') references 'NATInstance1' (condition 'NATInstanceCondition'), but these conditions are mutually exclusive — this reference will al
- **W2503** `PrivateSubnet2ARoute` (AWS::EC2::Route) → `Properties.InstanceId.Fn::If.1` L1010 in `quickstart_vpc`
  > Resource 'PrivateSubnet2ARoute' (condition 'PrivateSubnetsCondition') references 'NATInstance2' (condition 'NATInstanceCondition'), but these conditions are mutually exclusive — this reference will al
- **W2503** `PrivateSubnet3ARoute` (AWS::EC2::Route) → `Properties.InstanceId.Fn::If.1` L1073 in `quickstart_vpc`
  > Resource 'PrivateSubnet3ARoute' (condition 'PrivateSubnets&3AZCondition') references 'NATInstance3' (condition 'NATInstance&3AZCondition'), but these conditions are mutually exclusive — this reference
- **W2503** `PrivateSubnet4ARoute` (AWS::EC2::Route) → `Properties.InstanceId.Fn::If.1` L1136 in `quickstart_vpc`
  > Resource 'PrivateSubnet4ARoute' (condition 'PrivateSubnets&4AZCondition') references 'NATInstance4' (condition 'NATInstance&4AZCondition'), but these conditions are mutually exclusive — this reference
- **W2503** `PrivateSubnet1BRoute` (AWS::EC2::Route) → `Properties.InstanceId.Fn::If.1` L1199 in `quickstart_vpc`
  > Resource 'PrivateSubnet1BRoute' (condition 'AdditionalPrivateSubnetsCondition') references 'NATInstance1' (condition 'NATInstanceCondition'), but these conditions are mutually exclusive — this referen
- **W2503** `PrivateSubnet2BRoute` (AWS::EC2::Route) → `Properties.InstanceId.Fn::If.1` L1321 in `quickstart_vpc`
  > Resource 'PrivateSubnet2BRoute' (condition 'AdditionalPrivateSubnetsCondition') references 'NATInstance2' (condition 'NATInstanceCondition'), but these conditions are mutually exclusive — this referen
- **W2503** `PrivateSubnet3BRoute` (AWS::EC2::Route) → `Properties.InstanceId.Fn::If.1` L1443 in `quickstart_vpc`
  > Resource 'PrivateSubnet3BRoute' (condition 'AdditionalPrivateSubnets&3AZCondition') references 'NATInstance3' (condition 'NATInstance&3AZCondition'), but these conditions are mutually exclusive — this
- **W2503** `PrivateSubnet4BRoute` (AWS::EC2::Route) → `Properties.InstanceId.Fn::If.1` L1565 in `quickstart_vpc`
  > Resource 'PrivateSubnet4BRoute' (condition 'AdditionalPrivateSubnets&4AZCondition') references 'NATInstance4' (condition 'NATInstance&4AZCondition'), but these conditions are mutually exclusive — this
- **W2503** `NAT1EIP` (AWS::EC2::EIP) → `Properties.InstanceId.Fn::If.1` L1745 in `quickstart_vpc`
  > Resource 'NAT1EIP' (condition 'PrivateSubnetsCondition') references 'NATInstance1' (condition 'NATInstanceCondition'), but these conditions are mutually exclusive — this reference will always fail
- **W2503** `NAT2EIP` (AWS::EC2::EIP) → `Properties.InstanceId.Fn::If.1` L1764 in `quickstart_vpc`
  > Resource 'NAT2EIP' (condition 'PrivateSubnetsCondition') references 'NATInstance2' (condition 'NATInstanceCondition'), but these conditions are mutually exclusive — this reference will always fail
- **W2503** `NAT3EIP` (AWS::EC2::EIP) → `Properties.InstanceId.Fn::If.1` L1783 in `quickstart_vpc`
  > Resource 'NAT3EIP' (condition 'PrivateSubnets&3AZCondition') references 'NATInstance3' (condition 'NATInstance&3AZCondition'), but these conditions are mutually exclusive — this reference will always 
- **W2503** `NAT4EIP` (AWS::EC2::EIP) → `Properties.InstanceId.Fn::If.1` L1802 in `quickstart_vpc`
  > Resource 'NAT4EIP' (condition 'PrivateSubnets&4AZCondition') references 'NATInstance4' (condition 'NATInstance&4AZCondition'), but these conditions are mutually exclusive — this reference will always 

### E1151 — 10 findings — Validate VPC id format

- **E1151** `mySubnet` (AWS::EC2::Subnet) → `Properties.VpcId` L22 in `bad_core_conditions`
  > Value 'vpc-123456' does not match VPC ID format (vpc-xxxxxxxxx)
- **E1151** `mySubnet1` (AWS::EC2::Subnet) → `Properties.VpcId` L11 in `bad_functions_getaz`
  > Value 'vpc-123456' does not match VPC ID format (vpc-xxxxxxxxx)
- **E1151** `mySubnet2` (AWS::EC2::Subnet) → `Properties.VpcId` L20 in `bad_functions_getaz`
  > Value 'vpc-123456' does not match VPC ID format (vpc-xxxxxxxxx)
- **E1151** `mySubnet3` (AWS::EC2::Subnet) → `Properties.VpcId` L29 in `bad_functions_getaz`
  > Value 'vpc-123456' does not match VPC ID format (vpc-xxxxxxxxx)
- **E1151** `mySubnet` (AWS::EC2::Subnet) → `Properties.VpcId` L16 in `bad_mappings_used`
  > Value 'vpc-123456' does not match VPC ID format (vpc-xxxxxxxxx)
- **E1151** `mySubnet` (AWS::EC2::Subnet) → `Properties.VpcId` L19 in `good_mappings_used`
  > Value 'vpc-123456' does not match VPC ID format (vpc-xxxxxxxxx)
- **E1151** `mySubnet21` (AWS::EC2::Subnet) → `Properties.VpcId` L55 in `good_properties_ec2_vpc`
  > Value 'vpc-1234567' does not match VPC ID format (vpc-xxxxxxxxx)
- **E1151** `mySubnet22` (AWS::EC2::Subnet) → `Properties.VpcId` L63 in `good_properties_ec2_vpc`
  > Value 'vpc-1234567' does not match VPC ID format (vpc-xxxxxxxxx)
- **E1151** `SecurityGroups` (AWS::EC2::SecurityGroup) → `Properties.VpcId` L85 in `good_transform_language_extension`
  > Value '/network/vpc/primary/id' does not match VPC ID format (vpc-xxxxxxxxx)
- **E1151** `Subnet2` (AWS::EC2::Subnet) → `Properties.VpcId` L42 in `integration_ref-types`
  > Ref to 'FargateTaskRole' (AWS::IAM::Role) may not produce a valid 'AWS::EC2::VPC.Id' value

### W9013 — 10 findings

- **W9013** `TestBadStateMachine1` (AWS::StepFunctions::StateMachine) L36 in `bad_functions_sub_needed`
  > Hardcoded account ID in ARN — use AWS::AccountId pseudo-parameter
- **W9013** `TestBadStateMachine2` (AWS::StepFunctions::StateMachine) L57 in `bad_functions_sub_needed`
  > Hardcoded account ID in ARN — use AWS::AccountId pseudo-parameter
- **W9013** `TestGoodStateMachine1` (AWS::StepFunctions::StateMachine) L138 in `good_functions_sub_needed`
  > Hardcoded account ID in ARN — use AWS::AccountId pseudo-parameter
- **W9013** `LambdaFunction` (AWS::Lambda::Function) L161 in `good_generic`
  > Hardcoded account ID in ARN — use AWS::AccountId pseudo-parameter
- **W9013** `rDBPassword` (Custom::Secret) L83 in `good_no_value`
  > Hardcoded account ID in ARN — use AWS::AccountId pseudo-parameter
- **W9013** `TestPipeline` (AWS::CodePipeline::Pipeline) L6 in `good_resources_codepipeline`
  > Hardcoded account ID in ARN — use AWS::AccountId pseudo-parameter
- **W9013** `SkillFunction` (AWS::Lambda::Function) L8 in `good_transform_list_transform_not_sam`
  > Hardcoded account ID in ARN — use AWS::AccountId pseudo-parameter
- **W9013** `FifoProcessor` (AWS::Lambda::Function) L92 in `integration_cfn-gather`
  > Hardcoded account ID in ARN — use AWS::AccountId pseudo-parameter
- **W9013** `GetRSA` (Custom::GenerateKeys) L774 in `quickstart_openshift`
  > Hardcoded account ID in ARN — use AWS::AccountId pseudo-parameter
- **W9013** `rDBPassword` (Custom::Secret) L83 in `quickstart_test`
  > Hardcoded account ID in ARN — use AWS::AccountId pseudo-parameter

### E2001 — 10 findings — Parameters have appropriate properties

- **E2001** → `Parameters.AppVolumeSize.MaxValue` in `public_watchmaker`
  > Parameter 'AppVolumeSize': MaxValue must be a number
- **E2001** → `Parameters.AppVolumeSize.MinValue` in `public_watchmaker`
  > Parameter 'AppVolumeSize': MinValue must be a number
- **E2001** → `Parameters.OpenShiftAdminPassword.MaxLength` in `quickstart_openshift`
  > Parameter 'OpenShiftAdminPassword': MaxLength must be an integer
- **E2001** → `Parameters.OpenShiftAdminPassword.MinLength` in `quickstart_openshift`
  > Parameter 'OpenShiftAdminPassword': MinLength must be an integer
- **E2001** → `Parameters.OpenShiftAdminPassword.NoEcho` in `quickstart_openshift`
  > Parameter 'OpenShiftAdminPassword': NoEcho must be a boolean
- **E2001** → `Parameters.RedhatSubscriptionPassword.NoEcho` in `quickstart_openshift`
  > Parameter 'RedhatSubscriptionPassword': NoEcho must be a boolean
- **E2001** → `Parameters.OpenShiftAdminPassword.MaxLength` in `quickstart_openshift_master`
  > Parameter 'OpenShiftAdminPassword': MaxLength must be an integer
- **E2001** → `Parameters.OpenShiftAdminPassword.MinLength` in `quickstart_openshift_master`
  > Parameter 'OpenShiftAdminPassword': MinLength must be an integer
- **E2001** → `Parameters.OpenShiftAdminPassword.NoEcho` in `quickstart_openshift_master`
  > Parameter 'OpenShiftAdminPassword': NoEcho must be a boolean
- **E2001** → `Parameters.RedhatSubscriptionPassword.NoEcho` in `quickstart_openshift_master`
  > Parameter 'RedhatSubscriptionPassword': NoEcho must be a boolean

### W3010 — 9 findings

- **W3010** `Subnet1` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L26 in `integration_deployment-file-template`
  > Avoid hardcoding availability zones 'us-east-1a'
- **W3010** `rManagementDMZSubnetA` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L431 in `quickstart_nist_vpc_management`
  > Avoid hardcoding availability zones 'us-east-1b'
- **W3010** `rManagementDMZSubnetB` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L443 in `quickstart_nist_vpc_management`
  > Avoid hardcoding availability zones 'us-west-1c'
- **W3010** `rManagementPrivateSubnetA` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L455 in `quickstart_nist_vpc_management`
  > Avoid hardcoding availability zones 'us-east-1b'
- **W3010** `rManagementPrivateSubnetB` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L467 in `quickstart_nist_vpc_management`
  > Avoid hardcoding availability zones 'us-west-1c'
- **W3010** `rManagementDMZSubnetA` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L465 in `quickstart_vpc-management`
  > Avoid hardcoding availability zones 'us-east-1b'
- **W3010** `rManagementDMZSubnetB` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L483 in `quickstart_vpc-management`
  > Avoid hardcoding availability zones 'us-west-1c'
- **W3010** `rManagementPrivateSubnetA` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L501 in `quickstart_vpc-management`
  > Avoid hardcoding availability zones 'us-east-1b'
- **W3010** `rManagementPrivateSubnetB` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L519 in `quickstart_vpc-management`
  > Avoid hardcoding availability zones 'us-west-1c'

### E9004 — 8 findings — GetAtt validation of parameters

- **E9004** `NewVolume` (AWS::EC2::Volume) → `Properties.AvailabilityZone` L77 in `bad_conditions`
  > 'AvailabilityZone' is not one of ["InstanceId", "PrivateDnsName", "PrivateIp", "PublicDnsName", "PublicIp", "State", "VpcId"]
- **E9004** `myInstance` (AWS::EC2::Instance) → `Properties.ImageId.Fn::FindInMap.2` L7 in `bad_functions_base64`
  > 'AvailabilityZone' is not one of ["InstanceId", "PrivateDnsName", "PrivateIp", "PublicDnsName", "PublicIp", "State", "VpcId"]
- **E9004** `mySubnet3` (AWS::EC2::Subnet) → `Properties.AvailabilityZone` L29 in `bad_functions_getaz`
  > 'AvailbilityZone' is not one of ["BlockPublicAccessStates", "Ipv6CidrBlocks", "NetworkAclAssociationId", "SubnetId"]
- **E9004** `Resource2` (AWS::SNS::Topic) → `Properties.DisplayName` L8 in `bad_resources_circular_dependency_2`
  > 'TopicName' is not one of ["TopicArn"]
- **E9004** `Resource5` (AWS::SNS::Topic) → `Properties.DisplayName` L23 in `bad_resources_circular_dependency_2`
  > 'TopicName' is not one of ["TopicArn"]
- **E9004** `Resource7` (AWS::SNS::Topic) → `Properties.DisplayName` L33 in `bad_resources_circular_dependency_2`
  > 'TopicName' is not one of ["TopicArn"]
- **E9004** `Resource8` (AWS::SNS::Topic) → `Properties.DisplayName` L38 in `bad_resources_circular_dependency_2`
  > 'TopicName' is not one of ["TopicArn"]
- **E9004** `Instance1` (AWS::EC2::Instance) → `Properties.NetworkInterfaces.2.GroupSet.0` L26 in `integration_formats`
  > 'GroupName' is not one of ["GroupId", "Id"]

### W2502 — 7 findings

- **W2502** `ApplicationTemplate` (AWS::CloudFormation::Stack) → `DependsOn` L278 in `quickstart_nist_high_main`
  > Resource 'ApplicationTemplate' has DependsOn 'ProductionVpcTemplate' which is conditional (condition 'EulaAccepted'), but 'ApplicationTemplate' does not have a matching condition
- **W2502** `ConfigRulesTemplate` (AWS::CloudFormation::Stack) → `DependsOn` L389 in `quickstart_nist_high_main`
  > Resource 'ConfigRulesTemplate' has DependsOn 'IamTemplate' which is conditional (condition 'EulaAccepted'), but 'ConfigRulesTemplate' does not have a matching condition
- **W2502** `ConfigRulesTemplate` (AWS::CloudFormation::Stack) → `DependsOn` L389 in `quickstart_nist_high_main`
  > Resource 'ConfigRulesTemplate' has DependsOn 'LoggingTemplate' which is conditional (condition 'EulaAccepted'), but 'ConfigRulesTemplate' does not have a matching condition
- **W2502** `ConfigRulesTemplate` (AWS::CloudFormation::Stack) → `DependsOn` L389 in `quickstart_nist_high_main`
  > Resource 'ConfigRulesTemplate' has DependsOn 'ProductionVpcTemplate' which is conditional (condition 'EulaAccepted'), but 'ConfigRulesTemplate' does not have a matching condition
- **W2502** `ManagementVpcTemplate` (AWS::CloudFormation::Stack) → `DependsOn` L446 in `quickstart_nist_high_main`
  > Resource 'ManagementVpcTemplate' has DependsOn 'ProductionVpcTemplate' which is conditional (condition 'EulaAccepted'), but 'ManagementVpcTemplate' does not have a matching condition
- **W2502** `rDeepSecurityInfrastructureTemplate` (AWS::CloudFormation::Stack) → `DependsOn` L334 in `quickstart_nist_vpc_management`
  > Resource 'rDeepSecurityInfrastructureTemplate' has DependsOn 'rRouteMgmtProdDMZ' which is conditional (condition 'cCreatePeeringProduction'), but 'rDeepSecurityInfrastructureTemplate' does not have a 
- **W2502** `rDeepSecurityInfrastructureTemplate` (AWS::CloudFormation::Stack) → `DependsOn` L917 in `quickstart_vpc-management`
  > Resource 'rDeepSecurityInfrastructureTemplate' has DependsOn 'rRouteMgmtProdDMZ' which is conditional (condition 'cCreatePeeringProduction'), but 'rDeepSecurityInfrastructureTemplate' does not have a 

### W7001 — 6 findings — Check if Mappings are Used

- **W7001** L9 in `bad_core_conditions`
  > Mapping 'location' is not referenced by any Fn::FindInMap
- **W7001** L7 in `bad_functions_foreach_no_transform`
  > Mapping 'Buckets' is not referenced by any Fn::FindInMap
- **W7001** L9 in `good_core_conditions`
  > Mapping 'location' is not referenced by any Fn::FindInMap
- **W7001** L7 in `good_functions_foreach`
  > Mapping 'Buckets' is not referenced by any Fn::FindInMap
- **W7001** L7 in `good_mappings_used`
  > Mapping 'AcceptanceSubnets' is not referenced by any Fn::FindInMap
- **W7001** L196 in `public_watchmaker`
  > Mapping 'InstanceTypeMap' is not referenced by any Fn::FindInMap

### F0014 — 5 findings — Check Fn::And structure for validity

- **F0014** in `good_conditions_and`
  > Fn::And: element 0: [{'Ref': 'Users'}, ''] is not of type 'boolean'
- **F0014** in `good_conditions_and`
  > Fn::And: element 1: [{'Ref': 'Users'}, 'another'] is not of type 'boolean'
- **F0014** in `good_no_value`
  > Fn::Equals: argument 1: true is not of type 'string'
- **F0014** in `issues_sam_w_conditions`
  > Fn::Equals: argument 0: true is not of type 'string'
- **F0014** in `quickstart_test`
  > Fn::Equals: argument 1: true is not of type 'string'

### F1020 — 5 findings — Ref validation of value

- **F1020** `NodeGroup` (AWS::AutoScaling::AutoScalingGroup) L3 in `bad_core_parse_invalid_map`
  > Fn::GetAtt references non-existent resource 'NodeLaunchTemplate'
- **F1020** `NodeGroup` (AWS::AutoScaling::AutoScalingGroup) → `Properties.DesiredCapacity` L3 in `bad_core_parse_invalid_map`
  > 'NodeAutoScalingGroupDesiredCapacity' is not one of ["AWS::AccountId", "AWS::NoValue", "AWS::NotificationARNs", "AWS::Partition", "AWS::Region", "AWS::StackId", "AWS::StackName", "AWS::URLSuffix", "No
- **F1020** `NodeGroup` (AWS::AutoScaling::AutoScalingGroup) → `Properties.LaunchTemplate.LaunchTemplateId` L3 in `bad_core_parse_invalid_map`
  > 'NodeLaunchTemplate' is not one of ["AWS::AccountId", "AWS::NoValue", "AWS::NotificationARNs", "AWS::Partition", "AWS::Region", "AWS::StackId", "AWS::StackName", "AWS::URLSuffix", "NodeGroup"]
- **F1020** `NodeGroup` (AWS::AutoScaling::AutoScalingGroup) → `Properties.MaxSize` L3 in `bad_core_parse_invalid_map`
  > 'NodeAutoScalingGroupMaxSize' is not one of ["AWS::AccountId", "AWS::NoValue", "AWS::NotificationARNs", "AWS::Partition", "AWS::Region", "AWS::StackId", "AWS::StackName", "AWS::URLSuffix", "NodeGroup"
- **F1020** `NodeGroup` (AWS::AutoScaling::AutoScalingGroup) → `Properties.MinSize` L3 in `bad_core_parse_invalid_map`
  > 'NodeAutoScalingGroupMinSize' is not one of ["AWS::AccountId", "AWS::NoValue", "AWS::NotificationARNs", "AWS::Partition", "AWS::Region", "AWS::StackId", "AWS::StackName", "AWS::URLSuffix", "NodeGroup"

### F2012 — 5 findings

- **F2012** L4 in `bad_parameters_default`
  > Parameter 'CDLAllowedValues' Default 'three' is not in AllowedValues ["one", "two", "three,four"]
- **F2012** L4 in `bad_parameters_default`
  > Parameter 'CDLAllowedValuesWithSpaces' Default 'three,four' is not in AllowedValues ["one", "two", "three, four"]
- **F2012** L4 in `bad_parameters_default`
  > Parameter 'myAllowedValue' Default 'us-east-1a' is not in AllowedValues ["us-east-1b", "us-east-1c", "us-east-1d"]
- **F2012** L4 in `good_parameters_default`
  > Parameter 'CDLAllowedPatternWithSpaceInDefault' Default 'one, two' is not in AllowedValues ["one", "two", "three,four"]
- **F2012** L4 in `good_parameters_default`
  > Parameter 'CDLAllowedValuesWithSpaceInDefault' Default 'one, two' is not in AllowedValues ["one", "two", "three,four"]

### I3013 — 5 findings — Check resources with auto expiring content have explicit retention period

- **I3013** `DBInstance` (AWS::RDS::DBInstance) → `Properties.BackupRetentionPeriod` L10 in `bad_previous_generation_instances`
  > 'BackupRetentionPeriod' is a required property (The default retention period will delete the data after a pre-defined time. Set an explicit values to avoid data loss on resource)
- **I3013** `BadEngineInstance` (AWS::RDS::DBInstance) → `Properties.BackupRetentionPeriod` L116 in `integration_cfn-gather`
  > 'BackupRetentionPeriod' is a required property (The default retention period will delete the data after a pre-defined time. Set an explicit values to avoid data loss on resource)
- **I3013** `TestLogGroup` (AWS::Logs::LogGroup) → `Properties.RetentionInDays` L51 in `integration_getatt-types`
  > 'RetentionInDays' is a required property (The default retention period will delete the data after a pre-defined time. Set an explicit values to avoid data loss on resource)
- **I3013** `LogGroup` (AWS::Logs::LogGroup) → `Properties.RetentionInDays` L66 in `integration_ref-types`
  > 'RetentionInDays' is a required property (The default retention period will delete the data after a pre-defined time. Set an explicit values to avoid data loss on resource)
- **I3013** `WatchmakerInstanceLogGroup` (AWS::Logs::LogGroup) → `Properties.RetentionInDays` L1687 in `public_watchmaker`
  > 'RetentionInDays' is a required property (The default retention period will delete the data after a pre-defined time. Set an explicit values to avoid data loss on resource)

### W3002 — 5 findings — Warn when properties are configured to only work with the package command

- **W3002** `rDeepSecurityInfrastructureTemplate` (AWS::CloudFormation::Stack) → `Properties.TemplateURL` L333 in `quickstart_nist_vpc_management`
  > This code may only work with 'package' cli command
- **W3002** `rNatInstanceTemplate` (AWS::CloudFormation::Stack) → `Properties.TemplateURL` L557 in `quickstart_nist_vpc_management`
  > This code may only work with 'package' cli command
- **W3002** `rNatInstanceTemplate` (AWS::CloudFormation::Stack) → `Properties.TemplateURL` L527 in `quickstart_nist_vpc_production`
  > This code may only work with 'package' cli command
- **W3002** `rNatInstanceTemplate` (AWS::CloudFormation::Stack) → `Properties.TemplateURL` L377 in `quickstart_vpc-management`
  > This code may only work with 'package' cli command
- **W3002** `rDeepSecurityInfrastructureTemplate` (AWS::CloudFormation::Stack) → `Properties.TemplateURL` L915 in `quickstart_vpc-management`
  > This code may only work with 'package' cli command

### F3003 — 4 findings — Required Resource properties are missing

- **F3003** `MyApi` (AWS::Serverless::Api) → `Properties` L8 in `bad_transform_no_properties`
  > 'StageName' is a required property
- **F3003** `IamRole2` (AWS::IAM::Role) → `Properties` L27 in `integration_ref-no-value`
  > 'AssumeRolePolicyDocument' is a required property
- **F3003** `CloudFront1` (AWS::CloudFront::Distribution) → `Properties` L40 in `integration_ref-no-value`
  > 'DistributionConfig' is a required property
- **F3003** `rArchiveLogsBucket` (AWS::S3::Bucket) → `Properties` L44 in `quickstart_nist_logging`
  > 'OwnershipControls' is a required property

### F3002 — 4 findings — Resource properties are invalid

- **F3002** `EC2Instance` (AWS::EC2::Instance) → `Properties.Tags.1.BadKey` L54 in `bad_conditions`
  > Additional properties are not allowed ('BadKey' was unexpected)
- **F3002** `EC2Instance` (AWS::EC2::Instance) → `Properties.Tags.1.BadValue` L54 in `bad_conditions`
  > Additional properties are not allowed ('BadValue' was unexpected)
- **F3002** `myBucketPass` (AWS::S3::Bucket) → `Properties.BucketName1` L6 in `bad_core_directives`
  > Additional properties are not allowed ('BucketName1' was unexpected. Did you mean 'BucketName'?)
- **F3002** `myBucketPass` (AWS::S3::Bucket) → `Properties.BucketName1` L6 in `bad_core_mandatory_checks`
  > Additional properties are not allowed ('BucketName1' was unexpected. Did you mean 'BucketName'?)

### W9009 — 4 findings

- **W9009** `CloudFrontDistribution` (AWS::CloudFront::Distribution) → `Properties.DistributionConfig` L83 in `bad_conditions`
  > Property 'DistributionConfig' is deprecated
- **W9009** `CloudFrontDistribution` (AWS::CloudFront::Distribution) → `Properties.DistributionConfig` L4 in `bad_resources_cloudfront_invalid_aliases`
  > Property 'DistributionConfig' is deprecated
- **W9009** `CloudFrontDistribution` (AWS::CloudFront::Distribution) → `Properties.DistributionConfig` L40 in `good_conditions`
  > Property 'DistributionConfig' is deprecated
- **W9009** `CloudFront2` (AWS::CloudFront::Distribution) → `Properties.DistributionConfig` L41 in `integration_ref-no-value`
  > Property 'DistributionConfig' is deprecated

### W9002 — 4 findings

- **W9002** `TestBadStateMachine1` (AWS::StepFunctions::StateMachine) → `Properties.RoleArn` L36 in `bad_functions_sub_needed`
  > Property 'RoleArn' has a hardcoded ARN — use Ref, GetAtt, or a parameter instead
- **W9002** `TestBadStateMachine2` (AWS::StepFunctions::StateMachine) → `Properties.RoleArn` L57 in `bad_functions_sub_needed`
  > Property 'RoleArn' has a hardcoded ARN — use Ref, GetAtt, or a parameter instead
- **W9002** `TestGoodStateMachine1` (AWS::StepFunctions::StateMachine) → `Properties.RoleArn` L138 in `good_functions_sub_needed`
  > Property 'RoleArn' has a hardcoded ARN — use Ref, GetAtt, or a parameter instead
- **W9002** `TestPipeline` (AWS::CodePipeline::Pipeline) → `Properties.RoleArn` L6 in `good_resources_codepipeline`
  > Property 'RoleArn' has a hardcoded ARN — use Ref, GetAtt, or a parameter instead

### W1020 — 3 findings — Sub isn't needed if it doesn't have a variable defined

- **W1020** `NodeGroup` (AWS::AutoScaling::AutoScalingGroup) → `Properties.Tags.0.Value` L3 in `bad_core_parse_invalid_map`
  > Fn::Sub isn't needed because there are no variables
- **W1020** `NodeGroup` (AWS::AutoScaling::AutoScalingGroup) → `Properties.Tags.1.Key` L3 in `bad_core_parse_invalid_map`
  > Fn::Sub isn't needed because there are no variables
- **W1020** `myInstance` (AWS::EC2::Instance) → `Properties.AdditionalInfo` L9 in `bad_functions_sub_needed`
  > Fn::Sub '${AMIId}' can be simplified to !Ref AMIId

### I3100 — 3 findings — Checks for legacy instance type generations

- **I3100** `rNatInstance` (AWS::EC2::Instance) → `Properties.InstanceType` L93 in `quickstart_nat-instance`
  > Previous generation instance type 'm3.large' — consider upgrading
- **I3100** `rMgmtBastionInstance` (AWS::EC2::Instance) → `Properties.InstanceType` L479 in `quickstart_nist_vpc_management`
  > Previous generation instance type 'm3.large' — consider upgrading
- **I3100** `rMgmtBastionInstance` (AWS::EC2::Instance) → `Properties.InstanceType` L635 in `quickstart_vpc-management`
  > Previous generation instance type 'm3.large' — consider upgrading

### W2509 — 3 findings

- **W2509** L6 in `bad_properties_password`
  > Parameter 'MyNewPassword' appears to be a password but does not have NoEcho set to true
- **W2509** L6 in `bad_properties_password`
  > Parameter 'MyPassword' appears to be a password but does not have NoEcho set to true
- **W2509** L2 in `integration_resources-cloudformation-init`
  > Parameter 'DBPassword' appears to be a password but does not have NoEcho set to true

### F1104 — 2 findings

- **F1104** in `bad_conditions`
  > Fn::If references undefined condition 'isDev'
- **F1104** in `bad_conditions`
  > Fn::If references undefined condition 'isProd'

### F1060 — 2 findings

- **F1060** `EC2Instance` (AWS::EC2::Instance) L54 in `bad_conditions`
  > Fn::If condition 'isDev' does not exist in Conditions section
- **F1060** `EC2Instance` (AWS::EC2::Instance) L54 in `bad_conditions`
  > Fn::If condition 'isProd' does not exist in Conditions section

### F0013 — 2 findings — Check Fn::If structure for validity

- **F0013** in `bad_core_conditions`
  > Fn::If: must have exactly 3 elements, got 2
- **F0013** in `bad_core_conditions`
  > Fn::If: {'Fn::If': ['isPrimary', 't3.2xlarge', 't3.xlarge']} is not of type 'array'

### E1154 — 2 findings — Validate VPC subnet id format

- **E1154** `myInstance1` (AWS::EC2::Instance) → `Properties.SubnetId` L28 in `bad_core_conditions`
  > Value 'abc-123456' does not match Subnet ID format (subnet-xxxxxxxxx)
- **E1154** `rNatInstanceEni` (AWS::EC2::NetworkInterface) → `Properties.SubnetId` L75 in `quickstart_nat-instance`
  > Value '' does not match Subnet ID format (subnet-xxxxxxxxx)

### F1105 — 2 findings

- **F1105** in `bad_functions_base64`
  > 'Fn::GetAtt' is not allowed inside 'Fn::FindInMap'
- **F1105** in `bad_functions_import_value`
  > 'Fn::ImportValue' is not allowed inside 'Fn::Equals'

### E1150 — 2 findings — Validate security group format

- **E1150** `Instance1` (AWS::EC2::Instance) → `Properties.NetworkInterfaces.1.GroupSet.2` L26 in `integration_formats`
  > Ref to 'Vpc' (AWS::EC2::VPC) may not produce a valid 'AWS::EC2::SecurityGroup.Id' value
- **E1150** `Instance1` (AWS::EC2::Instance) → `Properties.NetworkInterfaces.GroupSet` L26 in `integration_formats`
  > 'sg-dne' is not a 'AWS::EC2::SecurityGroup.Id' with pattern '^sg-([a-fA-F0-9]{8}|[a-fA-F0-9]{17})$'

### W1102 — 2 findings

- **W1102** in `bad_functions_select`
  > Fn::Select: index (first argument) must be an integer or an intrinsic function
- **W1102** in `quickstart_vpc`
  > Fn::Select: Fn::Select index (first element) must be an integer

### W9007 — 2 findings

- **W9007** `rDBSubnetGroup` (AWS::RDS::DBSubnetGroup) → `Properties.SubnetIds` L69 in `good_no_value`
  > Array property 'SubnetIds' contains duplicate values
- **W9007** `rDBSubnetGroup` (AWS::RDS::DBSubnetGroup) → `Properties.SubnetIds` L69 in `quickstart_test`
  > Array property 'SubnetIds' contains duplicate values

### W2512 — 2 findings

- **W2512** `rSysAdminPolicy` (AWS::IAM::ManagedPolicy) L61 in `quickstart_iam`
  > IAM policy uses NotAction which grants all actions except those listed — consider using Action instead
- **W2512** `rSysAdminPolicy` (AWS::IAM::ManagedPolicy) L276 in `quickstart_nist_iam`
  > IAM policy uses NotAction which grants all actions except those listed — consider using Action instead

### I2003 — 2 findings

- **I2003** in `quickstart_openshift`
  > Parameter 'OpenShiftAdminPassword' AllowedPattern '(?=^.{6,255}$)((?=.*\d)(?=.*[A-Z])(?=.*[a-z])|(?=.*\d)(?=.*[^A-Za-z0-9])(?=.*[a-z])|(?=.*[^A-Za-z0-9])(?=.*[A-Z])(?=.*[a-z])|(?=.*\d)(?=.*[A-Z])(?=.*
- **I2003** in `quickstart_openshift_master`
  > Parameter 'OpenShiftAdminPassword' AllowedPattern '(?=^.{6,255}$)((?=.*\d)(?=.*[A-Z])(?=.*[a-z])|(?=.*\d)(?=.*[^A-Za-z0-9])(?=.*[a-z])|(?=.*[^A-Za-z0-9])(?=.*[A-Z])(?=.*[a-z])|(?=.*\d)(?=.*[A-Z])(?=.*

### F3030 — 1 findings — Check if properties have a valid value

- **F3030** `myBucketFirstAndLastPass` (AWS::S3::Bucket) → `Properties.VersioningConfiguration.Status` L19 in `bad_core_directives`
  > 'Enabled1' is not one of [String("Enabled"), String("Suspended")]

### W1001 — 1 findings — Ref/GetAtt to resource that is available when conditions are applied

- **W1001** `lambdaArn` → `Outputs/lambdaArn/Value` in `bad_functions_relationship_conditions`
  > Reference to 'LambdaExecutionRole' which is conditional on 'isPrimary' - target may not exist

### F1012 — 1 findings

- **F1012** `myInstance` (AWS::EC2::Instance) L7 in `bad_functions_base64`
  > Fn::FindInMap references non-existent mapping 'amimap'

### F6101 — 1 findings — Validate that outputs values are a string

- **F6101** L76 in `integration_getatt-types`
  > Output 'SubWithGetAtt': GetAtt 'CapacityReservation.InstanceCount' returns type 'integer', not 'string'

### F3034 — 1 findings — Check if a number is between min and max

- **F3034** `FifoMapping` (AWS::Lambda::EventSourceMapping) → `Properties` L105 in `integration_cfn-gather`
  > Cross-resource constraint: local.BatchSize is 15 but must be <= 10 (from referenced resource)

### W3011 — 1 findings — Check resources with UpdateReplacePolicy/DeletionPolicy have both

- **W3011** `rWebContentBucket` (AWS::S3::Bucket) L1178 in `quickstart_nist_application`
  > Both 'UpdateReplacePolicy' and 'DeletionPolicy' are needed to protect resource from deletion

### W3005 — 1 findings — Check obsolete DependsOn configuration for Resources

- **W3005** `FunctionToFormatCloudWatchEvent` (AWS::Lambda::Function) → `DependsOn` L1857 in `quickstart_cis_benchmark`
  > 'SnsTopicForCloudWatchEvents' dependency already enforced by a 'Sub' at 'Properties.Code.ZipFile'

### I9002 — 1 findings

- **I9002** `MyAliasRecordSet` (AWS::Route53::RecordSet) → `Properties.TTL` L107 in `bad_route53`
  > 'TTL' is ignored in this configuration (from extension)

### F0006 — 1 findings

- **F0006** `Fn::ForEach::Buckets` L12 in `good_functions_foreach`
  > Logical ID 'Fn::ForEach::Buckets' must be alphanumeric (A-Za-z0-9)

### E1040 — 1 findings — Check if GetAtt matches destination format

- **E1040** `Instance1` (AWS::EC2::Instance) → `Properties.NetworkInterfaces.1.GroupSet.2` L26 in `integration_formats`
  > {'Fn::GetAtt': ['Vpc', 'DefaultSecurityGroup']} does not match destination format of 'AWS::EC2::SecurityGroup.Id'

### E9003 — 1 findings

- **E9003** `SsmParameter` (AWS::SSM::Parameter) → `Properties.Value` L15 in `integration_getatt-types`
  > {'Fn::GetAtt': ['CapacityReservation', 'InstanceCount']} is not of type 'string'

### I3037 — 1 findings

- **I3037** `rNatInstanceEni` (AWS::EC2::NetworkInterface) → `Properties.GroupSet` L75 in `quickstart_nat-instance`
  > Array property 'GroupSet' contains duplicate value: ""

## Per-Template Breakdown — 50 templates with mismatches

### `bad_conditions` — 9 mismatches (12 TP, 0 FP, 15 EE, 9 FN)

- FN: `E8001` ×4, `E3024` ×2, `E1001`, `F0013`, `E3001`
- EE: `I9001` ×4, `F1104` ×2, `F1060` ×2, `F3002` ×2, `I9040` ×2, `W9010`, `E9004`, `W9009`

### `bad_generic` — 9 mismatches (31 TP, 0 FP, 44 EE, 9 FN)

- FN: `W1036` ×6, `E3673`, `E1011`, `F6101`
- EE: `I9001` ×15, `I9040` ×13, `F3012` ×7, `W9003` ×5, `W9010` ×3, `W1028`

### `good_functions_sub_needed_custom_excludes` — 7 mismatches (2 TP, 0 FP, 2 EE, 7 FN)

- FN: `E3530` ×6, `F3031`
- EE: `I9001`, `I9040`

### `bad_core_conditions` — 6 mismatches (17 TP, 0 FP, 30 EE, 6 FN)

- FN: `F3014` ×2, `F0013` ×2, `F3003`, `W3698`
- EE: `I9001` ×8, `I9040` ×7, `E1152` ×7, `F0013` ×2, `W7001`, `W8001`, `E1151`, `E1154`, `F3012`, `W1028`

### `bad_functions_sub_needed` — 6 mismatches (6 TP, 0 FP, 13 EE, 6 FN)

- FN: `I3510` ×2, `E3510` ×2, `F1029` ×2
- EE: `I9040` ×4, `I9001` ×2, `W9002` ×2, `W9013` ×2, `I3042` ×2, `W1020`

### `bad_parameters_configuration` — 6 mismatches (33 TP, 0 FP, 1 EE, 6 FN)

- FN: `E2001` ×4, `W2001`, `W2002`
- EE: `I9040`

### `bad_resources_circular_dependency` — 6 mismatches (24 TP, 0 FP, 44 EE, 6 FN)

- FN: `E3048` ×3, `W3037` ×2, `F1018`
- EE: `I9001` ×18, `I9040` ×9, `I3510` ×9, `W9003` ×5, `I3042`, `F3012`, `E1152`

### `bad_resources_deletionpolicy` — 6 mismatches (15 TP, 0 FP, 8 EE, 6 FN)

- FN: `F3016` ×6
- EE: `I9040` ×4, `W9008` ×3, `I9001`

### `bad_resources_updatereplacepolicy` — 6 mismatches (17 TP, 0 FP, 8 EE, 6 FN)

- FN: `F0018` ×6
- EE: `I9040` ×4, `W9008` ×3, `I9001`

### `bad_route53` — 6 mismatches (28 TP, 0 FP, 21 EE, 6 FN)

- FN: `E3023` ×5, `W1054`
- EE: `I9001` ×19, `W1028`, `I9002`

### `bad_functions_foreach_no_transform` — 5 mismatches (1 TP, 0 FP, 2 EE, 5 FN)

- FN: `E1032` ×3, `F0002`, `E6001`
- EE: `W2001`, `W7001`

### `bad_functions_select` — 5 mismatches (4 TP, 0 FP, 19 EE, 5 FN)

- FN: `E1017` ×5
- EE: `I9001` ×8, `E1152` ×4, `I9040` ×4, `F3012` ×2, `W1102`

### `bad_properties_rt_association` — 5 mismatches (2 TP, 0 FP, 21 EE, 5 FN)

- FN: `E3022` ×5
- EE: `I9001` ×13, `W1030` ×6, `W1028`, `I3042`

### `bad_properties_sg_ingress` — 5 mismatches (15 TP, 0 FP, 30 EE, 5 FN)

- FN: `F3014` ×4, `F3031`
- EE: `I9001` ×17, `W9003` ×7, `I9040` ×3, `W1030` ×2, `E1152`

### `bad_functions_join` — 4 mismatches (2 TP, 0 FP, 6 EE, 4 FN)

- FN: `E1021` ×4
- EE: `E1152` ×2, `I9001` ×2, `I9040` ×2

### `good_core_conditions` — 4 mismatches (6 TP, 0 FP, 22 EE, 4 FN)

- FN: `F3014` ×2, `W3698`, `F3003`
- EE: `I9001` ×8, `I9040` ×7, `W9010` ×4, `W7001`, `W8001`, `W1028`

### `good_transform_applications_location` — 4 mismatches (0 TP, 0 FP, 2 EE, 4 FN)

- FN: `I3011` ×4
- EE: `I9040` ×2

### `bad_duplicate` — 3 mismatches (0 TP, 0 FP, 2 EE, 3 FN)

- FN: `F0000` ×3
- EE: `I9040` ×2

### `bad_functions_import_value` — 3 mismatches (1 TP, 0 FP, 4 EE, 3 FN)

- FN: `E1016` ×2, `F0014`
- EE: `I9001` ×2, `F1105`, `I9040`

### `bad_parameters_default` — 3 mismatches (18 TP, 0 FP, 6 EE, 3 FN)

- FN: `F2015` ×3
- EE: `F2012` ×3, `W2001` ×2, `F0001`

### `bad_resources_primary_identifiers` — 3 mismatches (8 TP, 0 FP, 29 EE, 3 FN)

- FN: `E3019` ×2, `E3001`
- EE: `I9001` ×15, `I9040` ×10, `W1028` ×4

### `good_parameters_used_transform_language_extension` — 3 mismatches (1 TP, 0 FP, 4 EE, 3 FN)

- FN: `W8001` ×3
- EE: `W2001` ×4

### `bad_core_conditions_list` — 2 mismatches (1 TP, 0 FP, 1 EE, 2 FN)

- FN: `F0002`, `E8001`
- EE: `W2001`

### `bad_core_mandatory_checks` — 2 mismatches (5 TP, 0 FP, 5 EE, 2 FN)

- FN: `E3001` ×2
- EE: `I9040` ×4, `F3002`

### `bad_functions_base64` — 2 mismatches (1 TP, 0 FP, 5 EE, 2 FN)

- FN: `E1011`, `E1021`
- EE: `F1105`, `F1012`, `E9004`, `I9001`, `I9040`

### `bad_functions_getaz` — 2 mismatches (6 TP, 0 FP, 16 EE, 2 FN)

- FN: `E1017` ×2
- EE: `I9001` ×9, `E1151` ×3, `I9040` ×3, `E9004`

### `bad_modules_bad_has_update_policy` — 2 mismatches (1 TP, 0 FP, 0 EE, 2 FN)

- FN: `F3016`, `E5001`

### `bad_properties_ebs` — 2 mismatches (6 TP, 0 FP, 12 EE, 2 FN)

- FN: `E3671` ×2
- EE: `I9001` ×7, `W9010` ×2, `I9040` ×2, `W9003`

### `bad_templates_base` — 2 mismatches (1 TP, 0 FP, 1 EE, 2 FN)

- FN: `E1005` ×2
- EE: `F0001`

### `bad_templates_base_null` — 2 mismatches (1 TP, 0 FP, 0 EE, 2 FN)

- FN: `E1001`, `E1005`

### `good_functions_findinmap` — 2 mismatches (0 TP, 0 FP, 6 EE, 2 FN)

- FN: `E7001` ×2
- EE: `I9001` ×3, `I9040` ×3

### `good_functions_foreach` — 2 mismatches (0 TP, 0 FP, 3 EE, 2 FN)

- FN: `E3045`, `W3045`
- EE: `W2001`, `W7001`, `F0006`

### `integration_ref-no-value` — 2 mismatches (7 TP, 0 FP, 9 EE, 2 FN)

- FN: `F3012` ×2
- EE: `W1028` ×3, `I9040` ×3, `F3003` ×2, `W9009`

### `bad_conditions_equals` — 1 mismatches (17 TP, 0 FP, 0 EE, 1 FN)

- FN: `F1020`

### `bad_core_conditions_missing` — 1 mismatches (1 TP, 0 FP, 2 EE, 1 FN)

- FN: `F0014`
- EE: `W8001`, `F0001`

### `bad_core_directives` — 1 mismatches (4 TP, 0 FP, 6 EE, 1 FN)

- FN: `E3001`
- EE: `I9040` ×4, `F3002`, `F3030`

### `bad_core_parse_invalid_map` — 1 mismatches (0 TP, 0 FP, 7 EE, 1 FN)

- FN: `F0000`
- EE: `F1020` ×5, `W1020` ×2

### `bad_functions_ref` — 1 mismatches (11 TP, 0 FP, 19 EE, 1 FN)

- FN: `F1018`
- EE: `I9001` ×10, `I9040` ×4, `W9003` ×3, `W9010` ×2

### `bad_functions_relationship_conditions` — 1 mismatches (7 TP, 0 FP, 7 EE, 1 FN)

- FN: `W1001`
- EE: `I9040` ×4, `I9001` ×2, `W1001`

### `bad_mappings_name` — 1 mismatches (1 TP, 0 FP, 1 EE, 1 FN)

- FN: `E7001`
- EE: `F0001`

### `bad_mappings_used` — 1 mismatches (2 TP, 0 FP, 4 EE, 1 FN)

- FN: `W1034`
- EE: `I9001` ×2, `E1151`, `I9040`

### `bad_modules_bad_has_create_policy` — 1 mismatches (1 TP, 0 FP, 0 EE, 1 FN)

- FN: `E5001`

### `bad_modules_bad_uses_module_metadata` — 1 mismatches (0 TP, 0 FP, 0 EE, 1 FN)

- FN: `E5001`

### `bad_refs` — 1 mismatches (5 TP, 0 FP, 10 EE, 1 FN)

- FN: `F1018`
- EE: `I9001` ×6, `W9010` ×2, `I9040` ×2

### `bad_some_logs_stream_lambda` — 1 mismatches (12 TP, 0 FP, 12 EE, 1 FN)

- FN: `E2529`
- EE: `I9040` ×8, `I9001` ×4

### `bad_transform_no_properties` — 1 mismatches (0 TP, 0 FP, 2 EE, 1 FN)

- FN: `E0001`
- EE: `F3003`, `I9040`

### `good_custom_is-not-defined` — 1 mismatches (8 TP, 0 FP, 11 EE, 1 FN)

- FN: `E9004`
- EE: `I9040` ×5, `F3012` ×5, `I9001`

### `good_functions_sub` — 1 mismatches (11 TP, 0 FP, 13 EE, 1 FN)

- FN: `E1021`
- EE: `I9001` ×6, `I9040` ×5, `E1152` ×2

### `good_parameters_not_used_parameters` — 1 mismatches (3 TP, 0 FP, 6 EE, 1 FN)

- FN: `E1021`
- EE: `I9001` ×3, `W2001`, `I9040`, `E1152`

### `good_parameters_used_transforms` — 1 mismatches (3 TP, 0 FP, 5 EE, 1 FN)

- FN: `E1021`
- EE: `I9001` ×3, `I9040`, `E1152`

## Coverage Gaps

10 cfn-lint templates with no engine report:

- `bad_core_config_invalid_json` (1 expected diagnostics)
- `bad_core_config_invalid_yaml` (1 expected diagnostics)
- `bad_empty_file` (1 expected diagnostics)
- `bad_functions_get_stack_output` (7 expected diagnostics)
- `bad_json_parse` (1 expected diagnostics)
- `bad_string` (1 expected diagnostics)
- `bad_template` (1 expected diagnostics)
- `good_functions_get_stack_output` (0 expected diagnostics)
- `integration_get-stack-output` (2 expected diagnostics)
- `integration_module-sub-resources` (0 expected diagnostics)

## Root-Cause Analysis

### False Negative Root Causes

| Cause | Count | % of FN | Rules |
|-------|------:|--------:|-------|
| Other | 67 | 43.79% | E0001, E2001, E2529, E5001, E6001, E7001, E8001, E9004, F0000, F0002, F0013, F0014, F0018, F1018, F1020, F1029, F2015, F3003, F3012, F3014, F3016, F3031, F6101 |
| Resource property validation | 34 | 22.22% | E3001, E3019, E3022, E3023, E3024, E3045, E3048, E3510, E3530, E3671, E3673 |
| Intrinsic function validation | 27 | 17.65% | E1001, E1005, E1011, E1016, E1017, E1021, E1032 |
| Warning-level checks | 19 | 12.42% | W1001, W1034, W1036, W1054, W2001, W2002, W3037, W3045, W3698, W8001 |
| Informational checks | 6 | 3.92% | I3011, I3510 |

### False Positive Root Causes

| Cause | Count | % of FP | Rules |
|-------|------:|--------:|-------|

