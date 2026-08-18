# Rule Correctness Audit

Static analysis of `src/rules/src/registry.rs` vs cfn-lint and the
severity model documented in `product.md`.

## Summary

- Total rules: **301**
- By severity: Fatal=69, Error=147, Warn=62, Info=23
- By true origin: CfnLint=183, Engine=24, Engine(collision)=1, Schema=93
- By category: BestPractice=49, Deprecation=8, Intrinsic=52, Parameter=8, Reference=2, Resource=86, Schema=25, Security=14, Structure=57
- cfn-lint reference: 322 rule IDs loaded
- cfn-lint→engine mappings: 52 total (40 E→F promotions, 11 E→E same/split, 1 E→W downgrades)
- Engine-extra rules: 52 (1 with number collisions)

## 1. Origin correctness

True origin is derived from Fatal severity, explicit non-Fatal schema
evidence verified against required production emitters, and exact or
documented cfn-lint equivalences. The registry `origin:` field is compared
only after that derivation; mismatches indicate metadata needs updating.

_All registry origins match computed true origins._

## 2. Description parity vs cfn-lint

For non-Fatal CfnLint-origin rules, our description should align with
cfn-lint's `shortdesc`. Fatal rules are exempt

### Soft mismatches (8) - wording divergence

| ID | Sev | Sim | Our description | cfn-lint shortdesc |
|----|-----|----:|------------------|--------------------|
| `E0001` | Error | 0.10 | SAM (AWS::Serverless) transform would reject the template | Error found when transforming the template |
| `E2531` | Error | 0.14 | Check if Lambda Function Runtimes are blocked for create | Validate if lambda runtime is deprecated |
| `E6003` | Error | 0.14 | Outputs section must be an object of named output definitions | Check the type of Outputs |
| `E3040` | Error | 0.17 | Read only property should not be specified | Validate we aren't configuring read only properties |
| `W1051` | Warn | 0.17 | Dynamic reference resolves secret value but property expects the secret ARN | Validate dynamic references to secrets manager are not used when a secrets manager ARN was expected |
| `E1050` | Error | 0.22 | Dynamic reference must match the SSM, ssm-secure, or Secrets Manager format | Validate the structure of a dynamic reference |
| `E1029` | Error | 0.25 | Substitution variable ${X} requires Fn::Sub | Sub is required if a variable is used in a string |
| `W1019` | Warn | 0.25 | Parameter in Fn::Sub variable map is not used in the template string | Validate that parameters to a Fn::Sub are used |

## 3. Severity/category model compliance

### Warn in unexpected categories (6)

| ID | Category | Description |
|----|----------|-------------|
| `W1019` | Intrinsic | Parameter in Fn::Sub variable map is not used in the template string |
| `W1051` | Intrinsic | Dynamic reference resolves secret value but property expects the secret ARN |
| `W1054` | Intrinsic | String value matches a pseudo parameter; use Ref instead |
| `W1100` | Structure | YAML merge key '<<' is not supported by CloudFormation |
| `W1103` | Intrinsic | Unknown intrinsic function name |
| `W3030` | Schema | Value not in allowed enum |

## 4. Duplicate descriptions

_None._

## 5. Info rules that should likely be Warnings

_No candidates._

## 6. Engine rules implementing cfn-lint checks under a different ID

Engine-ID rules that implement a cfn-lint rule under a split or generic
ID (so an exact ID match is impossible). They are aliased to the cfn-lint
rule and PARTICIPATE in parity matching - an unmatched firing is a false
positive, not engine-extra. (There is no longer any blanket `ENGINE_STRICTER`
excuse list: rules cfn-lint also implements are never auto-waved-through.)

| ID | Severity | True origin | Description | cfn-lint rule |
|----|----------|-------------|-------------|---------------|
| `E9003` | Error | CfnLint | GetAtt return type may not match usage context | E1010, E1017 |
| `E9004` | Error | Schema | GetAtt attribute must exist on target resource type | E1010, E1017 |
| `E9006` | Error | CfnLint | Property value not valid for conditional extension enum | E3690, E3691 |

## 7. Missing cfn-lint coverage

cfn-lint rules that have no corresponding rule in our registry
(neither same ID, nor F-promoted equivalent, nor logically-covered via
schema-validator extensions or Fatal schema rules).

### Not implemented (24)

| cfn-lint ID | Severity | Description | Source file |
|-------------|----------|-------------|-------------|
| `E0002` | Error | Error processing rule on the template | rule.py |
| `E0003` | Error | Error with cfn-lint configuration | config.py |
| `E1101` | Error | Validate an item against additional checks | CfnLint.py |
| `E3056` | Error | EC2 health check type cannot be combined with other types | AutoScalingGroupHealthCheckType.py |
| `E3064` | Error | Validate unique PrivateDnsEnabled per service per VPC | VpcEndpointPrivateDnsDuplicate.py |
| `E3065` | Error | Check if a list has more unique values than allowed | MaxUniqueItems.py |
| `E3066` | Error | SAM resource attributes require the Serverless Transform | ServerlessTransformAttributes.py |
| `E3514` | Error | Validate IAM resource policy resource ARNs | ResourcePolicyResourceArn.py |
| `E3673` | Error | Validate if an ImageId is required | InstanceImageId.py |
| `E3720` | Error | Validate StorageEncrypted is set when KmsKeyId is specified | DbInstanceKmsKeyStorageEncrypted.py |
| `E3721` | Error | Validate ReplicaMode value for Oracle and Db2 engines | DbInstanceReplicaMode.py |
| `E3722` | Error | Cookies Forward must be a valid enum when CachePolicyId is absent | DistributionCacheBehaviorForwardEnum.py |
| `E3723` | Error | ResourcePath must start with / when method settings are configured | StageMethodSettingsResourcePath.py |
| `E3724` | Error | Validate Globals section | GlobalsTransform.py |
| `W1034` | Warn | Validate the values that come from a Fn::FindInMap function | FindInMapResolved.py |
| `W1036` | Warn | Validate the values that come from a Fn::GetAZs function | GetAzResolved.py |
| `W2002` | Warn | Parameter type is not officially supported by CloudFormation | UnsupportedParameterType.py |
| `W3699` | Warn | ReplicaMode is ignored for non-Oracle/Db2 engines | DbInstanceReplicaModeIgnored.py |
| `W3700` | Warn | Non-standard Domain values are converted to vpc | EipDomain.py |
| `W3701` | Warn | SSM Parameter Name should not use /aws/ or /ssm/ prefix | ParameterNamePrefix.py |
| `W3702` | Warn | awslayer ARN format may not be available | LambdaFunctionAwsLayer.py |
| `W3703` | Warn | VPNGateway Type should be ipsec.1 | VpnGatewayType.py |
| `W3704` | Warn | ForwardedValues is ignored when CachePolicyId is specified | DistributionCacheBehaviorForwardedValuesIgnored.py |
| `W3705` | Warn | MethodSettings entry is ignored without any setting properties | StageMethodSettingsIgnored.py |

### Covered via different mechanism (69)

These cfn-lint rule IDs have no matching engine ID but are enforced
through our schema-validator (extensions/patches from cfn-lint) or
via a Fatal schema rule covering the same concern.

| cfn-lint ID | cfn-lint description | Our mechanism | Note |
|-------------|----------------------|---------------|------|
| `E0100` | Validate deployment file configuration | `out-of-scope` | CLI deployment file |
| `E0200` | Validate parameter file configuration | `out-of-scope` | CLI parameter file |
| `E1001` | Basic CloudFormation Template Configuration | `F0002/F0005` | Top-level structure (partial: covers format version + section names only) |
| `E1003` | Validate the max size of a description | `F0011` | description max length 1024 |
| `E1157` | Validate KMS key ARN format | `schema-format` | KMS key ARN format (schema format field) |
| `E1158` | Validate SNS topic ARN format | `schema-format` | SNS topic ARN format (schema format field) |
| `E1159` | Validate ACM certificate ARN format | `schema-format` | ACM certificate ARN format (schema format field) |
| `E1160` | Validate Lambda function ARN format | `schema-format` | Lambda function ARN format (schema format field) |
| `E1161` | Validate S3 bucket name format | `schema-format` | S3 bucket name format (schema format field) |
| `E1162` | Validate KMS key ID format | `schema-format` | KMS key ID format (schema format field) |
| `E1164` | Validate KMS alias name format | `schema-format` | KMS alias name format (schema format field) |
| `E1700` | Rules have the appropriate configuration | `F8600` | Rules section config |
| `E1701` | Validate the configuration of Assertions | `F8603` | Rule Assertions required |
| `E1702` | Validate the configuration of Rules RuleCondition | `F8606` | Rule RuleCondition validation |
| `E2010` | Parameter limit not exceeded | `F0003` | Parameter limit 200 |
| `E2900` | Validate deployment file parameters are valid against template parameters | `out-of-scope` | CLI deployment parameters |
| `E3008` | Validate an array in order | `schema-patch` | Array prefixItems validation (compiled schema) |
| `E3009` | Check CloudFormation init configuration | `out-of-scope` | CFN init configuration (metadata) |
| `E3028` | Validate the metadata section of a resource | `out-of-scope` | Resource metadata section (rarely used) |
| `E3043` | Validate parameters for in a nested stack | `out-of-scope` | Nested stack parameters (runtime-only) |
| `E3046` | Validate ECS task logging configuration for awslogs | `schema-ext` | ECS awslogs config - via extensions |
| `E3063` | Validate GuardDuty Detector property exclusivity | `schema-patch` | GuardDuty Detector property exclusivity |
| `E3503` | ValidationDomain is superdomain of DomainName | `schema-patch` | ACM ValidationDomain subdomain of DomainName |
| `E3615` | Validate the period is a valid value | `schema-ext` | CloudWatch Alarm Period enum |
| `E3633` | Validate Lambda event source mapping StartingPosition is used correctly | `schema-ext` | Lambda StartingPosition validation |
| `E3634` | Validate Lambda event source mapping starting position is used with SQS | `schema-ext` | Lambda SQS starting position |
| `E3638` | Validate DynamoDB BillingMode pay per request configuration | `schema-ext` | DynamoDB BillingMode PayPerRequest |
| `E3661` | Validate Route53 health check has AlarmIdentifier when using CloudWatch | `schema-ext` | Route53 HealthCheck AlarmIdentifier |
| `E3674` | Primary cannoy be True when PrivateIpAddress is specified | `schema-patch` | EC2 NetworkInterface Primary+PrivateIp |
| `E3678` | Using the ZipFile attribute requires a runtime to be specified | `schema-ext` | Lambda ZipFile runtime required |
| `E3681` | Validate target group target type property restrictions | `schema-ext` | ELBv2 TargetGroup target type restrictions |
| `E3682` | Validate when using Aurora certain properies aren't required | `schema-patch` | Aurora properties not required |
| `E3683` | Validate target group protocol property restrictions | `schema-ext` | ELBv2 TargetGroup protocol restrictions |
| `E3684` | Validate target group health check protocol property restrictions | `schema-ext` | ELBv2 TargetGroup health check protocol |
| `E3686` | Validate allowed properties when using a serverless RDS DB cluster | `schema-patch` | Serverless RDS DB cluster properties |
| `E3688` | Validate that to and from ports are both -1 | `schema-ext` | SG ports must both be -1 |
| `E3689` | Validate MonitoringInterval and MonitoringRoleArn are used together | `schema-patch` | RDS MonitoringInterval+Role required together |
| `E3692` | Validate Multi-AZ DB cluster configuration | `schema-patch` | RDS Multi-AZ DB cluster config |
| `E3693` | Validate Aurora DB cluster configuration | `schema-patch` | Aurora DB cluster config |
| `E3695` | Validate Elasticache Cluster Engine and Engine Version | `schema-ext` | ElastiCache Engine and EngineVersion |
| `E3696` | LogLevel is not supported when LogFormat is set to Text | `schema-ext` | Lambda LogLevel/LogFormat relationship |
| `E3697` | Validate Lambda environment variables do not exceed 4 KB | `schema-patch` | Lambda environment variables size |
| `E3709` | Validate RDS DBInstance StorageEncrypted matches DBCluster | `schema-patch` | RDS DBInstance matches cluster StorageEncrypted |
| `E3711` | Validate ListenerRule target group protocol is not GENEVE | `schema-ext` | ListenerRule target protocol restrictions |
| `E3712` | TargetTrackingScaling policy requires ASG MaxSize greater than MinSize | `schema-ext` | ASG TargetTrackingScaling policy |
| `E3713` | Validate Fargate ECS services use supported log drivers | `schema-ext` | Fargate ECS log drivers |
| `E3714` | Validate LaunchTemplate SecurityGroup and Subnet are in the same VPC | `schema-patch` | LaunchTemplate SG/Subnet VPC match |
| `E3716` | Validate Lambda layer ARN length based on region | `schema-ext` | Lambda layer ARN length by region |
| `E3718` | Validate API Gateway Authorizer TTL based on type | `schema-ext` | API Gateway Authorizer TTL |
| `E3719` | Validate RDS BackupRetentionPeriod configuration | `schema-patch` | RDS BackupRetentionPeriod config |
| `E4001` | Metadata Interface have appropriate properties | `F0005` | Metadata Interface section validation |
| `E4002` | Validate the configuration of the Metadata section | `F0005` | Metadata section config |
| `E6002` | Outputs have required properties | `F0040` | Output Value required |
| `E6010` | Output limit not exceeded | `F0004` | Output limit 200 |
| `I1002` | Validate approaching the template size limit | `out-of-scope` | Template body size approaching limit (no approaching-limit analog) |
| `I3010` | Resource limit | `out-of-scope` | Resource count approaching limit (no approaching-limit analog) |
| `W1031` | Validate the values that come from a Fn::Sub function | `F3012+W9003` | Fn::Sub resolved values (via resolver) |
| `W1032` | Validate the values that come from a Fn::Join function | `F3012+W9003` | Fn::Join resolved values |
| `W1033` | Validate the values that come from a Fn::Split function | `F3012+W9003` | Fn::Split resolved values |
| `W1035` | Validate the values that come from a Fn::Select function | `F3012+W9003` | Fn::Select resolved values |
| `W1040` | Validate the values that come from a Fn::ToJsonString function | `F3012+W9003` | Fn::ToJsonString resolved values |
| `W2030` | Check if parameters have a valid value | `F2015` | Parameter Default enum check |
| `W2031` | Check if parameters have a valid value based on an allowed pattern | `F3031` | Parameter AllowedPattern check |
| `W3034` | Check if parameter values are between min and max | `E3034/F3034` | Parameter value numeric range |
| `W3690` | Validate DB Cluster Engine Version is not deprecated | `W2531` | DB Cluster Engine Version deprecated |
| `W3691` | Validate DB Instance Engine Version is not deprecated | `W2531` | DB Instance Engine Version deprecated |
| `W4001` | Metadata Interface parameters exist | `out-of-scope` | Metadata Interface parameters |
| `W4005` | Validate cfnlint configuration in the Metadata | `out-of-scope` | cfn-lint metadata config |
| `W6001` | Check Outputs using ImportValue | `out-of-scope` | Output ImportValue usage (cfn-lint checks cross-stack references) |

## 8. Source emission checks

Static regex scan of production runtime Rust and Rego source files.

**Scanned crates:**
- `template-model` (`src/template-model/src`)
- `schema-validator` (`src/schema-validator/src`)
- `validation-engine` (`src/validation-engine/src`)
- `diagnostics` (`src/diagnostics/src`)
- `cel-engine` (`src/cel-engine/src`)
- `rego-engine` (`src/rego-engine/src`)
- `rego-engine/handwritten` (`src/rego-engine/handwritten/rego`)

**Excluded:** generated code, registry definition, `#[cfg(test)]` modules,
bindings crates, `cfn-validate` (CLI frontend), `resources` (test fixtures),
`guard-translator` (IR only).

**Unregistered IDs:** none (across scanned production crates) ✅

**Rego severity mismatches:** none ✅

### Dual-use rule IDs (14)

Same rule ID emitted with semantically different messages.

**`E3013`** - registry: "CloudFront Aliases"

- Cluster 1 (1 sites): "CloudFront alias '{}' has wildcard in invalid position"
- Cluster 2 (1 sites): "CloudFront alias '{}' is not a valid domain name"

**`E3016`** - registry: "Check UpdatePolicy values for Resources"

- Cluster 1 (1 sites): "UpdatePolicy is not supported on resource type '{}'"
- Cluster 2 (1 sites): "{} is not of type 'object'"

**`E3023`** - registry: "Validate Route53 RecordSets"

- Cluster 1 (1 sites): "CNAME records must have at most 1 ResourceRecord"
- Cluster 2 (1 sites): "CNAME record Name '{}' must not match HostedZoneName '{}' exactly"

**`E3029`** - registry: "Validate Route53 record set aliases"

- Cluster 1 (1 sites): "TTL must not be set when AliasTarget is specified"
- Cluster 2 (1 sites): "AliasTarget cannot be used with record type '{}'"

**`E3048`** - registry: "Validate ECS Fargate tasks have required properties and values"

- Cluster 1 (4 sites): "Fargate requires NetworkMode to be specified as 'awsvpc'"
- Cluster 2 (1 sites): "Fargate Cpu value {} is not valid. Must be one of {}"
- Cluster 3 (2 sites): "Fargate does not support PlacementConstraints"

**`E3671`** - registry: "Validate block device mapping configuration"

- Cluster 1 (1 sites): "'Iops' is a required property when 'VolumeType' has a value of '{}'"
- Cluster 2 (1 sites): "{} is less than the minimum of {}"
- Cluster 3 (1 sites): "{} is greater than the maximum of {}"

**`E3701`** - registry: "Validate input and output artifact names are used properly"

- Cluster 1 (1 sites): "Duplicate OutputArtifact name '{}'"
- Cluster 2 (1 sites): "InputArtifact '{}' in stage '{}' action '{}' does not reference a previously def"

**`F0050`** - registry: "Mapping must have valid 3-level structure"

- Cluster 1 (2 sites): "Mapping '{}' must be a map"
- Cluster 2 (2 sites): "Mapping '{}' has {} top-level keys, maximum is 200"

**`F1020`** - registry: "Ref/GetAtt target must exist"

- Cluster 1 (1 sites): "Fn::GetAtt references non-existent resource '{}'"
- Cluster 2 (1 sites): "'{}' is not one of {}"

**`F2015`** - registry: "Default value is within parameter constraints"

- Cluster 1 (3 sites): "Parameter '{}' Default length {} is less than MinLength {}"
- Cluster 2 (1 sites): "Parameter '{}' Default {} exceeds MaxValue {}"

**`F6101`** - registry: "Output value must be a string"

- Cluster 1 (1 sites): "Fn::Sub variable '${{{}}}' does not reference a valid resource, parameter, or ps"
- Cluster 2 (1 sites): "GetAtt '{}.{}' references a resource that does not exist"
- Cluster 3 (1 sites): "'{}' is not one of {}"
- Cluster 4 (1 sites): "Output '{}': GetAtt '{}.{}' returns type '{}', not 'string'"

**`W1028`** - registry: "Check Fn::If has a path that cannot be reached"

- Cluster 1 (1 sites): "['Fn::If', 1] is not reachable. When setting condition '{}' to True"
- Cluster 2 (1 sites): "['Fn::If', 2] is not reachable. {}"

**`W1030`** - registry: "Validate the values that come from a Ref function"

- Cluster 1 (2 sites): "{{'Ref': '{}'}} is not a 'AWS::EC2::Image.Id' when 'Ref' is resolved"
- Cluster 2 (1 sites): "{{'Ref': '{}'}} is not a 'ipv4-network' when 'Ref' is resolved"

**`W2501`** - registry: "Check if Password Properties are correctly configured"

- Cluster 1 (2 sites): "Password should use a secure dynamic reference for Resources/{}/Properties/{}"
- Cluster 2 (1 sites): "Property '{}' should not be a hardcoded string - use a parameter with NoEcho or "
- Cluster 3 (1 sites): "Parameter {} used as {}, therefore NoEcho should be True"

**Engine source ID presence:** native CEL and handwritten Rego emit the same rule IDs ✅
_(ID presence only — behavioral parity is verified by running both engines on real templates.)_

_Scanned 453 Rust sites (284 IDs), 300 Rego sites (194 IDs)._

## Appendix: full rule inventory

| ID | Severity | Category | Registry origin | True origin | Description |
|----|----------|----------|-----------------|-------------|-------------|
| `E0001` | Error | Structure | CfnLint | CfnLint | SAM (AWS::Serverless) transform would reject the template |
| `E1002` | Error | Structure | CfnLint | CfnLint | Validate if a template size is too large |
| `E1005` | Error | Structure | CfnLint | CfnLint | Validate Transform configuration |
| `E1011` | Error | Intrinsic | Schema | Schema | Fn::FindInMap operands must be strings or one of Ref/Fn::FindInMap |
| `E1015` | Error | Intrinsic | Schema | Schema | GetAz validation of parameters |
| `E1016` | Error | Intrinsic | Schema | Schema | ImportValue validation of parameters |
| `E1017` | Error | Intrinsic | Schema | Schema | Fn::Select requires exactly two operands and a list source |
| `E1018` | Error | Intrinsic | Schema | Schema | Fn::Split source must be a string or a string-producing intrinsic |
| `E1019` | Error | Intrinsic | Schema | Schema | Fn::Sub variable map values must be strings or string-producing intrinsics |
| `E1021` | Error | Intrinsic | Schema | Schema | Fn::Base64 argument must be a string or a string-producing intrinsic |
| `E1022` | Error | Intrinsic | Schema | Schema | Fn::Join requires a string delimiter and a list of strings or string-producing intrinsics |
| `E1024` | Error | Intrinsic | Schema | Schema | Fn::Cidr requires a CIDR-format ipBlock string and integer count/cidrBits |
| `E1027` | Error | Intrinsic | CfnLint | CfnLint | Check dynamic references secure strings are in supported locations |
| `E1028` | Error | Intrinsic | Schema | Schema | Fn::If condition must exist in Conditions section |
| `E1029` | Error | Intrinsic | CfnLint | CfnLint | Substitution variable ${X} requires Fn::Sub |
| `E1030` | Error | Intrinsic | Schema | Schema | Fn::Length argument must be an array or a list-producing function |
| `E1031` | Error | Intrinsic | Schema | Schema | Fn::ToJsonString argument must be a non-empty array/object or a supported function |
| `E1033` | Error | Intrinsic | Schema | Schema | GetStackOutput validation of parameters |
| `E1040` | Error | Intrinsic | CfnLint | CfnLint | Check if GetAtt matches destination format |
| `E1041` | Error | Intrinsic | CfnLint | CfnLint | Check if Ref matches destination format |
| `E1050` | Error | Intrinsic | CfnLint | CfnLint | Dynamic reference must match the SSM, ssm-secure, or Secrets Manager format |
| `E1051` | Error | Intrinsic | CfnLint | CfnLint | Validate dynamic references to secrets manager are only in resource properties |
| `E1052` | Error | Intrinsic | CfnLint | CfnLint | Validate dynamic references to SSM are in a valid location |
| `E1103` | Error | Intrinsic | CfnLint | CfnLint | Validate the format of a value |
| `E1150` | Error | Intrinsic | CfnLint | CfnLint | Validate security group format |
| `E1151` | Error | Intrinsic | CfnLint | CfnLint | Validate VPC id format |
| `E1152` | Error | Intrinsic | CfnLint | CfnLint | Validate AMI id format |
| `E1153` | Error | Intrinsic | CfnLint | CfnLint | Validate security group name |
| `E1154` | Error | Intrinsic | CfnLint | CfnLint | Validate VPC subnet id format |
| `E1155` | Error | Intrinsic | CfnLint | CfnLint | Validate CloudWatch logs group name |
| `E1156` | Error | Intrinsic | CfnLint | CfnLint | Validate IAM role ARN format |
| `E2001` | Error | Parameter | CfnLint | CfnLint | Parameters have appropriate properties |
| `E2529` | Error | Resource | CfnLint | CfnLint | Check for SubscriptionFilters beyond 2 attachments to a CloudWatch Log Group |
| `E2530` | Error | Resource | CfnLint | CfnLint | SnapStart supports the configured runtime |
| `E2531` | Error | Deprecation | CfnLint | CfnLint | Check if Lambda Function Runtimes are blocked for create |
| `E2533` | Error | Deprecation | CfnLint | CfnLint | Check if Lambda Function Runtimes are updatable |
| `E3001` | Error | Resource | CfnLint | CfnLint | Basic CloudFormation Resource Check |
| `E3002` | Error | Schema | CfnLint | CfnLint | Resource properties are invalid |
| `E3003` | Error | Resource | CfnLint | CfnLint | Required Resource properties are missing |
| `E3005` | Error | Reference | CfnLint | CfnLint | Check DependsOn values for Resources |
| `E3010` | Error | Resource | CfnLint | CfnLint | Resource limit not exceeded |
| `E3011` | Error | Resource | CfnLint | CfnLint | Check property names in Resources |
| `E3012` | Error | Schema | CfnLint | CfnLint | Check resource properties values |
| `E3013` | Error | Resource | CfnLint | CfnLint | CloudFront Aliases |
| `E3016` | Error | Resource | CfnLint | CfnLint | Check UpdatePolicy values for Resources |
| `E3019` | Error | Resource | CfnLint | CfnLint | Validate that all resources have unique primary identifiers |
| `E3022` | Error | Resource | CfnLint | CfnLint | Resource SubnetRouteTableAssociation Properties |
| `E3023` | Error | Resource | CfnLint | CfnLint | Validate Route53 RecordSets |
| `E3024` | Error | Resource | CfnLint | CfnLint | Validate tag configuration |
| `E3025` | Error | Resource | CfnLint | CfnLint | Validates RDS DB Instance Class |
| `E3026` | Error | Resource | CfnLint | CfnLint | Check Elastic Cache Redis Cluster settings |
| `E3027` | Error | Resource | CfnLint | CfnLint | Validate AWS Event ScheduleExpression format |
| `E3029` | Error | Resource | CfnLint | CfnLint | Validate Route53 record set aliases |
| `E3030` | Error | Schema | CfnLint | CfnLint | Check if properties have a valid value |
| `E3031` | Error | Schema | CfnLint | CfnLint | Check if property values adhere to a specific pattern |
| `E3032` | Error | Schema | CfnLint | CfnLint | Check if an array has between min and max number of values |
| `E3034` | Error | Schema | CfnLint | CfnLint | Check if a number is between min and max |
| `E3038` | Error | Structure | CfnLint | CfnLint | Check if Serverless Resources have Serverless Transform |
| `E3039` | Error | Resource | CfnLint | CfnLint | AttributeDefinitions / KeySchemas mismatch |
| `E3040` | Error | Schema | CfnLint | CfnLint | Read only property should not be specified |
| `E3041` | Error | Resource | CfnLint | CfnLint | RecordSet HostedZoneName is a superdomain of or equal to Name |
| `E3042` | Error | Resource | CfnLint | CfnLint | Validate at least one essential container is specified |
| `E3044` | Error | Resource | CfnLint | CfnLint | ECS service using FARGATE or EXTERNAL cannot use DAEMON scheduling |
| `E3045` | Error | Resource | CfnLint | CfnLint | Validate AccessControl are set with OwnershipControls |
| `E3047` | Error | Resource | CfnLint | CfnLint | Validate ECS Fargate tasks have the right combination of CPU and memory |
| `E3048` | Error | Resource | CfnLint | CfnLint | Validate ECS Fargate tasks have required properties and values |
| `E3050` | Error | Resource | CfnLint | CfnLint | Check if REFing to a IAM resource with path set |
| `E3051` | Error | Resource | CfnLint | CfnLint | Validate the structure of a SSM document |
| `E3052` | Error | Resource | CfnLint | CfnLint | Validate ECS service requires NetworkConfiguration |
| `E3053` | Error | Resource | CfnLint | CfnLint | Validate ECS task definition has correct values for HostPort |
| `E3054` | Error | Resource | CfnLint | CfnLint | Validate ECS service using Fargate uses TaskDefinition that allows Fargate |
| `E3055` | Error | Resource | CfnLint | CfnLint | Check CreationPolicy values for Resources |
| `E3057` | Error | Resource | CfnLint | CfnLint | Validate that CloudFront TargetOriginId is a specified Origin |
| `E3059` | Error | Resource | CfnLint | CfnLint | Validate subnet CIDRs are within the CIDRs of the VPC |
| `E3060` | Error | Resource | CfnLint | CfnLint | Validate subnet CIDRs do not overlap with other subnets |
| `E3061` | Error | Resource | CfnLint | CfnLint | Validate the days for tierings in IntelligentTieringConfigurations |
| `E3062` | Error | Resource | CfnLint | CfnLint | Validates RDS DB Instance Class based on Engine and EngineVersion |
| `E3501` | Error | Resource | CfnLint | CfnLint | Validate SQS queue properties are valid |
| `E3502` | Error | Resource | CfnLint | CfnLint | Validate SQS DLQ queues are the same type |
| `E3504` | Error | Resource | CfnLint | CfnLint | Check minimum 90 period is met between BackupPlan cold and delete |
| `E3505` | Error | Resource | CfnLint | CfnLint | Validate SQS VisibilityTimeout is greater than a function's Timeout |
| `E3510` | Error | Resource | CfnLint | CfnLint | Validate identity based IAM policies |
| `E3511` | Error | Resource | CfnLint | CfnLint | Validate IAM role arn pattern |
| `E3512` | Error | Resource | CfnLint | CfnLint | Validate resource based IAM policies |
| `E3513` | Error | Resource | CfnLint | CfnLint | Validate ECR repository policy |
| `E3530` | Error | Resource | CfnLint | CfnLint | Validate IAM trust policies |
| `E3601` | Error | Resource | CfnLint | CfnLint | Validate the structure of a StateMachine definition |
| `E3617` | Error | Resource | CfnLint | CfnLint | Validate ManagedBlockchain instance type |
| `E3620` | Error | Resource | CfnLint | CfnLint | Validate a DocDB DB Instance class |
| `E3621` | Error | Resource | CfnLint | CfnLint | Validate the instance types for AppStream Fleet |
| `E3628` | Error | Resource | CfnLint | CfnLint | Validate EC2 instance types based on region |
| `E3635` | Error | Resource | CfnLint | CfnLint | Validate Neptune DB instance class |
| `E3636` | Error | Resource | CfnLint | CfnLint | Validate CodeBuild projects using S3 also have Location |
| `E3639` | Error | Resource | CfnLint | CfnLint | Validate DynamoDB table ProvisionedThroughput is set when BillingMode is PROVISIONED |
| `E3640` | Error | Resource | CfnLint | CfnLint | Validate SageMaker processing instance types based on region |
| `E3641` | Error | Resource | CfnLint | CfnLint | Validate GameLift Fleet EC2 instance type |
| `E3642` | Error | Resource | CfnLint | CfnLint | Validate SageMaker hosting instance types based on region |
| `E3643` | Error | Resource | CfnLint | CfnLint | Validate SageMaker transform instance types based on region |
| `E3644` | Error | Resource | CfnLint | CfnLint | Validate SageMaker cluster instance types based on region |
| `E3647` | Error | Resource | CfnLint | CfnLint | Validate ElastiCache cluster cache node type |
| `E3652` | Error | Resource | CfnLint | CfnLint | Validate Elasticsearch domain cluster instance |
| `E3653` | Error | Resource | CfnLint | CfnLint | Validate OpenSearch domain cluster instance type |
| `E3660` | Error | Resource | CfnLint | CfnLint | RestApi requires a name when not using an OpenAPI specification |
| `E3663` | Error | Resource | CfnLint | CfnLint | Validate Lambda environment variable names aren't reserved |
| `E3667` | Error | Resource | CfnLint | CfnLint | Validate Redshift cluster node type |
| `E3670` | Error | Resource | CfnLint | CfnLint | Validate the instance types for an AmazonMQ Broker |
| `E3671` | Error | Resource | CfnLint | CfnLint | Validate block device mapping configuration |
| `E3672` | Error | Resource | CfnLint | CfnLint | Validate the cluster node type for a DAX Cluster |
| `E3675` | Error | Resource | CfnLint | CfnLint | Validate EMR cluster instance type |
| `E3676` | Error | Resource | CfnLint | CfnLint | Validate ELBv2 protocols that require certificates have a certificate specified |
| `E3677` | Error | Resource | CfnLint | CfnLint | Lambda ZipFile requires nodejs or python runtime |
| `E3679` | Error | Resource | CfnLint | CfnLint | Validate ELB protocols that require certificates have a certificate specified |
| `E3680` | Error | Resource | CfnLint | CfnLint | Application load balancers require at least 2 subnets |
| `E3685` | Error | Resource | CfnLint | CfnLint | Container image functions cannot use Handler, Runtime, or Layers |
| `E3687` | Error | Resource | CfnLint | CfnLint | Validate to and from ports based on the protocol |
| `E3694` | Error | Resource | CfnLint | CfnLint | Validates RDS DB Cluster instance class |
| `E3698` | Error | Resource | CfnLint | CfnLint | API Gateway Stage and Deployment must use the same RestApi |
| `E3699` | Error | Resource | CfnLint | CfnLint | API Gateway Method and Authorizer must use the same RestApi |
| `E3700` | Error | Resource | CfnLint | CfnLint | Validate CodePipeline Source actions are only in the first stage |
| `E3701` | Error | Resource | CfnLint | CfnLint | Validate input and output artifact names are used properly |
| `E3702` | Error | Resource | CfnLint | CfnLint | Validate the number of input and output artifacts in a CodePipeline |
| `E3703` | Error | Resource | CfnLint | CfnLint | Validate the configuration of a pipeline action |
| `E3704` | Error | Resource | CfnLint | CfnLint | Validate TransitEncryptionEnabled is set when using Valkey engine |
| `E3705` | Error | Resource | CfnLint | CfnLint | Validate SQS FIFO queue EventSourceMapping BatchSize is at most 10 |
| `E3706` | Error | Resource | CfnLint | CfnLint | MaxSize must be greater than or equal to MinSize |
| `E3707` | Error | Resource | CfnLint | CfnLint | Validate RDS DBInstance Engine matches DBCluster Engine |
| `E3708` | Error | Resource | CfnLint | CfnLint | API Gateway Method AuthorizationType must match Authorizer Type |
| `E3710` | Error | Deprecation | CfnLint | CfnLint | Resource type is from a service that has been shut down |
| `E3715` | Error | Resource | CfnLint | CfnLint | VirtualName must use ephemeral device format when Ebs is absent |
| `E5001` | Error | Structure | CfnLint | CfnLint | Check that Modules resources are valid |
| `E6001` | Error | Structure | CfnLint | CfnLint | Outputs have appropriate properties |
| `E6003` | Error | Structure | CfnLint | CfnLint | Outputs section must be an object of named output definitions |
| `E6005` | Error | Structure | Schema | Schema | Condition referenced by an output must exist in the Conditions section |
| `E7001` | Error | Structure | CfnLint | CfnLint | Mappings are appropriately configured |
| `E8001` | Error | Structure | Schema | Schema | Conditions section must have valid structure |
| `E8002` | Error | Structure | Schema | Schema | Condition referenced by resource is not defined |
| `E8003` | Error | Intrinsic | Schema | Schema | Fn::Equals must take exactly two scalar operands |
| `E8004` | Error | Intrinsic | Schema | Schema | Fn::And must take between 2 and 10 boolean conditions |
| `E8005` | Error | Intrinsic | Schema | Schema | Fn::Not must take exactly one boolean condition |
| `E8006` | Error | Intrinsic | Schema | Schema | Fn::Or must take between 2 and 10 boolean conditions |
| `E8007` | Error | Intrinsic | Schema | Schema | Condition function value must be a string referencing a defined condition |
| `E9002` | Error | Resource | Engine | Engine | SecurityGroup FromPort must be <= ToPort for the TCP and UDP protocols |
| `E9003` | Error | Intrinsic | CfnLint | CfnLint | GetAtt return type may not match usage context |
| `E9004` | Error | Intrinsic | Schema | Schema | GetAtt attribute must exist on target resource type |
| `E9006` | Error | Schema | CfnLint | CfnLint | Property value not valid for conditional extension enum |
| `E9101` | Error | Intrinsic | Schema | Schema | Invalid nesting of intrinsic functions |
| `E9106` | Error | Structure | Schema | Schema | Circular dependency in condition definitions |
| `F0000` | Fatal | Structure | Schema | Schema | Duplicate key in template |
| `F0001` | Fatal | Structure | Schema | Schema | Resources section must exist and be non-empty |
| `F0002` | Fatal | Structure | Schema | Schema | AWSTemplateFormatVersion must be 2010-09-09 |
| `F0003` | Fatal | Structure | Schema | Schema | Maximum 200 parameters |
| `F0004` | Fatal | Structure | Schema | Schema | Maximum 200 outputs |
| `F0005` | Fatal | Structure | Schema | Schema | Top-level keys must be valid section names |
| `F0006` | Fatal | Structure | Schema | Schema | Logical IDs must be alphanumeric |
| `F0007` | Fatal | Structure | Schema | Schema | Maximum 500 resources |
| `F0008` | Fatal | Structure | Schema | Schema | Maximum 200 mappings |
| `F0009` | Fatal | Structure | Schema | Schema | Maximum 200 conditions |
| `F0010` | Fatal | Intrinsic | Schema | Schema | Fn::Sub second argument must be a map |
| `F0011` | Fatal | Structure | Schema | Schema | Description exceeds maximum 1024 characters |
| `F0013` | Fatal | Intrinsic | Schema | Schema | Fn::If must have exactly 3 elements |
| `F0014` | Fatal | Intrinsic | Schema | Schema | Boolean condition function (Fn::Equals/Fn::And/Fn::Or/Fn::Not) has invalid structure |
| `F0015` | Fatal | Parameter | Schema | Schema | Default value must match parameter Type |
| `F0016` | Fatal | Parameter | Schema | Schema | AllowedValues entries must match parameter Type |
| `F0017` | Fatal | Structure | Schema | Schema | Mapping level must be a map |
| `F0018` | Fatal | Structure | Schema | Schema | UpdateReplacePolicy must be valid |
| `F0040` | Fatal | Structure | Schema | Schema | Output must have Value property |
| `F0050` | Fatal | Structure | Schema | Schema | Mapping must have valid 3-level structure |
| `F1004` | Fatal | Structure | Schema | Schema | Description must be a string |
| `F1010` | Fatal | Intrinsic | Schema | Schema | Ref target must exist |
| `F1012` | Fatal | Intrinsic | Schema | Schema | FindInMap map name must exist in Mappings |
| `F1018` | Fatal | Intrinsic | Schema | Schema | Sub variables must resolve |
| `F1020` | Fatal | Intrinsic | Schema | Schema | Ref/GetAtt target must exist |
| `F1030` | Fatal | Intrinsic | Schema | Schema | Fn::Length requires the AWS::LanguageExtensions transform |
| `F1031` | Fatal | Intrinsic | Schema | Schema | Fn::ToJsonString requires the AWS::LanguageExtensions transform |
| `F1032` | Fatal | Intrinsic | Schema | Schema | Fn::ForEach requires the AWS::LanguageExtensions transform |
| `F1050` | Fatal | Intrinsic | Schema | Schema | Select index must be non-negative |
| `F1101` | Fatal | Structure | Schema | Schema | Invalid YAML/JSON syntax |
| `F2002` | Fatal | Parameter | Schema | Schema | Parameter Type must be valid |
| `F2003` | Fatal | Parameter | Schema | Schema | Parameter name must be alphanumeric |
| `F2011` | Fatal | Parameter | Schema | Schema | Parameter name exceeds maximum length |
| `F2012` | Fatal | Parameter | Schema | Schema | Parameter Default must be in AllowedValues |
| `F2015` | Fatal | Parameter | Schema | Schema | Default value is within parameter constraints |
| `F3002` | Fatal | Schema | Schema | Schema | Additional properties are not allowed |
| `F3003` | Fatal | Schema | Schema | Schema | Required property missing |
| `F3004` | Fatal | Reference | Schema | Schema | Circular dependency detected |
| `F3006` | Fatal | Schema | Schema | Schema | AWS resource type must be recognized and available in the configured region |
| `F3007` | Fatal | Structure | Schema | Schema | Logical ID used as both parameter and resource |
| `F3012` | Fatal | Schema | Schema | Schema | Property type mismatch |
| `F3014` | Fatal | Schema | Schema | Schema | Exactly one of properties required (requiredXor) |
| `F3016` | Fatal | Structure | Schema | Schema | DeletionPolicy must be valid |
| `F3017` | Fatal | Schema | Schema | Schema | Value not valid under anyOf |
| `F3018` | Fatal | Schema | Schema | Schema | Value not valid under oneOf |
| `F3020` | Fatal | Schema | Schema | Schema | Mutually exclusive properties |
| `F3021` | Fatal | Schema | Schema | Schema | Dependent property required |
| `F3030` | Fatal | Schema | Schema | Schema | Value does not match the required constant |
| `F3031` | Fatal | Schema | Schema | Schema | Value does not match pattern |
| `F3032` | Fatal | Schema | Schema | Schema | Array item count out of bounds |
| `F3033` | Fatal | Schema | Schema | Schema | String length out of bounds |
| `F3034` | Fatal | Schema | Schema | Schema | Numeric value out of bounds |
| `F3037` | Fatal | Schema | Schema | Schema | Array items not unique |
| `F3058` | Fatal | Schema | Schema | Schema | One of properties required (requiredOr) |
| `F6004` | Fatal | Structure | Schema | Schema | Output name must be alphanumeric |
| `F6005` | Fatal | Structure | Schema | Schema | Output Export name validation |
| `F6011` | Fatal | Structure | Schema | Schema | Output name exceeds maximum length |
| `F6101` | Fatal | Structure | Schema | Schema | Output value must be a string |
| `F7002` | Fatal | Structure | Schema | Schema | Mapping name exceeds maximum length |
| `F8600` | Fatal | Structure | Schema | Schema | Rules section must be an object |
| `F8601` | Fatal | Structure | Schema | Schema | Rule must be an object |
| `F8603` | Fatal | Structure | Schema | Schema | Rule missing required Assertions property |
| `F8604` | Fatal | Structure | Schema | Schema | Rule Assertions must be an array |
| `F8605` | Fatal | Structure | Schema | Schema | Rule Assertions must not be empty |
| `F8606` | Fatal | Structure | Schema | Schema | Rule RuleCondition must be a condition function |
| `F8607` | Fatal | Structure | Schema | Schema | Rule assertion must be an object |
| `F8609` | Fatal | Structure | Schema | Schema | Rule assertion missing required Assert property |
| `F8610` | Fatal | Structure | Schema | Schema | Rule assertion Assert must be a condition function |
| `F8611` | Fatal | Structure | Schema | Schema | Disallowed function in Rules section |
| `I1003` | Info | Structure | CfnLint | CfnLint | Validate if we are approaching the max size of a description |
| `I1022` | Info | Intrinsic | CfnLint | CfnLint | Use Sub instead of Join |
| `I2003` | Info | Structure | CfnLint | CfnLint | Validate AllowedPattern is a valid regex |
| `I2010` | Info | Structure | CfnLint | CfnLint | Parameter limit |
| `I2011` | Info | Structure | CfnLint | CfnLint | Parameter name limit |
| `I2530` | Info | BestPractice | CfnLint | CfnLint | Validate that SnapStart is configured for >= Java11 runtimes |
| `I3011` | Info | BestPractice | CfnLint | CfnLint | Check stateful resources have a set UpdateReplacePolicy/DeletionPolicy |
| `I3012` | Info | Structure | CfnLint | CfnLint | Resource name limit |
| `I3013` | Info | BestPractice | CfnLint | CfnLint | Check resources with auto expiring content have explicit retention period |
| `I3037` | Info | BestPractice | CfnLint | CfnLint | Check if a list that allows duplicates has any duplicates |
| `I3042` | Info | BestPractice | CfnLint | CfnLint | ARNs should use correctly placed Pseudo Parameters |
| `I3049` | Info | BestPractice | CfnLint | CfnLint | ELB target group relies on the default traffic-port health check for an ECS dynamic host port |
| `I3100` | Info | BestPractice | CfnLint | CfnLint | Checks for legacy instance type generations |
| `I3510` | Info | Security | CfnLint | CfnLint | Validate statement resources match the actions |
| `I6010` | Info | Structure | CfnLint | CfnLint | Output limit |
| `I6011` | Info | Structure | CfnLint | CfnLint | Output name limit |
| `I7002` | Info | Structure | CfnLint | CfnLint | Mapping name limit |
| `I7010` | Info | Structure | CfnLint | CfnLint | Mapping limit |
| `I9001` | Info | BestPractice | Engine | Engine | Create-only property updated triggers resource replacement |
| `I9002` | Info | BestPractice | Engine | Engine | Property is ignored in this configuration (from extension) |
| `I9003` | Info | BestPractice | Engine | Engine | Region-scoped values validated against all regions because no region was supplied |
| `I9040` | Info | BestPractice | Engine | Engine | Resource should have Tags |
| `I9052` | Info | Structure | Engine | Engine | Condition-dependent validation could not be completed because an analysis budget was exceeded |
| `W1001` | Warn | BestPractice | CfnLint | CfnLint | Ref/GetAtt to resource that is available when conditions are applied |
| `W1011` | Warn | Security | CfnLint | CfnLint | Instead of REFing a parameter for a secret use a dynamic reference |
| `W1019` | Warn | Intrinsic | CfnLint | CfnLint | Parameter in Fn::Sub variable map is not used in the template string |
| `W1020` | Warn | BestPractice | CfnLint | CfnLint | Sub isn't needed if it doesn't have a variable defined |
| `W1028` | Warn | BestPractice | CfnLint | CfnLint | Check Fn::If has a path that cannot be reached |
| `W1030` | Warn | BestPractice | CfnLint | CfnLint | Validate the values that come from a Ref function |
| `W1051` | Warn | Intrinsic | CfnLint | CfnLint | Dynamic reference resolves secret value but property expects the secret ARN |
| `W1053` | Warn | BestPractice | CfnLint | CfnLint | Dynamic references should not contain spaces |
| `W1054` | Warn | Intrinsic | CfnLint | CfnLint | String value matches a pseudo parameter; use Ref instead |
| `W1100` | Warn | Structure | CfnLint | CfnLint | YAML merge key '<<' is not supported by CloudFormation |
| `W1102` | Warn | BestPractice | Engine | Engine | Invalid intrinsic function usage |
| `W1103` | Warn | Intrinsic | Engine | Engine(collision) | Unknown intrinsic function name |
| `W2001` | Warn | BestPractice | CfnLint | CfnLint | Check if Parameters are Used |
| `W2010` | Warn | Security | CfnLint | CfnLint | NoEcho parameters are not masked when used in Metadata and Outputs |
| `W2501` | Warn | Security | CfnLint | CfnLint | Check if Password Properties are correctly configured |
| `W2502` | Warn | BestPractice | Engine | Engine | DependsOn conditional resource without matching condition |
| `W2503` | Warn | BestPractice | Engine | Engine | Resource references conditional resource with mutually exclusive condition |
| `W2506` | Warn | BestPractice | CfnLint | CfnLint | Check if ImageId Parameters have the correct type |
| `W2508` | Warn | Security | Engine | Engine | Security group allows open access to sensitive port |
| `W2509` | Warn | Security | CfnLint | CfnLint | Password parameter should have NoEcho |
| `W2511` | Warn | Security | CfnLint | CfnLint | Check IAM Resource Policies syntax |
| `W2512` | Warn | Security | Engine | Engine | IAM policy with NotAction |
| `W2530` | Warn | BestPractice | CfnLint | CfnLint | Validate that SnapStart is properly configured |
| `W2531` | Warn | Deprecation | CfnLint | CfnLint | Check if EOL Lambda Function Runtimes are used |
| `W2533` | Warn | BestPractice | CfnLint | CfnLint | Check required properties for Lambda if the deployment package is a .zip file |
| `W3002` | Warn | BestPractice | CfnLint | CfnLint | Warn when properties are configured to only work with the package command |
| `W3005` | Warn | BestPractice | CfnLint | CfnLint | Check obsolete DependsOn configuration for Resources |
| `W3010` | Warn | BestPractice | CfnLint | CfnLint | Availability zone properties should not be hardcoded |
| `W3011` | Warn | BestPractice | CfnLint | CfnLint | Check resources with UpdateReplacePolicy/DeletionPolicy have both |
| `W3030` | Warn | Schema | CfnLint | CfnLint | Value not in allowed enum |
| `W3037` | Warn | Security | CfnLint | CfnLint | Check IAM Permission configuration |
| `W3045` | Warn | Deprecation | CfnLint | CfnLint | Controlling access to an S3 bucket should be done with bucket policies |
| `W3049` | Warn | BestPractice | CfnLint | CfnLint | ELB target group health check uses a fixed port that will not follow an ECS dynamic host port |
| `W3660` | Warn | BestPractice | CfnLint | CfnLint | Validate if multiple resources are modifying a Rest API definition |
| `W3663` | Warn | Security | CfnLint | CfnLint | Validate SourceAccount is required property |
| `W3664` | Warn | BestPractice | CfnLint | CfnLint | Validate Lambda permission Principal matches SourceArn resource type |
| `W3671` | Warn | BestPractice | CfnLint | CfnLint | Iops is ignored for certain EBS volume types |
| `W3687` | Warn | BestPractice | CfnLint | CfnLint | Validate that ports aren't specified for certain protocols |
| `W3688` | Warn | BestPractice | CfnLint | CfnLint | When restoring DBCluster certain properties are ignored |
| `W3689` | Warn | BestPractice | CfnLint | CfnLint | When using a source DB certain properties are ignored |
| `W3693` | Warn | BestPractice | CfnLint | CfnLint | Validate Aurora DB cluster configuration for ignored properties |
| `W3694` | Warn | BestPractice | CfnLint | CfnLint | SNS Subscription Endpoint should match Protocol |
| `W3696` | Warn | Deprecation | CfnLint | CfnLint | Resource type is from a service that is sunsetting |
| `W3697` | Warn | Deprecation | CfnLint | CfnLint | Resource type is from a service in maintenance mode |
| `W3698` | Warn | BestPractice | CfnLint | CfnLint | VirtualName is ignored when Ebs is specified |
| `W7001` | Warn | BestPractice | CfnLint | CfnLint | Check if Mappings are Used |
| `W8001` | Warn | BestPractice | CfnLint | CfnLint | Check if Conditions are Used |
| `W8003` | Warn | BestPractice | CfnLint | CfnLint | Fn::Equals will always return true or false |
| `W8602` | Warn | BestPractice | Engine | Engine | Rule has unknown property |
| `W8608` | Warn | BestPractice | Engine | Engine | Rule assertion has unknown property |
| `W9002` | Warn | BestPractice | Engine | Engine | Hardcoded ARN property |
| `W9003` | Warn | BestPractice | CfnLint | CfnLint | Property type coercion warning |
| `W9006` | Warn | BestPractice | Engine | Engine | String length estimation through Fn::Sub |
| `W9007` | Warn | BestPractice | Engine | Engine | Array items must be unique when required |
| `W9008` | Warn | Security | Engine | Engine | RDS instance should have StorageEncrypted |
| `W9009` | Warn | Deprecation | Engine | Engine | Resource type sunset or shutdown |
| `W9010` | Warn | Security | Engine | Engine | Hardcoded AMI ID |
| `W9011` | Warn | Security | Engine | Engine | RDS instance PubliclyAccessible is true |
| `W9012` | Warn | BestPractice | Engine | Engine | Provided pseudo-parameter override value is not a valid AWS value |
| `W9013` | Warn | Security | Engine | Engine | Hardcoded account ID in ARN |
| `W9053` | Warn | BestPractice | Engine | Engine | Conditions are semantically equivalent and can be consolidated |
| `W9054` | Warn | BestPractice | Engine | Engine | Write-only property referenced in output |

