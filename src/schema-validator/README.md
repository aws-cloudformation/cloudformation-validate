# schema-validator

Validates CloudFormation resources against precompiled JSON Schema definitions derived from AWS resource provider
schemas. Produces diagnostics for structural violations — type mismatches, missing required properties,
invalid enum values, pattern failures, constraint violations, lifecycle issues, and cross-resource constraints.

## API

| Method                    | Purpose                                                    |
|---------------------------|------------------------------------------------------------|
| `SchemaValidator::new()`  | Create a new validator with all schemas loaded             |
| `validate(model, region)` | Run all schema checks, returns diagnostics + timing metric |
| `schema_count()`          | Number of loaded resource type schemas                     |
| `list_rules()`            | All schema rule definitions                                |

## Rules

Each constraint maps to a specific rule ID:

| Rule ID | Description                                                                 |
|---------|-----------------------------------------------------------------------------|
| `E3710` | Resource type is from a service that has been shut down                     |
| `W3696` | Resource type is from a service that is sunsetting                          |
| `W3697` | Resource type is from a service in maintenance mode                         |
| `E2533` | Lambda runtime has reached end-of-life                                      |
| `W2531` | Lambda runtime is deprecated                                                |
| `E9001` | Resource type is not available in the configured region                     |
| `F3002` | Unexpected property (with typo suggestion)                                  |
| `F3003` | Required property missing or null                                           |
| `F3012` | Property value does not match expected type                                 |
| `W9003` | Value auto-coerced to expected type (string↔number, bool→string)            |
| `F3014` | Exactly one of a set of properties must be specified                        |
| `F3017` | Value does not satisfy any sub-schema                                       |
| `F3018` | Value satisfies zero or more than one sub-schema                            |
| `F3020` | Mutually exclusive properties both present                                  |
| `F3021` | Dependent property missing                                                  |
| `F3030` | Value not in allowed set                                                    |
| `F3031` | String does not match regex pattern                                         |
| `F3032` | Array item count out of bounds                                              |
| `F3033` | String length out of bounds                                                 |
| `F3034` | Numeric value out of bounds                                                 |
| `F3037` | Array contains duplicate items                                              |
| `F3040` | Read-only property should not be specified                                  |
| `F3041` | Write-only property referenced in an Output via GetAtt                      |
| `F3058` | At least one of a set of properties must be present                         |
| `W9009` | Deprecated property is specified                                            |
| `E1103` | Value does not match format (VPC ID, Subnet ID, AMI ID, IAM Role ARN, etc.) |
| `I9001` | Create-only property — updating causes resource replacement                 |
| `I9002` | Property is ignored in this configuration                                   |
| `E3030` | Value violates a constraint derived from a referenced resource              |
| `E9006` | Value not in allowed set defined by a conditional extension                 |

Validation is condition-aware — property values are checked across all condition scenarios, and diagnostics include
the condition truth values that trigger each violation. Region-specific enum values (e.g., instance types) produce
region-aware error messages.
