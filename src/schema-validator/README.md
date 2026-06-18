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

Every rule ID the validator can emit, with descriptions mirrored verbatim from the rule registry (the single source of
truth surfaced by `--list-rules`):

| Rule ID | Description                                                |
|---------|------------------------------------------------------------|
| `E3710` | Resource type is from a service that has been shut down    |
| `W3696` | Resource type is from a service that is sunsetting         |
| `W3697` | Resource type is from a service in maintenance mode        |
| `W9009` | Resource type sunset or shutdown                           |
| `E2531` | Check if Lambda Function Runtimes are blocked for create   |
| `E2533` | Check if Lambda Function Runtimes are updatable            |
| `W2531` | Check if EOL Lambda Function Runtimes are used             |
| `E9001` | Resource type must be recognized                           |
| `E9006` | Property value not valid for conditional extension enum    |
| `F3002` | Additional properties are not allowed                      |
| `F3003` | Required property missing                                  |
| `F3012` | Property type mismatch                                     |
| `W9003` | Property type coercion warning                             |
| `F3014` | Exactly one of properties required (requiredXor)           |
| `F3058` | One of properties required (requiredOr)                    |
| `F3017` | Value not valid under anyOf                                |
| `F3018` | Value not valid under oneOf                                |
| `F3020` | Mutually exclusive properties                              |
| `F3021` | Dependent property required                                |
| `F3030` | Value not in allowed enum                                  |
| `F3031` | Value does not match pattern                               |
| `F3032` | Array item count out of bounds                             |
| `F3033` | String length out of bounds                                |
| `F3034` | Numeric value out of bounds                                |
| `F3037` | Array items not unique                                     |
| `E3030` | Check if properties have a valid value                     |
| `E3040` | Read only property should not be specified                 |
| `W9054` | Write-only property referenced in output                   |
| `E1103` | Validate the format of a value                             |
| `I9001` | Create-only property updated triggers resource replacement |
| `I9002` | Property is ignored in this configuration (from extension) |

Validation is condition-aware — property values are checked across all condition scenarios, and diagnostics include
the condition truth values that trigger each violation. Region-specific enum values (e.g., instance types) produce
region-aware error messages.
