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
