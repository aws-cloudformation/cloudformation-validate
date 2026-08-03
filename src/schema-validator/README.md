# schema-validator

Validates CloudFormation resources against precompiled JSON Schema definitions derived from AWS resource provider
schemas. Produces diagnostics for structural violations — type mismatches, missing required properties,
invalid enum values, pattern failures, constraint violations, lifecycle issues, and cross-resource constraints.

## API

| Method                    | Purpose                                                    |
|---------------------------|------------------------------------------------------------|
| `SchemaValidator::new()`  | Create a new validator with all schemas loaded             |
| `SchemaValidator::try_with_additional_schemas(pairs)` | Create a validator with caller-supplied overlay schemas merged on top of the bundled ones; fails on malformed input |
| `validate(model, region)` | Run all schema checks, returns diagnostics + timing metric |
| `schema_count()`          | Number of loaded resource type schemas                     |
| `list_rules()`            | All schema rule definitions                                |
| `init_metric()`           | Timing metric for one-time schema initialization           |
| `enrich_context(diagnostics, model)` | Attach resolved schema context to existing diagnostics |

## Additional (overlay) schemas

`try_with_additional_schemas` takes `(type_name, schema)` pairs, where `schema` is a CloudFormation resource provider
schema in registry format. Each one is compiled with the same transform the build pipeline uses for bundled schemas and
merged into the schema for its type; a type name with no bundled schema is registered as a new resource type.

The merge model, its scope limits, and the input the module rejects are documented on the `overlay` module
(`cargo doc -p schema-validator`). Library and binding callers should go through
`validation_engine::schema_validator_from_config`, while each engine constructor derives the same final merged catalog
for known types, GetAtt/Ref types, primary identifiers, and schema metadata — see
[validation-engine/API.md](../validation-engine/API.md).

`CompiledSchemaStore::apply_overlay` is the lower-level entry point. It validates its own input and reports whether the
overlay merged into a bundled schema or registered a new type; a rejected overlay leaves the store unchanged.
