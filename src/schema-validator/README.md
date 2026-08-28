# schema-validator

Validates CloudFormation resources against precompiled JSON Schema definitions derived from AWS resource provider
schemas. Produces diagnostics for structural violations - type mismatches, missing required properties,
invalid enum values, pattern failures, constraint violations, lifecycle issues, and cross-resource constraints.

## API

| Method                    | Purpose                                                    |
|---------------------------|------------------------------------------------------------|
| `SchemaValidator::new(config)` | Create a validator from a `SchemaValidatorConfig`; applies overlays if configured. Returns `Result<Self, SchemaValidatorConfigError>` |
| `SchemaValidator::default()` | Infallible constructor with no overlays (bundled schemas only) |
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

Key semantics:

- **Composition support:** `allOf`, `anyOf`, `oneOf`, and conditional `if`/`then`/`else` in `allOf` entries are fully
  represented. Composition branches may state any representable constraint (required, properties, type, enum, numeric
  bounds, lengths, etc.). `multipleOf` and `dependencies` (array-form property dependencies) are also supported.
- **`$ref` siblings:** Constraint siblings beside a `$ref` are accepted when they have a compiled representation.
  They are merged at validation time via `PropSchema::resolve`, keeping the reference live.
- **Authoritative `required` replacement:** An overlay that explicitly states `required` (even as `[]`) replaces the
  prior required list at that schema level; every requirement a replacement removes is logged. Omitting `required`
  preserves the base unchanged.
- **Catalog/config separation:** The overlay catalog exposes overlay-aware metadata (type names, GetAtt/Ref types,
  primary identifiers) without re-merging. `SchemaValidatorConfig` can be serialized/deserialized to rebuild.
- **Metadata alone is not sufficient:** `description`, `documentationUrl`, `sourceUrl`, and `replacementStrategy`
  alone are rejected - the overlay must carry at least one validatable constraint.

The merge model, its scope limits, and the input the module rejects are documented on the `overlay` module
(`cargo doc -p cloudformation-validate-schema-validator`). Library and binding callers construct a `SchemaValidator` via
`SchemaValidator::new(SchemaValidatorConfig { additional_schemas: ... })`. The optional
`EngineConfig::schema_validator_config` field holds the same config type, so the engine derives overlay-aware metadata
automatically when constructed standalone.
See [validation-engine/API.md](../validation-engine/API.md).

`CompiledSchemaStore::apply_overlay` is the lower-level entry point. It validates its own input and reports whether the
overlay merged into a bundled schema or registered a new type; a rejected overlay leaves the store unchanged.
