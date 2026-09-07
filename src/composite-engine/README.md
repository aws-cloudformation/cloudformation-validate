# composite-engine

Validates CloudFormation templates by composing two engines: one owns the built-in rules and the other evaluates the
caller-supplied external rules. Implements the [ValidationEngine](../validation-engine/README.md) trait, so it is a
drop-in engine for the shared validation pipeline.

## Architecture

```
  CompositeEngine::evaluate_rules(model, config)
       │
       ├── Built-in engine (CEL): all built-in rules
       └── External engine (Rego, external-only): custom Rego + translated Guard rules
       │
       ▼
  Vec<Diagnostic>   (concatenated; the pipeline finalizes once)
```

- **Built-in engine** - a [cel-engine](../cel-engine/README.md) constructed with no external rules, so it evaluates
  only the built-in rules it owns. It always runs, and honors `disable_builtin_rules`.
- **External engine** - a [rego-engine](../rego-engine/README.md) constructed in external-only mode: it neither loads
  nor advertises the built-in policies, so it contributes only custom Rego and translated Guard findings. It retains
  every documented Rego custom builtin and embedded data table; only the product's handwritten built-in policy packages
  are omitted. It is constructed only when the configuration supplies external rules, and it runs even when built-ins
  are disabled.

The two engines produce disjoint findings - built-ins from one, externals from the other - so `evaluate_rules`
concatenates them without deduplication. The surrounding pipeline performs the single finalize pass (dedup, sort,
filter, enrich).

## Configuration

Constructed from a
[`CompositeEngineConfig`](../validation-engine/src/engine.rs), which carries the external rules layered on top of the
built-ins plus the shared schema configuration:

- `rego_rules` - custom Rego rules for the external engine.
- `guard_rules` - Guard DSL rules, translated and evaluated by the external engine.
- `schema_validator_config` - optional additional schemas, observed by both engines.

There is no field for engine-native built-in custom rules, because the composite fixes which engine owns the built-ins.

```rust
use composite_engine::CompositeEngine;
use validation_engine::{CompositeEngineConfig, ExternalRuleSource};

let config = CompositeEngineConfig::new()
    .with_guard_rules([ExternalRuleSource { name: "rules.guard".into(), content: guard_source }]);
let engine = CompositeEngine::new(config)?;
```
