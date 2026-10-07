# composite-engine

Validates CloudFormation templates by composing two engines: one owns the built-in rules and the other evaluates the
caller-supplied Rego rules. Implements the [ValidationEngine](../validation-engine/README.md) trait, so it is a
drop-in engine for the shared validation pipeline.

## Architecture

```
  CompositeEngine::evaluate_rules(model, config)
       │
       ├── Built-in engine (CEL): all built-in rules + custom CEL rules + Guard rules
       └── External engine (Rego, external-only): custom Rego rules
       │
       ▼
  Vec<Diagnostic>   (concatenated; the pipeline finalizes once)
```

- **Built-in engine** - a [cel-engine](../cel-engine/README.md) constructed with the built-in rules it owns plus any
  custom CEL rules and Guard rules from the configuration. It always runs, and honors `disable_builtin_rules` (which
  suppresses the built-in rules only, not custom or Guard rules). Guard rules are evaluated by the shared Guard
  evaluator in [validation-engine](../validation-engine/README.md), which every engine calls, so hosting them here
  costs nothing and changes nothing.
- **External engine** - a [rego-engine](../rego-engine/README.md) constructed in external-only mode: it neither loads
  nor advertises the built-in policies, so it contributes only custom Rego findings. It retains every documented Rego
  custom builtin and embedded data table; only the product's handwritten built-in policy packages are omitted. It is
  constructed only when the configuration supplies Rego rules, and it runs even when built-ins are disabled.

The two engines produce disjoint findings - built-ins, custom CEL, and Guard from one, custom Rego from the other -
so `evaluate_rules` concatenates them without deduplication. The surrounding pipeline performs the single finalize pass
(dedup, sort, filter, enrich).

## Configuration

Constructed from a
[`CompositeEngineConfig`](../validation-engine/src/engine.rs), which carries the external rules layered on top of the
built-ins plus the shared schema configuration:

- `rego_rules` - custom Rego rules for the external engine.
- `cel_rules` - custom CEL rules, evaluated by the built-in CEL engine.
- `guard_rules` - Guard DSL rules, evaluated by the built-in CEL engine through the shared Guard evaluator.
- `schema_validator_config` - optional additional schemas, observed by both engines.

There is no field for engine-native built-in custom rules, because the composite fixes which engine owns the built-ins.

```rust
use composite_engine::CompositeEngine;
use validation_engine::{CompositeEngineConfig, ExternalRuleSource};

let config = CompositeEngineConfig::new()
    .with_cel_rules([ExternalRuleSource { name: "rules.json".into(), content: cel_source }])
    .with_rego_rules([ExternalRuleSource { name: "rules.rego".into(), content: rego_source }])
    .with_guard_rules([ExternalRuleSource { name: "rules.guard".into(), content: guard_source }]);
let engine = CompositeEngine::new(config)?;
```
