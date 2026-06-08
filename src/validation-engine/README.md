# validation-engine

Defines the `ValidationEngine` trait and orchestrates the full validation pipeline: schema validation → engine rule
evaluation → Step Functions validation → diagnostic enrichment → filtering → report assembly. Engine-agnostic — any
engine ([rego-engine](../rego-engine/README.md), [cel-engine](../cel-engine/README.md)) implements the trait and plugs
into this pipeline.

See [API.md](API.md) for usage examples and public API reference.

## How It Works

```
  bytes ──▶ SemanticModel ──▶ validate()
                                 │
                    ┌────────────┼────────────────────────┐
                    ▼            ▼                        ▼
             SchemaValidator  engine.evaluate_rules()  step_functions
             (Fatal schema    (Error/Warn/Info         ::validate_all
              violations)      lint rules)              _state_machines()
                    │            │                        │
                    └────────────┼────────────────────────┘
                                 ▼
                    merge + enrich + filter + report
                                 │
                                 ▼
                         ValidationReport
```

## ValidationEngine Trait

```rust
pub trait ValidationEngine {
    fn engine_name(&self) -> &str;
    fn evaluate_rules(&self, model: &Arc<SemanticModel>, config: &ValidateConfig)
                      -> Result<Vec<Diagnostic>, ValidationError>;
    fn list_rules(&self) -> Vec<RuleInfo>;
    fn rule_metadata(&self) -> &HashMap<String, RuleMetadataEntry>;
    fn external_rule_metadata(&self) -> HashMap<String, RuleMetadataEntry>;
    fn init_metric(&self) -> &PhaseMetric;
}
```

Engines implement `evaluate_rules` to run their rule evaluation logic against
the [SemanticModel](../template-model/README.md). The orchestration pipeline handles everything else.

## Pipeline

1. **Schema validation** — Fatal-severity diagnostics for structural violations.
2. **Engine rule evaluation** — Error/Warning/Info diagnostics from lint rules.
3. **Step Functions validation** — Validates `AWS::StepFunctions::StateMachine` definitions (rule `E3601`): StartAt
   references, state types, required fields, JSONata mode restrictions, recursive into Parallel/Map.
4. **Model diagnostics** — Parse-time diagnostics (duplicate keys, cycles, structure errors).
5. **Enrichment** — Adds section, phase, rule description. For `Detailed` level, attaches resolved property values
   and schema constraints as context.
6. **Finalization** — Applies include/exclude filters, severity gating, strict mode (Warn→Error), sorts by source
   location, deduplicates.
7. **Report assembly** — Severity counts, metadata, per-phase performance metrics.

**Parse error handling**: When `validate_bytes_with_path` encounters a parse failure, it creates a synthetic `F1101`
diagnostic and returns a `ValidationReport` with `status=Error` rather than returning `Err`.
