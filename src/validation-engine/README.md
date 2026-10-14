# validation-engine

Defines the `ValidationEngine` trait and orchestrates the full validation pipeline: schema validation → engine rule
evaluation → Step Functions and Metadata Context validation → diagnostic enrichment → filtering → report assembly. The
pipeline is engine-agnostic: any engine ([rego-engine](../rego-engine/README.md),
[cel-engine](../cel-engine/README.md), [composite-engine](../composite-engine/README.md)) implements the trait and
plugs into this pipeline.

See [API.md](API.md) for usage examples and public API reference.

## How It Works

```
  bytes ──▶ SemanticModel ──▶ validate()
                                 │
                                 ├── SchemaValidator (Fatal + schema-derived Error/Warn/Info)
                                 ├── engine.evaluate_rules() (built-in + custom rules)
                                 ├── step_functions::validate_all_state_machines()
                                 ├── context_check::check_context()
                                 └── model diagnostics
                                 │
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

1. **Schema validation** - Fatal structural diagnostics plus schema-derived Error/Warn/Info findings.
2. **Engine rule evaluation** - Built-in and custom rule diagnostics.
3. **Step Functions validation** - Validates `AWS::StepFunctions::StateMachine` definitions (rule `E3601`): StartAt
   references, state types, required fields, JSONata mode restrictions, recursive into Parallel/Map.
4. **Metadata Context validation** - Validates `com.aws.cloudformation.Context` blocks and reports missing context.
5. **Model diagnostics** - Parse-time diagnostics (duplicate keys, cycles, structure errors).
6. **Enrichment** - Backfills locations and entities at every detail level. At `Detailed`, also adds phase, rule
   description, resolved property values, and schema constraints as context.
7. **Finalization** - Applies strict mode (Warn→Error), include/exclude filters, and severity gating; then sorts by
   severity, rule number/ID, and source location before deduplicating.
8. **Report assembly** - Severity counts, metadata, per-phase performance metrics.

**Parse error handling**: When `validate_bytes_with_path` encounters a parse failure, it creates a synthetic `F1101`
diagnostic and returns a `ValidationReport` with `status=Error` rather than returning `Err`.
