# CloudFormation Validate

Standalone, embeddable Rust library and CLI that validates CloudFormation templates at author-time. Operates offline-first — all rules and schemas compile into the binary. Accepts a template as input, returns structured diagnostics as output.

## Architecture

```
                              ┌──────────────┐
                              │ cfn-validate  │
                              │ CLI + library │
                              └──────┬───────┘
                                     │
          ┌──────────────────────────┼──────────────────────────┐
          ▼                          ▼                          ▼
   ┌──────────────┐          ┌──────────────┐          ┌──────────────┐
   │ rego-engine   │          │  cel-engine   │          │   schema-    │
   │ Regorus +     │          │  native Rust  │          │   validator  │
   │ handwritten   │          │  + CEL        │          │  compiled    │
   └──────┬───────┘          └──────┬───────┘          │  JSON Schema │
          │                         │                   └──────┬───────┘
          └────────────┬────────────┘                          │
                       ▼                                       │
              ┌──────────────────┐                             │
              │validation-engine │◀────────────────────────────┘
              │ trait +          │
              │ orchestration    │
              └───────┬─────────┘
                      │
         ┌────────────┼────────────┐
         ▼            ▼            ▼
  ┌──────────────┐ ┌──────────┐ ┌──────────────┐
  │template-model│ │  guard-  │ │ diagnostics  │
  │ parser +     │ │translator│ │ shared types │
  │ resolver     │ │Guard→IR  │ └──────────────┘
  └──────────────┘ └──────────┘

  ┌──────────────┐          build-time codegen
  │ data-source  │ ·····▶ rego-engine, cel-engine,
  │ build-time   │         schema-validator, guard-translator
  │ pipeline     │
  └──────────────┘

  ┌──────────────┐  ┌──────────────┐
  │bindings-wasm │  │ bindings-jvm │    embedding layers
  │ Node/browser │  │ Kotlin/Java  │
  └──────────────┘  └──────────────┘
```

## Validation Pipeline

When a template is submitted for validation, the engine executes these steps:

1. **Parse** — [template-model](src/template-model/README.md) parses JSON/YAML bytes into an arena-based IR, resolves all intrinsic functions, builds a reference graph with cycle detection, and constructs a condition model with SAT solver. Produces a `SemanticModel`.

2. **Schema Validate** — [schema-validator](src/schema-validator/README.md) checks each resource against precompiled CloudFormation provider schemas. Produces Fatal-severity diagnostics for structural violations (type mismatches, missing required properties, invalid enums, pattern failures, constraint violations).

3. **Engine Evaluate** — The selected engine ([rego-engine](src/rego-engine/README.md) or [cel-engine](src/cel-engine/README.md)) evaluates lint rules against the `SemanticModel`. Produces Error/Warn/Info diagnostics for semantic issues (cross-resource references, best practices, security, resource-specific constraints).

4. **Step Functions Validate** — [validation-engine](src/validation-engine/README.md) validates `AWS::StepFunctions::StateMachine` definitions (state types, StartAt/Next references, required fields).

5. **Enrich** — Adds rule descriptions, section labels, phase tags, and context maps (actual values, schema constraints, resolution sources) to each diagnostic.

6. **Filter** — Applies include/exclude filters, severity gating, sorts by source location, deduplicates.

7. **Report** — Assembles a `ValidationReport` with diagnostics, summary counts, metadata, and optional performance metrics. Serializes to JSON in standard or detailed format.

## Modules

| Crate | Role |
|-------|------|
| [cfn-validate](src/cfn-validate/README.md) | CLI binary, benchmark binary, library facade |
| [validation-engine](src/validation-engine/README.md) | `ValidationEngine` trait, orchestration pipeline, Step Functions validation |
| [template-model](src/template-model/README.md) | Template parser, intrinsic function resolver, condition SAT solver, reference graph |
| [rules](src/rules/README.md) | Rule registry, severity model, category/phase constants, output format, filtering |
| [diagnostics](src/diagnostics/README.md) | Shared types: Diagnostic, SourceSpan, ValidationReport, performance metrics |
| [schema-validator](src/schema-validator/README.md) | Compiled JSON Schema validation against CloudFormation provider schemas |
| [rego-engine](src/rego-engine/README.md) | Rego-based rule evaluation via Regorus with hand-written policies and custom builtins |
| [cel-engine](src/cel-engine/README.md) | Native Rust rules + CEL interpreter for custom rules |
| [data-source](src/data-source/README.md) | Build-time pipeline: downloads schemas, syncs cfn-lint data, generates metadata |
| [guard-translator](src/guard-translator/README.md) | Parses Guard DSL into engine-agnostic IR, resolves rule packs |
| [bindings-wasm](src/bindings-wasm/) | WASM bindings (wasm-bindgen) for Node.js embedding |
| [bindings-jvm](src/bindings-jvm/) | JVM bindings (UniFFI) for Kotlin/Java embedding |

## Severity

| Severity | Prefix | Source | Meaning |
|----------|--------|--------|---------|
| Fatal | F | schema-validator | Structural schema violation — deployment will fail |
| Error | E | engine rules | Semantic error — likely deployment failure or incorrect behavior |
| Warn | W | engine rules | Security concern, deprecation, or risky pattern |
| Info | I | engine rules | Best practice suggestion |
| Debug | D | engine rules | Internal diagnostic detail |

## Quick Start

```bash
# Validate a template
cargo run -p cfn-validate -- template.yaml

# Validate with CEL engine
cargo run -p cfn-validate -- template.yaml --engine cel

# List all rules
cargo run -p cfn-validate -- --list-rules

# Validate with custom Guard rules
cargo run -p cfn-validate -- template.yaml --guard-rule-source ./my-rules/

# Detailed output
cargo run -p cfn-validate -- template.yaml --format detailed
```
