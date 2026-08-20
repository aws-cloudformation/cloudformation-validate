# Project Structure

## Workspace layout

```
src/
├── Cargo.toml                  # Workspace root
├── rust-toolchain.toml         # Pinned toolchain + wasm32 target
├── cfn-validate/               # CLI binary (`cfn-validate`) and library facade
├── validation-engine/          # ValidationEngine trait, orchestration pipeline, Step Functions validation
├── template-model/             # LEAF crate — parser (JSON/YAML), SemanticModel, intrinsic resolver,
│                               # condition SAT solver, reference graph, SAM transform, nesting, template
│                               # vocabulary (TopLevelSection/EntityType, SourceSpan, JsonValue), ParseDefect
│                               # parse findings; `inspect` example
├── diagnostics/                # Shared reporting types: Diagnostic, ValidationReport, metrics,
│                               # ParseDefect→Diagnostic conversion (depends on rules + template-model)
├── rules/                      # Rule registry (single source of truth for rule IDs, metadata,
│                               # severity, category, descriptions), filter, category/severity enums
│                               # (depends on template-model)
├── schema-validator/           # Compiled JSON Schema validation against provider schemas
├── rego-engine/                # Rego evaluation via Regorus + custom builtins + Guard→Rego translation
│   └── handwritten/rego/       # Hand-written Rego policies (structure, intrinsics, references,
│                               # resources, best_practices)
├── cel-engine/                 # Native Rust rules + CEL interpreter + Guard→CEL translation
│   └── src/rules/              # Native rules: structure, intrinsics, references, conditions,
│                               # resources, resources_extra, best_practices, patterns
├── data-source/                # BUILD-TIME — downloads schemas, syncs cfn-lint data, generates
│   ├── src/                    # schema-validator artifacts and CEL rules; build.rs embeds them and
│   │                           # the hand-written Rego policies into the binary (zstd)
│   ├── generated/              # Generated artifacts (committed, NEVER edit manually)
│   ├── handwritten/            # Hand-maintained JSON reference tables (deprecated resource types,
│   │                           # sensitive ports, GetAtt return-type overrides, schema-dependent
│   │                           # exclusion overrides)
│   └── upstream/               # Upstream schema sources (provider schemas, extensions)
├── guard-translator/           # Guard DSL → engine-agnostic IR
├── bindings-wasm/              # WASM bindings (wasm-bindgen) for Node.js embedding
│   ├── ts/                     # TypeScript wrapper + type definitions
│   ├── tests/                  # Node test suite (vitest, run.sh)
│   └── examples/               # Usage examples
├── bindings-jvm/               # JVM bindings (UniFFI) for Kotlin/Java embedding
│   ├── generated/              # Built jar (cloudformation-validate.jar)
│   ├── tests/                  # Kotlin test suite (run.sh)
│   └── examples/               # Usage examples
├── bindings-python/            # Python bindings (UniFFI) — wheel with per-platform natives
│   ├── python/                 # Hand-maintained public API (wrappers, re-exports, native dispatch)
│   ├── generated/              # Build output: assembled package + dist/*.whl (only the wheel is committed)
│   └── tests/                  # Python test suite (run.sh)
├── bindings-go/                # Go bindings (UniFFI via uniffi-bindgen-go) — JSON-over-FFI, cgo static linking
│   ├── go/                     # The published Go module: hand-maintained API + types, generated
│   │                           # internal/bindings_go, and per-platform libs/ static libraries (committed)
│   ├── tests/                  # Go test harness module (smoke, snapshot, config, security tests; run.sh)
│   ├── bench/                  # Go benchmark harness module (main.go — corpus/report benchmark)
│   └── native/                 # Hand-maintained cgo link directives copied into the generated package
└── resources/                  # Test-fixture CRATE (workspace member)
    ├── src/                    # Corpus discovery API (templates_dir, load_merged_snapshots, discover_snapshot_chunks, …)
    ├── examples/               # generate_validation_reports.rs — snapshot regeneration
    ├── templates/              # Test corpus
    │   ├── good/               # Valid templates — expect zero diagnostics
    │   ├── bad/                # Invalid templates — named after the rule/behavior they test
    │   ├── gh-issues/          # GitHub issue reproductions
    │   ├── issues/             # Bug reproductions
    │   ├── integration/        # Integration test templates
    │   ├── lsp/                # LSP-specific test templates
    │   ├── quickstart/         # AWS QuickStart templates (performance corpus)
    │   ├── public/             # Public example templates
    │   └── cdk/                # CDK-synthesized templates
    ├── expected/               # validation_reports*.json — numbered snapshot chunks (both engines must agree)
    ├── rules/                  # Custom rule fixtures for testing (Rego, CEL, Guard)
    └── security/               # Security/stress fixtures (pathological conditions, deep nesting)
```

## Top-level directories

- `.kiro/steering/` — tracked persistent guidance loaded by Kiro; `private-context.md` directs agents to load local
  confidential context and skills before starting work
- `.kiro/private/` — gitignored machine-local confidential agent context and skills for Kiro and Claude; never commit
  its filenames or contents
- `scripts/` — Python comparison/audit scripts and their `snapshots/` data (see `tech.md` for usage)
- `.github/workflows/` — CI: format check, clippy, cargo audit, coverage tests on all supported OSes, JVM + WASM +
  Python + Go test jobs
- `release-bin/` — prebuilt per-platform `cfn-validate` CLI binaries (committed); written by `cfn-validate/build.sh`
  and read by the release workflow
- `tmp/` — scratch files, debug output, tool artifacts (gitignored)

## Conventions — follow these exactly

### Naming

- Crate names use hyphens: `template-model`. Rust module names use underscores: `template_model`.
- Rule IDs match `[FEWID]\d{4}`. F = Fatal, E = Error, W = Warn, I = Info, D = Debug.
- A number cfn-lint uses is never reused for a different check; engine-assigned rules (aliases and engine-extra) use
  the 9xxx range. See `product.md` for the full origin taxonomy and numbering rules.
- Test templates in `templates/bad/` are named after the rule or behavior they test (e.g.
  `E3012_invalid_ref_target.yaml`).

### Where code must live

- **Generated code lives in `data-source/generated/`.** Never edit by hand. Regenerate by changing inputs in
  `data-source/handwritten/` or the upstream sync and rebuilding.
- **Hand-maintained reference data tables live in `data-source/handwritten/`.** These are JSON lookup files
  (deprecated resource types, sensitive ports, GetAtt return-type overrides, schema-dependent exclusion overrides)
  consumed by rules at runtime. Add a new entry here only when a rule needs a reusable data table — rules themselves
  go in `rego-engine/handwritten/rego/` or `cel-engine/src/rules/`.
- **Hand-written Rego policies live in `rego-engine/handwritten/rego/`.** These are hand-authored Rego rules organized
  by category (structure, intrinsics, references, resources, best_practices). They are embedded into the binary by
  `data-source/build.rs`.
- **All rules must be registered in the `rules` crate registry (`rules/src/registry.rs`).** A rule that evaluates but
  is not registered is a bug — the registry is the single source of truth for IDs, severity, category, and description.
- **Native Rust rules live under `cel-engine/src/rules/`.** Choose the appropriate module (structure, intrinsics,
  references, conditions, resources, resources_extra, best_practices). The CEL interpreter itself is only for
  user-supplied custom rules.
- **Test templates live in `resources/templates/`.** Repros go in `bad/` (or `gh-issues/` for GitHub issues),
  counter-examples in `good/`.

### Engine parity

- Every rule exists in both `rego-engine` and `cel-engine`, or in neither. No exceptions.
- The same template must produce the same diagnostics (rule ID, severity, location, message) through both engines.
  Divergence is a bug.
- Parity is achieved by making both engines correct, not by making one copy the other's output. For every mismatch,
  derive the expected behavior first from CloudFormation schemas, documentation, specifications, and semantics; then
  fix the incorrect engine or the shared layer where the defect originates.
- Never regress an engine that already has the correct behavior, and never remove or suppress a valid finding solely
  because the other engine misses it. A finding may be removed only when first-principles evidence proves that it is a
  false positive, with focused regression coverage for the corrected behavior.

### Diagnostics

- Every diagnostic carries a rule ID from the registry, a severity, a precise source span (start_line, start_column,
  end_line, end_column), and a resource path (logical ID + JSON path) when applicable.
- Diagnostics are structured data for programmatic consumption, not pretty-printed text. Human-readable formatting
  happens at render time in `cfn-validate`.

### Errors

- No silent failures. If resolution, parsing, or evaluation hits an unexpected state, return an `Err` following the
  existing `Result` conventions. Never default to a plausible-looking value to keep things going. Error diagnostics
  are reserved for problems in the template under validation — a parse error is the only failure that surfaces as a
  diagnostic instead of an `Err`.
- **No panics, no hard crashes.** Errors are propagated as `Result`s through the language boundary layers and surface
  to embedders as catchable errors (Kotlin/Java `ValidationError` exceptions and Python `ValidationError` via UniFFI,
  returned Go `error` values, thrown JS errors via wasm-bindgen) — never a process abort. Every fallible FFI entry
  point in `bindings-jvm`, `bindings-python`, `bindings-go`, and `bindings-wasm` is wrapped in
  `validation_engine::catch_panics` with a panic-to-error mapper as a last-resort backstop; new entry points must
  follow the same pattern.
- `unwrap()`/`expect()`/`panic!` are not error handling — on any reachable failure path, return an `Err` instead.
