# Technology Stack and Development Rules

## Language and toolchain

- Rust (edition 2024, resolver v2), Cargo workspace with 13 crates under `src/`
- Toolchain pinned by `src/rust-toolchain.toml` (includes `rustfmt`, `clippy`, and the `wasm32-unknown-unknown` target)
- `unsafe_code` is **forbidden** workspace-wide; clippy `correctness`/`suspicious`/`style`/`complexity`/`perf` are deny
- Release profile: LTO fat, codegen-units 1, opt-level 3, debuginfo stripped
- Key deps: `regorus` (Rego), CEL interpreter (custom rules), `serde`/`serde_json`/`yaml-rust2`, `log`/`env_logger`

## Build-time code generation

The `data-source` crate downloads CloudFormation provider schemas, syncs cfn-lint data, applies patches/extensions, and
generates schema-validator artifacts and (data-driven) CEL rules. Rego policies are hand-written in
`rego-engine/handwritten/rego/`. `data-source/build.rs` compresses every generated and hand-written artifact (zstd) and
exposes them as lazy byte constants via the `data-source::embedded` API. `rego-engine`, `cel-engine`, `schema-validator`,
and `guard-translator` consume those constants at runtime — none of them have their own `build.rs`. Everything compiles
into the binary — no runtime fetching.

`data-source/generated/` is committed generated code — **never hand-edit it, and never run the regeneration
pipeline yourself**. Regeneration is a maintainer-run operation; if a change requires regenerating these artifacts,
stop and ask the user to run it.

## Cargo usage rules

All `cargo` commands run from `src/` (the workspace root is the repo root; the Cargo workspace lives in `src/`).

```bash
cd src

# Build
cargo build                                   # whole workspace (debug)
cargo build -p cfn-validate                   # CLI -> target/debug/cfn-validate (add --release for optimized)

# Test — full workspace tests are EXPENSIVE: run targeted tests while iterating, and the full suite ONCE at the
# end of the task. Tee the output; never re-run to grab different output, never filter through head/tail/grep.
cargo test -p cel-engine <name>               # single crate / filtered test — preferred while iterating
cargo test --workspace 2>&1 | tee ../tmp/test-output.txt   # full suite — once, at task completion
# CI runs coverage, not plain test: cargo llvm-cov --locked --release --workspace --no-fail-fast

# Format + lint — run BOTH after every code change; CI gates on both; must pass clean
cargo fmt --all
cargo clippy --locked --all-targets --workspace -- -D warnings
```

Regenerate the golden file (`resources/expected/all_templates.json`) after any change that alters diagnostics:

```bash
cargo run --release -p resources --example generate_golden
```

It runs both engines on the whole corpus in parallel, verifies they agree, and rewrites the golden file.

## Reference projects — correctness baselines

Check these before implementing or fixing rules. If our output differs from the applicable reference, we are wrong.

- **cfn-lint** (E/W/I rules): `cfn-lint <template>` — cfn-lint-sourced rules must match on firing and location
  (messages may be more descriptive — see `product.md`).
- **cloudformation-guard** (Guard DSL): `cfn-guard validate -d <template> -r <rules.guard>` — `guard-translator`
  output must match Guard's evaluation.

Fatal rules are validated against the compiled CloudFormation resource schemas — they must reflect what
CloudFormation itself rejects, not the behavior of any external linter.

## Debugging and analysis tools

Use these, not `println!` or ad-hoc logging.

### inspect — use this first

`cargo run -p template-model --example inspect -- <template>` — dumps the full SemanticModel. Always start here when
debugging. If the model is wrong, fix `template-model`.

### cfn-validate

```bash
cargo run -p cfn-validate -- <template|dir> --engine rego|cel --format standard|detailed --level fatal|error|warn|info|debug
cargo run -p cfn-validate -- --list-rules
```

Always run with both engines to verify parity.

### Python scripts in `scripts/`

- `compare_cfnlint.py` — compares cfn-validate output against cfn-lint for accuracy verification. Requires a local
  cfn-lint checkout: `CFN_LINT_ROOT=<path> python3 scripts/compare_cfnlint.py --engine rego|cel`. First check whether
  cfn-lint is available on the machine (`cfn-lint --version`), then ask the user for the checkout path — never assume
  or hardcode one.
- `audit_rule_categorization.py` — audits rule registry for categorization consistency
- `generate_licenses.py` — generates third-party license files

### Debugging approach

If deeper investigation is needed, write a small standalone script or Rust example that isolates the behavior.
All temporary files, debug scripts, scratch artifacts, and tool output go in `./tmp/` at the project root. Never
scatter debug artifacts across the source tree.

### Code navigation — use LSP

Use the `code` tool's LSP operations (`goto_definition`, `find_references`, `get_hover`, `search_symbols`) to search,
navigate, refactor, and understand the codebase. LSP gives precise, compiler-aware results — prefer it over text-based
grep/search for anything involving symbols, types, call sites, or trait implementations.

## Fix priority order

Apply fixes at the highest-leverage layer, in this order:

1. `template-model` first — benefits every downstream engine and schema validator simultaneously.
2. `data-source` pipeline enrichment — both engines inherit the fix automatically.
3. Only if neither applies — `schema-validator`, `rego-engine`, or `cel-engine`. The fix MUST be applied to both engines
   in the same change. Parity is non-negotiable.

## Mandatory validation procedure

A fix is not done until all of the following pass. No shortcuts.

1. Identify or create a test template in `src/resources/templates/`. Repro in `templates/bad/`, counter-example in
   `templates/good/` if false-positive risk exists.
2. Check the SemanticModel with `inspect`. If the model is wrong, fix template-model first.
3. Run against the applicable reference (cfn-lint for E/W/I, cloudformation-guard for Guard). Confirm match. Fatal
   rules are validated against the compiled CloudFormation resource schemas — confirm the diagnostic reflects what
   the schema actually requires.
4. Run `cfn-validate` with both `--engine rego` and `--engine cel` on the repro template. Outputs must be identical on
   rule ID, severity, location, and message.
5. Run the full test corpus with both engines. Zero new false positives on `templates/good/`. Regenerate the golden
   file if diagnostics legitimately changed.
6. Run `cargo test --workspace` (the full suite — once, at the end of the task; use targeted `cargo test -p <crate>`
   while iterating). All tests pass.
7. Run `cargo fmt --all` and `cargo clippy --locked --all-targets --workspace -- -D warnings`. Both clean.

## Code quality — mandatory for every code change

Follow the `cloudformation-validate-development` skill (`.kiro/skills/cloudformation-validate-development/`): its
`references/source-code-rules.md` applies to all source code and `references/test-code-rules.md` applies to all test
code. Before writing any code, read sibling files in the same directory to learn existing patterns, naming, error
handling, and style — then match them.

Project-specific rules on top of the skill:

- Never put rule IDs (e.g. `E3012`, `W2001`) in code comments — rule IDs can change and the comment goes stale.
  Describe the behavior, not the ID.
- **Do not reference cfn-lint in code comments** — not by name and not by euphemism ("reference linter", "the linter",
  "the baseline tool"); an indirect reference is still a reference. This is a standalone tool; cfn-lint may only be
  named in Python scripts (`scripts/`), in `src/data-source` (the build-time pipeline that syncs cfn-lint data), and
  in the rule registry (`rules/src/registry.rs`).
- **Never reference CEL in `rego-engine` or Rego in `cel-engine`.** The engines are standalone.
- Imports from other workspace crates always at the top of the file — no inline `crate::` paths. External crates
  follow standard Rust conventions. Exception: `bindings-jvm` and `bindings-wasm`.
- Strings and constants reused across crates are defined once in an appropriate shared crate.
