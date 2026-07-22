---
name: cloudformation-validate-development
description: Development workflow, correctness rules, and code-quality standards for the cloudformation-validate repository — a Rust workspace that validates AWS CloudFormation templates with two parity rule engines (Rego and CEL). Use when writing, modifying, reviewing, or debugging any code in this repo; when adding or fixing validation rules; when running builds, tests, or lints; when regenerating the golden file; or when validating a fix against cfn-lint or cloudformation-guard baselines.
license: Apache-2.0
metadata:
  repository: cloudformation-validate
---

# cloudformation-validate development

`cloudformation-validate` is a fast, offline validator for AWS CloudFormation templates: parse JSON/YAML →
structured diagnostics (schema, semantic, security, best-practice). Rules and schemas compile into the binary — no
network, no credentials. Ships as a Rust CLI, Rust library, Node WASM package, and JVM (Kotlin/Java) library over one
shared core.

## Code quality — read the references first

Before writing or modifying code, read the applicable reference file and apply every rule in it:

- [references/source-code-rules.md](references/source-code-rules.md) — applies to ALL source code
- [references/test-code-rules.md](references/test-code-rules.md) — applies to ALL test code

Also read sibling files in the directory you are editing to learn existing patterns, naming, error handling, and
style — then match them. Always follow the code style of the project.

## Commands

All `cargo` commands run from `src/` (the Cargo workspace lives in `src/`, not the repo root). The toolchain is
pinned by `src/rust-toolchain.toml`.

```bash
cd src

# Build
cargo build                                   # whole workspace (debug)
cargo build -p cfn-validate                   # CLI -> target/debug/cfn-validate (add --release for optimized)

# Test — full workspace tests are EXPENSIVE: run targeted tests while iterating, and the full suite ONCE at the
# end of the task. Tee the output; do not re-run to grab different output.
cargo test -p cel-engine <name>               # single crate / filtered test — preferred while iterating
cargo test --workspace 2>&1 | tee ../tmp/test-output.txt   # full suite — once, at task completion
# CI runs coverage, not plain test: cargo llvm-cov --locked --release --workspace --no-fail-fast

# Format + lint — run BOTH after every code change; CI gates on both; must pass clean.
cargo fmt --all
cargo clippy --locked --all-targets --workspace -- -D warnings

# Run the CLI
cargo run -p cfn-validate -- <template|dir> --engine rego|cel --format standard|detailed --level fatal|error|warn|info|debug
cargo run -p cfn-validate -- --list-rules

# Regenerate the golden file (resources/expected/all_templates.json) after any change that alters diagnostics.
# Runs both engines on the whole corpus in parallel, verifies they agree, rewrites the golden file.
cargo run --release -p resources --example generate_golden
```

## Debugging tools (use these, not `println!`)

```bash
# Dump the full SemanticModel — ALWAYS start here. If the model is wrong, fix template-model.
cargo run -p template-model --example inspect -- <template>

# Accuracy vs cfn-lint. Requires a local cfn-lint checkout — first check whether cfn-lint is available on the
# machine (`cfn-lint --version`), then ask the user for the checkout path; never assume or hardcode a location.
CFN_LINT_ROOT=<path> python3 scripts/compare_cfnlint.py --engine rego|cel
```

If deeper investigation is needed, write a small standalone script or Rust example that isolates the behavior.
Scratch files, debug output, and tool artifacts go in `./tmp/` at the project root — never scatter them in the tree.

Prefer LSP operations (goto definition, find references, symbol search) over text grep for symbol-level navigation.

## Architecture (the non-obvious rules)

- **The two engines must stay at parity.** `EngineType::Rego` (default) and `EngineType::Cel` must produce identical
  diagnostics (ID, severity, location, message) for any template — divergence is a bug. Every rule exists in both
  engines or in neither; add/fix it in both in the same change. Rego rules are hand-written policies in
  `rego-engine/handwritten/rego/`; CEL rules are native Rust in `cel-engine/src/rules/` (the CEL interpreter is only
  for user-supplied custom rules).
- **`rules/src/registry.rs` (`RULE_REGISTRY`) is the single source of truth** for every rule's ID, severity,
  category, and description. A rule that evaluates but isn't registered is a bug. IDs match `[FEWID]\d{4}`
  (F=Fatal, E=Error, W=Warn, I=Info, D=Debug; enum variant `Warn`, serialized `WARN`).
- **Never hand-edit `data-source/generated/`, and never run the regeneration pipeline yourself.** It is committed
  generated code; regeneration is a maintainer-run operation — if a change requires regenerating these artifacts,
  stop and ask the user to run it. `data-source/handwritten/` holds reusable JSON reference tables; add one only
  when a rule needs a data table.
- **Custom rules** load from CLI/library as CEL (`.json`), Rego (`.rego`), or Guard DSL (`.guard`, translated to an
  engine-agnostic IR by `guard-translator`). See `src/CUSTOM_RULES.md`.

## Correctness rules — non-negotiable

- **Fatal (F)** rules must reflect what CloudFormation itself rejects per the compiled resource schemas — no semantic
  interpretation, no cross-resource analysis. cfn-lint has no Fatal severity: both **Fatal (F)** and **Error (E)**
  here map to a cfn-lint **Error**. When comparing against cfn-lint, treat an F diagnostic as equivalent to the
  cfn-lint Error it was promoted from (e.g. `F3006` ↔ cfn-lint `E3006`) — same trigger and location, only the local
  severity differs.
- **cfn-lint-sourced E/W/I** rules must match cfn-lint on *firing and location* — the same rule triggers on the same
  construct at the same location (or a more precise one). That is the baseline: if whether-or-where a rule fires
  differs, we are wrong. But **rule descriptions and diagnostic messages may and should be more accurate and
  descriptive than cfn-lint's** — the accuracy check (`scripts/compare_cfnlint.py`) matches on rule ID + resource +
  path, not message text, so clearer wording is never a mismatch. Guard DSL rules are baselined against
  `cfn-guard validate`.
- **False positives compared to cfn-lint are never allowed.** Any rule that has a cfn-lint equivalent and fires where
  cfn-lint would not is a false positive — it is a bug, not an "extra finding."
- **Zero false positives** against the corpus. `resources/templates/good/` must stay clean; `templates/bad/` files
  are named after the rule/behavior they test.
- **No silent failures / no half measures.** On unexpected states, return an `Err` following the existing `Result`
  conventions rather than defaulting to a plausible value. Error diagnostics are reserved for problems in the
  template under validation — a parse error is the only failure that surfaces as a diagnostic instead of an `Err`.
- **No panics, no hard crashes.** Errors propagate as `Result`s through the language boundary layers and surface to
  embedders as catchable errors (Kotlin/Java `ValidationError` exceptions via UniFFI, thrown JS errors via
  wasm-bindgen) — never a process abort. Fallible FFI entry points in `bindings-jvm`/`bindings-wasm` are wrapped in
  `validation_engine::catch_panics` with a panic-to-error mapper as a last-resort backstop; new entry points must
  follow the same pattern. `unwrap()`/`expect()`/`panic!` are never error handling on reachable paths.

### Rule origin taxonomy

For each rule in `rules/src/registry.rs`, its TRUE origin is, in priority order:

1. **Schema** — the check is grounded in the compiled CloudFormation resource schemas or in CloudFormation-defined
   template syntax and shape (template sections, required properties, types, enums, patterns, value constraints).
   These rules are **Fatal or Error** and are classified as Schema **even when cfn-lint performs the same check** —
   CloudFormation itself defines the contract, not the linter. A Schema rule promoted from a cfn-lint Error keeps the
   cfn-lint number with the prefix changed (e.g. `E3006` → `F3006`).
2. **Exact cfn-lint ID → CfnLint** — only for rules that are *not* schema-grounded (semantic, cross-resource,
   security, best-practice checks).
3. **Engine ID that aliases a cfn-lint rule → CfnLint** (split/generic, e.g. `E9003`/`E9004` ← `E1010`,
   `E9006` ← `E3690`), again only when not schema-grounded.
4. **Otherwise → Engine** (or `Engine(collision)` if the number exists under another prefix).

**Rule numbering:** a number cfn-lint uses is reserved for the equivalent check — never reuse a cfn-lint number for a
*different* check. Engine-assigned rules (aliases of split/generic cfn-lint rules and engine-extra rules) get their
own numbers in the **9xxx** range (e.g. `E9003`, `W9003`).

A rule is **"engine-extra"** (a correct finding cfn-lint never emits) *only* when it has no cfn-lint equivalent at
all: true origin `Engine`/`Engine(collision)`, or a Schema Fatal with no cfn-lint promotion. Rules with *any*
cfn-lint equivalent are excluded from "engine-extra," so an unmatched firing of one of them surfaces as a **false
positive** rather than being excused. The one intentional exception is **W9003** (cfn-lint coerces silently; the
engine warns).

## Fix priority order

Fix at the highest-leverage layer: `template-model` first (benefits everything downstream), then the `data-source`
pipeline (both engines inherit it), then — only if neither applies — `schema-validator`/`rego-engine`/`cel-engine`,
applied to both engines in the same change.

## Validating a fix (the procedure)

1. Add/repro a template under `src/resources/templates/` (repro in `bad/`, counter-example in `good/`).
2. Check the SemanticModel with `inspect`; fix `template-model` if the model is wrong.
3. Compare against the reference (cfn-lint for E/W/I; cfn-guard for Guard; the compiled schemas for Fatal).
4. Run `cfn-validate` with both engines — outputs must be identical.
5. Run the full corpus with both engines — zero new false positives; regenerate the golden file if diagnostics
   legitimately changed.
6. `cargo test --workspace` passes (full suite — once, at the end of the task; targeted `cargo test -p <crate>` while
   iterating).
7. `cargo fmt --all` and `cargo clippy --locked --all-targets --workspace -- -D warnings` both pass clean.

## Project-specific conventions (MUST FOLLOW)

- Self-documenting names; no `data`/`info`/`temp`/`result`/`manager`/`processor`. Comments explain *why*, never
  *what*. (Full rules in [references/source-code-rules.md](references/source-code-rules.md).)
- **No hardcoded rule IDs in code comments** — IDs can change and the comment goes stale. Describe the behavior, not
  the ID.
- **Do not reference cfn-lint in code comments** — not by name and not by euphemism ("reference linter", "the
  linter", "the baseline tool", etc.); an indirect reference is still a reference. This is a standalone tool;
  cfn-lint may only be named in Python scripts (`scripts/`), in `src/data-source` (the build-time data pipeline that
  syncs cfn-lint data), and in the rule registry (`rules/src/registry.rs`).
- **NEVER reference CEL in `rego-engine` or Rego in `cel-engine`.** The engines are standalone.
- Imports from other workspace crates always at the top of the file — no inline `crate::` paths. External crates
  follow standard Rust conventions. Does not apply to `bindings-jvm` or `bindings-wasm`.
- `unsafe_code` is forbidden workspace-wide.
