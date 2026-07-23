# CLAUDE.md

`cloudformation-validate` is a fast, offline validator for
AWS CloudFormation templates: parse JSON/YAML → structured diagnostics (schema, semantic, security,
best-practice). Rules + schemas compile into the binary — no network, no credentials. Ships as a Rust CLI,
Rust library, Node WASM package, and JVM (Kotlin/Java) library over one shared core.

Deeper architecture notes live in `.kiro/steering/` (`product.md`, `structure.md`, `tech.md`)

## Commands

All `cargo` commands run from `src/`. Toolchain pinned by `src/rust-toolchain.toml`

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

# Format + lint — run BOTH after every code change; must pass clean.
cargo fmt --all
cargo clippy --locked --all-targets --workspace -- -D warnings

# Run the CLI
cargo run -p cfn-validate -- <template|dir> --engine rego|cel --format standard|detailed --level fatal|error|warn|info|debug
cargo run -p cfn-validate -- --list-rules
```

### Debugging tools (use these, not `println!`)

```bash
# Dump the full SemanticModel — ALWAYS start here. If the model is wrong, fix template-model.
cargo run -p template-model --example inspect -- <template>

# Accuracy vs cfn-lint. Requires a local cfn-lint checkout — first check whether cfn-lint is available on the
# machine (`cfn-lint --version`), then ask the user for the checkout path; never assume or hardcode a location.
CFN_LINT_ROOT=<path> python3 scripts/compare_cfnlint.py --engine rego|cel
```

Scratch files, debug output, and tool artifacts go in `./tmp/` at the project root — never scatter them in
the tree.

## Architecture (the non-obvious rules)

- **The two engines must stay at parity.** `EngineType::Rego` (default) and `EngineType::Cel` must produce
  identical diagnostics (ID, severity, location, message) for any template — divergence is a bug. Every rule
  exists in both engines or in neither; add/fix it in both in the same change. Rego rules are hand-written
  policies in `rego-engine/handwritten/rego/`; CEL rules are native Rust in `cel-engine/src/rules/` (the CEL
  interpreter is only for user-supplied custom rules).
- **`rules/src/registry.rs` (`RULE_REGISTRY`) is the single source of truth** for every rule's ID, severity,
  category, and description. A rule that evaluates but isn't registered is a bug. IDs match `[FEWID]\d{4}`
  (F=Fatal, E=Error, W=Warn, I=Info, D=Debug; enum variant `Warn`, serialized `WARN`).
- **Never hand-edit `data-source/generated/`, and never run the regeneration pipeline yourself.** It is committed
  generated code; regeneration is a maintainer-run operation — if a change requires regenerating these artifacts,
  stop and ask the user to run it. `data-source/handwritten/` holds reusable JSON reference tables; add one only
  when a rule needs a data table.
- **Custom rules** load from CLI/library as CEL (`.json`), Rego (`.rego`), or Guard DSL (`.guard`, translated
  to engine-agnostic IR by `guard-translator`). See `src/CUSTOM_RULES.md`.

## Correctness rules — non-negotiable

- **Fatal (F)** rules must reflect what CloudFormation itself rejects per the compiled resource schemas — no semantic
  interpretation, no cross-resource analysis. cfn-lint has no Fatal severity: both **Fatal (F)** and **Error (E)** here
  map to a cfn-lint **Error**. When comparing against cfn-lint, treat an F diagnostic as equivalent to the cfn-lint
  Error it was promoted from (e.g. `F3006` ↔ cfn-lint `E3006`) — same trigger and location, only the local severity
  differs.
- **cfn-lint-sourced E/W/I** rules must match cfn-lint on *firing and location* — the same rule triggers on the same
  construct at the same location (or a more precise one). That is the baseline: if whether-or-where a rule fires
  differs, we are wrong. But **rule descriptions and diagnostic messages may and should be more accurate and
  descriptive than cfn-lint's** — the accuracy check (`scripts/compare_cfnlint.py`) matches on rule ID + resource +
  path, not message text, so clearer wording is never a mismatch. Guard DSL rules are baselined against
  `cfn-guard validate`.
- **False positives compared to cfn-lint are never allowed.** Any rule that has a cfn-lint equivalent and fires where
  cfn-lint would not is a false positive — it is a bug, not an "extra finding." This is non-negotiable.
- **Zero false positives** against the corpus. `resources/templates/good/` must stay clean; `templates/bad/` files are
  named after the rule/behavior they test.

### Rule origin taxonomy

For each rule in `rules/src/registry.rs`, its TRUE origin is, in priority order:

1. **F-prefix** A guaranteed deploy failure and even when cfn-lint also performs it. It uses the cfn-lint number
   promoted E→F (e.g. `E3006` → `F3006`).
2. **Exact cfn-lint ID → CfnLint.**
3. **Engine ID that aliases a cfn-lint rule → CfnLint** (split/generic, e.g. `E9003`/`E9004` ← `E1010`,
   `E9006` ← `E3690`).
4. **Otherwise → Engine** (or `Engine(collision)` if the number exists under another prefix).

cfn-lint has no Fatal category so cloudformation-validate Fatal and Errors are equivalent to cfn-lint Errors

A rule is **"engine-extra"** (a correct finding cfn-lint never emits) *only* when it has no cfn-lint equivalent at all:
true origin `Engine`/`Engine(collision)`, or a Schema Fatal with no cfn-lint promotion. Rules with *any* cfn-lint
equivalent are excluded from "engine-extra," so an unmatched firing of one of them surfaces as a **false positive**
rather than being excused. The one intentional exception is **W9003** (cfn-lint coerces silently; the engine warns).

- **No silent failures / no half measures.** On unexpected states, return an `Err` following the existing `Result`
  conventions rather than defaulting to a plausible value. Error diagnostics are reserved for problems in the
  template under validation — a parse error is the only failure that surfaces as a diagnostic instead of an `Err`.
  Fix at the highest-leverage layer: `template-model` first, then `data-source`, then the engines/schema-validator
  (and then in both engines, same change).
- **No panics, no hard crashes.** Errors and exceptions never panic the process — they propagate as `Result`s through
  the language boundary layers and surface to embedders as catchable errors (Kotlin/Java `ValidationError` exceptions
  via UniFFI, thrown JS errors via wasm-bindgen). Fallible FFI entry points in `bindings-jvm`/`bindings-wasm` are
  wrapped in `validation_engine::catch_panics` with a panic-to-error mapper as a last-resort backstop; new entry
  points must follow the same pattern. `unwrap()`/`expect()`/`panic!` are never error handling on reachable paths.

## Validating a fix (the procedure, condensed)

1. Add/repro a template under `src/resources/templates/` (repro in `bad/`, counter-example in `good/`).
2. Check the SemanticModel with `inspect`; fix `template-model` if the model is wrong.
3. Compare against the reference (cfn-lint for E/W/I; cfn-guard for Guard; schemas for Fatal).
4. Run `cfn-validate` with both engines — outputs must be identical.
5. Run the full corpus with both engines — zero new false positives.
6. `cargo test --workspace` passes (full suite — once, at the end of the task; targeted `cargo test -p <crate>` while
   iterating).

## Conventions (IMPORTANT - MUST FOLLOW)

- **The `cloudformation-validate-development` skill (`.kiro/skills/cloudformation-validate-development/`) MUST be
  followed for every code change** — its `references/source-code-rules.md` applies to all source code and
  `references/test-code-rules.md` applies to all test code.
- Self-documenting names; no `data`/`info`/`temp`/`result`/`manager`/`processor`. Comments explain *why*, never *what*.
- **No hardcoded rule IDs in code comments** — IDs can change and the comment goes stale. Describe the behavior, not the
  ID.
- **Do not reference cfn-lint in code comments** — not by name and not by euphemism ("reference linter", "the
  linter", "the baseline tool", etc.); an indirect reference is still a reference. This is a standalone tool; cfn-lint
  may only be named in Python scripts (`scripts/`), in `src/data-source` (the build-time data pipeline that syncs
  cfn-lint data), and in the rule registry (`rules/src/registry.rs`).
- `unsafe_code` is forbidden workspace-wide. Prefer LSP (goto/refs/symbols) over text grep for symbol-level navigation.
- Read sibling files before writing — match existing patterns, naming, and error handling.
- Always follow code style of the project
- Imports from other crates in the projects should always happen at the top - no inline [crate::]. For external crates
  follow standard Rust conventions. Does not apply to bindings-jvm or bindings-wasm crates
- NEVER reference cel in rego-engine or rego in cel-engines. The engines are standalone
