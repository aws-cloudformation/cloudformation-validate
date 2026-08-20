# CLAUDE.md

`cloudformation-validate` is a fast, offline validator for
AWS CloudFormation templates: parse JSON/YAML → structured diagnostics (schema, semantic, security,
best-practice). Rules + schemas compile into the binary - no network, no credentials. Ships as a Rust CLI,
Rust library, Node WASM package, Python package, Go module, and JVM (Kotlin/Java) library over one shared core.

Deeper architecture notes live in `.kiro/steering/` (`product.md`, `structure.md`, `tech.md`, `private-context.md`,
and `version-control.md`).

## Confidential agent context and skills

Before starting any task, if `.kiro/private/` exists, recursively discover and read every readable regular file in it
before planning or making changes. Do not follow symlinks that resolve outside `.kiro/private/`. Use applicable content
as supplemental agent context, and follow any task-relevant skill instructions found there, resolving conflicts
according to the normal instruction priority. Treat both filenames and contents as confidential: do not quote,
summarize, or copy them into tracked files, logs, commit messages, review descriptions, or responses unless the user
explicitly asks for that specific disclosure. The directory and its contents must remain untracked and must never be
added to version control. If the directory is absent or empty, continue normally.

## Version control

Never run `git add` or `git commit` in this repository for any path. Do not stage or commit changes through another
tool. Leave all changes unstaged for the user to review and manage.

## Commands and validation selection

All `cargo` commands run from `src/`. The toolchain is pinned by `src/rust-toolchain.toml`. Run only checks that
exercise the files and behavior changed; if no files changed, run no tests or validation commands.

```bash
cd src

# Build
cargo build                                   # whole workspace (debug)
cargo build -p cfn-validate                   # CLI -> target/debug/cfn-validate (add --release for optimized)

# Core Rust tests - only when they cover the changed behavior
cargo test -p cel-engine <name>               # single crate / filtered test - preferred while iterating
cargo test --workspace 2>&1 | tee ../tmp/test-output.txt   # broad core changes only; at most once at completion
# CI runs coverage, not plain test: cargo llvm-cov --locked --release --workspace --no-fail-fast

# Required after every Rust source change
cargo fmt --all
cargo clippy --locked --all-targets --workspace -- -D warnings

# Run the CLI
cargo run -p cfn-validate -- <template|dir> --engine rego|cel --format standard|detailed --level fatal|error|warn|info|debug
cargo run -p cfn-validate -- --list-rules
```

Validation depends on the changed surface:

- Core Rust changes: run format, clippy, and the narrowest Cargo tests that exercise the change. Use the full workspace
  suite only for broad or cross-crate core changes for which it provides meaningful coverage.
- Binding-layer Rust changes: run format and clippy, then the affected binding's `build.sh` and `tests/run.sh`. Do not
  use `cargo test` as a substitute; it does not exercise the packaged Node.js, JVM, Python, or Go API. Generated binding
  artifacts are committed only by the `build-artifacts` workflow. If generation is needed for local verification,
  generate, test, and then revert every generated binding artifact.
- Non-Rust-only changes such as documentation, GitHub workflows, scripts, or binding-language code: do not run Cargo
  format, clippy, or tests unless the file is a Cargo/build input and the command actually exercises it. Use the
  artifact-specific syntax checker, build, test runner, or dry-run instead.
- Rule, schema-data, or template changes still require the focused validator, engine-parity, corpus, and snapshot
  checks that exercise the changed diagnostics; they do not justify unrelated Cargo tests.

### Debugging tools (use these, not `println!`)

```bash
# Dump the full SemanticModel - ALWAYS start here. If the model is wrong, fix template-model.
cargo run -p template-model --example inspect -- <template>

# Accuracy vs cfn-lint. Requires a local cfn-lint checkout - first check whether cfn-lint is available on the
# machine (`cfn-lint --version`), then ask the user for the checkout path; never assume or hardcode a location.
CFN_LINT_ROOT=<path> python3 scripts/compare_cfnlint.py --engine rego|cel
```

Scratch files, debug output, and tool artifacts go in `./tmp/` at the project root - never scatter them in
the tree.

## Architecture (the non-obvious rules)

- **The two engines must stay at parity, but parity must preserve correctness.** `EngineType::Rego` (default) and
  `EngineType::Cel` must produce identical diagnostics (ID, severity, location, message) for any template - divergence
  is a bug. A mismatch is a signal to investigate, not permission to make the outputs agree mechanically. Establish
  the correct behavior from CloudFormation's contracts and semantics first, preserve an engine that already implements
  that behavior, and fix the incorrect engine or the shared lower-level implementation. Never regress the correct
  engine or remove or suppress a valid finding solely because the other engine misses it. Remove a finding only when
  first-principles evidence establishes that it is a false positive, with focused regression coverage for the corrected
  behavior. Every rule exists in both engines or in neither; add/fix it in both in the same change. Rego rules are
  hand-written policies in `rego-engine/handwritten/rego/`; CEL rules are native Rust in `cel-engine/src/rules/` (the
  CEL interpreter is only for user-supplied custom rules).
- **`rules/src/registry.rs` (`RULE_REGISTRY`) is the single source of truth** for every rule's ID, severity,
  category, and description. A rule that evaluates but isn't registered is a bug. IDs match `[FEWID]\d{4}`
  (F=Fatal, E=Error, W=Warn, I=Info, D=Debug; enum variant `Warn`, serialized `WARN`).
- **Never hand-edit `data-source/generated/`, and never run the regeneration pipeline yourself.** It is committed
  generated code; regeneration is a maintainer-run operation - if a change requires regenerating these artifacts,
  stop and ask the user to run it. `data-source/handwritten/` holds reusable JSON reference tables; add one only
  when a rule needs a data table.
- **Generated binding artifacts are workflow-owned.** The `build-artifacts` workflow commits them. Local generation
  is permitted only when needed to test a hand-maintained change, and every generated artifact must be reverted after
  the affected binding tests pass.
- **Custom rules** load from CLI/library as CEL (`.json`), Rego (`.rego`), or Guard DSL (`.guard`, translated
  to engine-agnostic IR by `guard-translator`). See `src/CUSTOM_RULES.md`.

## Correctness rules - non-negotiable

- Derive expected validation behavior from first principles: compiled CloudFormation schemas and template syntax,
  official documentation and resource specifications, intrinsic/resource semantics, and focused valid and invalid
  examples. External tools are comparison evidence, not unquestionable truth.
- **Fatal (F)** rules must reflect what CloudFormation itself rejects per the compiled resource schemas - no semantic
  interpretation, no cross-resource analysis. cfn-lint has no Fatal severity: both **Fatal (F)** and **Error (E)** here
  map to a cfn-lint **Error**. A promoted rule keeps the number with the prefix changed (for example,
  `F3006` ↔ cfn-lint `E3006`); this numbering relationship does not make cfn-lint authoritative.
- **A rule whose number matches cfn-lint SHOULD implement the same check and behave similarly on firing and location,**
  including a schema-grounded E→F promotion with the same numeric portion. Shared numbering is a compatibility
  contract, not proof that cfn-lint's implementation is correct.
- **cfn-lint-sourced E/W/I** rules should normally match cfn-lint on firing and location, and comparison is required.
  A mismatch is evidence to investigate, not proof that this project is wrong. Never copy cfn-lint behavior solely to
  make a comparison pass. When stronger CloudFormation evidence shows cfn-lint is incorrect, intentionally diverge,
  add focused accepted/rejected regression coverage, and record the evidence and rationale in the change description.
  Messages may and should be more accurate and descriptive; `scripts/compare_cfnlint.py` matches rule ID + resource +
  path, not message text. Guard DSL rules are compared against `cfn-guard validate`.
- A finding absent from cfn-lint is a **candidate false positive** when the rule has a cfn-lint equivalent. Investigate
  it and accept it only with authoritative evidence and regression coverage; never relabel it as an engine-extra merely
  to excuse a mismatch.
- **Zero false positives** against valid CloudFormation behavior and `resources/templates/good/`. `templates/bad/`
  files are named after the rule or behavior they test.

### Rule origin taxonomy

For each rule in `rules/src/registry.rs`, its TRUE origin is, in priority order:

1. **Schema** - grounded in compiled CloudFormation resource schemas or CloudFormation-defined template syntax and
   shape, even when cfn-lint performs the same check. Schema rules are Fatal or Error; a promoted rule keeps the
   cfn-lint number with E→F (for example, `E3006` → `F3006`).
2. **Exact cfn-lint ID → CfnLint** - only when not schema-grounded.
3. **Engine ID that aliases a cfn-lint rule → CfnLint** (split/generic, for example `E9003`/`E9004` ← `E1010`,
   `E9006` ← `E3690`), again only when not schema-grounded.
4. **Otherwise → Engine** (or `Engine(collision)` if the number exists under another prefix).

A cfn-lint number is reserved for the equivalent check; engine-assigned rules use the 9xxx range. A rule is
**engine-extra** only when it has no cfn-lint equivalent. Unmatched behavior for a rule with an equivalent follows the
evidence-based mismatch procedure above. **W9003** is a known intentional divergence: cfn-lint coerces silently while
this engine warns.

- **No silent failures / no half measures.** On unexpected states, return an `Err` following the existing `Result`
  conventions rather than defaulting to a plausible value. Error diagnostics are reserved for problems in the
  template under validation - a parse error is the only failure that surfaces as a diagnostic instead of an `Err`.
  Fix at the highest-leverage layer: `template-model` first, then `data-source`, then the engines/schema-validator
  (and then in both engines, same change).
- **No panics, no hard crashes.** Errors and exceptions never panic the process - they propagate as `Result`s through
  the language boundary layers and surface to embedders as catchable errors. Every fallible FFI entry point is wrapped
  in `validation_engine::catch_panics` with a panic-to-error mapper as a last-resort backstop; new entry points must
  follow the same pattern. `unwrap()`/`expect()`/`panic!` are never error handling on reachable paths.

## Validating a diagnostic behavior fix (condensed)

Apply only the steps relevant to the actual change; this procedure is not a blanket requirement for documentation or
workflow-only edits.

1. Establish expected behavior independently from CloudFormation schemas, documentation/specifications, semantics,
   and focused valid/invalid examples.
2. Add or reproduce a template under `src/resources/templates/` (`bad/` for the repro, `good/` for a counter-example).
3. Check the SemanticModel with `inspect`; fix `template-model` if the model is wrong.
4. Compare against cfn-lint for E/W/I or cfn-guard for Guard. Investigate a cfn-lint mismatch using the independent
   evidence rather than assuming cfn-lint is correct. Validate Fatal behavior against the compiled schemas.
5. Run `cfn-validate` with both engines, then the corpus; preserve parity and zero false positives. Regenerate the
   snapshot files if diagnostics legitimately changed.
6. For core Rust changes, run only Cargo tests that cover the change; use the workspace suite once only when its broad
   coverage is relevant. For every Rust change, run format and clippy. For binding changes, run the affected packaged
   binding build/tests instead of Cargo tests and revert any generated binding artifacts afterward.

## Conventions (IMPORTANT - MUST FOLLOW)

- **The `cloudformation-validate-development` skill (`.kiro/skills/cloudformation-validate-development/`) MUST be
  followed for every code change** - its `references/source-code-rules.md` applies to all source code and
  `references/test-code-rules.md` applies to all test code.
- Self-documenting names; no `data`/`info`/`temp`/`result`/`manager`/`processor`. Comments explain *why*, never *what*.
- **No hardcoded rule IDs in code comments** - IDs can change and the comment goes stale. Describe the behavior, not the
  ID.
- **Do not reference cfn-lint in code comments** - not by name and not by euphemism ("reference linter", "the
  linter", "the baseline tool", etc.); an indirect reference is still a reference. This is a standalone tool; cfn-lint
  may only be named in Python scripts (`scripts/`), in `src/data-source` (the build-time data pipeline that syncs
  cfn-lint data), and in the rule registry (`rules/src/registry.rs`).
- `unsafe_code` is forbidden workspace-wide. Prefer LSP (goto/refs/symbols) over text grep for symbol-level navigation.
- Read sibling files before writing - match existing patterns, naming, and error handling.
- Always follow code style of the project.
- Imports from other crates in the project should always happen at the top - no inline `crate::`. For external crates,
  follow standard Rust conventions. Does not apply to `bindings-jvm` or `bindings-wasm`.
- Never reference CEL in `rego-engine` or Rego in `cel-engine`. The engines are standalone.
