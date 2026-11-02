# cloudformation-validate agent guide

## Purpose

`cloudformation-validate` is a fast, offline, embeddable AWS CloudFormation validator. It parses JSON or YAML templates and returns structured diagnostics through a Rust CLI and Rust, Node.js, Python, Go, and JVM libraries. Rules and schemas compile into shipped artifacts; runtime validation does not fetch data or use credentials.

## Required context

Before planning or making changes:

1. Follow `.kiro/steering/private-context.md`.
2. Read the applicable project guidance in `.kiro/steering/product.md`, `.kiro/steering/structure.md`, `.kiro/steering/tech.md`, and `.kiro/steering/version-control.md`.
3. For implementation planning, source or test changes, and code review, load `.kiro/skills/cloudformation-validate-development/SKILL.md` and its applicable source-code or test-code reference.
4. Read the relevant implementation, callers, tests, and sibling files before proposing a change.

The steering files and development skill are the canonical detailed guidance. Keep this entry point concise instead of copying those documents here.

## Agent roles

- **authoring** owns requirements, technical designs, implementation plans, project documentation, and pull-request descriptions. It does not implement source, tests, fixtures, build logic, workflows, agent configuration, or steering.
- **development** owns scoped implementation and change-appropriate verification. It may update documentation when that work is part of the implementation.
- **pr-reviewing** is read-only. It reviews a supplied patch or locally available changes and does not alter files, Git state, branches, or remote systems.

If a request crosses a role boundary, stop at the boundary and ask the user to continue with the appropriate agent rather than silently broadening the task.

## Architecture and correctness

- Run every Cargo command from `src/`, the Cargo workspace root.
- Treat `template-model` as the first place to investigate incorrect semantic behavior. Prefer a shared-layer fix over engine-specific work when the defect is shared.
- Rego and CEL are independent implementations of built-in rules. They must produce the same rule ID, severity, location, and message because both are correct, not because one copies or weakens the other. Composite uses CEL built-ins and is not a third implementation.
- `src/rules/src/registry.rs` is the single source of truth for rule metadata.
- Derive CloudFormation behavior from provider schemas, template syntax, official documentation, and intrinsic or resource semantics. External validators provide compatibility evidence, not authority.
- Return errors for unexpected states. Do not silently substitute defaults. Reachable `unwrap()`, `expect()`, and `panic!()` are not error handling.
- Preserve public APIs and serialized formats unless the requested change explicitly includes a compatible migration.

## File ownership

- Never hand-edit or locally regenerate `src/data-source/generated/`. Stop and ask the user when a change requires the maintainer-owned regeneration pipeline.
- Snapshot files under `src/resources/expected/` are developer-regenerated when diagnostics legitimately change; this is separate from data-source generation.
- Generated binding artifacts and release binaries are workflow-owned. Generate them locally only when required to test a hand-maintained binding change, then restore only artifacts created by that task.
- Put scratch files, debug scripts, and captured command output in repository-root `tmp/`.
- Preserve unrelated user changes. Do not use destructive cleanup to obtain a clean tree.

## Change-appropriate verification

- **Rust source:** from `src/`, run `cargo fmt --all`, `cargo clippy --locked --all-targets --workspace -- -D warnings`, and the narrowest tests that exercise the change. Run the full workspace suite only when broad or cross-crate behavior warrants it.
- **Binding layer:** run Rust format and Clippy for Rust changes, then run the affected binding's `build.sh` and `tests/run.sh`. Cargo tests do not replace packaged-consumer tests.
- **Diagnostic behavior:** establish expected behavior first, add focused invalid and valid fixtures as needed, inspect the SemanticModel, compare with the applicable external implementation, run `rego`, `cel`, and `composite`, then run the corpus and regenerate snapshots when output legitimately changes.
- **Documentation, scripts, workflows, or binding-language-only work:** run only checks that exercise the changed artifact.
- If no files changed, run no validation commands. Never claim a command passed unless it was run successfully.

## Git and operations

- Never run `git add` or `git commit`, and never stage or commit through another tool. Leave every change unstaged for the user.
- Do not release, publish, tag, deploy, or modify AWS resources unless the user explicitly expands the scope and the applicable safety procedure has been followed.
