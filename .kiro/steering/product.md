# Product Context

## What this is

cloudformation-validate — a fast, offline, embeddable validator for AWS CloudFormation templates. It parses a template
(JSON or YAML) and returns structured diagnostics — schema violations, semantic errors, security concerns, and
best-practice suggestions — at author-time, before deployment. All rules and resource schemas compile into the binary:
no network, no credentials, no runtime fetching.

It ships as a Rust CLI (`cfn-validate`), an embeddable Rust library, a Node.js package (WASM), a Python package, a Go
module, and a JVM library (Kotlin/Java) — all backed by the same validation core.

## The problem

Developers and agentic workflows get no IaC diagnostics until deployment time. The existing ecosystem (cfn-lint, Guard,
Hooks, ValidateTemplate, CFN Language Server) is fragmented — each tool forces trade-offs between schema correctness,
embeddability, offline capability, and author-time feedback.

This engine unifies them into one embeddable runtime with sub-second, structured diagnostics for humans and agents.

## Goal

Be strictly better than cfn-lint and cloudformation-guard on:

- Accuracy — zero false positives on real templates
- Customizability — Rego, CEL, Guard DSL, and compliance packs
- Performance — sub-second per template

Consumers in priority order: IDE language servers, CI/CD, agentic workflows, AWS services, direct CLI.

## Severity model

| Severity | Prefix | Source           | Meaning                                                                                                              |
|----------|--------|------------------|----------------------------------------------------------------------------------------------------------------------|
| Fatal    | F      | schema-validator | Structural template violation guaranteed to cause a CloudFormation deployment failure based on the resource schemas. |
| Error    | E      | engine rules     | Semantic issue — likely deploy failure or wrong runtime behavior.                                                    |
| Warn     | W      | engine rules     | Security risk, deprecation, or risky pattern.                                                                        |
| Info     | I      | engine rules     | Best practice or optimization.                                                                                       |
| Debug    | D      | engine rules     | Internal diagnostic detail.                                                                                          |

The enum variant is `Warn`, not `Warning`. Serialized form is `WARN`.

Fatal severity is reserved for structural violations the schema validator can prove against the compiled
CloudFormation resource schemas — no semantic interpretation, no cross-resource analysis, no runtime context. Anything
requiring those belongs to E/W/I and is evaluated by the rule engines. cfn-lint-sourced rules keep their original
E/W/I severity.

## Relationship to cfn-lint — the correctness baseline

cfn-lint has no Fatal severity: both **Fatal (F)** and **Error (E)** here map to a cfn-lint **Error**. A Fatal rule
promoted from a cfn-lint Error keeps the cfn-lint number with the prefix changed (e.g. `F3006` ↔ cfn-lint `E3006`) —
same trigger and location, only the local severity differs.

cfn-lint-sourced E/W/I rules must match cfn-lint on **firing and location** — the same rule triggers on the same
construct at the same location (or a more precise one). That is the baseline: if whether-or-where a rule fires
differs, we are wrong. But **rule descriptions and diagnostic messages may and should be more accurate and descriptive
than cfn-lint's** — the accuracy check (`scripts/compare_cfnlint.py`) matches on rule ID + resource + path, not
message text, so clearer wording is never a mismatch. Guard DSL rules are baselined against `cfn-guard validate`.

**False positives compared to cfn-lint are never allowed.** Any rule that has a cfn-lint equivalent and fires where
cfn-lint would not is a false positive — a bug, not an "extra finding."

### Rule origin taxonomy

For each rule in `rules/src/registry.rs`, its TRUE origin is, in priority order:

1. **Schema** — the check is grounded in the compiled CloudFormation resource schemas or in CloudFormation-defined
   template syntax and shape (template sections, required properties, types, enums, patterns, value constraints).
   These rules are **Fatal or Error** and are classified as Schema **even when cfn-lint performs the same check** —
   what makes them Schema is that CloudFormation itself defines the contract, not that a linter also checks it. A
   Schema rule promoted from a cfn-lint Error keeps the cfn-lint number with the prefix changed (e.g.
   `E3006` → `F3006`).
2. **Exact cfn-lint ID → CfnLint** — only for rules that are *not* schema-grounded (semantic, cross-resource,
   security, best-practice checks).
3. **Engine ID that aliases a cfn-lint rule → CfnLint** (split/generic, e.g. `E9003`/`E9004` ← `E1010`,
   `E9006` ← `E3690`), again only when not schema-grounded.
4. **Otherwise → Engine** (or `Engine(collision)` if the number exists under another prefix).

**Rule numbering:** a number cfn-lint uses is reserved for the equivalent check — if `cloudformation-validate`
implements that check, it uses the same number (prefix promoted E→F when schema-grounded); it must never reuse a
cfn-lint number for a *different* check. Engine-assigned rules — both aliases of split/generic cfn-lint rules and
engine-extra rules — get their own numbers in the **9xxx** range (e.g. `E9003`, `W9003`).

A rule is **"engine-extra"** (a correct finding cfn-lint never emits) *only* when it has no cfn-lint equivalent at
all: true origin `Engine`/`Engine(collision)`, or a Schema Fatal with no cfn-lint promotion. Rules with *any* cfn-lint
equivalent are excluded from "engine-extra," so an unmatched firing of one of them surfaces as a **false positive**
rather than being excused. The one intentional exception is **W9003** (cfn-lint coerces silently; the engine warns).

## Non-negotiable principles

These apply to every change. No exceptions.

- No half measures. Only completely correct solutions. Quick patches that leave root causes unaddressed are not
  acceptable.
- No silent failures. Unexpected states produce errors, never plausible-looking defaults.
- No hard crashes. Errors and exceptions never panic the process — they propagate through the language boundary
  layers (JVM, Python, Go, WASM) as catchable errors so callers can handle them.
- Fatal rules must reflect what CloudFormation itself rejects based on the compiled resource schemas.
- cfn-lint-sourced rules must match cfn-lint on firing and location (messages may be better — see above).
- Rego and CEL engines must have parity — same rules, results, severities, messages.
- Zero false positives against `resources/templates/good/` and against cfn-lint's rule set.
- Every fix validated end-to-end on a real template with both `inspect` and `cfn-validate`.
