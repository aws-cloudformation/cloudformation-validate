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

## Relationship to cfn-lint — compatibility evidence

Correctness does not come from reproducing another tool. Derive how validation **should** behave from first principles
using the strongest available evidence: compiled CloudFormation resource schemas and template syntax, official
CloudFormation documentation and resource specifications, intrinsic and resource semantics, and focused valid and
invalid templates. cfn-lint is a valuable compatibility comparison, but it is not authoritative and can contain bugs.

cfn-lint has no Fatal severity: both **Fatal (F)** and **Error (E)** here map to a cfn-lint **Error**. A Fatal rule
promoted from a cfn-lint Error keeps the cfn-lint number with the prefix changed (e.g. `F3006` ↔ cfn-lint `E3006`).
The numbering relationship does not make cfn-lint the source of truth for the rule's behavior. A rule whose number
matches cfn-lint SHOULD implement the same check and behave similarly on firing and location, including a
schema-grounded E→F promotion with the same numeric portion.

cfn-lint-sourced E/W/I rules should normally match cfn-lint on **firing and location**, and comparison against it is a
required compatibility check for those rules. A mismatch is evidence to investigate, not proof that this project is
wrong. Establish the expected behavior independently before changing an implementation; never copy cfn-lint behavior
solely to make a comparison pass. If first-principles evidence shows that cfn-lint is incorrect, intentionally diverge
and add focused regression coverage for both the accepted and rejected cases. Record the evidence and rationale in the
change description. **Rule descriptions and diagnostic messages may and should be more accurate and descriptive than
cfn-lint's** — `scripts/compare_cfnlint.py` matches on rule ID + resource + path, not message text. Guard DSL rules are
compared against `cfn-guard validate`.

A finding that cfn-lint does not emit is a **candidate false positive** when the rule has a cfn-lint equivalent. It must
be investigated and is accepted only when authoritative evidence shows that the finding is correct and regression
tests protect the intended behavior. It must not be relabeled as an "engine-extra" merely to excuse the mismatch.

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
equivalent are excluded from "engine-extra"; unmatched behavior follows the evidence-based mismatch procedure above.
**W9003** is a known intentional divergence: cfn-lint coerces silently while this engine warns.

## Non-negotiable principles

These apply to every change. No exceptions.

- No half measures. Only completely correct solutions. Quick patches that leave root causes unaddressed are not
  acceptable.
- Derive validation behavior from CloudFormation's contracts and semantics. External tools provide comparison evidence,
  not unquestionable truth.
- No silent failures. Unexpected states produce errors, never plausible-looking defaults.
- No hard crashes. Errors and exceptions never panic the process — they propagate through the language boundary
  layers (JVM, Python, Go, WASM) as catchable errors so callers can handle them.
- Fatal rules must reflect what CloudFormation itself rejects based on the compiled resource schemas.
- Investigate cfn-lint mismatches; preserve compatibility when it is correct and intentionally diverge when stronger
  evidence proves that it is not.
- Rego and CEL engines must have parity — same rules, results, severities, messages.
- Zero false positives against valid CloudFormation behavior and `resources/templates/good/`.
- Every validation-behavior fix is validated end-to-end on a real template with both `inspect` and `cfn-validate`.
