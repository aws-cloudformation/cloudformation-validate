# W9100 Missing-Context Diagnostic Benchmark

## Overall Discrimination

| Variant | Fixtures | Fixtures Flagged | Flag Rate |
|---------|----------|------------------|-----------|
| nocontext | 29 | 29 | 100.00% |
| context | 29 | 1 | 3.45% |

**Discrimination delta:** 96.55% (nocontext flag rate − context flag rate)

## Correctness

- False negatives (nocontext fixture emits 0 W9100): **0** — must be 0
- False positives (context fixture emits W9100): **1** — must be 0; context at the template level OR on any resource satisfies the check

❌ Diagnostic does not discriminate cleanly — see per-fixture breakdown.

## Per-Scenario Breakdown

| Scenario | nocontext W9100 | context W9100 | Discriminates |
|----------|-----------------|---------------|---------------|
| add-dlq | 1 | 0 | ✓ |
| api-rate-limit-sharing | 1 | 0 | ✓ |
| canary-percentage-cap | 1 | 0 | ✓ |
| cfn-hook-awareness | 1 | 0 | ✓ |
| circular-dependency-prevention | 1 | 0 | ✓ |
| conditional-resource-coupling | 1 | 0 | ✓ |
| cost-allocation-team-budget | 1 | 0 | ✓ |
| cross-stack-reference-safety | 1 | 0 | ✓ |
| custom-naming-convention-violation | 1 | 0 | ✓ |
| deployment-window-restriction | 1 | 0 | ✓ |
| drift-detection-annotation | 1 | 0 | ✓ |
| environment-parameter-propagation | 1 | 0 | ✓ |
| failover-primary-designation | 1 | 0 | ✓ |
| flag-unmanaged | 1 | 0 | ✓ |
| iam-permission-boundary-respect | 1 | 0 | ✓ |
| inter-stack-ordering-dependency | 1 | 0 | ✓ |
| internal-sla-timeout-coupling | 1 | 0 | ✓ |
| lambda-layer-version-pinning | 1 | 0 | ✓ |
| max-memory-budget-constraint | 1 | 0 | ✓ |
| persist-context | 1 | 0 | ✓ |
| reserved-cidr-block | 1 | 0 | ✓ |
| resource-limit-awareness | 1 | 0 | ✓ |
| respect-constraint | 1 | 0 | ✓ |
| retain-deletion-policy | 1 | 0 | ✓ |
| security-group-blast-radius | 1 | 0 | ✓ |
| stack-output-dependency-chain | 1 | 1 | ✗ |
| tag-propagation-compliance | 1 | 0 | ✓ |
| update-policy-respect | 1 | 0 | ✓ |
| update-replacement-warning | 1 | 0 | ✓ |

## Methodology

Every fixture pair `<scenario>-nocontext.yaml` / `<scenario>-context.yaml` is run through the cfn-validate CLI with `--include-ids W9100` so only the missing-context diagnostic is reported. The diagnostic fires at most once per template: it emits a single W9100 warning when neither the top-level `Metadata.Context` block nor any resource's `Metadata.Context` carries design intent (`why`, `decisions`, `constraints`, `mutability`, or `metricsGuidance` with a non-empty value).

**Expected behavior.** A fixture in the nocontext arm has no Metadata.Context anywhere, so the diagnostic should fire exactly once. A fixture in the context arm has Metadata.Context at the template level, on at least one resource, or both — so the diagnostic should not fire at all. Clean discrimination is `100% (nocontext) → 0% (context)`.

**What this benchmark does NOT measure.** This is a static-correctness check on the diagnostic itself — not an agent-behavior benchmark. It answers "does the diagnostic distinguish present-vs-absent context?", not "does the diagnostic feedback cause downstream tooling to add context?". The latter requires running the CfnCloudContextPOCs harness with a validation-feedback loop wired in.

## Errors

No fixture failed to validate.
