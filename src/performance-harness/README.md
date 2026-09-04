# Performance harness

Performance is checked against a versioned environment profile, never against another Git revision.

* `expected/github-ubuntu-x64-amd-epyc-7763.json`, `expected/github-ubuntu-x64-amd-epyc-9v74.json`, and `expected/github-ubuntu-x64-intel-xeon-platinum-8573c.json` are separate tight contracts for CPU models used by GitHub-hosted `ubuntu-latest` x64 runners. The harness derives and enforces the matching model automatically.
* `expected/local-macos-arm64.json` is the contract for the recorded reference Apple Silicon Mac. The harness rejects a different Mac model instead of comparing unlike hardware.

The `check` command spawns the current release executable for both engines across synthetic, real-template, and security workloads. Each case discards its first process launch, then uses the median of five independent launches. An apparent failure receives four additional samples and is evaluated again over the combined set.

Only robust end-to-end metrics are enforced: initialization plus first validation, warm validation time per call above the profile's stability floor, and peak resident memory. Per-case ratios are normalized by the run-wide geometric-mean ratio for that metric, removing common GitHub host-speed shifts; the raw aggregate separately fails broad changes that exceed its explicit band. The long cross-reference-fanout timing case is aggregate-only because identical-tree GitHub runs showed workload-specific variance beyond the normal residual range.

The checked-in two-sided limits are intentionally tight:

* GitHub: normalized per-case timing ±15%, raw aggregate timing ±10%, normalized RSS ±3%, aggregate RSS ±1%.
* Reference Mac: normalized per-case timing ±8%, raw aggregate init ±7%, raw aggregate warm ±6%, normalized RSS ±2%, aggregate RSS ±1%.

Crossing an upper bound is a regression. Crossing a lower bound is an unexpectedly large improvement and also fails so the baseline cannot silently become stale. Apparent failures are evaluated again after confirmation samples.

## Run locally

On the recorded reference Mac, the profile is selected automatically:

```bash
cd src
cargo run --locked --release -p performance-harness -- check
```

Results and a ready-to-review candidate baseline are written under `tmp/performance-check/` at the repository root.

## Update an expected file

Update the local reference profile only after confirming an intentional performance change:

```bash
cd src
cargo run --locked --release -p performance-harness -- update
```

GitHub expectations must be measured on GitHub-hosted runners. Every workflow run uploads `performance-candidate-baseline.json`; after a confirmed improvement or an intentional regression, use the candidate to update the matching CPU-specific profile in review. Never copy local Linux measurements into a GitHub profile.

A previously unseen GitHub CPU still fails the required check. Instead of failing before measurement, the harness collects nine independent launches per case and uploads a CPU-enforced candidate plus raw results. Validate repeated hosted-runner evidence before adding the candidate under its suggested deterministic profile name; the unknown hardware cannot pass until that profile is checked in.

Changing workloads causes an exact case-set mismatch and requires an intentional baseline regeneration. Environment mismatches fail before measurement rather than producing misleading performance results.
