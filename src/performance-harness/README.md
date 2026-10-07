# Performance harness

CI checks performance by comparing the tested revision with the last release, both built and measured on the same
runner. No measurement is checked in, so a new runner CPU model or a schema/data-source update cannot make an
expectation stale.

## How a comparison runs

The `performance-regression` workflow builds the harness twice - once from the tested commit (head) and once from the
base revision - and runs:

```bash
cd src
cargo run --locked --release -p performance-harness -- \
  compare --base-executable <base performance-harness> [--base-revision <revision>] [--title <text>] [--output-dir <directory>]
```

The head harness defines the workloads, templates, and evaluation; the base executable supplies only its `measure`
worker, so the `measure` command-line interface and its JSON output must stay backward compatible.

For every engine (rego, cel, composite) and every synthetic, real-template, and security workload, the harness
discards one launch of each side, then runs five base/head launch pairs back to back on one pinned CPU, alternating
which side starts each pair. A metric's ratio is the median of the per-pair head/base ratios, which cancels host speed
changes shared by both launches of a pair. An apparent regression receives four more pairs and is evaluated again.

The enforced metrics are initialization plus first validation, warm validation time per call, and peak resident
memory. A metric is gated only when the base measurement is above its stability floor (5 ms, 0.30 ms, and 16 MiB); the
long cross-reference-fanout workload gates only memory per case, and the deep-nesting workloads gate only warm time.
The limits are:

| Metric                  | Per case | Aggregate (geometric mean) |
|-------------------------|---------:|---------------------------:|
| Init + first, warm/call |    1.20x |                      1.08x |
| Peak RSS                |    1.10x |                      1.05x |

Exceeding a limit fails the check. Improvements and changed diagnostics are reported but never fail, because there is
no checked-in expectation to keep current. Results are written to `performance-comparison.md` (also added to the job
summary) and `performance-comparison.json`.

## Where the check runs and what it compares against

`Check expected performance` runs on every pull request and push to `main`, on manual runs of the `Validate` and
`Performance` workflows, and during a release. Pull requests and pushes gate on it; the release workflow runs it with
`performance-gate: false`, so the report is attached to the release run but never blocks publishing.

The base is the release tag recorded in [`drift-anchor.txt`](drift-anchor.txt). Comparing every tested commit with the
last accepted release shows the cost of the change under review together with everything that has accumulated on `main`
since that release, so small regressions that would each pass a commit-to-commit comparison cannot add up unnoticed.
When the check fails on a pull request that did not itself change performance, `main` has drifted past the budget since
the release: fix the regression, or advance the anchor as described below. The check is skipped when the tested commit
is the anchored release itself.

A manual run of the `Performance` workflow can set `base` to `parent` (the tested commit's first parent, which isolates
one change) or to any git revision for investigation.

### Advancing the drift anchor

`drift-anchor.txt` holds one release tag (`MAJOR.MINOR.PATCH`, optionally `-beta`) and nothing else. Bundled schema
data only grows, so peak memory trends upward with every data-source update and the check will eventually fail even
without a code regression; one measured update cost about 1% aggregate peak memory and under 0.5% aggregate time, so
the 1.05x memory limit absorbs several of them. Replace the tag in a reviewed change once the accumulated change since
it is understood and accepted - normally with each new release, so that every release is checked against the previous
one. The anchor is a tag rather than recorded numbers, so it is independent of runner hardware and never needs
measurements from a GitHub runner to update.

## Run locally

Build the base harness from a clean export of the base revision, then pass it to `compare`. Reusing the workspace
target directory avoids rebuilding the unchanged third-party dependencies:

```bash
mkdir -p tmp/perf-base && git archive main | tar -x -C tmp/perf-base
(cd tmp/perf-base/src && CARGO_TARGET_DIR="$PWD/../../../src/target" cargo build --locked --release -p performance-harness)
cp src/target/release/performance-harness tmp/perf-base-harness
cd src
cargo run --locked --release -p performance-harness -- compare --base-executable ../tmp/perf-base-harness
```

Results are written under `tmp/performance-check/` at the repository root. A full comparison takes about 15-20
minutes; run it on an otherwise idle machine, because a background load that hits only one launch of a pair shows up
as noise.
