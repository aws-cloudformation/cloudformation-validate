# resources

Test-fixture crate for `cloudformation-validate`. It holds the on-disk corpus consumed by the workspace's integration
and snapshot tests, and exposes fixture paths plus discovery used by snapshot generation.

## Layout

| Directory    | Contents                                                                                       |
|--------------|------------------------------------------------------------------------------------------------|
| `templates/` | CloudFormation templates grouped by intent (`bad/`, `good/`, `cdk/`, `public/`, …)             |
| `rules/`     | Custom-rule fixtures loaded by rule tests, and the benchmark rule packs (see below)             |
| `security/`  | Security-scenario fixtures used by security tests and snapshot generation                      |
| `expected/`  | `validation_reports1.json`, `validation_reports2.json`, … numbered chunk snapshots              |

## Benchmark rule packs

`scripts/compare_benchmarks.py` measures the Rego and composite engines with the built-in rules alone and under
separate custom-rule loads. Its `custom` scenario loads every `.rego` file in `rules/`, while its `guard` scenario
loads every `.guard` file; the harnesses receive the directory and load the files themselves. The packs are therefore
exactly the `.guard` and `.rego` files of this directory - a new fixture joins the next benchmark
automatically, and one that fails to evaluate on a corpus template shows up in the report's "Templates Failing Under
a Rule Pack" list rather than silently.

- **Guard pack** (`guard_*.guard`, 19 files, 35 non-parameterized rule declarations under 34 distinct names (the count
  the report shows), plus 4 parameterized helper rules). Three files are fixtures the rule tests use
  (`guard_encryption.guard`, `guard_multi.guard`, `guard_semantics.guard`). The other 16 are the security and
  compliance rules of [cloudformation-guard](https://github.com/aws-cloudformation/cloudformation-guard) at commit
  `814bd00a4e6d761e8b5c9f615dd510b1a2a7c374`, copied verbatim. Local filenames use the pattern `guard_<upstream stem
  with hyphens replaced by underscores>.guard`. The pack includes every CloudFormation example under `guard-examples/`
  (security policies, encryption, deployment safety, cross-account access, tagging, network reachability) plus the
  compliance rules among the `guard/resources/validate/` fixtures (`workshop`, `db_param_port_rule`, and the three
  `s3_bucket_*` rules). The remaining upstream fixtures exercise evaluator semantics and built-in functions rather
  than check anything (`seven-compliant-rules`, `count`, `join`, `substring`, ...) and are left out: every Guard file
  costs roughly the same per template regardless of what it checks (about 0.5 ms on the corpus average), so the pack
  is limited to rules worth paying for and the benchmark job stays well inside the runner's time limit. Guard type
  blocks (used by the three test fixtures) are an evaluation error on the 26 corpus templates whose `Resources`
  section is empty; those templates are reported as failed in the Guard scenarios and excluded from their timings.
- **Custom Rego pack** (`rego_*.rego`, 10 files). Three are the rule-test fixtures; the other seven are authored
  here for the benchmark and hold 50 rule IDs across seven packages (`custom_iam`, `custom_network`,
  `custom_encryption`, `custom_s3`, `custom_compute`, `custom_data`, `custom_graph`). They are deliberately
  expensive and realistic: policy-document decomposition over every policy-bearing resource type, a whole-template
  credential scan over serialized properties, table-driven encryption checks resolved per condition scenario,
  pairwise subnet CIDR overlap under compatible conditions, service-role trust chains followed through references,
  pairwise duplicate-definition detection, and transitive dependency hubs computed with the graph builtins. Every
  rule evaluates cleanly on every corpus template. Keep new rules deterministic (no wall-clock or random builtins)
  and check `cfn-validate resources/templates --engine rego --rule-source <file>` reports no
  `Custom rule package ... failed to evaluate` errors before adding one.

Both benchmarked engines see the same packs, so the Guard scenario also compares Rego and composite aggregate
diagnostic counts (Fatal/Error/Warn/Info) under load.

## Snapshot generation

`expected/validation_reports*.json` are sanitized `cfn-validate --format detailed --level debug` reports for the
regular template corpus and every JSON/YAML fixture under `security/`, using the rego, cel, and composite engines.
Durations are zeroed; top-level `version` and `performance` plus metadata bundle versions and `rulesEvaluated` are
removed; findings listed in `expected/snapshot_excluded_rule_ids.txt` are excluded. Reports are deterministically
partitioned by sorted template key into numbered chunk files with at most 100 templates each. Regenerate them with the
`generate_validation_reports` example, which builds the release `cfn-validate` binary, runs all three engines on every
fixture in parallel across CPU cores, verifies the engines agree, prints each template's validation time in
milliseconds and the summed total in seconds, removes any legacy single file and stale extra chunks, and writes fresh
numbered chunks. The composite report is the one persisted; with no custom rules it matches the standalone rego and
cel engines:

```bash
cargo run --release -p resources --example generate_validation_reports
```

`discover_snapshot_templates()` combines the regular corpus returned by `discover_templates()` with security fixtures
using canonical `security/`-prefixed keys. Core and binding snapshot comparisons use regular-template-only discovery;
the core suite calls the security-inclusive API only to assert that its discovered keys match every persisted report
key.

## Library API

| Function                        | Purpose                                                                      |
|---------------------------------|------------------------------------------------------------------------------|
| `resources_root()`              | This crate's root directory                                                  |
| `workspace_root()`              | The Cargo workspace root (parent of this crate), under which `target/` lives |
| `templates_dir()`               | The `templates/` directory                                                   |
| `security_dir()`                | The `security/` fixture directory                                            |
| `expected_dir()`                | The `expected/` directory                                                    |
| `TEMPLATES_PER_CHUNK`           | Maximum templates per snapshot chunk file (100)                              |
| `snapshot_chunk_filename(n)`    | Build the filename for 1-based chunk index n                                 |
| `discover_snapshot_chunks()`    | Discover all numbered chunk files in numeric order                           |
| `load_merged_snapshots()`       | Load and merge all chunks, failing on duplicates or malformed data           |
| `legacy_validation_reports_file()` | Path to the legacy single file (for cleanup only)                         |
| `discover_templates()`          | Every JSON/YAML template recursively under `templates/`, as sorted relative paths |
| `discover_snapshot_templates()` | All templates plus `security/` fixtures as sorted canonical keys                 |
