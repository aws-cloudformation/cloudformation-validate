# resources

Test-fixture crate for `cloudformation-validate`. It holds the on-disk corpus consumed by the workspace's integration
and snapshot tests, and exposes fixture paths plus discovery used by snapshot generation.

## Layout

| Directory    | Contents                                                                                       |
|--------------|------------------------------------------------------------------------------------------------|
| `templates/` | CloudFormation templates grouped by intent (`bad/`, `good/`, `cdk/`, `public/`, …)             |
| `rules/`     | Custom-rule fixtures loaded by rule tests                                                      |
| `security/`  | Security-scenario fixtures used by security tests and snapshot generation                      |
| `expected/`  | `validation_reports1.json`, `validation_reports2.json`, … numbered chunk snapshots              |

## Snapshot generation

`expected/validation_reports*.json` are the recorded `cfn-validate --format detailed` output for the regular template
corpus and every JSON/YAML fixture under `security/`, using both the rego and cel engines. Reports are
deterministically partitioned by sorted template key into numbered chunk files with at most 100 templates each.
Regenerate them with the `generate_validation_reports` example, which builds the release `cfn-validate` binary, runs
both engines on every fixture in parallel across CPU cores, verifies the engines agree, prints the elapsed validation
time in milliseconds, removes any legacy single file and stale extra chunks, and writes fresh numbered chunks:

```bash
cargo run --release -p resources --example generate_validation_reports
```

`discover_snapshot_templates()` combines the regular corpus returned by `discover_templates()` with security fixtures
using canonical `security/`-prefixed keys. Core and binding snapshot tests maintain regular-template-only discovery and
do not call the security-inclusive snapshot API.

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
