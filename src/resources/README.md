# resources

Test-fixture crate for `cloudformation-validate`. It holds the on-disk corpus consumed by the workspace's integration
and golden tests, and exposes fixture paths plus discovery used by snapshot generation.

## Layout

| Directory    | Contents                                                                                       |
|--------------|------------------------------------------------------------------------------------------------|
| `templates/` | CloudFormation templates grouped by intent (`bad/`, `good/`, `cdk/`, `public/`, …)             |
| `rules/`     | Custom-rule fixtures loaded by rule tests                                                      |
| `security/`  | Security-scenario fixtures used by security tests and snapshot generation                      |
| `expected/`  | `validation_reports.json` snapshots for regular templates and security fixtures                |

## Snapshot generation

`expected/validation_reports.json` is the recorded `cfn-validate --format detailed` output for the regular template corpus
and every JSON/YAML fixture under `security/`, using both the rego and cel engines. Regenerate it with the
`generate_validation_reports` example, which builds the release `cfn-validate` binary, runs both engines on every
fixture in parallel across CPU cores, verifies the engines agree, prints the elapsed validation time in milliseconds,
and writes the rego report (minus fields that differ per run or per engine) to the snapshot file:

```bash
cargo run --release -p resources --example generate_validation_reports
```

`discover_snapshot_templates()` combines the regular corpus returned by `discover_templates()` with security fixtures
using canonical `security/`-prefixed keys. Core and binding golden tests maintain regular-template-only discovery and do
not call the security-inclusive snapshot API.

## Library API

| Function                        | Purpose                                                                      |
|---------------------------------|------------------------------------------------------------------------------|
| `resources_root()`              | This crate's root directory                                                  |
| `workspace_root()`              | The Cargo workspace root (parent of this crate), under which `target/` lives |
| `templates_dir()`               | The `templates/` directory                                                   |
| `security_dir()`                | The `security/` fixture directory                                            |
| `expected_dir()`                | The `expected/` directory                                                    |
| `validation_reports_file()`     | Path to `expected/validation_reports.json`                                   |
| `discover_templates()`          | Regular template corpus as sorted, template-relative paths                   |
| `discover_snapshot_templates()` | Regular templates plus `security/` fixtures as sorted canonical keys         |
| `GOLDEN_DIRS`                   | Template-relative directories in the regular snapshot corpus                 |
