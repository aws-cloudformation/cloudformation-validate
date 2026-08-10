# resources

Test-fixture crate for `cloudformation-validate`. It holds the on-disk corpus consumed by the workspace's integration
and golden tests, and exposes the canonical template-discovery order so fixture producers and consumers agree on exactly
which files make up the corpus.

## Layout

| Directory    | Contents                                                                               |
|--------------|----------------------------------------------------------------------------------------|
| `templates/` | CloudFormation templates grouped by intent (`bad/`, `good/`, `cdk/`, `public/`, …)     |
| `rules/`     | Custom-rule fixtures loaded by rule tests                                              |
| `security/`  | Security-scenario fixtures                                                             |
| `expected/`  | The golden `validation_reports.json` - the recorded detailed report for every template |

## Golden generation

`expected/validation_reports.json` is the recorded `cfn-validate --format detailed` output for the whole template
corpus,
under both the rego and cel engines. Regenerate it with the `generate_validation_reports` example, which builds the
release
`cfn-validate` binary, runs both engines on every template in parallel across CPU cores, verifies the engines agree, and
writes the rego report (minus fields that differ per run or per engine) to the golden file:

```bash
cargo run --release -p resources --example generate_validation_reports
```

## Library API

| Function                    | Purpose                                                                      |
|-----------------------------|------------------------------------------------------------------------------|
| `resources_root()`          | This crate's root directory                                                  |
| `workspace_root()`          | The Cargo workspace root (parent of this crate), under which `target/` lives |
| `templates_dir()`           | The `templates/` directory                                                   |
| `expected_dir()`            | The `expected/` directory                                                    |
| `validation_reports_file()` | Path to `expected/validation_reports.json`                                   |
| `discover_templates()`      | Every template under `GOLDEN_DIRS`, as sorted forward-slash relative paths   |
| `GOLDEN_DIRS`               | Template subdirectories covered by the golden corpus                         |
