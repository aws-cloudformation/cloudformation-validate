# cfn-validate

The command-line front end for the validation engine. This crate builds two binaries — `cfn-validate` (the validator)
and `cfn-benchmark` (a performance harness) — plus a small support library used by the binaries.

The CLI wires the workspace together: it parses a template with [template-model](../template-model/README.md), selects
an engine ([rego-engine](../rego-engine/README.md) or [cel-engine](../cel-engine/README.md)), runs the
[validation-engine](../validation-engine/README.md) pipeline (including [schema-validator](../schema-validator/README.md)),
and renders the resulting report as JSON.

> To embed validation in your own Rust program, depend on `validation-engine`, an engine crate, and `schema-validator`
> directly — see [validation-engine/API.md](../validation-engine/API.md). This crate is the CLI, not a library facade.

## How it works

```
  template.yaml ──▶ cfn-validate ──▶ JSON report (stdout)
                         │
                         ├── Parse template (template-model)
                         ├── Select engine (rego-engine or cel-engine)
                         ├── Run validation pipeline (validation-engine)
                         │   ├── Schema validation (schema-validator)
                         │   ├── Engine rule evaluation
                         │   ├── Step Functions validation
                         │   ├── Enrichment + filtering
                         │   └── Report assembly
                         └── Format output (standard / detailed)
```

## `cfn-validate`

Validates a CloudFormation template or all files in a directory. Recursively collects `.yaml`, `.yml`, and `.json` files
when given a directory path.

```
cfn-validate <TEMPLATE|DIR> [OPTIONS]
```

**Filter options:**

| Option                         | Description                        |
|--------------------------------|------------------------------------|
| `--include-ids ID,...`         | Only report these rule IDs         |
| `--exclude-ids ID,...`         | Suppress these rule IDs            |
| `--include-categories CAT,...` | Only report these categories       |
| `--exclude-categories CAT,...` | Suppress these categories          |
| `--include-range E3000-E3099`  | Only report rules in numeric range |
| `--exclude-range E3000-E3099`  | Suppress rules in numeric range    |

**Output options:**

| Option                                       | Description                      |
|----------------------------------------------|----------------------------------|
| `--format standard\|detailed`                | Detail level (default: detailed) |
| `--level fatal\|error\|warning\|info\|debug` | Minimum severity (default: info) |

**Engine options:**

| Option                       | Description                                          |
|------------------------------|------------------------------------------------------|
| `--engine rego\|cel`         | Validation engine (default: rego)                    |
| `--rule-source <PATH>`       | Load a custom Rego/CEL rule file (repeatable)        |
| `--guard-rule-source <PATH>` | Load Guard (`.guard`) rule file or directory (repeatable) |

**Parameter options:**

| Option                         | Description                                      |
|--------------------------------|--------------------------------------------------|
| `--region REGION`              | Set the `AWS::Region` pseudo-parameter           |
| `--parameter Key=Value`        | Override a template parameter value (repeatable) |
| `--pseudo-parameter Key=Value` | Override a pseudo-parameter value (repeatable)   |

Supported pseudo-parameters: `AWS::AccountId`, `AWS::NotificationARNs`, `AWS::Partition`, `AWS::Region`,
`AWS::StackId`, `AWS::StackName`, `AWS::URLSuffix`.

**Other options:**

| Option              | Description                                              |
|---------------------|---------------------------------------------------------|
| `--strict`          | Upgrade Warning-severity diagnostics to Error           |
| `--no-strict`       | Explicitly disable strict mode (the default)            |
| `--no-engine-rules` | Suppress engine-native (`RuleOrigin::Engine`) diagnostics |
| `--list-rules`      | List all available rules and exit                       |
| `--help`, `-h`      | Print usage and exit                                    |

**Exit codes:**

- `0` — no errors or fatal diagnostics
- `1` — errors or fatal diagnostics found
- `2` — usage error (bad arguments, file not found, engine init failure)

## `cfn-benchmark`

A performance harness that measures validation throughput against a template or directory. Useful for detecting
regressions in parsing, resolution, rule evaluation, and schema validation.

```
cargo run -p cfn-validate --bin cfn-benchmark -- <TEMPLATE|DIR> --engine rego|cel
```

## Library API

The crate's library target (`cfn_validate`) exposes the two helpers the binaries share:

| Function                              | Description                                                            |
|---------------------------------------|------------------------------------------------------------------------|
| `collect_files(path) -> Vec<PathBuf>` | Recursively collects `.yaml`/`.yml`/`.json` files from a path, sorted. |
| `parse_range(s) -> Option<IdRange>`   | Parses a rule ID range string like `E3000-E3099` into an `IdRange`.    |
