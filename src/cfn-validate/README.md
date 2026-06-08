# cfn-validate

CLI binary and library facade for the CloudFormation Validation Engine. Provides the `cfn-validate` binary
and re-exports all workspace crate APIs through a single entry point.

## How It Works

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

## Commands

### `cfn-validate`

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

| Option                       | Description                                |
|------------------------------|--------------------------------------------|
| `--engine rego\|cel`         | Validation engine (default: rego)          |
| `--rule-source <PATH>`       | Load custom rule file (repeatable)         |
| `--guard-rule-source <PATH>` | Load Guard (.guard) rule file or directory |

**Parameter options:**

| Option                         | Description                                      |
|--------------------------------|--------------------------------------------------|
| `--region REGION`              | Set AWS::Region pseudo-parameter                 |
| `--parameter Key=Value`        | Override a template parameter value (repeatable) |
| `--pseudo-parameter Key=Value` | Override a pseudo-parameter value (repeatable)   |

Supported pseudo-parameters: `AWS::AccountId`, `AWS::NotificationARNs`, `AWS::Partition`, `AWS::Region`,
`AWS::StackId`, `AWS::StackName`, `AWS::URLSuffix`.

**Other options:**

| Option              | Description                                             |
|---------------------|---------------------------------------------------------|
| `--strict`          | Upgrade Warning-severity diagnostics to Error           |
| `--no-strict`       | Explicitly disable strict mode                          |
| `--no-engine-rules` | Suppress engine-native (RuleOrigin::Engine) diagnostics |
| `--list-rules`      | List all available rules and exit                       |

**Exit codes:**

- `0` — no errors or fatal diagnostics
- `1` — errors or fatal diagnostics found
- `2` — usage error (bad arguments, file not found, engine init failure)

## Library API

The library crate (`cfn_validate`) exports:

| Function                              | Description                                                            |
|---------------------------------------|------------------------------------------------------------------------|
| `collect_files(path) -> Vec<PathBuf>` | Recursively collects `.yaml`/`.yml`/`.json` files from a path. Sorted. |
| `parse_range(s) -> Option<IdRange>`   | Parses a rule ID range string like `E3000-E3099` into an `IdRange`.    |
