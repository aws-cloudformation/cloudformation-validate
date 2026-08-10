# cfn-validate

The command-line front end for the validation engine.

The CLI wires the workspace together: it parses a template with [template-model](../template-model/README.md), selects
an engine ([rego-engine](../rego-engine/README.md) or [cel-engine](../cel-engine/README.md)), runs the
[validation-engine](../validation-engine/README.md) pipeline (
including [schema-validator](../schema-validator/README.md)),
and renders the resulting report as JSON.

> To embed validation in your own Rust program, depend on `validation-engine`, an engine crate, and `schema-validator`
> directly - see [validation-engine/API.md](../validation-engine/API.md). This crate is the CLI, not a library facade.

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
| `--include-resource-id ID[=RULE]` | Only report rules on a logical resource ID |
| `--exclude-resource-id ID[=RULE]` | Suppress rules on a logical resource ID |
| `--include-logical-id ID[:TYPE][=RULE]` | Only report rules on a named template entity (resource, parameter, output, mapping, condition, or rule); `:TYPE` (e.g. `:Parameter`) scopes to one entity type |
| `--exclude-logical-id ID[:TYPE][=RULE]` | Suppress rules on a named template entity |
| `--include-resource-type TYPE[=RULE]` | Only report rules on a resource type |
| `--exclude-resource-type TYPE[=RULE]` | Suppress rules on a resource type |
| `--include-service SERVICE[=RULE]` | Only report rules on a service prefix (e.g. `AWS::AutoScaling`) |
| `--exclude-service SERVICE[=RULE]` | Suppress rules on a service prefix |

Scoped filters take an optional `=RULE` suffix: `--exclude-logical-id MyParam=W2001` suppresses only W2001 on
`MyParam`, while `--exclude-logical-id MyParam` suppresses every rule on it. The logical-id flags additionally take an
optional `:TYPE` scope: `--exclude-logical-id MyThing:Parameter` suppresses rules on the parameter `MyThing` without
touching a same-named entity of another type.

**Output options:**

| Option                                    | Description                      |
|-------------------------------------------|----------------------------------|
| `--format standard\|detailed`             | Detail level (default: detailed) |
| `--level fatal\|error\|warn\|info\|debug` | Minimum severity (default: info) |

**Engine options:**

| Option                       | Description                                               |
|------------------------------|-----------------------------------------------------------|
| `--engine rego\|cel`         | Validation engine (default: rego)                         |
| `--rule-source <PATH>`       | Load a custom Rego/CEL rule file (repeatable)             |
| `--guard-rule-source <PATH>` | Load Guard (`.guard`) rule file or directory (repeatable) |
| `--additional-schema <PATH>` | Merge a CloudFormation resource provider schema (`.json`) file, or every `.json` in a directory, on top of the bundled schemas (repeatable) |

`--additional-schema` is for templates that use a property or allowed value CloudFormation has not published to the
registry yet: the supplied schema is merged into the bundled schema for its `typeName`, and a `typeName` with no bundled
schema is registered as a new resource type. An overlay never silently drops a bundled constraint, though stating an
extra `required` or dependency entry does add one. Anything that cannot be applied exits `2` rather than being ignored -
a malformed or unreadable schema, a path that does not exist, a directory containing no `.json` file, or a schema using a
construct the validator cannot represent. Directories are scanned one level deep. See
[validation-engine/API.md](../validation-engine/API.md#additional-resource-provider-schemas) for the merge model and its
scope limits.

**Parameter options:**

| Option                         | Description                                      |
|--------------------------------|--------------------------------------------------|
| `--region REGION`              | Set the `AWS::Region` pseudo-parameter           |
| `--parameter Key=Value`        | Override a template parameter value (repeatable) |
| `--pseudo-parameter Key=Value` | Override a pseudo-parameter value (repeatable)   |

Supported pseudo-parameters: `AWS::AccountId`, `AWS::NotificationARNs`, `AWS::Partition`, `AWS::Region`,
`AWS::StackId`, `AWS::StackName`, `AWS::URLSuffix`.

**Other options:**

| Option              | Description                                               |
|---------------------|-----------------------------------------------------------|
| `--strict`          | Upgrade Warn-severity diagnostics to Error                |
| `--disable-builtin-rules` | Disable all built-in rules; only evaluate custom and guard rules |
| `--list-rules`      | List all available rules and exit                         |
| `--help`, `-h`      | Print usage and exit                                      |

**Exit codes:**

- `0` - no errors or fatal diagnostics
- `1` - errors or fatal diagnostics found
- `2` - usage error (bad arguments, file not found, engine init failure)
