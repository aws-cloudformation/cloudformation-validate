# Custom Rules Reference

## CEL Rules (JSON)

A JSON file with a `rules` array. Each rule's `expression` is a [CEL](https://cel.dev/) expression that fires when it evaluates to `true`.

### Schema

| Field | Required | Description |
|-------|----------|-------------|
| `rule_id` | Yes | Unique identifier shown in diagnostics |
| `severity` | Yes | `FATAL`, `ERROR`, `WARN`, `INFO`, or `DEBUG` |
| `expression` | Yes | CEL expression — fires when `true` |
| `message` | Yes | Diagnostic message |
| `resource_type` | No | Scope to a resource type (e.g. `AWS::S3::Bucket`). Omit for global rules. |
| `category` | No | Category label for filtering |
| `prop_path` | No | Property path for source location (e.g. `Properties.BucketEncryption`) |
| `suggested_fix` | No | Remediation hint |

### Context Variables

When `resource_type` is set, the expression runs once per matching resource:

| Variable | Type | Description |
|----------|------|-------------|
| `name` | string | Logical resource ID |
| `resource` | map | Full resolved resource |
| `properties` | map | Resolved properties |
| `resolved_properties` | map | Properties with fully resolved intrinsic values |

Global variables (always available):

| Variable | Type | Description |
|----------|------|-------------|
| `resources` | map | All resources keyed by logical ID |
| `parameters` | map | All parameters with type, default, constraints |
| `conditions` | map | All conditions |
| `outputs` | map | All outputs |
| `mappings` | map | All mappings |
| `template` | map | Template metadata (transforms, format version, description) |

### Example

```json
{
  "rules": [
    {
      "rule_id": "CUSTOM001",
      "severity": "ERROR",
      "resource_type": "AWS::S3::Bucket",
      "expression": "!has(properties.BucketEncryption)",
      "message": "S3 bucket must have encryption configured",
      "prop_path": "Properties.BucketEncryption",
      "suggested_fix": "Add BucketEncryption with SSEAlgorithm: aws:kms"
    },
    {
      "rule_id": "CUSTOM002",
      "severity": "WARN",
      "resource_type": "AWS::Lambda::Function",
      "expression": "has(properties.Runtime) && properties.Runtime == 'python3.8'",
      "message": "Lambda uses deprecated Python 3.8 runtime",
      "prop_path": "Properties.Runtime",
      "suggested_fix": "Upgrade to python3.12 or later"
    },
    {
      "rule_id": "CUSTOM003",
      "severity": "INFO",
      "expression": "size(resources) > 200",
      "message": "Template has over 200 resources — consider nested stacks"
    }
  ]
}
```

---

## Rego Rules

A `.rego` file that declares a package and populates a `violation` set using diagnostic builtins.

### Structure

```rego
package my_rules

import rego.v1

violation contains v if {
    some name, res in input.resources
    res.resourceType == "AWS::S3::Bucket"
    not res.properties.BucketEncryption
    v := make_diag("CUSTOM001", "ERROR", name, "S3 bucket must have encryption configured")
}
```

1. Declare a `package`.
2. Import `rego.v1`.
3. Add elements to `violation` using `make_diag` builtins.

### Input Model

| Path | Description |
|------|-------------|
| `input.resources[id].resourceType` | e.g. `"AWS::S3::Bucket"` |
| `input.resources[id].properties` | Resolved property values |
| `input.resources[id].condition` | Condition name (if conditional) |
| `input.resources[id].dependsOn` | DependsOn targets |
| `input.parameters` | Parameters with type, default, constraints |
| `input.conditions` | Conditions with expression and dependencies |
| `input.outputs` | Outputs with resolved values |
| `input.mappings` | Mappings |
| `input.template` | Template metadata (transforms, formatVersion, description) |
| `input.edges` | Reference graph edges |

### Diagnostic Builtins

| Builtin | Signature |
|---------|-----------|
| `make_diag` | `(rule_id, severity, resource_id, message)` |
| `make_diag_at` | `(rule_id, severity, resource_id, prop_path, message)` |
| `make_diag_full` | `(rule_id, severity, resource_id, prop_path, message, suggested_fix, doc_url)` |
| `make_diag_related` | `(rule_id, severity, resource_id, prop_path, message, related_locations)` |
| `make_diag_conditional` | `(rule_id, severity, resource_id, prop_path, message, conditions)` |

Severity is a string: `"FATAL"`, `"ERROR"`, `"WARN"`, `"INFO"`, `"DEBUG"`. Pass `""` for `resource_id` on template-level diagnostics. Pass `""` for optional string args to omit them.

### Template Introspection Builtins

Called as bare functions (no namespace prefix). See the [rego-engine README](rego-engine/README.md) for the full list.
Key ones:

| Builtin | Purpose |
|---------|---------|
| `resolve(resource_id, path)` | Resolve a property through intrinsics |
| `has_property(resource_id, path)` | Check if a property exists |
| `resources_of_type(type)` | Get all logical IDs of a resource type |
| `is_dynamic(resource_id, path)` | Check if a property is unresolvable |
| `schema_enum(resource_type, prop)` | Get allowed enum values |

### Example

```rego
package encryption_rules

import rego.v1

violation contains v if {
    some name, res in input.resources
    res.resourceType == "AWS::S3::Bucket"
    not res.properties.BucketEncryption
    v := make_diag_at("CUSTOM001", "ERROR", name,
        "Properties.BucketEncryption",
        "S3 bucket must have encryption configured")
}

violation contains v if {
    some name, res in input.resources
    res.resourceType == "AWS::Lambda::Function"
    res.properties.Runtime == "python3.8"
    v := make_diag_full("CUSTOM002", "WARN", name,
        "Properties.Runtime",
        "Lambda uses deprecated Python 3.8 runtime",
        "Upgrade to python3.12 or later",
        "https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html")
}
```

---

## Guard DSL Rules

[CloudFormation Guard](https://docs.aws.amazon.com/cfn-guard/latest/ug/what-is-guard.html) declarative rules. Translated internally — works with both `RegoEngine` and `CelEngine`.

### Structure

```
rule <rule_name> {
    <ResourceType> {
        <property_check>
        <<error message>>
    }
}
```

### Operators

| Operator | Meaning |
|----------|---------|
| `==`, `!=` | Equality |
| `>`, `>=`, `<`, `<=` | Numeric comparison |
| `IN` | Value in list |
| `NOT` | Negation |
| `EXISTS` / `NOT EXISTS` | Property presence |
| `IS_STRING`, `IS_LIST`, `IS_INT` | Type checks |

### Example

```
rule s3_encryption {
    AWS::S3::Bucket {
        Properties.BucketEncryption EXISTS
        <<S3 bucket must have encryption configured>>
    }
}

rule s3_versioning {
    AWS::S3::Bucket {
        Properties.VersioningConfiguration.Status == "Enabled"
        <<S3 bucket must have versioning enabled>>
    }
}

rule lambda_timeout {
    AWS::Lambda::Function {
        Properties.Timeout EXISTS
        <<Lambda function should have an explicit timeout>>
    }
}
```

---

## Choosing a Format

| | CEL (JSON) | Rego | Guard DSL |
|---|---|---|---|
| **Best for** | Property checks, data-driven rules | Complex cross-resource logic | Declarative compliance |
| **Engine** | `CelEngine` | `RegoEngine` | Either |
| **Template introspection** | Context variables | Full builtin library | Property checks only |
| **Cross-resource** | Via `resources` global | Via `input.resources` + builtins | No |
