# rules

Shared foundation crate for rule definitions, severity model, category enum, and diagnostic filtering.

## Severity

| Variant | Ord | Meaning                                            |
|---------|-----|----------------------------------------------------|
| `Debug` | 0   | Internal diagnostic detail                         |
| `Info`  | 1   | Best practice suggestion (default)                 |
| `Warn`  | 2   | Security concern, deprecation, or risky pattern    |
| `Error` | 3   | Semantic error — likely deployment failure         |
| `Fatal` | 4   | Structural schema violation — deployment will fail |

Severity is derived from the first character of a rule ID: `F`→Fatal, `E`→Error, `W`→Warn, `I`→Info, `D`→Debug.

## Rule Registry

`RULE_REGISTRY` is the single source of truth for all rule IDs. Each entry has an `id`, `category`, `description`,
and `origin`.

`RuleInfo` is the serializable representation of a rule, produced from a `RuleDefinition` via `to_rule_info()` (e.g. by iterating `RULE_REGISTRY`):

```rust
pub struct RuleInfo {
    pub id: String,
    pub severity: Severity,
    pub category: Option<String>,
    pub description: String,
    pub origin: RuleOrigin,
}
```

## Category

| Variant        | Display                |
|----------------|------------------------|
| `Schema`       | `"Schema"`             |
| `Structure`    | `"Structure"`          |
| `Intrinsic`    | `"Intrinsic Function"` |
| `BestPractice` | `"Best Practice"`      |
| `Resource`     | `"Resource"`           |
| `Security`     | `"Security"`           |
| `Parameter`    | `"Parameter"`          |
| `Reference`    | `"Reference"`          |
| `Deprecation`  | `"Deprecation"`        |
| `General`      | `"General"`            |

Custom and guard rules use freeform category strings.

## RuleOrigin

| Variant   | Meaning                                      |
|-----------|----------------------------------------------|
| `Schema`  | Derived from CloudFormation provider schemas |
| `CfnLint` | Ported from cfn-lint                         |
| `Engine`  | Implemented in this validation engine        |
| `Custom`  | User-supplied custom rule                    |
| `Guard`   | CloudFormation Guard rule                    |

## Filtering

`FilterConfig` holds `include` and `exclude` filters across 6 dimensions:

| Dimension        | Match logic                                      |
|------------------|--------------------------------------------------|
| By ID            | Exact rule ID match                              |
| By category      | Match all rules in a category                    |
| By ID range      | Numeric range with prefix (e.g. `E3000`–`E3099`) |
| By regex         | Regex against rule ID                            |
| By resource ID   | Suppress a rule for a specific logical resource  |
| By resource type | Suppress a rule for a resource type              |

Include-then-exclude: if include filters are non-empty, a diagnostic must match at least one; any diagnostic matching
an exclude filter is removed.
