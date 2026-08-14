# rules

Rule metadata crate: rule definitions, severity model, category enum, and diagnostic filtering. Builds on
`template-model`, which owns the template vocabulary (`TopLevelSection`, `EntityType`) the filters reference.

## Severity

| Variant | Ord | Meaning                                            |
|---------|-----|----------------------------------------------------|
| `Debug` | 0   | Internal diagnostic detail                         |
| `Info`  | 1   | Best practice suggestion (default)                 |
| `Warn`  | 2   | Security concern, deprecation, or risky pattern    |
| `Error` | 3   | Semantic error - likely deployment failure         |
| `Fatal` | 4   | Structural schema violation - deployment will fail |

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

| Variant   | Meaning                                                                                          |
|-----------|--------------------------------------------------------------------------------------------------|
| `Schema`  | From CloudFormation's own definitions - provider schemas or template-language structure/syntax/shape rules that CloudFormation itself rejects |
| `CfnLint` | Lint judgment ported from cfn-lint (the template would still deploy, or the check's data originates in cfn-lint) |
| `Engine`  | Implemented in this validation engine                                                            |
| `Custom`  | User-supplied custom rule                                                                        |
| `Guard`   | CloudFormation Guard rule                                                                        |

## Filtering

`FilterConfig` holds `include` and `exclude` filters across 8 dimensions:

| Dimension        | Match logic                                              |
|------------------|----------------------------------------------------------|
| By ID            | Exact rule ID match                                      |
| By category      | Match all rules in a category                            |
| By ID range      | Numeric range with prefix (e.g. `E3000`–`E3099`)         |
| By regex         | Regex against rule ID                                    |
| By resource ID   | A rule (or every rule) on a specific logical resource    |
| By logical ID    | A rule (or every rule) on a named template entity, optionally scoped to one entity type |
| By resource type | A rule (or every rule) on a resource type                |
| By service       | A rule (or every rule) on a service (provider + service) |

The resource-ID, logical-ID, resource-type, and service dimensions each carry an optional `rule_id`: set it to scope
the filter to a single rule, or omit it to scope the filter to every rule on that entity, resource, type, or service.
The service is matched verbatim against the `service-provider::service-name` prefix of the resource type - its first
two `::`-delimited segments (e.g. `AWS::AutoScaling` in `AWS::AutoScaling::LaunchConfiguration`).

The resource-ID dimension matches only diagnostics attributed to a resource; the logical-ID dimension additionally
matches diagnostics on Parameters, Outputs, Mappings, Conditions, and template Rules (for resource diagnostics the two
carry the same value). A `LogicalIdFilter` also carries an optional `entity_type`: set it to match only entities of
that type (so `MyThing` as a Parameter is suppressed without touching a same-named Resource), or omit it to match
entities of every type.

Include-then-exclude: if include filters are non-empty, a diagnostic must match at least one; any diagnostic matching
an exclude filter is removed.
