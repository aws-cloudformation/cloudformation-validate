# rego-engine

Validates CloudFormation templates using Rego policies evaluated by the [Regorus](https://github.com/microsoft/regorus)
interpreter. Implements the [ValidationEngine](../validation-engine/README.md) trait. Custom builtins bridge Rego
policies to the [SemanticModel](../template-model/README.md) for deep template introspection that pure Rego cannot
express.

## Architecture

Rules are organized into Rego packages by category:

| Package          | Eval Path                       | Category             |
|------------------|---------------------------------|----------------------|
| `structure`      | `data.structure.violation`      | Template structure   |
| `intrinsics`     | `data.intrinsics.violation`     | Intrinsic functions  |
| `references`     | `data.references.violation`     | Cross-resource refs  |
| `best_practices` | `data.best_practices.violation` | Best practices       |
| `resources`      | `data.resources.violation`      | Resource-specific    |
| `all_violations` | `data.all_violations.violation` | All packages at once |

Rules come from four sources: handwritten Rego policies (embedded), generated data from
data-source (embedded), user-provided custom Rego policies, and Guard DSL files translated
to Rego at engine initialization.

## Custom Builtins

These builtins are registered with the Regorus interpreter and called as bare functions in Rego policies — there is no
namespace prefix. For example, a policy calls `resolve(name, "Properties.BucketName")`, not `cfn.resolve(...)`.

### Template Resolution

| Builtin              | Signature                                                     | Purpose                                              |
|----------------------|---------------------------------------------------------------|------------------------------------------------------|
| `resolve`            | `(resource_id, path) → value`                                 | Resolve a property value through intrinsic functions |
| `resolve_all`        | `(resource_id, path) → [values]`                              | Resolve all scenario values for a property           |
| `resolve_scenarios`  | `(resource_id, path) → [{value, conditions}]`                 | Resolve all (value, condition_map) pairs             |
| `resolve_ref_target` | `(resource_id, path) → {resourceType, condition, properties}` | Resolve the target of a reference                    |
| `resolve_type`       | `(resource_id, path) → type_string`                           | Get the resolved value type                          |
| `is_dynamic`         | `(resource_id, path) → bool`                                  | Check if a property contains unresolvable content    |
| `is_from_parameter`  | `(resource_id, path) → bool`                                  | Check if a property originates from a parameter      |
| `is_from_intrinsic`  | `(resource_id, path) → bool`                                  | Check if a property originates from an intrinsic     |
| `follow_ref`         | `(resource_id, path) → target_id`                             | Follow a Ref/GetAtt to its target resource           |
| `flatten_list`       | `(resource_id, path) → [{value, index}]`                      | Flatten nested arrays                                |

### Resource Queries

| Builtin             | Signature                         | Purpose                                  |
|---------------------|-----------------------------------|------------------------------------------|
| `get_resource`      | `(resource_id) → resource_object` | Get full resolved resource data          |
| `has_property`      | `(resource_id, path) → bool`      | Check if a property exists on a resource |
| `resources_of_type` | `(type_name) → [resource_ids]`    | Get all logical IDs of a resource type   |
| `has_transform`     | `(transform_name) → bool`         | Check if a transform is declared         |

### Graph Queries

| Builtin              | Signature                               | Purpose                                     |
|----------------------|-----------------------------------------|---------------------------------------------|
| `ref_targets`        | `(resource_id) → [target_ids]`          | Outgoing reference targets                  |
| `ref_sources`        | `(resource_id) → [source_ids]`          | Incoming reference sources                  |
| `depends_on`         | `(resource_a, resource_b) → bool`       | Transitive dependency check                 |
| `edges_from`         | `(resource_id) → [edge_objects]`        | Detailed outgoing edges                     |
| `edges_to`           | `(resource_id) → [edge_objects]`        | Detailed incoming edges                     |
| `pipeline_artifacts` | `(resource_id) → {issues: [{message}]}` | Extract CodePipeline artifact relationships |

### Condition Analysis

| Builtin                   | Signature                                       | Purpose                                          |
|---------------------------|-------------------------------------------------|--------------------------------------------------|
| `conditions_compatible`   | `(cond_a, cond_b) → bool`                       | Can both conditions be true simultaneously?      |
| `condition_implies`       | `(cond_a, cond_b) → bool`                       | Does cond_a=true force cond_b=true?              |
| `conjunction_implies`     | `(guard1, guard2, target) → bool`               | Does the conjunction of two guards imply target? |
| `resource_condition`      | `(resource_id) → condition_name`                | Get the Condition on a resource                  |
| `is_satisfiable`          | `(assumptions) → bool`                          | Is a set of condition assumptions satisfiable?   |
| `unreachable_if_branches` | `(resource_id) → [{resourceId, path, message}]` | Find unreachable Fn::If branches in a resource   |

### Parameter / Mapping

| Builtin                | Signature                    | Purpose                              |
|------------------------|------------------------------|--------------------------------------|
| `param_allowed_values` | `(param_name) → [values]`    | Get AllowedValues for a parameter    |
| `param_type`           | `(param_name) → type_string` | Get the declared Type of a parameter |
| `mapping_value`        | `(map, key1, key2) → value`  | Look up a value in Mappings          |

### Schema Introspection

| Builtin                | Signature                                  | Purpose                        |
|------------------------|--------------------------------------------|--------------------------------|
| `schema_properties`    | `(resource_type) → [property_names]`       | List schema-defined properties |
| `schema_required`      | `(resource_type) → [required_names]`       | List required properties       |
| `schema_type`          | `(resource_type, property) → type_string`  | Get schema type for a property |
| `schema_enum`          | `(resource_type, property) → [values]`     | Get allowed enum values        |
| `attribute_type`       | `(resource_type, property) → type_string`  | Get schema attribute type      |
| `getatt_return_type`   | `(resource_type, attribute) → type_string` | Get GetAtt return type         |
| `schema_string_length` | `(resource_type, property) → {min, max}`   | Get string length constraints  |

### Diagnostic Construction

| Builtin                 | Signature                                                                        | Purpose                           |
|-------------------------|----------------------------------------------------------------------------------|-----------------------------------|
| `make_diag`             | `(rule_id, severity, resource_id, message) → diag`                               | Create a basic diagnostic         |
| `make_diag_at`          | `(rule_id, severity, resource_id, prop_path, message) → diag`                    | Diagnostic with property path     |
| `make_diag_full`        | `(rule_id, severity, resource_id, prop_path, message, fix, doc_url) → diag`      | Full diagnostic with fix and URL  |
| `make_diag_related`     | `(rule_id, severity, resource_id, prop_path, message, related_locations) → diag` | Diagnostic with related locations |
| `make_diag_conditional` | `(rule_id, severity, resource_id, prop_path, message, conditions) → diag`        | Diagnostic with condition context |

### Utilities

| Builtin                  | Signature                       | Purpose                                       |
|--------------------------|---------------------------------|-----------------------------------------------|
| `arn_matches`            | `(arn, pattern) → bool`         | Match an ARN against a pattern with wildcards |
| `ip_overlaps`            | `(cidr_a, cidr_b) → bool`       | Check if two CIDR blocks overlap              |
| `ip_subnet_of`           | `(subnet, supernet) → bool`     | Check if a CIDR is a subnet of another        |
| `is_valid_cidr_strict`   | `(cidr) → bool`                 | Validate CIDR notation                        |
| `ensure_list`            | `(value) → [value]`             | Wrap scalar in array, pass arrays through     |
| `input_region`           | `() → region_string`            | Get the configured AWS region                 |
| `coerce_to_number`       | `(value) → number`              | CloudFormation-style number coercion          |
| `coerce_to_string`       | `(value) → string`              | CloudFormation-style string coercion          |
| `cfn_type_compatible`    | `(value, expected_type) → bool` | Check CFN type compatibility with coercion    |
| `estimate_string_length` | `(resource_id, path) → number`  | Estimate resolved string length               |
