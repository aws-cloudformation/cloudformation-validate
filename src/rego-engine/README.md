# rego-engine

Validates CloudFormation templates using Rego policies evaluated by the [Regorus](https://github.com/AnyReg/regorus)
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
[data-source](../data-source/README.md) (embedded), user-provided custom Rego policies, and Guard DSL files translated
to Rego at engine initialization.

## Custom Builtins

Available as `cfn.<name>` in Rego policies.

### Template Resolution

| Builtin                  | Signature                                                     | Purpose                                              |
|--------------------------|---------------------------------------------------------------|------------------------------------------------------|
| `cfn.resolve`            | `(resource_id, path) → value`                                 | Resolve a property value through intrinsic functions |
| `cfn.resolve_all`        | `(resource_id, path) → [values]`                              | Resolve all scenario values for a property           |
| `cfn.resolve_scenarios`  | `(resource_id, path) → [{value, conditions}]`                 | Resolve all (value, condition_map) pairs             |
| `cfn.resolve_ref_target` | `(resource_id, path) → {resourceType, condition, properties}` | Resolve the target of a reference                    |
| `cfn.resolve_type`       | `(resource_id, path) → type_string`                           | Get the resolved value type                          |
| `cfn.is_dynamic`         | `(resource_id, path) → bool`                                  | Check if a property contains unresolvable content    |
| `cfn.is_from_parameter`  | `(resource_id, path) → bool`                                  | Check if a property originates from a parameter      |
| `cfn.is_from_intrinsic`  | `(resource_id, path) → bool`                                  | Check if a property originates from an intrinsic     |
| `cfn.follow_ref`         | `(resource_id, path) → target_id`                             | Follow a Ref/GetAtt to its target resource           |
| `cfn.flatten_list`       | `(resource_id, path) → [{value, index}]`                      | Flatten nested arrays                                |

### Resource Queries

| Builtin                 | Signature                         | Purpose                                  |
|-------------------------|-----------------------------------|------------------------------------------|
| `cfn.get_resource`      | `(resource_id) → resource_object` | Get full resolved resource data          |
| `cfn.has_property`      | `(resource_id, path) → bool`      | Check if a property exists on a resource |
| `cfn.resources_of_type` | `(type_name) → [resource_ids]`    | Get all logical IDs of a resource type   |
| `cfn.has_transform`     | `(transform_name) → bool`         | Check if a transform is declared         |

### Graph Queries

| Builtin                  | Signature                               | Purpose                                     |
|--------------------------|-----------------------------------------|---------------------------------------------|
| `cfn.ref_targets`        | `(resource_id) → [target_ids]`          | Outgoing reference targets                  |
| `cfn.ref_sources`        | `(resource_id) → [source_ids]`          | Incoming reference sources                  |
| `cfn.depends_on`         | `(resource_a, resource_b) → bool`       | Transitive dependency check                 |
| `cfn.edges_from`         | `(resource_id) → [edge_objects]`        | Detailed outgoing edges                     |
| `cfn.edges_to`           | `(resource_id) → [edge_objects]`        | Detailed incoming edges                     |
| `cfn.pipeline_artifacts` | `(resource_id) → {issues: [{message}]}` | Extract CodePipeline artifact relationships |

### Condition Analysis

| Builtin                       | Signature                                       | Purpose                                          |
|-------------------------------|-------------------------------------------------|--------------------------------------------------|
| `cfn.conditions_compatible`   | `(cond_a, cond_b) → bool`                       | Can both conditions be true simultaneously?      |
| `cfn.condition_implies`       | `(cond_a, cond_b) → bool`                       | Does cond_a=true force cond_b=true?              |
| `cfn.conjunction_implies`     | `(guard1, guard2, target) → bool`               | Does the conjunction of two guards imply target? |
| `cfn.resource_condition`      | `(resource_id) → condition_name`                | Get the Condition on a resource                  |
| `cfn.is_satisfiable`          | `(assumptions) → bool`                          | Is a set of condition assumptions satisfiable?   |
| `cfn.unreachable_if_branches` | `(resource_id) → [{resourceId, path, message}]` | Find unreachable Fn::If branches in a resource   |

### Parameter / Mapping

| Builtin                    | Signature                    | Purpose                              |
|----------------------------|------------------------------|--------------------------------------|
| `cfn.param_allowed_values` | `(param_name) → [values]`    | Get AllowedValues for a parameter    |
| `cfn.param_type`           | `(param_name) → type_string` | Get the declared Type of a parameter |
| `cfn.mapping_value`        | `(map, key1, key2) → value`  | Look up a value in Mappings          |

### Schema Introspection

| Builtin                    | Signature                                  | Purpose                        |
|----------------------------|--------------------------------------------|--------------------------------|
| `cfn.schema_properties`    | `(resource_type) → [property_names]`       | List schema-defined properties |
| `cfn.schema_required`      | `(resource_type) → [required_names]`       | List required properties       |
| `cfn.schema_type`          | `(resource_type, property) → type_string`  | Get schema type for a property |
| `cfn.schema_enum`          | `(resource_type, property) → [values]`     | Get allowed enum values        |
| `cfn.attribute_type`       | `(resource_type, property) → type_string`  | Get schema attribute type      |
| `cfn.getatt_return_type`   | `(resource_type, attribute) → type_string` | Get GetAtt return type         |
| `cfn.schema_string_length` | `(resource_type, property) → {min, max}`   | Get string length constraints  |

### Diagnostic Construction

| Builtin                     | Signature                                                                        | Purpose                           |
|-----------------------------|----------------------------------------------------------------------------------|-----------------------------------|
| `cfn.make_diag`             | `(rule_id, severity, resource_id, message) → diag`                               | Create a basic diagnostic         |
| `cfn.make_diag_at`          | `(rule_id, severity, resource_id, prop_path, message) → diag`                    | Diagnostic with property path     |
| `cfn.make_diag_full`        | `(rule_id, severity, resource_id, prop_path, message, fix, doc_url) → diag`      | Full diagnostic with fix and URL  |
| `cfn.make_diag_related`     | `(rule_id, severity, resource_id, prop_path, message, related_locations) → diag` | Diagnostic with related locations |
| `cfn.make_diag_conditional` | `(rule_id, severity, resource_id, prop_path, message, conditions) → diag`        | Diagnostic with condition context |

### Utilities

| Builtin                      | Signature                       | Purpose                                       |
|------------------------------|---------------------------------|-----------------------------------------------|
| `cfn.arn_matches`            | `(arn, pattern) → bool`         | Match an ARN against a pattern with wildcards |
| `cfn.ip_overlaps`            | `(cidr_a, cidr_b) → bool`       | Check if two CIDR blocks overlap              |
| `cfn.ip_subnet_of`           | `(subnet, supernet) → bool`     | Check if a CIDR is a subnet of another        |
| `cfn.is_valid_cidr_strict`   | `(cidr) → bool`                 | Validate CIDR notation                        |
| `cfn.ensure_list`            | `(value) → [value]`             | Wrap scalar in array, pass arrays through     |
| `cfn.input_region`           | `() → region_string`            | Get the configured AWS region                 |
| `cfn.coerce_to_number`       | `(value) → number`              | CloudFormation-style number coercion          |
| `cfn.coerce_to_string`       | `(value) → string`              | CloudFormation-style string coercion          |
| `cfn.cfn_type_compatible`    | `(value, expected_type) → bool` | Check CFN type compatibility with coercion    |
| `cfn.estimate_string_length` | `(resource_id, path) → number`  | Estimate resolved string length               |
