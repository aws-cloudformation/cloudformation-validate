# template-model

Parses CloudFormation JSON/YAML templates into a rich semantic model. Resolves all intrinsic functions, builds a
reference graph with cycle detection, and models conditions with a SAT solver. Has zero knowledge of CloudFormation
resource schemas - it is purely a modeling library.

## How It Works

```
  bytes ──▶ Parse (JSON/YAML) ──▶ Resolve intrinsics ──▶ Build reference graph ──▶ SemanticModel
```

1. **Parse** - Reads JSON or YAML (auto-detected), extracts all template sections (Parameters, Mappings, Conditions,
   Resources, Outputs, Rules, Metadata, Transforms, Globals).
2. **Resolve** - Walks each resource and output, resolving all intrinsic functions into `ResolvedValue` variants.
3. **Validate** - Builds a reference graph, detects cycles, validates intrinsic function nesting, and emits parse-time
   diagnostics (`F3004` cycles, `E1028` undefined conditions, `E1101` invalid nesting, `W8003` tautological conditions).

## Intrinsic Function Support

All CloudFormation intrinsic functions are resolved:

`Ref`, `Fn::GetAtt`, `Fn::Sub`, `Fn::Join`, `Fn::Select`, `Fn::If`, `Fn::FindInMap` (with optional default),
`Fn::Split`, `Fn::Base64`, `Fn::Cidr`, `Fn::GetAZs`, `Fn::ImportValue`, `Fn::Transform`, `Fn::And`, `Fn::Or`,
`Fn::Not`, `Fn::Equals`, `Fn::ToJsonString`, `Fn::Length`, `Fn::ForEach`.

Rules-section intrinsics: `Fn::ValueOf`, `Fn::ValueOfAll`, `Fn::RefAll`, `Fn::Contains`, `Fn::EachMemberEquals`,
`Fn::EachMemberIn`.

## ResolvedValue

Each property resolves to one of these variants:

| Variant        | Meaning                                                                |
|----------------|------------------------------------------------------------------------|
| `Concrete`     | Fully resolved JSON value                                              |
| `List`         | Array with mixed resolved/unresolved elements                          |
| `Map`          | Object with mixed resolved/unresolved values                           |
| `Enum`         | Set of possible values (from AllowedValues or FindInMap)               |
| `Conditional`  | Value depends on a condition (carries both branches)                   |
| `Reference`    | Unresolved reference to another resource (Ref, GetAtt, Sub, DependsOn) |
| `Dynamic`      | Cannot resolve statically (e.g., Transform output, cross-stack import) |
| `TypedDynamic` | Like Dynamic but carries the parameter's declared type                 |

## SemanticModel API

### Creating a Model

```rust
let bytes = std::fs::read("template.yaml").unwrap();
let model = SemanticModel::from_bytes(&bytes).unwrap();
```

With configuration:

```rust
use std::collections::HashMap;
use template_model::{SemanticModel, ParseConfig, PseudoParameterOverrides};

let config = ParseConfig {
  parameters: HashMap::from([("Environment".into(), "Production".into())]),
  pseudo_parameters: PseudoParameterOverrides {
    region: Some("eu-west-1".into()),
    account_id: Some("123456789012".into()),
    ..Default::default()
  },
};

let result = SemanticModel::parse(&bytes, config).unwrap();
let model = result.model;
```

### Query Methods

| Method                                      | Purpose                                                      |
|---------------------------------------------|--------------------------------------------------------------|
| `parse(bytes, config)`                      | Full parse pipeline with configuration                       |
| `from_bytes(bytes)`                         | Parse with default config                                    |
| `resource(id)`                              | Look up a `ResolvedResource` by logical ID                   |
| `resources_of_type(type_name)`              | All logical IDs of a given resource type                     |
| `resolve(resource_id, path)`                | Top-level property lookup                                    |
| `resolve_deep(resource_id, path)`           | Nested path traversal                                        |
| `resolve_scenarios(resource_id, path)`      | All (value, condition_map) pairs for a property              |
| `resolve_scenarios_json(resource_id, path)` | Scenarios filtered to concrete JSON values with SAT checking |
| `follow_ref(resource_id, path)`             | Follow a Ref/GetAtt to its target resource                   |
| `is_from_parameter(resource_id, path)`      | Check if a property originates from a parameter reference    |
| `is_from_intrinsic(resource_id, path)`      | Check if a property originates from an intrinsic function    |
| `source_location(path)`                     | Source span for a template path                              |
| `resource_span(resource_id, prop_path)`     | Source span for a resource property                          |
| `estimate_string_length(resource_id, path)` | Estimate resolved string length for constraint checking      |

### Key Fields

| Field               | Type / Purpose                                                            |
|---------------------|---------------------------------------------------------------------------|
| `format_version`    | `Option<String>` - `AWSTemplateFormatVersion` value                       |
| `description`       | `Option<String>` - template `Description`                                 |
| `transforms`        | `Vec<String>` - declared transforms                                       |
| `parameters`        | `HashMap<String, ParameterInfo>` - parsed parameter definitions           |
| `mappings`          | 3-level `MappingData` HashMap                                             |
| `conditions`        | `ConditionModel` with SAT solver                                          |
| `resources`         | `HashMap<String, ResolvedResource>` - resolved resources with diagnostics |
| `outputs`           | `HashMap<String, ResolvedOutput>` - resolved outputs                      |
| `graph`             | `ReferenceGraph` with cycle information                                   |
| `resources_by_type` | `HashMap<String, Vec<String>>` - logical IDs grouped by resource type     |
| `diagnostics`       | All parse-time findings, as plain `ParseDefect` values                    |
| `template_metadata` | Raw JSON of the Metadata section                                          |

### ParseConfig

| Field               | Default                    | Effect                                                                                          |
|---------------------|----------------------------|-------------------------------------------------------------------------------------------------|
| `parameters`        | empty `HashMap`            | Parameter overrides - `Ref` resolves to `Concrete` instead of `Enum`/`TypedDynamic`             |
| `pseudo_parameters` | all `None` (uses defaults) | Override `AWS::Region` (`us-east-1`), `AWS::AccountId` (`123456789012`), `AWS::Partition`, etc. |

Supports AWS SAM templates with automatic handling of SAM transforms and implicit resources.

## Commands

### `inspect` (example binary)

Prints a detailed human-readable dump of the semantic model for a template or directory of templates.

```
cargo run -p cloudformation-validate-template-model --example inspect -- <TEMPLATE|DIR>
```
