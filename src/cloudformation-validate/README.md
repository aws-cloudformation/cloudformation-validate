# cloudformation-validate

Rust library facade for fast, offline validation of AWS CloudFormation templates. It exposes both validation engines,
schema validation, orchestration, diagnostics, rule filtering, and template-model types from one package.

```rust
use cloudformation_validate::{
    EngineConfig, RegoEngine, SchemaValidator, ValidateConfig, validate_bytes_with_path,
};

let schema_validator = SchemaValidator::default();
let engine = RegoEngine::new(EngineConfig::default())?;
let report = validate_bytes_with_path(
    &engine,
    &schema_validator,
    b"Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n",
    ValidateConfig::default(),
    "template.yaml".to_string(),
)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

The `cfn-validate` command-line executable is distributed separately through GitHub Releases and is not part of this
crates.io package.
