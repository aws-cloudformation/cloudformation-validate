# cloudformation-validate

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Main CI](https://github.com/aws-cloudformation/cloudformation-validate/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/aws-cloudformation/cloudformation-validate/actions/workflows/ci.yml)
[![CodeQL](https://github.com/aws-cloudformation/cloudformation-validate/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/aws-cloudformation/cloudformation-validate/actions/workflows/codeql.yml)
[![Offline](https://img.shields.io/badge/runtime-fully%20offline-success)](#features)

[![Latest release](https://img.shields.io/github/v/release/aws-cloudformation/cloudformation-validate?include_prereleases)](https://github.com/aws-cloudformation/cloudformation-validate/releases)
[![npm version](https://img.shields.io/npm/v/%40aws%2Fcloudformation-validate?logo=npm)](https://www.npmjs.com/package/@aws/cloudformation-validate)
[![Maven Central](https://img.shields.io/maven-central/v/software.amazon.cloudformation/cloudformation-validate?logo=apachemaven)](https://central.sonatype.com/artifact/software.amazon.cloudformation/cloudformation-validate)
[![PyPI version](https://img.shields.io/pypi/v/cloudformation-validate?logo=pypi)](https://pypi.org/project/cloudformation-validate/)
[![Go Reference](https://pkg.go.dev/badge/github.com/aws-cloudformation/cloudformation-validate/src/bindings-go/go.svg)](https://pkg.go.dev/github.com/aws-cloudformation/cloudformation-validate/src/bindings-go/go)

[![Rust toolchain](https://img.shields.io/badge/Rust%20toolchain-1.96.0-orange?logo=rust)](src/rust-toolchain.toml)
[![Node.js](https://img.shields.io/node/v/%40aws%2Fcloudformation-validate?logo=nodedotjs)](src/bindings-wasm/README.md)
[![Python](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Ftest.pypi.org%2Fpypi%2Fcloudformation-validate%2Fjson&query=%24.info.requires_python&label=Python&logo=python)](src/bindings-python/README.md)
[![Go](https://img.shields.io/badge/Go-%3E%3D1.26-00ADD8?logo=go)](src/bindings-go/README.md)
[![JVM](https://img.shields.io/badge/JVM-21%2B-orange?logo=openjdk)](src/bindings-jvm/README.md)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](INSTALLATION.md)

Fast, offline, embeddable validation for AWS CloudFormation templates.

`cloudformation-validate` parses a CloudFormation template (JSON or YAML) and returns structured diagnostics - schema
violations, semantic errors, security concerns, and best-practice suggestions - before you deploy. It runs entirely
offline: every rule and resource schema is compiled into the binary, so there is no network access, no credentials, and
no runtime fetching.

It ships as a Rust CLI, an embeddable Rust library, a Node.js package (WASM), a Python package, a Go module, and a
JVM library (Kotlin/Java) - all backed by the same validation core.

## Features

- **Offline-first.** Rules and AWS resource schemas are baked into the binary. Nothing is fetched at runtime.
- **Structured diagnostics.** Every finding carries a stable rule ID, severity, precise source span (line/column),
  resource path, and an optional suggested fix - designed for IDEs, CI, and agents, not just humans.
- **Two interchangeable engines.** A [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) engine and a
  [CEL](https://cel.dev/) engine evaluate the same rule set and produce identical results.
- **Additional schemas.** Merge your own CloudFormation resource provider schemas on top of the bundled ones, so
  templates using properties or values CloudFormation has not published yet validate cleanly
  (`--additional-schema`, or `EngineConfig.schema_validator_config.additional_schemas` when embedding).
- **Custom rules.** Extend validation with your own rules in CEL (JSON), Rego, or
  [CloudFormation Guard](https://docs.aws.amazon.com/cfn-guard/latest/ug/what-is-guard.html) DSL.
- **Embeddable everywhere.** Use it from the CLI, Rust, Node.js, Python, Go, or the JVM.
- **Sub-second** validation for typical templates.

## How it works

When a template is submitted, `cloudformation-validate` runs a fixed pipeline:

1. **Parse** - read JSON/YAML, resolve intrinsic functions (`Ref`, `Fn::GetAtt`, `Fn::Sub`, `Fn::If`, …), build a
   reference graph with cycle detection, and model conditions with a SAT solver, producing a semantic model.
2. **Schema validate** - check each resource against the compiled CloudFormation provider schemas, producing
   Fatal-severity diagnostics for structural violations (type mismatches, missing required properties, invalid enums,
   pattern and constraint failures).
3. **Evaluate rules** - the selected engine (Rego or CEL) evaluates lint rules against the semantic model, producing
   Error/Warning/Info diagnostics for semantic issues, cross-resource references, security risks, and best practices.
4. **Validate Step Functions** - check `AWS::StepFunctions::StateMachine` definitions (state types, `StartAt`/`Next`
   references, required fields).
5. **Enrich, filter, report** - attach rule descriptions and context, apply include/exclude filters and severity
   gating, sort by source location, deduplicate, and assemble a structured JSON report.

## Installation

Use a prebuilt CLI or install a published language binding; Rust and this source repository are not required.

| Interface | Published artifact | Install |
|-----------|--------------------|---------|
| CLI | [GitHub Releases](https://github.com/aws-cloudformation/cloudformation-validate/releases) | [Download the newest binary for Linux, macOS, or Windows](INSTALLATION.md#command-line-interface) |
| Node.js | [npm: `@aws/cloudformation-validate`](https://www.npmjs.com/package/@aws/cloudformation-validate) | `npm install @aws/cloudformation-validate` |
| Python | [PyPI](https://pypi.org/project/cloudformation-validate/) / [TestPyPI beta](https://test.pypi.org/project/cloudformation-validate/) | `python3 -m pip install cloudformation-validate` |
| Go | [Go module](https://pkg.go.dev/github.com/aws-cloudformation/cloudformation-validate/src/bindings-go/go) | `go get github.com/aws-cloudformation/cloudformation-validate/src/bindings-go/go@latest` |
| JVM | [Maven Central: `software.amazon.cloudformation:cloudformation-validate`](https://central.sonatype.com/artifact/software.amazon.cloudformation/cloudformation-validate) | `implementation("software.amazon.cloudformation:cloudformation-validate:latest.release")` |

See [INSTALLATION.md](INSTALLATION.md) for platform-specific CLI download instructions, runtime requirements, prerelease
channels, version pinning, Maven syntax, and release signature verification.

## Quick start

```bash
# Validate a single template
cargo run -p cfn-validate -- template.yaml

# Validate every template in a directory (recurses, picks up .yaml/.yml/.json)
cargo run -p cfn-validate -- ./templates/

# Use the CEL engine instead of the default Rego engine
cargo run -p cfn-validate -- template.yaml --engine cel

# Compact output for IDEs/CI
cargo run -p cfn-validate -- template.yaml --format standard

# Only report errors and above
cargo run -p cfn-validate -- template.yaml --level error

# List every available rule and exit
cargo run -p cfn-validate -- --list-rules

# Load custom Guard rules
cargo run -p cfn-validate -- template.yaml --guard-rule-source ./my-rules/
```

## Embedding as a library

### Rust

Construct an engine and a schema validator once, then validate many templates:

```rust
use rego_engine::RegoEngine;
use schema_validator::SchemaValidator;
use validation_engine::{validate_bytes_with_path, EngineConfig, ValidateConfig};

let schema_validator = SchemaValidator::default();
let engine = RegoEngine::new(EngineConfig::default())?;

let bytes = std::fs::read("template.yaml") ?;
let report = validate_bytes_with_path(
    & engine,
    & schema_validator,
    & bytes,
    ValidateConfig::default (),
    "template.yaml".to_string(),
) ?;

for d in & report.diagnostics {
    println!("[{}] {} - {}", d.severity, d.rule_id, d.message);
}
```

See [validation-engine/API.md](src/validation-engine/API.md) for the full embedding API.

### Node.js [(bindings-wasm)](src/bindings-wasm/README.md)

```typescript
import {RegoEngine, TemplateFile} from "@aws/cloudformation-validate";

const engine = new RegoEngine();
const report = engine.validateStandard(new TemplateFile("template.yaml"));
for (const d of report.diagnostics) {
    console.log(`[${d.severity}] ${d.ruleId}: ${d.message}`);
}
engine.free();
```

### Python [(bindings-python)](src/bindings-python/README.md)

```python
from cloudformation_validate import RegoEngine

engine = RegoEngine()
report = engine.validate_standard("template.yaml")
for d in report.diagnostics:
    print(f"[{d.severity.name}] {d.rule_id}: {d.message}")
```

### Go [(bindings-go)](src/bindings-go/README.md)

```go
import cfnvalidate "github.com/aws-cloudformation/cloudformation-validate/src/bindings-go/go"

engine, err := cfnvalidate.NewRegoEngine(nil)
if err != nil {
    log.Fatal(err)
}
defer engine.Destroy()

report, err := engine.ValidateStandardFile("template.yaml", nil)
for _, d := range report.Diagnostics {
    fmt.Printf("[%s] %s: %s\n", d.Severity, d.RuleID, d.Message)
}
```

### JVM Java/Kotlin [(bindings-jvm)](src/bindings-jvm/README.md)

```kotlin
import software.amazon.cloudformation.validate.*
import java.io.File

val engine = RegoEngine()
val report = engine.validateStandard(File("template.yaml"))
for (d in report.diagnostics) {
    println("[${d.severity}] ${d.ruleId}: ${d.message}")
}
```

## Rules

Bring your own rules in any of three formats - all loadable from the CLI and the library:

- **CEL** (`.json`) - property and data-driven checks, evaluated by the CEL engine.
- **Rego** (`.rego`) - complex cross-resource logic, evaluated by the Rego engine.
- **Guard DSL** (`.guard`) - declarative compliance rules, translated automatically and usable with either engine.

See [RULES](src/rules/README.md) and [CUSTOM_RULES.md](src/CUSTOM_RULES.md) for the formats, available context, and
examples.

## Modules

This is a Cargo workspace. The main crates:

| Crate                                                | Role                                                                                                                          |
|------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------|
| [cfn-validate](src/cfn-validate/README.md)           | `cfn-validate` CLI                                                                                                            |
| [validation-engine](src/validation-engine/README.md) | `ValidationEngine` trait, orchestration pipeline, Step Functions validation                                                   |
| [template-model](src/template-model/README.md)       | Template parser, intrinsic resolver, condition SAT solver, reference graph                                                    |
| [rules](src/rules/README.md)                         | Rule registry, severity model, categories, and diagnostic filtering                                                           |
| [diagnostics](src/diagnostics/README.md)             | Shared reporting types: `Diagnostic`, `ValidationReport`, metrics                                                             |
| [schema-validator](src/schema-validator/README.md)   | JSON Schema validation against compiled CloudFormation provider schemas                                                       |
| [rego-engine](src/rego-engine/README.md)             | Rego-based rule evaluation with custom builtins                                                                               |
| [cel-engine](src/cel-engine/README.md)               | Native Rust rules plus a CEL interpreter for custom rules                                                                     |
| [guard-translator](src/guard-translator/README.md)   | Parses Guard DSL into an engine-agnostic intermediate representation                                                          |
| [data-source](src/data-source/README.md)             | Build-time pipeline: downloads and processes CloudFormation schemas, generates the validation artifacts baked into the binary |

## Security

If you discover a potential security issue, please do **not** open a public GitHub issue. Report it privately through
[AWS Vulnerability Reporting](https://aws.amazon.com/security/vulnerability-reporting/) instead.

## License

Licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE) for attributions and
[THIRD-PARTY-LICENSES.txt](src/THIRD-PARTY-LICENSES.txt) for third-party license details.
