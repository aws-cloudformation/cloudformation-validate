# data-source

Build-time pipeline that downloads CloudFormation resource provider schemas (with patches pre-applied), derives
per-region resource-type data from the downloaded schemas, syncs rule-source extensions and additional specs (when a
cfn-lint root is provided), processes schemas, and generates all validation artifacts consumed by engine crates at
compile time. Everything compiles into the binary - no runtime fetching.

## Commands

```bash
# Generate from existing upstream data
cargo run -p data-source --features maintenance --example generate

# Refresh all upstream sources, then generate every output (cfn-lint root is required)
cargo run -p data-source --features maintenance --example sync -- --cfn-lint-root <DIR>

# Generate the AWS API operation catalog; unit tests run first
PYTHONPATH=<path-to-botocore-or-aws-cli-checkout> \
  python3 data-source/scripts/generate_aws_api_catalog.py \
    --provider-schemas data-source/upstream/schemas \
    --compiled-schemas data-source/generated/schema-validator/compiled_schemas.json \
    --output data-source/generated/data/aws_api_operation_catalog.json
```

The `generate` and `sync` examples require the `maintenance` feature, which enables dependencies used only by the
data maintenance pipeline. `sync` is the complete workflow: it refreshes every upstream source, records source
versions, and generates all outputs. `generate` reruns code generation from the existing upstream data without network
access.

`--cfn-lint-root` is required by `sync`, which fails before starting work when it is absent.
A successful sync records both strict, source-qualified values together only after all source processing succeeds.

## Directory Structure

```
data-source/
├── handwritten/                       # Manually authored data, checked in
├── upstream/                          # Raw data synced from external sources
│   ├── schemas/                       # Downloaded CFN + SAM schemas (per resource type)
│   ├── providers/                     # Per-region type→hash maps (from the enhanced archive)
│   └── extensions/                    # Rule-source extension files (only with --cfn-lint-root)
└── generated/                         # All processed/codegen output (never edit manually)
    ├── patched_schemas/               # Schemas with patches+extensions applied
    ├── data/                          # Extracted metadata consumed by all engines
    ├── cel-rules/                     # CEL rule descriptors
    └── schema-validator/              # Compiled schemas for schema-validator
```
