# data-source

Build-time pipeline that downloads CloudFormation resource provider schemas (with patches pre-applied), derives
per-region resource-type data from the downloaded schemas, syncs rule-source extensions and additional specs (when a
cfn-lint root is provided), processes schemas, and generates all validation artifacts consumed by engine crates at
compile time. Everything compiles into the binary - no runtime fetching.

## Commands

```bash
# Sync only - download schemas and sync all upstream data (cfn-lint root is required)
cargo run -p data-source --features full --example sync -- --cfn-lint-root <DIR>

# Generate only - run all codegens from existing upstream data
cargo run -p data-source --features full --example generate

# Full - sync all sources then generate
cargo run -p data-source --features full --example full -- --cfn-lint-root <DIR>
```

The `sync`, `generate`, and `full` examples require the `full` cargo feature (it pulls in the network and archive
dependencies used only at build/sync time).

`--cfn-lint-root` is required by both `sync` and `full`; each command fails before starting work when it is absent.
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
