# data-source

Build-time pipeline that downloads CloudFormation resource provider schemas (with patches pre-applied), derives
per-region resource-type data from the downloaded schemas, syncs rule-source extensions and additional specs (when a
cfn-lint root is provided), processes schemas, and generates all validation artifacts consumed by engine crates at
compile time. Everything compiles into the binary - no runtime fetching.

## Commands

```bash
# Sync only - download schemas, sync rule-source upstream data
cargo run -p data-source --features full --example sync -- [--cfn-lint-root <DIR>]

# Generate only - run all codegens from existing upstream data
cargo run -p data-source --features full --example generate

# Full - sync then generate
cargo run -p data-source --features full --example full -- [--cfn-lint-root <DIR>]
```

The `sync`, `generate`, and `full` examples require the `full` cargo feature (it pulls in the network and archive
dependencies used only at build/sync time).

`--cfn-lint-root` is optional. Without it, the sync still downloads schemas and builds per-region resource-type data,
but skips the rule-source steps (extensions, additional specs, and cfn-lint tables).

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
