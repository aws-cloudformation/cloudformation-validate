# data-source

Build-time pipeline that downloads CloudFormation resource provider schemas, syncs rule-source patches/extensions/region
data, processes schemas, and generates all validation artifacts consumed by engine crates at compile time. Everything
compiles into the binary — no runtime fetching.

## Commands

```bash
# Sync only — download schemas, sync rule-source upstream data
cargo run -p data-source --example sync -- [--cfn-lint-root <DIR>]

# Generate only — run all codegens from existing upstream data
cargo run -p data-source --example generate

# Full — sync then generate
cargo run -p data-source --example full -- [--cfn-lint-root <DIR>]
```

`--cfn-lint-root` is optional. Without it, the sync skips patch/extension/region sync.

## Directory Structure

```
data-source/
├── handwritten/                       # Manually authored data, checked in
├── upstream/                          # Raw data synced from external sources
│   ├── schemas/                       # Downloaded CFN + SAM schemas
│   ├── patches/                       # Rule-source JSON patches
│   └── extensions/                    # Rule-source extension files
└── generated/                         # All processed/codegen output (never edit manually)
    ├── patched_schemas/               # Schemas with patches+extensions applied
    ├── data/                          # Extracted metadata consumed by all engines
    ├── cel-rules/                     # CEL rule descriptors
    └── schema-validator/              # Compiled schemas for schema-validator
```
