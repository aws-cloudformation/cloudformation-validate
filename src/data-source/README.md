# data-source

Build-time pipeline that downloads CloudFormation resource provider schemas (with patches pre-applied), derives
per-region resource-type data from the downloaded schemas, syncs rule-source extensions and additional specs (when a
cfn-lint root is provided), processes schemas, and generates all validation artifacts consumed by engine crates at
compile time. Everything compiles into the binary - no runtime fetching.

## Commands

```bash
# Generate schema and rule artifacts from existing upstream data
cargo run -p cloudformation-validate-data-source --features maintenance --example generate

# Refresh all upstream sources, then generate every output (cfn-lint root is required)
cargo run -p cloudformation-validate-data-source --features maintenance --example sync -- --cfn-lint-root <DIR>

# Regenerate the AWS CLI operation catalog (standalone; independent of sync/generate).
# --aws-cli-root points at a local aws-cli checkout. The resource data must already be
# present (upstream/schemas from a prior sync, plus the committed compiled schemas).
cargo run -p cloudformation-validate-data-source --features maintenance \
  --example generate_aws_cli_catalog -- --aws-cli-root <DIR>
```

The examples require the `maintenance` feature, which enables dependencies used only by the data maintenance
pipeline. `sync` is the schema/rule workflow: it refreshes every upstream source, records source versions, and
generates the schema and rule outputs. `generate` reruns that schema and rule generation from existing upstream data
without network access.

`--cfn-lint-root` is required by `sync`, which fails before starting work when it is absent. A successful sync records
its source-qualified versions only after all source processing succeeds.

### AWS CLI operation catalog

`generate_aws_cli_catalog` is a separate command that (re)builds
`generated/data/aws_cli_operation_catalog.json`, the adapter catalog that maps AWS CLI operations to CloudFormation
resource types for `validateAwsCliCommand`. It is intentionally decoupled from `sync`/`generate` because it derives
from AWS CLI botocore service models plus CloudFormation provider handler metadata and is regenerated on its own
cadence. It only generates the catalog and never downloads or processes schemas: it reads the provider schemas
already present under `upstream/schemas` (written by `sync`) and the committed compiled schemas under
`generated/schema-validator`, and fails with a clear message if either is missing.


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
