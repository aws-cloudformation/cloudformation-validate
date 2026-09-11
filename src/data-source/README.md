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
pipeline. `sync` is the complete schema/rule workflow: it clears `upstream/`, `generated/patched_schemas/`, and
`generated/data/` so no stale artifact survives, refreshes every upstream source, records source versions, and
generates all outputs. `generate` reruns code generation from the existing upstream data without network access.

`--cfn-lint-root` is required by `sync`, which fails before starting work when it is absent. A successful sync records
its source-qualified versions only after all source processing succeeds.

### AWS CLI operation catalog

`generate_aws_cli_catalog` is a separate command that (re)builds
`generated/data/aws_cli_operation_catalog.json`, the adapter catalog that maps AWS CLI operations to CloudFormation
resource types for `validateAwsCliCommand`. It is intentionally decoupled from `sync`/`generate` because it derives
from AWS CLI botocore service models plus CloudFormation provider handler metadata and is regenerated on its own
cadence. It only generates the catalog and never downloads or processes schemas: it reads the provider schemas
already present under `upstream/schemas` (written by `sync`) and the committed compiled schemas under
`generated/schema-validator`, and fails with a clear message if either is missing. Because `sync` clears
`generated/data/`, the catalog must be regenerated after every sync; the command also records the AWS CLI release it
used as `aws_cli_version` in `generated/data/source_versions.json`.

Besides the operation-to-type and parameter-to-property pairs, each mapping records the API value domain that the
compiled CloudFormation schema cannot represent (`unrepresentable`: enum members, numeric bounds, string lengths, list
sizes, tag key/value lengths), derived by comparing the botocore input shape against the compiled property schema. The
runtime uses it to skip synthesis for a command whose values the service accepts but CloudFormation would reject.
Same-named inputs whose meaning differs from the CloudFormation property are excluded by the reviewed
`PROPERTY_SEMANTIC_DENYLIST` in the script. Re-run the command after `sync`, after changing the generator's mapping
rules, or after updating the AWS CLI checkout.


## Directory Structure

```
data-source/
├── handwritten/                       # Manually authored data, checked in
├── upstream/                          # Raw data synced from external sources (not committed)
│   ├── schemas/                       # Downloaded CFN + SAM schemas (per resource type)
│   ├── providers/                     # Per-region type→hash maps (from the enhanced archive)
│   ├── extensions/                    # Rule-source extension files (only with --cfn-lint-root)
│   ├── step_functions_statemachine.json  # Step Functions state machine schema from the rule source
│   └── getatt_additions.json          # Raw GetAtt additions, folded into generated/data/getatt_attributes.json
└── generated/                         # All processed/codegen output (never edit manually)
    ├── patched_schemas/               # Schemas with patches+extensions applied (not committed)
    ├── data/                          # Extracted metadata consumed by all engines
    ├── cel-rules/                     # CEL rule descriptors
    └── schema-validator/              # Compiled schemas for schema-validator
```
