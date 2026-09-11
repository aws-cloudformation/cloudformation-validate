# data-source

Build-time pipeline that downloads CloudFormation resource provider schemas (with patches pre-applied), derives
per-region resource-type data from the downloaded schemas, syncs rule-source extensions and additional specs (when a
cfn-lint root is provided), processes schemas, and generates all validation artifacts consumed by engine crates at
compile time. Everything compiles into the binary - no runtime fetching.

## Commands

```bash
# Generate schema and rule artifacts from existing upstream data
cargo run -p cloudformation-validate-data-source --features maintenance --example generate

# Refresh all upstream sources, then generate every output (cfn-lint root is required;
# --aws-cli-root, a local aws-cli checkout, also regenerates the AWS CLI operation catalog)
cargo run -p cloudformation-validate-data-source --features maintenance --example sync -- --cfn-lint-root <DIR> [--aws-cli-root <DIR>]
```

The examples require the `maintenance` feature, which enables dependencies used only by the data maintenance
pipeline. `sync` is the complete schema/rule workflow: it clears `upstream/`, `generated/patched_schemas/`, and
`generated/data/` so no stale artifact survives, refreshes every upstream source, records source versions, and
generates all outputs. `generate` reruns code generation from the existing upstream data without network access.

`--cfn-lint-root` is required by `sync`, which fails before starting work when it is absent. A successful sync records
its source-qualified versions only after all source processing succeeds.

### AWS CLI operation catalog

`generated/data/aws_cli_operation_catalog.json` is the adapter catalog that maps AWS CLI operations to CloudFormation
resource types for `validateAwsCliCommand`. It derives from AWS CLI botocore service models plus CloudFormation
provider handler metadata, so `sync` produces it as its final step, after the provider schemas and compiled schemas
exist. With `--aws-cli-root <DIR>` (a local aws-cli checkout whose `awscli/` supplies botocore), `sync` runs
`scripts/generate_aws_cli_catalog.py` and records the AWS CLI release it used as `aws_cli_version` in
`generated/data/source_versions.json`. Without it, `sync` keeps the committed catalog and re-verifies its mappings
against the refreshed compiled schemas, failing with a request for `--aws-cli-root` if any mapped property no longer
exists or became read-only. A repository that has never generated a catalog must pass `--aws-cli-root`, because the
build script embeds the catalog.

Besides the operation-to-type and parameter-to-property pairs, each mapping records the API value domain that the
compiled CloudFormation schema cannot represent (`unrepresentable`: enum members, numeric bounds, string lengths, list
sizes, tag key/value lengths, and the API/CloudFormation regex `pattern` pair when the two differ), derived by comparing
the botocore input shape against the compiled property schema. The
runtime uses it to skip synthesis for a command whose values the service accepts but CloudFormation would reject.
Same-named inputs whose meaning differs from the CloudFormation property are excluded by the reviewed
`PROPERTY_SEMANTIC_DENYLIST` in the script. Pass `--aws-cli-root` after changing the generator's mapping rules or after
updating the AWS CLI checkout.


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
