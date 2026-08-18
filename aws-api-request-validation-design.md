# Validating AWS API Requests

## Summary

`cloudformation-validate` normally receives a CloudFormation template. A direct AWS API request carries resource configuration as operation parameters, so it has no template to validate. This feature accepts the request context and determines whether the operation represents CloudFormation resource state. It validates supplied `TemplateBody` bytes or builds a temporary, one-resource template from mapped request fields. A generated operation catalog supplies the service-operation, resource-type, and field mappings. Requests that produce no template return `SKIPPED` with a reason.

## Request and result

An Amazon Web Services (AWS) application programming interface (API) request enters this feature. Required fields are service name, operation name, and parameters. Three optional fields carry the request method, read-only status, and request-signing service prefix.

Parameter values use a tagged type. Variants represent null, Boolean, signed integer, unsigned integer, number, string, bytes, array, object, and unsupported values. This representation keeps `TemplateBody` bytes and 64-bit integer values intact.

The result contains an operation class, `VALIDATED` or `SKIPPED` status, template source, matched resource types, reason, and optional `cloudformation-validate` report. Template source is one of `TEMPLATE_BODY`, `CLOUD_CONTROL_DESIRED_STATE`, `SYNTHESIZED_CREATE`, or `SYNTHESIZED_UPDATE`.

## Operation catalog format and loading

The embedded catalog contains adapter rows with:

- `service`: canonical AWS service name.
- `operation`: exact API operation name.
- `phase`: `create`, `update`, or `delete`.
- `cfn_type`: CloudFormation resource type.
- `mappings`: request-field and CloudFormation-property pairs named `source` and `target`.

At startup, the catalog loader checks non-empty identities and unique service-operation keys. It lowercases the service portion of each key and keeps the operation name unchanged. The resulting map supports exact lookup by `(service, operation)`.

The data build compresses the catalog into the `cloudformation-validate` artifact. Runtime request processing does not load service models or catalog files.

## Catalog generation

The generator combines three sources.

1. **Enhanced CloudFormation provider schemas** supply each resource type and its create and delete handler permissions.
2. **Botocore service models** resolve permission actions to exact services and operations. They also supply operation input fields and types.
3. **CloudFormation property definitions** supply writable property names, read-only properties, identifiers, and accepted value types.

The generator applies five stages:

1. **Find candidate operations.** For one resource type, read its create or delete handler permissions. Keep actions whose verb matches that lifecycle phase.
2. **Resolve the API operation.** Match each permission against Botocore service identities and operation names. Known service aliases handle naming differences between CloudFormation and AWS APIs.
3. **Map request fields to properties.** Compare Botocore input fields with writable CloudFormation properties. Accept equal names and narrow renames such as `Bucket` to `BucketName`. Record mappings whose value types align. String maps targeting `Tags` use the tag conversion.
4. **Choose one adapter.** Rank candidates by resource-name agreement, lifecycle verb, mapped-field count, and mapping coverage. A candidate without name agreement needs two mappings covering 30 percent of its inputs. Equal-ranked candidates and unresolved service-operation collisions produce no adapter. Known data operations are excluded.
5. **Write the catalog.** Add hand-authored update adapters and remove generation-only fields. Sort entries, then write each adapter’s service, operation, phase, resource type, and mappings.

The S3 bucket example has four links.

`AWS::S3::Bucket` → create permission `s3:CreateBucket` → Botocore input `Bucket` → CloudFormation property `BucketName`.

It emits service `s3`, operation `CreateBucket`, phase `create`, resource type `AWS::S3::Bucket`, and mapping `Bucket → BucketName`.

Create and delete adapters come from provider handler permissions. Update adapters remain hand-authored because update requests contain changed fields rather than complete resource state.

## Operation classification

Each request receives one of six classes: `READ_ONLY`, `CLOUD_FORMATION_CREATE`, `CLOUD_FORMATION_UPDATE`, `CLOUD_FORMATION_DELETE`, `DATA_PLANE_MUTATION`, or `UNMAPPED_MUTATION`.

The classifier applies these rules in order:

1. Known CloudFormation operations receive fixed classes. Stack and change-set creation operations use `CLOUD_FORMATION_CREATE`; stack updates use `CLOUD_FORMATION_UPDATE`; template inspection uses `READ_ONLY`.
2. An explicit read-only status produces `READ_ONLY`.
3. An exact catalog match uses the adapter phase and resource type.
4. The classifier splits an uncataloged operation name into words and selects its effective verb. Modifier prefixes such as `Admin`, `Batch`, `Bulk`, and `Transact` move the effective verb to the next word.
5. Read verbs or `GET` and `HEAD` produce `READ_ONLY`. Data verbs produce `DATA_PLANE_MUTATION`.
6. Exact Cloud Control `CreateResource`, `UpdateResource`, and `DeleteResource` calls read `TypeName` when it names a known resource type. Create and delete receive lifecycle classes. Update receives `UNMAPPED_MUTATION`.
7. Remaining writes use `DATA_PLANE_MUTATION` for the configured content-changing verb set and `UNMAPPED_MUTATION` otherwise. These classes contain no inferred resource type.

The canonical service name controls catalog and special-operation lookup. The service prefix does not replace it. Service matching changes ASCII letter case only; operation matching remains exact.

## Template construction and validation

Template construction follows the classification result.

1. A recognized CloudFormation operation with a non-empty `TemplateBody` string or byte sequence sends those bytes directly to `cloudformation-validate`.
2. A recognized CloudFormation operation containing `TemplateURL` returns `SKIPPED` because no template bytes are present.
3. A `READ_ONLY` request without a direct `TemplateBody` path returns `SKIPPED`.
4. Cloud Control `CreateResource` with `TypeName` and `DesiredState` parses the state string or bytes as a JSON object. It uses `TypeName` as the resource type. Cloud Control `UpdateResource` returns `SKIPPED` because it carries `PatchDocument`.
5. A cataloged create or update loads the mapped resource’s CloudFormation property definitions. Delete and other classes return `SKIPPED` before field mapping.
6. For every adapter mapping, the runtime confirms that the target property exists. It excludes read-only properties and, for updates, identifying properties. Missing source fields are ignored.
7. Strings, Booleans, integers, numbers, and lists of simple values map when their types match the target property. A string map targeting `Tags` becomes a sorted array of `{Key, Value}` objects. Other object values, bytes, nulls, and unsupported values do not enter the temporary template.
8. If no field maps, the request returns `SKIPPED`. Otherwise, the runtime creates one resource named `Resource` with the matched type and mapped properties.
9. `cloudformation-validate` processes the temporary template. For catalog-generated templates, the result retains findings only for properties inserted during field mapping and recalculates report counts.

The final response returns the operation class, status, template source, resource types, reason, and validation report when validation ran.


