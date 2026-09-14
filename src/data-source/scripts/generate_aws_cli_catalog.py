#!/usr/bin/env python3
"""Generate the AWS API operation adapter catalog for validation-engine.

Derives CloudFormation-type -> API-operation adapters from two sources:

1. CloudFormation resource provider schemas WITH handler metadata, as synced
   into ``upstream/schemas`` (from the
   https://github.com/aws-cloudformation/resource-provider-enhanced-schemas
   releases). Each type's own create/delete handler permissions contain the
   type's canonical lifecycle API actions. Every mapping is verified against
   the committed compiled schemas
   (``generated/schema-validator/compiled_schemas.json``).
2. Botocore service models (importable ``botocore`` from an AWS CLI checkout),
   which resolve IAM action prefixes to real services and operations and
   provide exact input shapes.

Derivation direction is type -> operation, scoped to one type's own handler
permissions at a time. The global inverse (operation -> type by name) is
unsafe and is never used. Every candidate must pass all of:

- service identity resolution: an IAM action prefix denotes a botocore service
  only by exact identity match (botocore service name, endpoint prefix, signing
  name, or service id, compared literally and case-insensitively with
  punctuation preserved) or a reviewed action-prefix override
  (``ACTION_PREFIX_SERVICE_OVERRIDES``). There is no substring, fuzzy, or
  punctuation-folding fallback, so a prefix never denotes a service merely
  because one string contains the other or differs only in punctuation.
- service relatedness: the resolved service must relate to the type's own CFN
  segment; a botocore-service-name match beats an IAM-prefix match beats a
  signing-identity match, and lower-priority relationships are dropped when a
  stronger one exists
- lifecycle verb family match for the handler role
- structural verification: operation input members must map onto writable
  properties of the type in the validator's OWN compiled schemas by
  case-insensitive identifier match, or via the reviewed identifier-rename
  allowlist (``PROPERTY_RENAME_ALLOWLIST``); a differently-named property is
  accepted only for a fully reviewed cfn_type/service/operation/source/target
  context; a same-named member whose meaning differs from the property
  (``PROPERTY_SEMANTIC_DENYLIST``) never maps
- value-domain verification: every CloudFormation constraint the botocore
  model does not enforce at least as strictly (enum members, numeric bounds,
  string lengths, list and tag-map sizes, tag key/value lengths, and a
  ``pattern`` the API lacks or states differently) is recorded per mapping as
  an ``unrepresentable`` domain so the runtime skips synthesis for a value
  outside it instead of reporting a CloudFormation finding against a call the
  service may accept
- noun agreement or property-overlap thresholds; ties are dropped entirely
- global reverse uniqueness: one (service, operation) key maps to exactly one
  catalog entry; unresolvable collisions are dropped entirely

Types or operations that fail any gate are omitted: an uncovered operation is
validated as SKIPPED at runtime, never guessed.

Usage:
    python3 generate_aws_cli_catalog.py \
        --botocore-root /path/to/aws-cli/awscli \
        --provider-schemas ../upstream/schemas \
        --compiled-schemas ../generated/schema-validator/compiled_schemas.json \
        --output ../generated/data/aws_cli_operation_catalog.json
"""

import argparse
import hashlib
import importlib
import json
import re
import sys
import zipfile
from collections import defaultdict
from pathlib import Path

FORMAT_VERSION = 1

# Multiple provider types can list the same underlying operation. Keep a
# collision only when the API action itself names one uniquely correct type;
# every unreviewed or representation-version collision is dropped.
COLLISION_PREFERENCES = {
    ('dynamodb', 'CreateTable'): 'AWS::DynamoDB::Table',
    ('ec2', 'CreateTransitGatewayVpcAttachment'):
        'AWS::EC2::TransitGatewayVpcAttachment',
    ('eks', 'CreateAccessEntry'): 'AWS::EKS::AccessEntry',
}

CREATE_VERBS = (
    'create', 'put', 'register', 'add', 'allocate', 'provision', 'launch',
    'run', 'import', 'request', 'publish', 'set', 'establish',
    'associate', 'attach', 'enable', 'deploy', 'subscribe', 'purchase',
    'copy', 'initialize', 'define', 'build', 'issue', 'schedule', 'submit',
    'grant', 'start',
)
DELETE_VERBS = (
    'delete', 'remove', 'deregister', 'release', 'terminate', 'cancel',
    'disassociate', 'detach', 'revoke', 'deprovision', 'destroy',
    'unsubscribe', 'purge',
)

# Reviewed property-identifier renames. A create/delete input member maps onto a
# differently-named CloudFormation property only when the full context
# (cfn_type, service, operation, source member, target property) appears here.
# Same-identifier mappings (case-insensitive) never need an entry; every rename
# below was individually audited against the resource's own schema. An
# unreviewed `<member>` -> `<member>Name` or `Name` -> `<Segment>Name` transform
# is rejected, so a resource-name rename can never be synthesized implicitly.
PROPERTY_RENAME_ALLOWLIST = frozenset({
    ('AWS::Batch::ComputeEnvironment', 'batch', 'DeleteComputeEnvironment', 'computeEnvironment', 'ComputeEnvironmentName'),
    ('AWS::Batch::ConsumableResource', 'batch', 'DeleteConsumableResource', 'consumableResource', 'ConsumableResourceName'),
    ('AWS::Batch::JobDefinition', 'batch', 'DeregisterJobDefinition', 'jobDefinition', 'JobDefinitionName'),
    ('AWS::Batch::JobQueue', 'batch', 'DeleteJobQueue', 'jobQueue', 'JobQueueName'),
    ('AWS::Batch::ServiceEnvironment', 'batch', 'DeleteServiceEnvironment', 'serviceEnvironment', 'ServiceEnvironmentName'),
    ('AWS::CloudTrail::Trail', 'cloudtrail', 'CreateTrail', 'Name', 'TrailName'),
    ('AWS::CloudTrail::Trail', 'cloudtrail', 'DeleteTrail', 'Name', 'TrailName'),
    ('AWS::CodeArtifact::Domain', 'codeartifact', 'CreateDomain', 'domain', 'DomainName'),
    ('AWS::CodeArtifact::Domain', 'codeartifact', 'DeleteDomain', 'domain', 'DomainName'),
    ('AWS::CodeArtifact::PackageGroup', 'codeartifact', 'CreatePackageGroup', 'domain', 'DomainName'),
    ('AWS::CodeArtifact::PackageGroup', 'codeartifact', 'DeletePackageGroup', 'domain', 'DomainName'),
    ('AWS::CodeArtifact::Repository', 'codeartifact', 'CreateRepository', 'domain', 'DomainName'),
    ('AWS::CodeArtifact::Repository', 'codeartifact', 'CreateRepository', 'repository', 'RepositoryName'),
    ('AWS::CodeArtifact::Repository', 'codeartifact', 'DeleteRepository', 'domain', 'DomainName'),
    ('AWS::CodeArtifact::Repository', 'codeartifact', 'DeleteRepository', 'repository', 'RepositoryName'),
    ('AWS::ECS::CapacityProvider', 'ecs', 'CreateCapacityProvider', 'cluster', 'ClusterName'),
    ('AWS::ECS::CapacityProvider', 'ecs', 'DeleteCapacityProvider', 'cluster', 'ClusterName'),
    ('AWS::ECS::Cluster', 'ecs', 'DeleteCluster', 'cluster', 'ClusterName'),
    ('AWS::ECS::Service', 'ecs', 'DeleteService', 'service', 'ServiceName'),
    ('AWS::Glue::Database', 'glue', 'DeleteDatabase', 'Name', 'DatabaseName'),
    ('AWS::Lex::BotAlias', 'lex-models', 'DeleteBotAlias', 'name', 'BotAliasName'),
    ('AWS::S3::Bucket', 's3', 'CreateBucket', 'Bucket', 'BucketName'),
    ('AWS::S3::Bucket', 's3', 'DeleteBucket', 'Bucket', 'BucketName'),
    ('AWS::S3Outposts::Bucket', 's3control', 'CreateBucket', 'Bucket', 'BucketName'),
    ('AWS::S3Tables::Table', 's3tables', 'CreateTable', 'name', 'TableName'),
    ('AWS::S3Tables::Table', 's3tables', 'DeleteTable', 'name', 'TableName'),
    ('AWS::S3Tables::TableBucket', 's3tables', 'CreateTableBucket', 'name', 'TableBucketName'),
    ('AWS::SNS::Topic', 'sns', 'CreateTopic', 'Name', 'TopicName'),
    ('AWS::StepFunctions::StateMachine', 'stepfunctions', 'CreateStateMachine', 'name', 'StateMachineName'),
    ('AWS::Timestream::ScheduledQuery', 'timestream-query', 'CreateScheduledQuery', 'Name', 'ScheduledQueryName'),
})

# Reviewed same-identifier mappings whose meaning differs between the API and
# the CloudFormation property, so a value that is valid for the API can never
# be the CloudFormation value. Each entry names an API member carrying a bare
# resource identifier where the same-named CloudFormation property carries the
# resource ARN (its schema pattern is anchored on ``^arn:``). Such a member is
# never mapped; when supplied, the request is skipped at runtime.
PROPERTY_SEMANTIC_DENYLIST = frozenset({
    ('AWS::Connect::ApprovedOrigin', 'connect', 'AssociateApprovedOrigin', 'InstanceId', 'InstanceId'),
    ('AWS::Connect::ContactFlowModuleAlias', 'connect', 'CreateContactFlowModuleAlias', 'ContactFlowModuleId', 'ContactFlowModuleId'),
    ('AWS::Connect::ContactFlowModuleVersion', 'connect', 'CreateContactFlowModuleVersion', 'ContactFlowModuleId', 'ContactFlowModuleId'),
    ('AWS::Connect::ContactFlowVersion', 'connect', 'CreateContactFlowVersion', 'ContactFlowId', 'ContactFlowId'),
    ('AWS::Connect::IntegrationAssociation', 'connect', 'CreateIntegrationAssociation', 'InstanceId', 'InstanceId'),
    ('AWS::Connect::SecurityKey', 'connect', 'AssociateSecurityKey', 'InstanceId', 'InstanceId'),
    ('AWS::S3Outposts::BucketPolicy', 's3control', 'PutBucketPolicy', 'Bucket', 'Bucket'),
})

# CFN service segments whose botocore/IAM service identity differs beyond casing.
# Maps a normalized CFN service segment to the exact normalized botocore service
# identities it may relate to (lowercased, punctuation stripped). This reviewed
# table is how a segment relates to a differently-named service: relatedness comes
# only from an exact identity/prefix match or an explicit entry here, never from
# one string being a substring of another.
SEGMENT_ALIASES = {
    'msk': ('kafka',),
    'opensearchservice': ('es',),
    'certificatemanager': ('acm',),
    'elasticloadbalancingv2': ('elasticloadbalancing',),
    'ses': ('sesv2',),
    'amazonmq': ('mq',),
    'bcm': ('bcmdashboards',),
    'cognito': ('cognitoidentity', 'cognitoidp'),
    'eventschemas': ('schemas',),
    'kinesisfirehose': ('firehose',),
    'macie': ('macie2',),
    'mediapackage': ('mediapackagevod',),
    'route53recoverycontrol': ('route53recoverycontrolconfig',),
    'timestream': ('timestreaminfluxdb',),
}

# Services handled by dedicated validation paths; adapters must not shadow them.
EXCLUDED_SERVICES = frozenset({'cloudformation', 'cloudcontrol'})

# Reviewed IAM action-prefix -> canonical botocore service overrides. Keys are the
# literal-lowercase action prefix (the form `resolve` receives), matched exactly
# with punctuation preserved. These cover IAM prefixes that are not themselves a
# botocore service identity, so exact identity resolution alone would miss them.
# Each entry was audited against the resource's own handler permissions and the
# canonical service's operations:
#   `kafka-cluster` (MSK topic data-plane actions) -> `kafka`
#   `s3-outposts`   (S3 on Outposts bucket actions) -> `s3control`
# They are exact reviewed entries, not substring or punctuation-folded aliases.
ACTION_PREFIX_SERVICE_OVERRIDES = {
    'kafka-cluster': 'kafka',
    's3-outposts': 's3control',
}

# Hand-reviewed update adapters. Update APIs carry partial state, so update
# entries are curated rather than derived; each is verified like derived ones.
CURATED_UPDATE_ADAPTERS = [
    {
        'cfn_type': 'AWS::Lambda::Function',
        'service': 'lambda',
        'operation': 'UpdateFunctionConfiguration',
        'phase': 'update',
        'mappings': [
            {'source': 'Runtime', 'target': 'Runtime'},
            {'source': 'Role', 'target': 'Role'},
            {'source': 'Handler', 'target': 'Handler'},
            {'source': 'Description', 'target': 'Description'},
            {'source': 'Timeout', 'target': 'Timeout'},
            {'source': 'MemorySize', 'target': 'MemorySize'},
        ],
        'ignored_inputs': ['FunctionName'],
    },
]

# Operations that mutate runtime state without representing desired-state
# creation. The generator fails if a derivation ever selects one of these.
FORBIDDEN_OPERATIONS = frozenset({
    ('ecs', 'RunTask'),
    ('ec2', 'StartInstances'),
    ('ec2', 'StopInstances'),
    ('ec2', 'RebootInstances'),
    ('iot', 'StartThingRegistrationTask'),
    ('lambda', 'Invoke'),
    ('sns', 'Publish'),
    ('sqs', 'SendMessage'),
    ('s3', 'PutObject'),
    ('dynamodb', 'PutItem'),
    ('logs', 'StartQuery'),
    ('acm', 'RemoveTagsFromCertificate'),
    ('robomaker', 'DeregisterRobot'),
    ('quicksight', 'CreateTopic'),
    ('quicksight', 'DeleteTopic'),
})

# Explicit input member names safe to ignore during all-or-nothing synthesis.
# These are request-control fields that do not represent desired resource state.
# Detection: by exact name match from this curated set, or botocore shape
# metadata (idempotencyToken trait).
IGNORED_INPUT_NAMES = frozenset({
    'ClientToken',
    'ClientRequestToken',
    'IdempotencyToken',
    'RequestToken',
    'DryRun',
})


def _ignored_inputs_for_operation(members, phase, service, operation):
    """Determine which input members are safe to ignore.

    Returns a sorted list of member names that the runtime can discard without
    affecting state validation.  Only exact name matches against the curated
    request-control set and botocore idempotency-token metadata qualify.
    """
    ignored = set()
    for name, shape in members.items():
        if name in IGNORED_INPUT_NAMES:
            ignored.add(name)
        elif getattr(shape, 'metadata', None) and shape.metadata.get(
            'idempotencyToken'
        ):
            ignored.add(name)
        elif hasattr(shape, 'serialization') and isinstance(
            shape.serialization, dict
        ) and shape.serialization.get('idempotencyToken'):
            ignored.add(name)
    return sorted(ignored)


# Known-good pairs the derivation must reproduce exactly; guards regressions
# in the derivation rules themselves.
EXPECTED_PAIRS = {
    'AWS::S3::Bucket': ('s3', 'CreateBucket'),
    'AWS::DynamoDB::Table': ('dynamodb', 'CreateTable'),
    'AWS::IAM::Role': ('iam', 'CreateRole'),
    'AWS::Lambda::Function': ('lambda', 'CreateFunction'),
    'AWS::SNS::Topic': ('sns', 'CreateTopic'),
    'AWS::SQS::Queue': ('sqs', 'CreateQueue'),
    'AWS::EC2::Instance': ('ec2', 'RunInstances'),
    'AWS::EC2::VPC': ('ec2', 'CreateVpc'),
    'AWS::KMS::Key': ('kms', 'CreateKey'),
    'AWS::Logs::LogGroup': ('logs', 'CreateLogGroup'),
    'AWS::CloudWatch::Alarm': ('cloudwatch', 'PutMetricAlarm'),
    'AWS::StepFunctions::StateMachine': ('stepfunctions', 'CreateStateMachine'),
    'AWS::Kinesis::Stream': ('kinesis', 'CreateStream'),
    'AWS::SecretsManager::Secret': ('secretsmanager', 'CreateSecret'),
    'AWS::ElasticLoadBalancingV2::LoadBalancer': ('elbv2', 'CreateLoadBalancer'),
}


def _parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--botocore-root', required=True, type=Path)
    parser.add_argument('--provider-schemas', required=True, type=Path)
    parser.add_argument('--compiled-schemas', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    return parser.parse_args()


def _normalize(value):
    """Fold a CFN resource noun or segment for relatedness comparison.

    Case- and punctuation-insensitive, so segment/noun agreement ignores both.
    This folding is deliberately lossy and is only ever used to judge whether a
    resolved service relates to a type's own segment; it must never key service
    identity resolution, where punctuation is significant.
    """
    return ''.join(c for c in value.lower() if c.isalnum())


def _identity_key(value):
    """Fold a service identity or IAM action prefix for exact lookup.

    Case-insensitive only, preserving punctuation, so ``s3-control`` and
    ``s3control`` stay distinct keys. Service resolution keys on this form, so
    no punctuation difference can be erased into a false identity match.
    """
    return value.lower()


class BotocoreIndex:
    """Resolves IAM action prefixes to concrete botocore operations."""

    def __init__(self):
        botocore_session = importlib.import_module('botocore.session')
        self._session = botocore_session.Session()
        self._identities = {}
        self._operations = {}
        self._by_identity = defaultdict(set)
        for service in self._session.get_available_services():
            model = self._session.get_service_model(service)
            identity_sources = [
                value
                for value in (
                    service,
                    model.endpoint_prefix or '',
                    model.signing_name or '',
                    str(getattr(model, 'service_id', '') or ''),
                )
                if value
            ]
            self._identities[service] = {
                _normalize(value) for value in identity_sources
            }
            for value in identity_sources:
                self._by_identity[_identity_key(value)].add(service)
            self._operations[service] = {
                op.lower(): op for op in model.operation_names
            }

    @property
    def service_count(self):
        return len(self._operations)

    @property
    def operation_count(self):
        """Total number of operations across all services."""
        return sum(len(ops) for ops in self._operations.values())

    def input_members(self, service, operation):
        model = self._session.get_service_model(service)
        shape = model.operation_model(operation).input_shape
        return dict(shape.members) if shape else {}

    def resolve(self, action_prefix, action_name):
        """Every (service, operation) the exact action identity can denote.

        Resolution is exact and case-insensitive with punctuation preserved:
        ``action_prefix`` is a literal-lowercase IAM prefix that must equal one
        of a botocore service's literal-lowercase identity components (service
        name, endpoint prefix, signing name, or service id). The only
        non-identity resolutions are the reviewed
        ``ACTION_PREFIX_SERVICE_OVERRIDES``. There is no substring, fuzzy, or
        punctuation-folding fallback, so an IAM prefix never denotes a service
        because one string contains the other or differs only in punctuation.
        """
        resolved = set()
        for service in self._by_identity.get(action_prefix, ()):
            operation = self._operations[service].get(action_name.lower())
            if operation:
                resolved.add((service, operation))
        override_service = ACTION_PREFIX_SERVICE_OVERRIDES.get(action_prefix)
        if override_service is not None:
            operation = self._operations.get(override_service, {}).get(
                action_name.lower()
            )
            if operation:
                resolved.add((override_service, operation))
        return resolved

    def identity_tier(self, action_prefix, service, segment_aliases):
        """Lower is a stronger identity match; None means unrelated."""
        if _normalize(service) in segment_aliases:
            return 0
        if action_prefix in segment_aliases:
            return 1
        if self._identities[service] & segment_aliases:
            return 2
        return None


def _verb_rank(operation, verbs):
    lowered = operation.lower()
    for index, verb in enumerate(verbs):
        if lowered.startswith(verb):
            return index
    return None


def _noun_matches(operation, resource_segment):
    normalized = _normalize(operation)
    if normalized.endswith(resource_segment):
        return True
    if normalized.endswith(resource_segment + 's'):
        return True
    if resource_segment.endswith('y') and normalized.endswith(
        resource_segment[:-1] + 'ies'
    ):
        return True
    return False


def _source_sha256(source_path):
    digest = hashlib.sha256()
    if source_path.is_file():
        digest.update(source_path.read_bytes())
        return digest.hexdigest()
    for path in sorted(source_path.rglob('*.json')):
        digest.update(path.relative_to(source_path).as_posix().encode())
        digest.update(b'\0')
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _aws_cli_version(botocore_root):
    """Release version of the AWS CLI checkout whose ``awscli/`` is ``botocore_root``.

    Read textually from ``awscli/__init__.py`` because importing ``awscli``
    installs import hooks and is not needed to learn the version.
    """
    init_path = botocore_root / '__init__.py'
    match = re.search(
        r"^__version__\s*=\s*['\"]([^'\"]+)['\"]", init_path.read_text(), re.M
    )
    if match is None:
        raise SystemExit(f'cannot determine the AWS CLI version from {init_path}')
    return match.group(1)


def _load_provider_schemas(source_path):
    schemas = {}
    if source_path.is_dir():
        documents = (
            (path.as_posix(), path.read_bytes())
            for path in sorted(source_path.rglob('*.json'))
        )
    else:
        archive = zipfile.ZipFile(source_path)
        documents = (
            (name, archive.read(name))
            for name in sorted(archive.namelist())
            if name.endswith('.json')
        )
    try:
        for _, contents in documents:
            try:
                schema = json.loads(contents)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            type_name = schema.get('typeName') if isinstance(schema, dict) else None
            if type_name and type_name.startswith('AWS::'):
                schemas[type_name] = schema
    finally:
        if not source_path.is_dir():
            archive.close()
    return schemas


def _compiled_constraints(compiled_schemas, type_name):
    schema = compiled_schemas.get(type_name)
    if not isinstance(schema, dict):
        return None
    property_schemas = schema.get('properties') or {}
    read_only = set(schema.get('read_only_properties') or [])
    primary = set(schema.get('primary_identifier') or [])
    definitions = schema.get('definitions') or {}
    return property_schemas, read_only, primary, definitions


def _resolve_schema_node(node, definitions, seen=frozenset()):
    if not isinstance(node, dict):
        return {}
    reference = node.get('ref_name')
    if reference and reference not in seen:
        return _resolve_schema_node(
            definitions.get(reference), definitions, seen | {reference}
        )
    return node


def _schema_types(node, definitions):
    node = _resolve_schema_node(node, definitions)
    schema_type = node.get('type')
    if isinstance(schema_type, str):
        types = {schema_type}
    elif isinstance(schema_type, list):
        types = {value for value in schema_type if isinstance(value, str)}
    else:
        types = set()
    for alternatives in ('any_of', 'one_of'):
        for alternative in node.get(alternatives) or []:
            types.update(_schema_types(alternative, definitions))
    return types


def _schema_node_for_type(node, definitions, expected_type):
    node = _resolve_schema_node(node, definitions)
    if expected_type in _schema_types(node, definitions):
        if expected_type in _schema_types(
            {key: value for key, value in node.items()
             if key not in ('any_of', 'one_of')}, definitions
        ):
            return node
        for alternatives in ('any_of', 'one_of'):
            for alternative in node.get(alternatives) or []:
                selected = _schema_node_for_type(
                    alternative, definitions, expected_type
                )
                if selected:
                    return selected
    return None


def _resolve_tag_schema_node(node, definitions):
    seen = set()
    while isinstance(node, dict):
        reference = node.get('ref_name')
        if not reference:
            return node
        if set(node) != {'ref_name'} or reference in seen:
            return None
        seen.add(reference)
        node = definitions.get(reference)
    return None


def _key_value_tag_branch_match(schema_node, definitions):
    schema_node = _resolve_tag_schema_node(schema_node, definitions)
    if schema_node is None:
        return None
    supported_keys = {
        'type', 'properties', 'required', 'additional_properties',
        'description',
    }
    if set(schema_node) - supported_keys:
        return None

    schema_type = schema_node.get('type')
    if isinstance(schema_type, str):
        schema_types = {schema_type}
    elif isinstance(schema_type, list):
        if not all(isinstance(value, str) for value in schema_type):
            return None
        schema_types = set(schema_type)
    elif schema_type is None:
        schema_types = set()
    else:
        return None
    if schema_types and 'object' not in schema_types:
        return False, set()

    properties = schema_node.get('properties') or {}
    required = schema_node.get('required') or []
    additional_properties = schema_node.get('additional_properties')
    if (not isinstance(properties, dict)
            or not isinstance(required, list)
            or not all(isinstance(field, str) for field in required)
            or (additional_properties is not None
                and not isinstance(additional_properties, bool))):
        return None

    generated_fields = {'Key', 'Value'}
    property_names = set(properties)
    if not set(required) <= generated_fields:
        return False, set()
    if (additional_properties is False
            and not generated_fields <= property_names):
        return False, set()
    for field in generated_fields & property_names:
        if 'string' not in _schema_types(properties[field], definitions):
            return False, set()
    return True, property_names & generated_fields


def _is_key_value_tag_array(target_schema, definitions):
    array_schema = _schema_node_for_type(
        target_schema, definitions, 'array'
    )
    if not array_schema:
        return False
    item_schema = _resolve_tag_schema_node(
        array_schema.get('items') or {}, definitions
    )
    if item_schema is None:
        return False

    base_schema = {
        key: value for key, value in item_schema.items()
        if key not in ('any_of', 'one_of')
    }
    base_match = _key_value_tag_branch_match(base_schema, definitions)
    if base_match is None or not base_match[0]:
        return False
    base_fields = base_match[1]

    any_of = item_schema.get('any_of') or []
    any_of_fields = [set()]
    if any_of:
        any_of_fields = []
        for alternative in any_of:
            alternative_match = _key_value_tag_branch_match(
                alternative, definitions
            )
            if alternative_match is not None and alternative_match[0]:
                any_of_fields.append(alternative_match[1])
        if not any_of_fields:
            return False

    one_of = item_schema.get('one_of') or []
    one_of_fields = [set()]
    if one_of:
        one_of_fields = []
        for alternative in one_of:
            alternative_match = _key_value_tag_branch_match(
                alternative, definitions
            )
            if alternative_match is None:
                return False
            if alternative_match[0]:
                one_of_fields.append(alternative_match[1])
        if len(one_of_fields) != 1:
            return False

    generated_fields = {'Key', 'Value'}
    return any(
        generated_fields <= base_fields | any_fields | one_fields
        for any_fields in any_of_fields
        for one_fields in one_of_fields
    )


def _is_runtime_safe_mapping(source_shape, target_schema, definitions, target):
    source_type = source_shape.type_name
    target_types = _schema_types(target_schema, definitions)
    if source_type in ('string', 'boolean'):
        return source_type in target_types
    if source_type in ('integer', 'long'):
        return bool({'integer', 'number'} & target_types)
    if source_type in ('float', 'double'):
        return 'number' in target_types
    if source_type == 'list' and source_shape.member.type_name in (
        'string', 'boolean', 'integer', 'long', 'float', 'double'
    ):
        array_schema = _schema_node_for_type(
            target_schema, definitions, 'array'
        )
        return bool(
            array_schema
            and _is_runtime_safe_mapping(
                source_shape.member,
                array_schema.get('items') or {},
                definitions,
                target,
            )
        )
    if source_type == 'map' and target == 'Tags':
        return (
            source_shape.value.type_name == 'string'
            and _is_key_value_tag_array(target_schema, definitions)
        )
    return False


def _shape_bounds(shape):
    """botocore ``min``/``max`` traits: string length, list size, or numeric range."""
    metadata = getattr(shape, 'metadata', None) or {}
    return metadata.get('min'), metadata.get('max')


def _cfn_pattern_rejects(pattern, value):
    """True only when the CloudFormation pattern provably rejects ``value``.

    JSON Schema patterns are unanchored ECMA regexes; ``re.search`` mirrors
    that. A pattern Python cannot compile is treated as not rejecting anything,
    so a mapping is never restricted on unverifiable evidence.
    """
    try:
        return re.search(pattern, value) is None
    except re.error:
        return False


def _anchor_pattern(pattern):
    """``pattern`` wrapped so it must match a whole value.

    Services validate a botocore ``pattern`` against the entire input, so this
    is the form in which an API pattern describes the values the service
    accepts. Wrapping in a non-capturing group keeps a top-level alternation
    (``^$|arn:.+``) anchored as a whole.
    """
    return f'^(?:{pattern})$'


def _strip_anchors(pattern):
    """``pattern`` without a leading ``^`` or trailing unescaped ``$``.

    Two patterns that differ only in these anchors describe the same whole
    values, because both the service and the schema validator apply them to
    the complete string.
    """
    if pattern.startswith('^'):
        pattern = pattern[1:]
    if pattern.endswith('$') and not pattern.endswith('\\$'):
        pattern = pattern[:-1]
    return pattern


def _pattern_divergence(source_shape, node):
    """The CloudFormation ``pattern`` the API does not enforce, if any.

    When the API declares no ``pattern``, the CloudFormation pattern alone is
    recorded: every value it rejects is unrepresentable, because the service may
    still accept it. When both sides declare a pattern, regex inclusion is
    undecidable in general, so a textual difference (beyond the ``^``/``$``
    anchors, which the schema validator and the service both apply to whole
    values) is recorded as a candidate divergence and settled per value at
    runtime: a value the API pattern accepts and the CloudFormation pattern
    rejects skips synthesis. The API pattern is recorded anchored to the whole
    value, as the service applies it; the CloudFormation pattern is recorded as
    written, as the schema validator applies it, and is not pre-checked here:
    the runtime compiles it exactly as the schema validator does, so a pattern
    neither can compile guards nothing, which matches the validator reporting
    nothing for it. Returns ``None`` when CloudFormation has no pattern, when the
    two are the same pattern, or when the API pattern is not a regex Python can
    compile, so a mapping is never restricted on evidence the generator cannot
    read.
    """
    api_pattern = (getattr(source_shape, 'metadata', None) or {}).get('pattern')
    cfn_pattern = node.get('pattern')
    if not cfn_pattern:
        return None
    if not api_pattern:
        return {'cloudformation': cfn_pattern}
    if _strip_anchors(api_pattern) == _strip_anchors(cfn_pattern):
        return None
    anchored_api_pattern = _anchor_pattern(api_pattern)
    if not _compiles(anchored_api_pattern):
        return None
    return {'api': anchored_api_pattern, 'cloudformation': cfn_pattern}


def _compiles(pattern):
    try:
        re.compile(pattern)
    except re.error:
        return False
    return True


def _unenforced_maximum(api_maximum, cfn_maximum):
    """``cfn_maximum`` when the API allows more: a higher maximum or none at all."""
    if cfn_maximum is None:
        return None
    if api_maximum is None or api_maximum > cfn_maximum:
        return cfn_maximum
    return None


def _unenforced_minimum(api_minimum, cfn_minimum):
    """``cfn_minimum`` when the API allows less: a lower minimum or none at all."""
    if cfn_minimum is None:
        return None
    if api_minimum is None or api_minimum < cfn_minimum:
        return cfn_minimum
    return None


def _size_minimum(cfn_minimum):
    """A length or item-count minimum, with the vacuous zero treated as absent."""
    return cfn_minimum or None


def _string_unrepresentable(source_shape, target_schema, definitions):
    node = (
        _schema_node_for_type(target_schema, definitions, 'string')
        or _resolve_schema_node(target_schema, definitions)
    )
    domain = {}
    api_min, api_max = _shape_bounds(source_shape)
    cfn_min = node.get('min_length')
    cfn_max = node.get('max_length')
    cfn_enum = node.get('enum')
    api_enum = list(getattr(source_shape, 'enum', None) or [])
    if api_enum:
        pattern = node.get('pattern')
        rejected = sorted(
            value for value in api_enum
            if (isinstance(cfn_enum, list) and value not in cfn_enum)
            or (pattern and _cfn_pattern_rejects(pattern, value))
            or (cfn_min is not None and len(value) < cfn_min)
            or (cfn_max is not None and len(value) > cfn_max)
        )
        if rejected:
            domain['rejected_values'] = rejected
        return domain
    if isinstance(cfn_enum, list) and cfn_enum:
        domain['allowed_values'] = list(cfn_enum)
    max_length = _unenforced_maximum(api_max, cfn_max)
    if max_length is not None:
        domain['max_length'] = max_length
    min_length = _unenforced_minimum(api_min, _size_minimum(cfn_min))
    if min_length is not None:
        domain['min_length'] = min_length
    pattern_divergence = _pattern_divergence(source_shape, node)
    if pattern_divergence:
        domain['pattern'] = pattern_divergence
    return domain


def _numeric_unrepresentable(source_shape, target_schema, definitions):
    node = (
        _schema_node_for_type(target_schema, definitions, 'integer')
        or _schema_node_for_type(target_schema, definitions, 'number')
        or _resolve_schema_node(target_schema, definitions)
    )
    domain = {}
    api_min, api_max = _shape_bounds(source_shape)
    maximum = _unenforced_maximum(api_max, node.get('maximum'))
    if maximum is not None:
        domain['maximum'] = maximum
    minimum = _unenforced_minimum(api_min, node.get('minimum'))
    if minimum is not None:
        domain['minimum'] = minimum
    return domain


def _size_unrepresentable(source_shape, array_schema):
    """List-size or tag-map-size bounds of ``array_schema`` the API does not enforce."""
    domain = {}
    api_min, api_max = _shape_bounds(source_shape)
    max_items = _unenforced_maximum(api_max, array_schema.get('max_items'))
    if max_items is not None:
        domain['max_length'] = max_items
    min_items = _unenforced_minimum(api_min, _size_minimum(array_schema.get('min_items')))
    if min_items is not None:
        domain['min_length'] = min_items
    return domain


def _tag_field_schema(item_schema, definitions, field):
    """Schema node of the ``Key`` or ``Value`` field of a Key/Value tag item."""
    item_schema = _resolve_tag_schema_node(item_schema, definitions) or {}
    candidates = [item_schema]
    for alternatives in ('any_of', 'one_of'):
        candidates.extend(item_schema.get(alternatives) or [])
    for candidate in candidates:
        candidate = _resolve_tag_schema_node(candidate, definitions) or {}
        properties = candidate.get('properties') or {}
        if field in properties:
            return properties[field]
    return {}


def _unrepresentable_domain(source_shape, target_schema, definitions, target):
    """Values of ``source_shape`` that ``target_schema`` rejects without the API
    model proving that the service rejects them too.

    A CloudFormation constraint is recorded whenever the API declares a wider
    one or none at all, because a value outside it may still be legal for the
    service and must not be reported as a CloudFormation violation. A
    constraint the API enforces at least as strictly is not recorded, so a
    value outside it keeps its CloudFormation finding. The returned mapping is
    empty when the API enforces every CloudFormation constraint. Keys name the
    CloudFormation constraint the API does not enforce: ``rejected_values``
    (API enum members CloudFormation rejects), ``allowed_values`` (the
    CloudFormation enum when the API declares none), ``minimum``/``maximum``
    (numeric bounds), ``min_length``/``max_length`` (string length, list size,
    or tag-map size), ``pattern`` (the CloudFormation regex, paired with the
    anchored API regex when the API declares a different one; settled per
    value at runtime), ``items`` (nested domain of list elements),
    ``tag_key``/``tag_value`` (nested string domains for tag maps).
    """
    source_type = source_shape.type_name
    if source_type == 'string':
        return _string_unrepresentable(source_shape, target_schema, definitions)
    if source_type in ('integer', 'long', 'float', 'double'):
        return _numeric_unrepresentable(source_shape, target_schema, definitions)
    if source_type == 'list':
        array_schema = _schema_node_for_type(
            target_schema, definitions, 'array'
        ) or {}
        domain = {}
        item_domain = _unrepresentable_domain(
            source_shape.member, array_schema.get('items') or {}, definitions,
            target,
        )
        if item_domain:
            domain['items'] = item_domain
        domain.update(_size_unrepresentable(source_shape, array_schema))
        return domain
    if source_type == 'map' and target == 'Tags':
        array_schema = _schema_node_for_type(
            target_schema, definitions, 'array'
        ) or {}
        item_schema = array_schema.get('items') or {}
        domain = _size_unrepresentable(source_shape, array_schema)
        for field, key in (('Key', 'tag_key'), ('Value', 'tag_value')):
            field_domain = _string_unrepresentable(
                source_shape.key if field == 'Key' else source_shape.value,
                _tag_field_schema(item_schema, definitions, field),
                definitions,
            )
            if field_domain:
                domain[key] = field_domain
        return domain
    return {}


def _mapping_entry(source, target, unrepresentable):
    entry = {'source': source, 'target': target}
    if unrepresentable:
        entry['unrepresentable'] = unrepresentable
    return entry


def _property_mappings(
    members, property_schemas, writable_by_lower, resource_segment, definitions,
    cfn_type, service, operation
):
    """Return mappings the runtime can serialize without nested rewriting.

    A member maps onto a property with the same identifier (case-insensitive)
    unconditionally unless the pair is a reviewed semantic mismatch
    (``PROPERTY_SEMANTIC_DENYLIST``). A member that maps onto a
    differently-named property is a reviewed rename, accepted only when
    (cfn_type, service, operation, member, target) is present in
    ``PROPERTY_RENAME_ALLOWLIST``. Each mapping carries the API value domain the
    CloudFormation schema cannot represent, when any exists.
    """
    mappings = []
    for member in sorted(members):
        lowered = member.lower()
        target = None
        if lowered in writable_by_lower:
            target = writable_by_lower[lowered]
            if (cfn_type, service, operation, member, target) in PROPERTY_SEMANTIC_DENYLIST:
                target = None
        else:
            renamed_target = None
            if lowered + 'name' in writable_by_lower:
                renamed_target = writable_by_lower[lowered + 'name']
            elif lowered == 'name' and resource_segment + 'name' in writable_by_lower:
                renamed_target = writable_by_lower[resource_segment + 'name']
            if renamed_target is not None and (
                cfn_type, service, operation, member, renamed_target
            ) in PROPERTY_RENAME_ALLOWLIST:
                target = renamed_target
        if target and _is_runtime_safe_mapping(
            members[member], property_schemas[target], definitions, target
        ):
            mappings.append(_mapping_entry(
                member,
                target,
                _unrepresentable_domain(
                    members[member], property_schemas[target], definitions, target
                ),
            ))
    return mappings


def _derive_role(role, verbs, provider_schemas, compiled_schemas, index, require_mappings):
    adapters = {}
    counters = defaultdict(int)
    for type_name, schema in sorted(provider_schemas.items()):
        constraints = _compiled_constraints(compiled_schemas, type_name)
        if constraints is None:
            counters['type_not_compiled'] += 1
            continue
        property_schemas, read_only, primary, definitions = constraints
        handlers = schema.get('handlers')
        handler = handlers.get(role) if isinstance(handlers, dict) else None
        if not isinstance(handler, dict):
            counters['no_handler'] += 1
            continue
        _, service_segment, resource_segment = type_name.split('::', 2)
        service_segment = _normalize(service_segment)
        resource_segment = _normalize(resource_segment)
        if service_segment in EXCLUDED_SERVICES:
            counters['excluded_service'] += 1
            continue
        segment_aliases = {service_segment}
        segment_aliases.update(SEGMENT_ALIASES.get(service_segment, ()))
        candidates = set()
        has_unavailable_exact_lifecycle_operation = False
        for action in handler.get('permissions') or []:
            if not isinstance(action, str) or ':' not in action:
                continue
            prefix, action_name = action.split(':', 1)
            rank = _verb_rank(action_name, verbs)
            if rank is None:
                continue
            identity_prefix = _identity_key(prefix)
            segment_prefix = _normalize(prefix)
            resolved_actions = index.resolve(identity_prefix, action_name)
            related_actions = {
                (service, operation)
                for service, operation in resolved_actions
                if index.identity_tier(segment_prefix, service, segment_aliases)
                is not None
            }
            if (
                segment_prefix in segment_aliases
                and _noun_matches(action_name, resource_segment)
                and not related_actions
            ):
                has_unavailable_exact_lifecycle_operation = True
            for service, operation in related_actions:
                if (
                    _normalize(service) in EXCLUDED_SERVICES
                    or (service, operation) in FORBIDDEN_OPERATIONS
                ):
                    continue
                tier = index.identity_tier(segment_prefix, service, segment_aliases)
                candidates.add((tier, rank, service, operation))
        if not candidates:
            counters['no_candidates'] += 1
            continue
        best_tier = min(candidate[0] for candidate in candidates)
        candidates = {c for c in candidates if c[0] == best_tier}
        writable_by_lower = {
            p.lower(): p for p in set(property_schemas) - read_only
        }
        scored = []
        for _, rank, service, operation in candidates:
            members = index.input_members(service, operation)
            mappings = _property_mappings(
                members, property_schemas, writable_by_lower,
                resource_segment, definitions, type_name, service, operation
            )
            precision = len(mappings) / len(members) if members else 0.0
            noun = _noun_matches(operation, resource_segment)
            scored.append((
                0 if noun else 1,
                rank,
                -len(mappings),
                -precision,
                service,
                operation,
                mappings,
                noun,
            ))
        scored.sort()
        top = scored[0]
        noun, mappings = top[7], top[6]
        precision = -top[3]
        accepted = (noun and (mappings or not require_mappings)) or (
            len(mappings) >= 2 and precision >= 0.3
        )
        if has_unavailable_exact_lifecycle_operation and not noun:
            accepted = False
            counters['stale_model_rejected'] += 1
        if not accepted:
            counters['rejected'] += 1
            continue
        tied = [
            entry
            for entry in scored[1:]
            if entry[0] == top[0]
            and entry[1] == top[1]
            and entry[2] == top[2]
            and abs(entry[3] - top[3]) < 1e-9
            and (entry[4], entry[5]) != (top[4], top[5])
        ]
        if tied:
            counters['tied_rejected'] += 1
            continue
        adapters[type_name] = {
            'cfn_type': type_name,
            'service': top[4],
            'operation': top[5],
            'phase': role,
            'mappings': list(mappings),
            'ignored_inputs': _ignored_inputs_for_operation(
                index.input_members(top[4], top[5]), role, top[4], top[5]
            ),
            'noun_matched': noun,
        }
        counters['verified'] += 1
    return adapters, counters


def _enforce_global_uniqueness(adapters):
    """One (service, operation) key -> exactly one adapter, or none at all."""
    by_key = defaultdict(list)
    for adapter in adapters:
        by_key[(adapter['service'].lower(), adapter['operation'])].append(adapter)
    kept, dropped = [], []
    for _, group in sorted(by_key.items()):
        if len(group) == 1:
            kept.append(group[0])
            continue
        key = (group[0]['service'].lower(), group[0]['operation'])
        preferred_type = COLLISION_PREFERENCES.get(key)
        preferred = [
            adapter for adapter in group
            if adapter['cfn_type'] == preferred_type
        ]
        if len(preferred) == 1:
            kept.append(preferred[0])
            dropped.extend(
                adapter for adapter in group if adapter is not preferred[0]
            )
        else:
            dropped.extend(group)
    return kept, dropped


def _verify_curated_updates(compiled_schemas, index):
    """Return the curated update adapters, verified like derived ones.

    Each returned adapter is a copy whose mappings carry the API value domain the
    CloudFormation schema cannot represent.
    """
    verified_adapters = []
    for adapter in CURATED_UPDATE_ADAPTERS:
        constraints = _compiled_constraints(compiled_schemas, adapter['cfn_type'])
        if constraints is None:
            raise SystemExit(
                f"curated update adapter references unknown type {adapter['cfn_type']}"
            )
        property_schemas, read_only, primary, definitions = constraints
        members = index.input_members(adapter['service'], adapter['operation'])
        mapping_sources = set()
        verified_mappings = []
        for mapping in adapter['mappings']:
            if mapping['source'] not in members:
                raise SystemExit(
                    f"curated mapping source {mapping['source']} is not an input of "
                    f"{adapter['service']}:{adapter['operation']}"
                )
            mapping_sources.add(mapping['source'])
            target = mapping['target']
            if target not in property_schemas or target in read_only or target in primary:
                raise SystemExit(
                    f"curated mapping target {target} is invalid for {adapter['cfn_type']}"
                )
            if (
                adapter['cfn_type'], adapter['service'], adapter['operation'],
                mapping['source'], target,
            ) in PROPERTY_SEMANTIC_DENYLIST:
                raise SystemExit(
                    f"curated mapping {mapping['source']} -> {target} is a reviewed "
                    "semantic mismatch"
                )
            if not _is_runtime_safe_mapping(
                members[mapping['source']], property_schemas[target],
                definitions, target
            ):
                raise SystemExit(
                    f"curated mapping {mapping['source']} -> {target} is not "
                    "runtime shape-compatible"
                )
            verified_mappings.append(_mapping_entry(
                mapping['source'],
                target,
                _unrepresentable_domain(
                    members[mapping['source']], property_schemas[target],
                    definitions, target,
                ),
            ))
        for ignored_name in adapter.get('ignored_inputs', []):
            if ignored_name not in members:
                raise SystemExit(
                    f"curated ignored_inputs entry '{ignored_name}' is not an input of "
                    f"{adapter['service']}:{adapter['operation']}"
                )
            if ignored_name in mapping_sources:
                raise SystemExit(
                    f"curated ignored_inputs entry '{ignored_name}' overlaps a mapping "
                    f"source in {adapter['service']}:{adapter['operation']}"
                )
        verified_adapters.append({**adapter, 'mappings': verified_mappings})
    return verified_adapters


def _count_patterns(domain):
    """Number of CloudFormation ``pattern`` guards in ``domain`` and its nested domains."""
    count = 1 if domain.get('pattern') else 0
    for nested in ('items', 'tag_key', 'tag_value'):
        if domain.get(nested):
            count += _count_patterns(domain[nested])
    return count


def _compute_coverage(unique_adapters, index, compiled_schemas):
    """Compute catalog and state-validation coverage metrics.

    Catalog coverage counts all adapters regardless of phase.
    State-validation coverage counts only create/update adapters with at least
    one property mapping.

    Denominators:
      services    — botocore available services (index.service_count)
      resources   — compiled CloudFormation schema types (len(compiled_schemas))
      commands    — total botocore operations (index.operation_count)
      writable_properties — unique (type, property) pairs across all compiled
                            schemas excluding read-only properties
    """
    botocore_services = index.service_count
    botocore_operations = index.operation_count
    compiled_types = len(compiled_schemas)

    writable_pairs = set()
    for type_name, schema in compiled_schemas.items():
        if not isinstance(schema, dict):
            continue
        properties = schema.get('properties') or {}
        read_only = set(schema.get('read_only_properties') or [])
        for prop in set(properties) - read_only:
            writable_pairs.add((type_name, prop))

    state_adapters = [
        a for a in unique_adapters
        if a['phase'] in ('create', 'update') and len(a.get('mappings', [])) > 0
    ]

    covered_writable_pairs = set()
    for adapter in state_adapters:
        for mapping in adapter.get('mappings', []):
            covered_writable_pairs.add((adapter['cfn_type'], mapping['target']))

    phases = defaultdict(int)
    for adapter in unique_adapters:
        phases[adapter['phase']] += 1

    guarded_mappings = 0
    patterns = 0
    for adapter in unique_adapters:
        for mapping in adapter.get('mappings', []):
            domain = mapping.get('unrepresentable')
            if domain:
                guarded_mappings += 1
                patterns += _count_patterns(domain)

    return {
        'guarded_mappings': guarded_mappings,
        'patterns': patterns,
        'catalog_services': {
            'covered': len({a['service'] for a in unique_adapters}),
            'total': botocore_services,
        },
        'catalog_resources': {
            'covered': len({a['cfn_type'] for a in unique_adapters}),
            'total': compiled_types,
        },
        'catalog_commands': {
            'covered': len(unique_adapters),
            'total': botocore_operations,
        },
        'state_services': {
            'covered': len({a['service'] for a in state_adapters}),
            'total': botocore_services,
        },
        'state_resources': {
            'covered': len({a['cfn_type'] for a in state_adapters}),
            'total': compiled_types,
        },
        'state_commands': {
            'covered': len(state_adapters),
            'total': botocore_operations,
        },
        'writable_properties': {
            'covered': len(covered_writable_pairs),
            'total': len(writable_pairs),
        },
        'lifecycle_adapters': dict(phases),
    }


def _render_matching(role, counters):
    """Explain, in plain terms, how resource types were matched to one API operation."""
    rejection_reasons = (
        ('type_not_compiled', 'not present in the compiled CloudFormation schemas'),
        ('no_handler', f'the provider schema declares no {role} handler'),
        (
            'excluded_service',
            'CloudFormation and Cloud Control types are validated directly, not through adapters',
        ),
        (
            'no_candidates',
            f'the {role} handler permissions name no operation in this AWS CLI release',
        ),
        (
            'rejected',
            'the best candidate operation failed the resource-name / property-overlap checks',
        ),
        ('tied_rejected', 'several operations tied for best candidate'),
    )
    known_outcomes = {
        'verified',
        'stale_model_rejected',
        *(outcome for outcome, _ in rejection_reasons),
    }
    unknown_outcomes = set(counters) - known_outcomes
    if unknown_outcomes:
        names = ', '.join(sorted(unknown_outcomes))
        raise ValueError(f'no reader-facing description for matching outcomes: {names}')

    matched = counters.get('verified', 0)
    unmatched = sum(counters.get(outcome, 0) for outcome, _ in rejection_reasons)
    stale_model_rejected = counters.get('stale_model_rejected', 0)
    if stale_model_rejected > counters.get('rejected', 0):
        raise ValueError('stale-model rejection count exceeds total candidate rejections')

    lines = [
        f'{role.capitalize()} operations: {matched:,} of {matched + unmatched:,} resource types '
        f'matched to exactly one {role} API operation',
    ]
    if unmatched:
        lines.append(f'  The other {unmatched:,} resource types were not matched because:')
    for outcome, description in rejection_reasons:
        count = counters.get(outcome, 0)
        if count == 0:
            continue
        lines.append(f'    {count:>5,}  {description}')
        if outcome == 'rejected' and stale_model_rejected:
            lines.append(
                f'    {"":>5}  ({stale_model_rejected:,} of these because the exact {role} '
                'operation named by the handler is missing from this AWS CLI release)'
            )
    return lines


def _render_fraction(description, entry):
    covered = entry['covered']
    total = entry['total']
    percent = (covered / total * 100) if total > 0 else 0.0
    return f'  {covered:>6,} of {total:>6,} ({percent:5.1f}%)  {description}'


def _render_coverage(coverage, dropped_count):
    """Describe what the final catalog covers, with every denominator named."""
    lifecycle = coverage.get('lifecycle_adapters', {})
    adapter_count = sum(lifecycle.values())
    by_phase = ', '.join(
        f'{lifecycle.get(phase, 0):,} {phase}'
        for phase in ('create', 'update', 'delete')
        if lifecycle.get(phase, 0)
    )
    for phase in sorted(set(lifecycle) - {'create', 'update', 'delete'}):
        by_phase += f', {lifecycle[phase]:,} {phase}'
    lines = [
        f'Catalog contents: {adapter_count:,} adapters ({by_phase})',
        (
            f'  {dropped_count:,} candidate adapters were dropped so that each API operation '
            'maps to exactly one resource type'
        ),
        (
            f"  {coverage['guarded_mappings']:,} property mappings record CloudFormation constraints the API "
            f"does not enforce ({coverage['patterns']:,} as regex patterns settled per value); "
            'a value outside them skips validation instead of producing a finding'
        ),
        '',
        'What an AWS CLI call can be checked against',
        (
            '  A create or update call whose adapter maps at least one writable property is modeled as '
            'CloudFormation resource state and validated; every other call is classified and skipped.'
        ),
        _render_fraction(
            'compiled CloudFormation resource types whose create/update call is validated',
            coverage['state_resources'],
        ),
        _render_fraction(
            'writable properties of those types that a call can populate',
            coverage['writable_properties'],
        ),
        _render_fraction(
            'AWS CLI services with at least one validated create/update operation',
            coverage['state_services'],
        ),
        _render_fraction(
            'AWS CLI operations that are validated (most operations are reads or data-plane calls)',
            coverage['state_commands'],
        ),
        '',
        'What the catalog classifies (create, update, or delete of a known resource type)',
        _render_fraction(
            'compiled CloudFormation resource types with at least one adapter',
            coverage['catalog_resources'],
        ),
        _render_fraction('AWS CLI services with at least one adapter', coverage['catalog_services']),
        _render_fraction('AWS CLI operations with an adapter', coverage['catalog_commands']),
    ]
    return lines


def _render_generation_report(
    create_counters,
    delete_counters,
    dropped_count,
    coverage,
    source,
    output_path,
):
    """Render the complete catalog generation report."""
    lines = [
        'AWS CLI operation catalog',
        f'  Written to: {output_path}',
        (
            f"  Derived from: AWS CLI {source['aws_cli_version']} "
            f"(botocore {source['botocore_version']}, {source['botocore_service_count']:,} services), "
            f"{source['provider_type_count']:,} provider schemas with handler metadata, "
            f"{source['compiled_type_count']:,} compiled CloudFormation resource types"
        ),
        (
            '  An adapter links one CloudFormation resource type and lifecycle phase '
            '(create, update, delete) to the one AWS CLI operation that performs it.'
        ),
        '',
        'How resource types were matched to API operations',
    ]
    lines.extend(_render_matching('create', create_counters))
    lines.extend(_render_matching('delete', delete_counters))
    lines.append(
        '  Update operations: hand-reviewed adapters only, because update APIs carry partial state'
    )
    lines.append('')
    lines.extend(_render_coverage(coverage, dropped_count))
    return lines


def main():
    args = _parse_args()
    if not args.botocore_root.is_dir():
        raise SystemExit(
            f'botocore root directory not found: {args.botocore_root}'
        )
    sys.path.insert(0, str(args.botocore_root.resolve()))
    try:
        botocore_module = importlib.import_module('botocore')
    except ModuleNotFoundError as error:
        raise SystemExit(
            f'cannot import botocore from {args.botocore_root}: {error}'
        ) from error

    compiled_schemas = json.loads(args.compiled_schemas.read_text())
    provider_schemas = _load_provider_schemas(args.provider_schemas)
    index = BotocoreIndex()

    creates, create_counters = _derive_role(
        'create', CREATE_VERBS, provider_schemas, compiled_schemas, index, True
    )
    deletes, delete_counters = _derive_role(
        'delete', DELETE_VERBS, provider_schemas, compiled_schemas, index, False
    )
    curated_updates = _verify_curated_updates(compiled_schemas, index)

    all_adapters = list(creates.values()) + list(deletes.values()) + curated_updates
    unique_adapters, dropped = _enforce_global_uniqueness(all_adapters)

    for adapter in unique_adapters:
        key = (adapter['service'], adapter['operation'])
        if key in FORBIDDEN_OPERATIONS:
            raise SystemExit(f'forbidden operation selected: {key} for {adapter["cfn_type"]}')

    final_creates = {
        a['cfn_type']: a for a in unique_adapters if a['phase'] == 'create'
    }
    for type_name, expected in sorted(EXPECTED_PAIRS.items()):
        actual = final_creates.get(type_name)
        if actual is None:
            raise SystemExit(f'expected pair missing after uniqueness: {type_name}')
        if (actual['service'], actual['operation']) != expected:
            raise SystemExit(
                f'expected pair mismatch for {type_name}: '
                f"got {(actual['service'], actual['operation'])}, want {expected}"
            )

    for adapter in unique_adapters:
        adapter.pop('noun_matched', None)
        if not adapter.get('ignored_inputs'):
            adapter.pop('ignored_inputs', None)
    unique_adapters.sort(key=lambda a: (a['cfn_type'], a['phase']))
    document = {
        'format_version': FORMAT_VERSION,
        'source': {
            'provider_schemas_sha256': _source_sha256(
                args.provider_schemas
            ),
            'compiled_schemas_sha256': _source_sha256(
                args.compiled_schemas
            ),
            'aws_cli_version': _aws_cli_version(args.botocore_root),
            'botocore_version': botocore_module.__version__,
            'botocore_service_count': index.service_count,
            'provider_type_count': len(provider_schemas),
            'compiled_type_count': len(compiled_schemas),
        },
        'adapters': unique_adapters,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=1, sort_keys=True) + '\n')

    coverage = _compute_coverage(unique_adapters, index, compiled_schemas)
    for line in _render_generation_report(
        create_counters,
        delete_counters,
        len(dropped),
        coverage,
        document['source'],
        args.output,
    ):
        print(line)
    return 0


if __name__ == '__main__':
    sys.exit(main())
