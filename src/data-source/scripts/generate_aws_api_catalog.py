#!/usr/bin/env python3
"""Generate the AWS API operation adapter catalog for validation-engine.

Derives CloudFormation-type -> API-operation adapters from two public sources:

1. CloudFormation resource provider schemas WITH handler metadata
   (https://github.com/aws-cloudformation/resource-provider-enhanced-schemas
   releases, ``schemas-standard.zip``). Each type's own create/delete handler
   permissions contain the type's canonical lifecycle API actions.
2. Botocore service models (importable ``botocore``), which resolve IAM action
   prefixes to real services and operations and provide exact input shapes.

Derivation direction is type -> operation, scoped to one type's own handler
permissions at a time. The global inverse (operation -> type by name) is
unsafe and is never used. Every candidate must pass all of:

- service identity tiering: the action must belong to the type's own service
  (botocore service name match beats IAM-prefix match beats signing-identity
  match beats substring; lower tiers are dropped when a higher tier exists)
- lifecycle verb family match for the handler role
- structural verification: operation input members must map onto writable
  properties of the type in the validator's OWN compiled schemas (verbatim,
  or via the reviewed identifier-rename rules below)
- noun agreement or property-overlap thresholds; ties are dropped entirely
- global reverse uniqueness: one (service, operation) key maps to exactly one
  catalog entry; unresolvable collisions are dropped entirely

Types or operations that fail any gate are omitted: an uncovered operation is
validated as SKIPPED at runtime, never guessed.

Usage:
    PYTHONPATH=<path with botocore> python3 generate_aws_api_catalog.py \
        --provider-schemas schemas-standard.zip \
        --compiled-schemas ../generated/schema-validator/compiled_schemas.json \
        --output ../generated/data/aws_api_operation_catalog.json
"""

import argparse
import hashlib
import json
import sys
import zipfile
from collections import defaultdict
from pathlib import Path

import botocore
import botocore.session

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

# CFN service segments whose IAM/service identity differs beyond casing.
SEGMENT_ALIASES = {
    'msk': 'kafka',
    'opensearchservice': 'es',
    'certificatemanager': 'acm',
    'elasticloadbalancingv2': 'elasticloadbalancing',
    'ses': 'sesv2',
}

# Services handled by dedicated validation paths; adapters must not shadow them.
EXCLUDED_SERVICES = frozenset({'cloudformation', 'cloudcontrol'})

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
    parser.add_argument('--provider-schemas', required=True, type=Path)
    parser.add_argument('--compiled-schemas', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    return parser.parse_args()


def _normalize(value):
    return ''.join(c for c in value.lower() if c.isalnum())


class BotocoreIndex:
    """Resolves IAM action prefixes to concrete botocore operations."""

    def __init__(self):
        self._session = botocore.session.Session()
        self._identities = {}
        self._operations = {}
        self._by_identity = defaultdict(set)
        for service in self._session.get_available_services():
            model = self._session.get_service_model(service)
            identities = {
                _normalize(value)
                for value in (
                    service,
                    model.endpoint_prefix or '',
                    model.signing_name or '',
                    str(getattr(model, 'service_id', '') or ''),
                )
                if value
            }
            self._identities[service] = identities
            for identity in identities:
                self._by_identity[identity].add(service)
            self._operations[service] = {
                op.lower(): op for op in model.operation_names
            }

    @property
    def service_count(self):
        return len(self._operations)

    def input_members(self, service, operation):
        model = self._session.get_service_model(service)
        shape = model.operation_model(operation).input_shape
        return dict(shape.members) if shape else {}

    def resolve(self, action_prefix, action_name):
        """Every (service, operation) the action can denote."""
        resolved = set()
        for service in self._by_identity.get(action_prefix, ()):
            operation = self._operations[service].get(action_name.lower())
            if operation:
                resolved.add((service, operation))
        if resolved:
            return resolved
        for identity, services in self._by_identity.items():
            if action_prefix in identity or identity in action_prefix:
                for service in services:
                    operation = self._operations[service].get(
                        action_name.lower()
                    )
                    if operation:
                        resolved.add((service, operation))
        return resolved

    def identity_tier(self, action_prefix, service, segment_aliases):
        """Lower is a stronger identity match; None means unrelated."""
        if _normalize(service) in segment_aliases:
            return 0
        if action_prefix in segment_aliases:
            return 1
        if self._identities[service] & segment_aliases:
            return 2
        if any(
            action_prefix in alias or alias in action_prefix
            for alias in segment_aliases
        ):
            return 3
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


def _is_key_value_tag_array(target_schema, definitions):
    array_schema = _schema_node_for_type(
        target_schema, definitions, 'array'
    )
    if not array_schema:
        return False
    item_schema = _resolve_schema_node(
        array_schema.get('items') or {}, definitions
    )
    alternatives = [item_schema]
    for key in ('any_of', 'one_of'):
        alternatives.extend(
            _resolve_schema_node(option, definitions)
            for option in item_schema.get(key) or []
        )
    return any(
        {'Key', 'Value'} <= set(option.get('properties') or {})
        for option in alternatives
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


def _property_mappings(
    members, property_schemas, writable_by_lower, resource_segment, definitions
):
    """Return mappings the runtime can serialize without nested rewriting."""
    mappings = []
    for member in sorted(members):
        lowered = member.lower()
        target = None
        if lowered in writable_by_lower:
            target = writable_by_lower[lowered]
        elif lowered + 'name' in writable_by_lower:
            target = writable_by_lower[lowered + 'name']
        elif lowered == 'name' and resource_segment + 'name' in writable_by_lower:
            target = writable_by_lower[resource_segment + 'name']
        if target and _is_runtime_safe_mapping(
            members[member], property_schemas[target], definitions, target
        ):
            mappings.append((member, target))
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
        if service_segment in SEGMENT_ALIASES:
            segment_aliases.add(SEGMENT_ALIASES[service_segment])
        candidates = set()
        has_unavailable_exact_lifecycle_operation = False
        for action in handler.get('permissions') or []:
            if not isinstance(action, str) or ':' not in action:
                continue
            prefix, action_name = action.split(':', 1)
            rank = _verb_rank(action_name, verbs)
            if rank is None:
                continue
            prefix = _normalize(prefix)
            resolved_actions = index.resolve(prefix, action_name)
            related_actions = {
                (service, operation)
                for service, operation in resolved_actions
                if index.identity_tier(prefix, service, segment_aliases)
                is not None
            }
            if (
                prefix in segment_aliases
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
                tier = index.identity_tier(prefix, service, segment_aliases)
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
                resource_segment, definitions
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
            'mappings': [
                {'source': source, 'target': target}
                for source, target in mappings
            ],
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
    for adapter in CURATED_UPDATE_ADAPTERS:
        constraints = _compiled_constraints(compiled_schemas, adapter['cfn_type'])
        if constraints is None:
            raise SystemExit(
                f"curated update adapter references unknown type {adapter['cfn_type']}"
            )
        property_schemas, read_only, primary, definitions = constraints
        members = index.input_members(adapter['service'], adapter['operation'])
        for mapping in adapter['mappings']:
            if mapping['source'] not in members:
                raise SystemExit(
                    f"curated mapping source {mapping['source']} is not an input of "
                    f"{adapter['service']}:{adapter['operation']}"
                )
            target = mapping['target']
            if target not in property_schemas or target in read_only or target in primary:
                raise SystemExit(
                    f"curated mapping target {target} is invalid for {adapter['cfn_type']}"
                )
            if not _is_runtime_safe_mapping(
                members[mapping['source']], property_schemas[target],
                definitions, target
            ):
                raise SystemExit(
                    f"curated mapping {mapping['source']} -> {target} is not "
                    "runtime shape-compatible"
                )


def main():
    args = _parse_args()
    compiled_schemas = json.loads(args.compiled_schemas.read_text())
    provider_schemas = _load_provider_schemas(args.provider_schemas)
    index = BotocoreIndex()

    creates, create_counters = _derive_role(
        'create', CREATE_VERBS, provider_schemas, compiled_schemas, index, True
    )
    deletes, delete_counters = _derive_role(
        'delete', DELETE_VERBS, provider_schemas, compiled_schemas, index, False
    )
    _verify_curated_updates(compiled_schemas, index)

    all_adapters = (
        list(creates.values())
        + list(deletes.values())
        + [dict(adapter) for adapter in CURATED_UPDATE_ADAPTERS]
    )
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
            'botocore_version': botocore.__version__,
            'botocore_service_count': index.service_count,
            'provider_type_count': len(provider_schemas),
            'compiled_type_count': len(compiled_schemas),
        },
        'adapters': unique_adapters,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=1, sort_keys=True) + '\n')

    phases = defaultdict(int)
    for adapter in unique_adapters:
        phases[adapter['phase']] += 1
    print(f'create derivation: {dict(create_counters)}')
    print(f'delete derivation: {dict(delete_counters)}')
    print(f'uniqueness dropped: {len(dropped)}')
    print(
        f"catalog: {len(unique_adapters)} adapters "
        f"({phases['create']} create, {phases['update']} update, "
        f"{phases['delete']} delete) -> {args.output}"
    )
    return 0


if __name__ == '__main__':
    sys.exit(main())
