# Data stores: public exposure and backup posture of RDS, DocumentDB, Neptune, Redshift, and DMS, plus DynamoDB recovery and key-schema consistency.
package custom_data

import rego.v1

_public_flags := [
	["AWS::RDS::DBInstance", "Properties.PubliclyAccessible"],
	["AWS::RDS::DBCluster", "Properties.PubliclyAccessible"],
	["AWS::Redshift::Cluster", "Properties.PubliclyAccessible"],
	["AWS::DMS::ReplicationInstance", "Properties.PubliclyAccessible"],
]

_backed_up_types := ["AWS::RDS::DBInstance", "AWS::RDS::DBCluster", "AWS::DocDB::DBCluster", "AWS::Neptune::DBCluster"]

_protected_types := ["AWS::RDS::DBInstance", "AWS::RDS::DBCluster", "AWS::DocDB::DBCluster", "AWS::Neptune::DBCluster", "AWS::DynamoDB::Table"]

_retaining_policies := {"Snapshot", "Retain", "RetainExceptOnCreate"}

_minimum_retention_days := 7

_true_like(value) if value == true

_true_like(value) if value == "true"

_conditions(scenario) := object.get(scenario, "conditions", {})

_scenario_diag(rule_id, severity, name, path, message, scenario) := make_diag_conditional(rule_id, severity, name, path, message, _conditions(scenario)) if {
	count(_conditions(scenario)) > 0
}

_scenario_diag(rule_id, severity, name, path, message, scenario) := make_diag_at(rule_id, severity, name, path, message) if {
	count(_conditions(scenario)) == 0
}

# Replicas and cluster members inherit their backup settings from the source or cluster.
_inherits_backups(name) if has_property(name, "SourceDBInstanceIdentifier")

_inherits_backups(name) if has_property(name, "DBClusterIdentifier")

_inherits_backups(name) if has_property(name, "SourceDBClusterIdentifier")

_deletion_protected(name) if {
	some value in resolve_all(name, "Properties.DeletionProtection")
	_true_like(value)
}

_deletion_protected(name) if {
	some value in resolve_all(name, "Properties.DeletionProtectionEnabled")
	_true_like(value)
}

_retained(name) if _retaining_policies[input.resources[name].deletionPolicy]

_pitr_enabled(name) if {
	some value in resolve_all(name, "Properties.PointInTimeRecoverySpecification.PointInTimeRecoveryEnabled")
	_true_like(value)
}

_pitr_enabled(name) if is_dynamic(name, "Properties.PointInTimeRecoverySpecification")

_key_attributes(table) := array.concat(primary, indexes) if {
	primary := [[sprintf("Properties.KeySchema.%d.AttributeName", [i]), key.AttributeName] |
		some i, key in table.KeySchema
		is_string(key.AttributeName)
	]
	indexes := [[sprintf("Properties.%s.%d.KeySchema.%d.AttributeName", [field, i, j]), key.AttributeName] |
		some field in ["GlobalSecondaryIndexes", "LocalSecondaryIndexes"]
		some i, index in table[field]
		some j, key in index.KeySchema
		is_string(key.AttributeName)
	]
}

violation contains _scenario_diag("data.publicly-accessible", "ERROR", name, path, sprintf("%s is reachable from the public internet", [type]), scenario) if {
	some [type, path] in _public_flags
	some name in resources_of_type(type)
	some scenario in resolve_scenarios(name, path)
	_true_like(scenario.value)
}

violation contains make_diag_at("data.backup-retention-short", "WARN", name, "Properties.BackupRetentionPeriod", sprintf("automated backups are kept for %d days; keep at least %d", [days, _minimum_retention_days])) if {
	some type in _backed_up_types
	some name in resources_of_type(type)
	not _inherits_backups(name)
	some value in resolve_all(name, "Properties.BackupRetentionPeriod")
	days := coerce_to_integer(value)
	days < _minimum_retention_days
}

violation contains make_diag_at("data.backup-retention-short", "WARN", name, "Properties.BackupRetentionPeriod", "BackupRetentionPeriod is not set; the default keeps automated backups for a single day") if {
	some type in _backed_up_types
	some name in resources_of_type(type)
	not _inherits_backups(name)
	not has_property(name, "BackupRetentionPeriod")
}

violation contains make_diag("data.deletion-protection-missing", "WARN", name, "data store is deleted with the stack; enable deletion protection or set DeletionPolicy to Snapshot or Retain") if {
	some type in _protected_types
	some name in resources_of_type(type)
	not _deletion_protected(name)
	not _retained(name)
}

violation contains make_diag_at("data.dynamodb-point-in-time-recovery-disabled", "INFO", name, "Properties.PointInTimeRecoverySpecification", "table does not enable point-in-time recovery") if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	not _pitr_enabled(name)
}

violation contains make_diag_at("data.dynamodb-key-attribute-undefined", "ERROR", name, path, sprintf("key attribute %s is not declared in AttributeDefinitions", [attribute])) if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	table := input.resources[name].properties
	defined := {definition.AttributeName | some definition in table.AttributeDefinitions; is_string(definition.AttributeName)}
	count(defined) > 0
	some [path, attribute] in _key_attributes(table)
	not defined[attribute]
}
