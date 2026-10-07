# S3 bucket hygiene: public access block per condition scenario, bucket-name grammar, self-logging, lifecycle transition ordering, versioning retention, and Lambda notification permissions.
package custom_s3

import rego.v1

_public_access_flags := ["BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets"]

# Colder storage classes rank higher; a transition must never move objects to a lower rank later in time.
_storage_class_rank := {
	"STANDARD_IA": 1,
	"ONEZONE_IA": 2,
	"INTELLIGENT_TIERING": 3,
	"GLACIER_IR": 4,
	"GLACIER": 5,
	"DEEP_ARCHIVE": 6,
}

_bucket_name_checks := [
	["shape", "must be 3-63 lowercase letters, digits, dots, or hyphens, starting and ending with a letter or digit"],
	["dots", "must not contain consecutive dots"],
	["ip", "must not be formatted like an IP address"],
	["prefix", "must not start with xn--, sthree-, or amzn-s3-demo-"],
	["suffix", "must not end with -s3alias, --ol-s3, .mrap, or --x-s3"],
]

_true_like(value) if value == true

_true_like(value) if value == "true"

_conditions(scenario) := object.get(scenario, "conditions", {})

_scenario_diag(rule_id, severity, name, path, message, scenario) := make_diag_conditional(rule_id, severity, name, path, message, _conditions(scenario)) if {
	count(_conditions(scenario)) > 0
}

_scenario_diag(rule_id, severity, name, path, message, scenario) := make_diag_at(rule_id, severity, name, path, message) if {
	count(_conditions(scenario)) == 0
}

_missing_public_access_flags(properties) := [flag |
	some flag in _public_access_flags
	not _true_like(object.get(properties, ["PublicAccessBlockConfiguration", flag], null))
]

_bucket_name_violates("shape", bucket_name) if not regex.match(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`, bucket_name)

_bucket_name_violates("dots", bucket_name) if contains(bucket_name, "..")

_bucket_name_violates("ip", bucket_name) if regex.match(`^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$`, bucket_name)

_bucket_name_violates("prefix", bucket_name) if strings.any_prefix_match(bucket_name, ["xn--", "sthree-", "amzn-s3-demo-"])

_bucket_name_violates("suffix", bucket_name) if strings.any_suffix_match(bucket_name, ["-s3alias", "--ol-s3", ".mrap", "--x-s3"])

_bucket_name_problems(bucket_name) := {message |
	some [check, message] in _bucket_name_checks
	_bucket_name_violates(check, bucket_name)
}

_expires_noncurrent_versions(name) if {
	some rule in input.resources[name].properties.LifecycleConfiguration.Rules
	rule.Status == "Enabled"
	some field in ["NoncurrentVersionExpiration", "NoncurrentVersionExpirationInDays"]
	object.get(rule, field, null) != null
}

_s3_invoke_permission(function) if {
	some _, res in input.resources
	res.resourceType == "AWS::Lambda::Permission"
	res.properties.Principal == "s3.amazonaws.com"
	res.properties.FunctionName.__ref == function
}

violation contains _scenario_diag("s3.public-access-block-incomplete", "ERROR", name, "Properties.PublicAccessBlockConfiguration", sprintf("public access block does not enable %v", [missing]), scenario) if {
	some name in resources_of_type("AWS::S3::Bucket")
	not is_dynamic(name, "Properties.PublicAccessBlockConfiguration")
	some scenario in properties_scenarios(name, ["PublicAccessBlockConfiguration"])
	missing := _missing_public_access_flags(object.get(scenario, "properties", {}))
	count(missing) > 0
}

violation contains make_diag_at("s3.bucket-name-invalid", "ERROR", name, "Properties.BucketName", sprintf("bucket name '%s' %s", [bucket_name, problem])) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some bucket_name in resolve_all(name, "Properties.BucketName")
	is_string(bucket_name)
	not contains(bucket_name, "${")
	some problem in _bucket_name_problems(bucket_name)
}

violation contains make_diag_at("s3.logging-to-self", "WARN", name, "Properties.LoggingConfiguration.DestinationBucketName", "bucket delivers its own access logs to itself, which recursively generates log objects") if {
	some name in resources_of_type("AWS::S3::Bucket")
	follow_ref(name, "Properties.LoggingConfiguration.DestinationBucketName") == name
}

violation contains make_diag_at("s3.versioning-without-noncurrent-expiration", "INFO", name, "Properties.LifecycleConfiguration", "versioned bucket has no enabled lifecycle rule expiring noncurrent object versions") if {
	some name in resources_of_type("AWS::S3::Bucket")
	some status in resolve_all(name, "Properties.VersioningConfiguration.Status")
	status == "Enabled"
	not _expires_noncurrent_versions(name)
}

violation contains make_diag_at("s3.lifecycle-transition-order", "WARN", name, sprintf("Properties.LifecycleConfiguration.Rules.%d.Transitions", [i]), sprintf("transition to %s after %d days is followed by the warmer class %s after %d days", [colder.StorageClass, colder_days, warmer.StorageClass, warmer_days])) if {
	some name in resources_of_type("AWS::S3::Bucket")
	rules := input.resources[name].properties.LifecycleConfiguration.Rules
	is_array(rules)
	some i, rule in rules
	transitions := rule.Transitions
	is_array(transitions)
	some j, colder in transitions
	some k, warmer in transitions
	j != k
	colder_days := coerce_to_integer(colder.TransitionInDays)
	warmer_days := coerce_to_integer(warmer.TransitionInDays)
	colder_days < warmer_days
	_storage_class_rank[colder.StorageClass] > _storage_class_rank[warmer.StorageClass]
}

violation contains make_diag_at("s3.lambda-notification-without-permission", "WARN", name, sprintf("Properties.NotificationConfiguration.LambdaConfigurations.%d.Function", [i]), sprintf("no AWS::Lambda::Permission lets s3.amazonaws.com invoke %s, so the notification configuration will fail to deploy", [target])) if {
	some name in resources_of_type("AWS::S3::Bucket")
	configurations := input.resources[name].properties.NotificationConfiguration.LambdaConfigurations
	is_array(configurations)
	some i, configuration in configurations
	target := configuration.Function.__ref
	is_string(target)
	input.resources[target].resourceType == "AWS::Lambda::Function"
	not _s3_invoke_permission(target)
}
