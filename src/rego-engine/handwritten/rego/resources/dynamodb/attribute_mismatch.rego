package resources

import rego.v1

# DynamoDB AttributeDefinitions must exactly match the set of attributes
# referenced in the table KeySchema, all GlobalSecondaryIndexes KeySchema, and
# all LocalSecondaryIndexes KeySchema.
#
# When all index content is resolvable, both missing and unused definitions are
# reported. When any index is authored but its content cannot be resolved
# (conditional, dynamic), only missing definitions from the table KeySchema are
# reported — unused definitions are suppressed because the unknown index could
# reference them.

# Case 1: all indexes resolvable — report both missing and unused.
violation contains make_diag_full("E3039", "ERROR", name,
    "Properties",
    msg,
    "",
    "") if {
    some name in resources_of_type("AWS::DynamoDB::Table")

    # AttributeDefinitions must resolve to a concrete array
    attr_defs := resolve(name, "Properties.AttributeDefinitions")
    is_array(attr_defs)

    # All definition entries must have a string AttributeName (conservative bail)
    every ad in attr_defs { is_string(ad.AttributeName) }

    # Table KeySchema must resolve to a concrete array
    key_schema := resolve(name, "Properties.KeySchema")
    is_array(key_schema)

    # All table KeySchema entries must have a string AttributeName
    every ks in key_schema { is_string(ks.AttributeName) }

    # Only fire this variant when all indexes are fully resolvable
    not _ddb_has_unresolvable_index(name)

    # Collect defined attribute names as a set
    defined := {ad.AttributeName | some ad in attr_defs}

    # Collect referenced attribute names from all KeySchema locations
    referenced := _ddb_all_key_attrs(name, key_schema)

    # Only fire when the two sets differ
    defined != referenced

    missing := referenced - defined
    unused := defined - referenced
    missing_part := _format_set("missing definitions", missing)
    unused_part := _format_set("unused definitions", unused)
    parts := [p | some p in [missing_part, unused_part]; p != ""]
    msg := sprintf("AttributeDefinitions does not match KeySchema attributes. %s", [concat("; ", parts)])
}

# Case 2: index content unknown — report only missing definitions from table
# KeySchema. Unused definitions are suppressed because the unknown index could
# reference any defined attribute.
violation contains make_diag_full("E3039", "ERROR", name,
    "Properties",
    msg,
    "",
    "") if {
    some name in resources_of_type("AWS::DynamoDB::Table")

    # AttributeDefinitions must resolve to a concrete array
    attr_defs := resolve(name, "Properties.AttributeDefinitions")
    is_array(attr_defs)

    # All definition entries must have a string AttributeName (conservative bail)
    every ad in attr_defs { is_string(ad.AttributeName) }

    # Table KeySchema must resolve to a concrete array
    key_schema := resolve(name, "Properties.KeySchema")
    is_array(key_schema)

    # All table KeySchema entries must have a string AttributeName
    every ks in key_schema { is_string(ks.AttributeName) }

    # This variant fires only when index content is unknown
    _ddb_has_unresolvable_index(name)

    # Collect defined attribute names as a set
    defined := {ad.AttributeName | some ad in attr_defs}

    # Missing definitions from the table and every concrete index branch remain
    # provable even when another index branch is unknown.
    referenced := _ddb_all_key_attrs(name, key_schema)
    missing := referenced - defined
    count(missing) > 0

    missing_part := _format_set("missing definitions", missing)
    msg := sprintf("AttributeDefinitions does not match KeySchema attributes. %s", [missing_part])
}

# Compute the union of all KeySchema attribute names across table, GSI, and LSI.
_ddb_all_key_attrs(name, table_ks) := result if {
    table_refs := {ks.AttributeName | some ks in table_ks; is_string(ks.AttributeName)}
    gsi_refs := _ddb_gsi_key_attrs(name)
    lsi_refs := _ddb_lsi_key_attrs(name)
    result := table_refs | gsi_refs | lsi_refs
}

# GSI/LSI attributes are the union across every concrete reachable scenario.
_ddb_gsi_key_attrs(name) := {ks.AttributeName |
    some scenario in resolve_scenarios(name, "Properties.GlobalSecondaryIndexes")
    is_array(scenario.value)
    some index in scenario.value
    is_array(index.KeySchema)
    some ks in index.KeySchema
    is_string(ks.AttributeName)
}

_ddb_lsi_key_attrs(name) := {ks.AttributeName |
    some scenario in resolve_scenarios(name, "Properties.LocalSecondaryIndexes")
    is_array(scenario.value)
    some index in scenario.value
    is_array(index.KeySchema)
    some ks in index.KeySchema
    is_string(ks.AttributeName)
}

# True when the GSI property is authored (present in template)
_ddb_gsi_authored(name) if {
    has_property(name, "GlobalSecondaryIndexes")
}

# True when the LSI property is authored (present in template)
_ddb_lsi_authored(name) if {
    has_property(name, "LocalSecondaryIndexes")
}

# Unknown raw scenarios and malformed concrete scenarios both prevent an
# unused-definition conclusion. Known key attributes remain available through
# the union helpers above for missing-definition checks.
_ddb_has_unresolvable_index(name) if {
    _ddb_gsi_authored(name)
    has_unresolved_scenario(name, "Properties.GlobalSecondaryIndexes")
}

_ddb_has_unresolvable_index(name) if {
    _ddb_lsi_authored(name)
    has_unresolved_scenario(name, "Properties.LocalSecondaryIndexes")
}

_ddb_has_unresolvable_index(name) if {
    some scenario in resolve_scenarios(name, "Properties.GlobalSecondaryIndexes")
    scenario.value != null
    not is_array(scenario.value)
}

_ddb_has_unresolvable_index(name) if {
    some scenario in resolve_scenarios(name, "Properties.LocalSecondaryIndexes")
    scenario.value != null
    not is_array(scenario.value)
}

_ddb_has_unresolvable_index(name) if {
    some path in ["Properties.GlobalSecondaryIndexes", "Properties.LocalSecondaryIndexes"]
    some scenario in resolve_scenarios(name, path)
    is_array(scenario.value)
    some index in scenario.value
    not is_array(index.KeySchema)
}

_ddb_has_unresolvable_index(name) if {
    some path in ["Properties.GlobalSecondaryIndexes", "Properties.LocalSecondaryIndexes"]
    some scenario in resolve_scenarios(name, path)
    is_array(scenario.value)
    some index in scenario.value
    is_array(index.KeySchema)
    some key in index.KeySchema
    not is_string(key.AttributeName)
}

# Helper: format a set part for the diagnostic message
_format_set(label, s) := result if {
    count(s) > 0
    sorted := sort(s)
    result := sprintf("%s: [%s]", [label, concat(", ", sorted)])
}

_format_set(label, s) := "" if {
    count(s) == 0
}
