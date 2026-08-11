package resources

import rego.v1

# DynamoDB AttributeDefinitions must exactly match the set of attributes
# referenced in the table KeySchema, all GlobalSecondaryIndexes KeySchema, and
# all LocalSecondaryIndexes KeySchema.
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

    # Bail if any authored index property cannot resolve to expected shape
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

# Compute the union of all KeySchema attribute names across table, GSI, and LSI.
_ddb_all_key_attrs(name, table_ks) := result if {
    table_refs := {ks.AttributeName | some ks in table_ks; is_string(ks.AttributeName)}
    gsi_refs := _ddb_gsi_key_attrs(name)
    lsi_refs := _ddb_lsi_key_attrs(name)
    result := table_refs | gsi_refs | lsi_refs
}

# GSI KeySchema attribute names (empty set when property is truly absent)
_ddb_gsi_key_attrs(name) := refs if {
    gsis := resolve(name, "Properties.GlobalSecondaryIndexes")
    is_array(gsis)
    refs := {ks.AttributeName |
        some gsi in gsis
        some ks in gsi.KeySchema
        is_string(ks.AttributeName)
    }
}

_ddb_gsi_key_attrs(name) := set() if {
    not _ddb_gsi_authored(name)
}

# LSI KeySchema attribute names (empty set when property is truly absent)
_ddb_lsi_key_attrs(name) := refs if {
    lsis := resolve(name, "Properties.LocalSecondaryIndexes")
    is_array(lsis)
    refs := {ks.AttributeName |
        some lsi in lsis
        some ks in lsi.KeySchema
        is_string(ks.AttributeName)
    }
}

_ddb_lsi_key_attrs(name) := set() if {
    not _ddb_lsi_authored(name)
}

# True when the GSI property is authored (present in template)
_ddb_gsi_authored(name) if {
    has_property(name, "GlobalSecondaryIndexes")
}

# True when the LSI property is authored (present in template)
_ddb_lsi_authored(name) if {
    has_property(name, "LocalSecondaryIndexes")
}

# Conservative bail: true when an authored index property cannot resolve to
# the expected array/object/string shape. Covers:
# 1. Property authored but resolve does not yield an array (dynamic value)
# 2. Resolved array but an index item KeySchema is not an array
# 3. Resolved KeySchema array but an entry lacks a string AttributeName
_ddb_has_unresolvable_index(name) if {
    _ddb_gsi_authored(name)
    gsis := resolve(name, "Properties.GlobalSecondaryIndexes")
    not is_array(gsis)
}

_ddb_has_unresolvable_index(name) if {
    gsis := resolve(name, "Properties.GlobalSecondaryIndexes")
    is_array(gsis)
    some gsi in gsis
    not is_array(gsi.KeySchema)
}

_ddb_has_unresolvable_index(name) if {
    gsis := resolve(name, "Properties.GlobalSecondaryIndexes")
    is_array(gsis)
    some gsi in gsis
    is_array(gsi.KeySchema)
    some ks in gsi.KeySchema
    not is_string(ks.AttributeName)
}

_ddb_has_unresolvable_index(name) if {
    _ddb_lsi_authored(name)
    lsis := resolve(name, "Properties.LocalSecondaryIndexes")
    not is_array(lsis)
}

_ddb_has_unresolvable_index(name) if {
    lsis := resolve(name, "Properties.LocalSecondaryIndexes")
    is_array(lsis)
    some lsi in lsis
    not is_array(lsi.KeySchema)
}

_ddb_has_unresolvable_index(name) if {
    lsis := resolve(name, "Properties.LocalSecondaryIndexes")
    is_array(lsis)
    some lsi in lsis
    is_array(lsi.KeySchema)
    some ks in lsi.KeySchema
    not is_string(ks.AttributeName)
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
