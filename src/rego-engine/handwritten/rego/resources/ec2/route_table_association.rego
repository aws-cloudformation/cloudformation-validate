package resources

import rego.v1

# E3022: EC2 allows exactly one route table per subnet; two associations
# naming the same subnet fail at deploy time. The shared detector produces
# one finding per clashing association.
violation contains make_diag_full("E3022", "ERROR", finding.resourceId,
    "Properties.SubnetId", finding.message,
    "Associate each subnet with exactly one route table", "") if {
    some finding in duplicate_subnet_route_table_associations()
}
