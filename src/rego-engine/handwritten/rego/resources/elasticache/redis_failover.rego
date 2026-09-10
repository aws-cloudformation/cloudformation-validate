package resources

import rego.v1

# E3026: ElastiCache Redis - AutomaticFailoverEnabled required when NumCacheClusters > 1
# NumCacheClusters is ignored when NumNodeGroups is specified
violation contains make_diag_at("E3026", "ERROR", name,
    "Properties.AutomaticFailoverEnabled",
    "AutomaticFailoverEnabled must be true when NumCacheClusters > 1 and Engine is 'redis'") if {
    cfn_rule_active("E3026")
    some name in resources_of_type("AWS::ElastiCache::ReplicationGroup")
    engine := resolve(name, "Properties.Engine")
    engine == "redis"
    not has_property(name, "NumNodeGroups")
    num := resolve(name, "Properties.NumCacheClusters")
    is_number(num)
    num > 1
    not is_dynamic(name, "Properties.AutomaticFailoverEnabled")
    failover := resolve(name, "Properties.AutomaticFailoverEnabled")
    failover != true
}
