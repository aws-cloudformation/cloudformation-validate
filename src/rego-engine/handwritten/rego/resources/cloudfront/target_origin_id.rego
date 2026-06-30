package resources

import rego.v1

# E3057: CloudFront DefaultCacheBehavior.TargetOriginId must reference an Origin
# Id or an OriginGroup Id defined in the same DistributionConfig. Only the
# DefaultCacheBehavior is validated (CacheBehaviors targets are not checked).
violation contains make_diag_full("E3057", "ERROR", name,
    "Properties.DistributionConfig.DefaultCacheBehavior.TargetOriginId",
    sprintf("TargetOriginId '%s' does not match any Origin Id in the distribution", [target_id]),
    "Set TargetOriginId to match one of the Origin Ids defined in Origins",
    "") if {
    some name in resources_of_type("AWS::CloudFront::Distribution")
    dist := resolve(name, "Properties.DistributionConfig")
    is_object(dist)
    dcb := object.get(dist, "DefaultCacheBehavior", null)
    is_object(dcb)
    target_id := dcb.TargetOriginId
    is_string(target_id)
    not target_id in valid_target_origin_ids(dist)
}

# Valid TargetOriginId values: the Id of every Origin plus the Id of every
# OriginGroup item.
valid_target_origin_ids(dist) := ids if {
    origins := object.get(dist, "Origins", [])
    origin_ids := {o.Id | some o in origins; is_object(o); o.Id}
    group_items := object.get(object.get(dist, "OriginGroups", {}), "Items", [])
    group_ids := {g.Id | some g in group_items; is_object(g); g.Id}
    ids := origin_ids | group_ids
}
