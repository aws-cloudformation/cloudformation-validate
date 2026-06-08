package resources

import rego.v1

# E3057: CloudFront TargetOriginId must reference a defined Origin
violation contains make_diag_full("E3057", "ERROR", name,
    "Properties.DistributionConfig.DefaultCacheBehavior.TargetOriginId",
    sprintf("TargetOriginId '%s' does not match any Origin Id in the distribution", [target_id]),
    "Set TargetOriginId to match one of the Origin Ids defined in Origins",
    "") if {
    some name in resources_of_type("AWS::CloudFront::Distribution")
    dist := resolve(name, "Properties.DistributionConfig")
    is_object(dist)
    origins := object.get(dist, "Origins", [])
    is_array(origins)
    origin_ids := {o.Id | some o in origins; is_object(o); o.Id}
    dcb := object.get(dist, "DefaultCacheBehavior", null)
    is_object(dcb)
    target_id := dcb.TargetOriginId
    is_string(target_id)
    not target_id in origin_ids
}

violation contains make_diag_full("E3057", "ERROR", name,
    "Properties.DistributionConfig.CacheBehaviors",
    sprintf("CacheBehavior TargetOriginId '%s' does not match any Origin Id", [target_id]),
    "Set TargetOriginId to match one of the Origin Ids defined in Origins",
    "") if {
    some name in resources_of_type("AWS::CloudFront::Distribution")
    dist := resolve(name, "Properties.DistributionConfig")
    is_object(dist)
    origins := object.get(dist, "Origins", [])
    is_array(origins)
    origin_ids := {o.Id | some o in origins; is_object(o); o.Id}
    cbs := object.get(dist, "CacheBehaviors", [])
    is_array(cbs)
    some cb in cbs
    is_object(cb)
    target_id := cb.TargetOriginId
    is_string(target_id)
    not target_id in origin_ids
}
