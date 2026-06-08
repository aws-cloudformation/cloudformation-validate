package multi_custom_test

import rego.v1

violation contains v if {
    some name, res in input.resources
    res.resourceType == "AWS::S3::Bucket"
    not res.properties.VersioningConfiguration
    v := {"rule_id": "CUSTOM010", "severity": "error", "message": "S3 bucket must have versioning enabled", "resource_id": name}
}

violation contains v if {
    some name, res in input.resources
    res.resourceType == "AWS::S3::Bucket"
    not res.properties.LifecycleConfiguration
    v := {"rule_id": "CUSTOM011", "severity": "warn", "message": "S3 bucket should have lifecycle rules configured", "resource_id": name}
}
