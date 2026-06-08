package custom_test

import rego.v1

violation contains v if {
    some name, res in input.resources
    res.resourceType == "AWS::S3::Bucket"
    not res.properties.BucketEncryption
    v := {"rule_id": "CUSTOM001", "severity": "error", "message": "S3 bucket must have encryption configured", "resource_id": name}
}
