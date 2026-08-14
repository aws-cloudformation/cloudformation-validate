package custom_arbitrary_id

import rego.v1

violation contains v if {
    some name, res in input.resources
    res.resourceType == "AWS::S3::Bucket"
    not res.properties.BucketEncryption
    v := {"rule_id": "Firewall.check-1", "severity": "warn", "message": "S3 bucket must have encryption configured", "resource_id": name}
}
