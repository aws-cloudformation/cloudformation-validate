pub const DEFAULT_REGION: &str = "us-east-1";
pub const DEFAULT_PARTITION: &str = "aws";
pub const DEFAULT_URL_SUFFIX: &str = "amazonaws.com";

const CN_REGIONS: &[&str] = &["cn-north-1", "cn-northwest-1"];
const GOV_REGIONS: &[&str] = &["us-gov-east-1", "us-gov-west-1"];

pub const AVAILABILITY_ZONES: &[(&str, &[&str])] = &[
    ("af-south-1", &["af-south-1a", "af-south-1b", "af-south-1c"]),
    ("ap-east-1", &["ap-east-1a", "ap-east-1b", "ap-east-1c"]),
    ("ap-east-2", &["ap-east-2a", "ap-east-2b", "ap-east-2c"]),
    ("ap-northeast-1", &["ap-northeast-1a", "ap-northeast-1b", "ap-northeast-1c", "ap-northeast-1d"]),
    ("ap-northeast-2", &["ap-northeast-2a", "ap-northeast-2b", "ap-northeast-2c", "ap-northeast-2d"]),
    ("ap-northeast-3", &["ap-northeast-3a", "ap-northeast-3b", "ap-northeast-3c"]),
    ("ap-south-1", &["ap-south-1a", "ap-south-1b", "ap-south-1c"]),
    ("ap-south-2", &["ap-south-2a", "ap-south-2b", "ap-south-2c"]),
    ("ap-southeast-1", &["ap-southeast-1a", "ap-southeast-1b", "ap-southeast-1c"]),
    ("ap-southeast-2", &["ap-southeast-2a", "ap-southeast-2b", "ap-southeast-2c"]),
    ("ap-southeast-3", &["ap-southeast-3a", "ap-southeast-3b", "ap-southeast-3c"]),
    ("ap-southeast-4", &["ap-southeast-4a", "ap-southeast-4b", "ap-southeast-4c"]),
    ("ap-southeast-5", &["ap-southeast-5a", "ap-southeast-5b", "ap-southeast-5c"]),
    ("ap-southeast-6", &["ap-southeast-6a", "ap-southeast-6b", "ap-southeast-6c"]),
    ("ap-southeast-7", &["ap-southeast-7a", "ap-southeast-7b", "ap-southeast-7c"]),
    ("ca-central-1", &["ca-central-1a", "ca-central-1b", "ca-central-1c", "ca-central-1d"]),
    ("ca-west-1", &["ca-west-1a", "ca-west-1b", "ca-west-1c"]),
    ("cn-north-1", &["cn-north-1a", "cn-north-1b", "cn-north-1c"]),
    ("cn-northwest-1", &["cn-northwest-1a", "cn-northwest-1b", "cn-northwest-1c"]),
    ("eu-central-1", &["eu-central-1a", "eu-central-1b", "eu-central-1c"]),
    ("eu-central-2", &["eu-central-2a", "eu-central-2b", "eu-central-2c"]),
    ("eu-isoe-west-1", &["eu-isoe-west-1a", "eu-isoe-west-1b", "eu-isoe-west-1c"]),
    ("eu-north-1", &["eu-north-1a", "eu-north-1b", "eu-north-1c"]),
    ("eu-south-1", &["eu-south-1a", "eu-south-1b", "eu-south-1c"]),
    ("eu-south-2", &["eu-south-2a", "eu-south-2b", "eu-south-2c"]),
    ("eu-west-1", &["eu-west-1a", "eu-west-1b", "eu-west-1c"]),
    ("eu-west-2", &["eu-west-2a", "eu-west-2b", "eu-west-2c"]),
    ("eu-west-3", &["eu-west-3a", "eu-west-3b", "eu-west-3c"]),
    ("eusc-de-east-1", &["eusc-de-east-1a", "eusc-de-east-1b", "eusc-de-east-1c"]),
    ("il-central-1", &["il-central-1a", "il-central-1b", "il-central-1c"]),
    ("me-central-1", &["me-central-1a", "me-central-1b", "me-central-1c"]),
    ("me-south-1", &["me-south-1a", "me-south-1b", "me-south-1c"]),
    ("mx-central-1", &["mx-central-1a", "mx-central-1b", "mx-central-1c"]),
    ("sa-east-1", &["sa-east-1a", "sa-east-1b", "sa-east-1c"]),
    ("us-east-1", &["us-east-1a", "us-east-1b", "us-east-1c", "us-east-1d", "us-east-1e", "us-east-1f"]),
    ("us-east-2", &["us-east-2a", "us-east-2b", "us-east-2c"]),
    ("us-gov-east-1", &["us-gov-east-1a", "us-gov-east-1b", "us-gov-east-1c"]),
    ("us-gov-west-1", &["us-gov-west-1a", "us-gov-west-1b", "us-gov-west-1c"]),
    ("us-iso-east-1", &["us-iso-east-1a", "us-iso-east-1b", "us-iso-east-1c"]),
    ("us-iso-west-1", &["us-iso-west-1a", "us-iso-west-1b", "us-iso-west-1c"]),
    ("us-isob-east-1", &["us-isob-east-1a", "us-isob-east-1b", "us-isob-east-1c"]),
    ("us-isof-east-1", &["us-isof-east-1a", "us-isof-east-1b", "us-isof-east-1c"]),
    ("us-isof-south-1", &["us-isof-south-1a", "us-isof-south-1b", "us-isof-south-1c"]),
    ("us-west-1", &["us-west-1a", "us-west-1c"]),
    ("us-west-2", &["us-west-2a", "us-west-2b", "us-west-2c", "us-west-2d"]),
];

const AWS_REGION_NAMES: [&str; AVAILABILITY_ZONES.len()] = {
    let mut names = [""; AVAILABILITY_ZONES.len()];
    let mut i = 0;
    while i < AVAILABILITY_ZONES.len() {
        names[i] = AVAILABILITY_ZONES[i].0;
        i += 1;
    }
    names
};

pub const AWS_REGIONS: &[&str] = &AWS_REGION_NAMES;

pub fn is_known_region(region: &str) -> bool {
    AWS_REGIONS.contains(&region)
}

pub fn availability_zones_for_region(region: &str) -> Option<&'static [&'static str]> {
    AVAILABILITY_ZONES.iter().find(|(name, _)| *name == region).map(|(_, zones)| *zones)
}

pub fn partition_for_region(region: &str) -> &'static str {
    if CN_REGIONS.contains(&region) {
        "aws-cn"
    } else if GOV_REGIONS.contains(&region) {
        "aws-us-gov"
    } else {
        DEFAULT_PARTITION
    }
}

pub fn url_suffix_for_region(region: &str) -> &'static str {
    if CN_REGIONS.contains(&region) { "amazonaws.com.cn" } else { DEFAULT_URL_SUFFIX }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_for_standard_regions() {
        assert_eq!(partition_for_region("us-east-1"), "aws");
        assert_eq!(partition_for_region("eu-west-1"), "aws");
        assert_eq!(partition_for_region("ap-southeast-1"), "aws");
    }

    #[test]
    fn partition_for_china_regions() {
        assert_eq!(partition_for_region("cn-north-1"), "aws-cn");
        assert_eq!(partition_for_region("cn-northwest-1"), "aws-cn");
    }

    #[test]
    fn partition_for_govcloud_regions() {
        assert_eq!(partition_for_region("us-gov-east-1"), "aws-us-gov");
        assert_eq!(partition_for_region("us-gov-west-1"), "aws-us-gov");
    }

    #[test]
    fn url_suffix_for_standard_regions() {
        assert_eq!(url_suffix_for_region("us-east-1"), "amazonaws.com");
        assert_eq!(url_suffix_for_region("eu-west-1"), "amazonaws.com");
        assert_eq!(url_suffix_for_region("us-gov-west-1"), "amazonaws.com");
    }

    #[test]
    fn url_suffix_for_china_regions() {
        assert_eq!(url_suffix_for_region("cn-north-1"), "amazonaws.com.cn");
        assert_eq!(url_suffix_for_region("cn-northwest-1"), "amazonaws.com.cn");
    }

    #[test]
    fn aws_regions_derives_from_availability_zones() {
        assert_eq!(AWS_REGIONS.len(), AVAILABILITY_ZONES.len());
        for ((region, _), name) in AVAILABILITY_ZONES.iter().zip(AWS_REGIONS.iter()) {
            assert_eq!(region, name, "AWS_REGIONS must mirror AVAILABILITY_ZONES region names in order");
        }
    }

    #[test]
    fn availability_zones_table_is_sorted_and_unique() {
        for pair in AVAILABILITY_ZONES.windows(2) {
            assert!(
                pair[0].0 < pair[1].0,
                "AVAILABILITY_ZONES must be sorted by region: {} !< {}",
                pair[0].0,
                pair[1].0
            );
        }
    }

    #[test]
    fn availability_zones_lookup_matches_region() {
        assert_eq!(
            availability_zones_for_region("us-east-1"),
            Some(["us-east-1a", "us-east-1b", "us-east-1c", "us-east-1d", "us-east-1e", "us-east-1f"].as_slice())
        );
        assert_eq!(availability_zones_for_region("us-west-1"), Some(["us-west-1a", "us-west-1c"].as_slice()));
        assert_eq!(availability_zones_for_region("mars-north-1"), None);
    }

    #[test]
    fn is_known_region_covers_gov_cn_and_rejects_unknown() {
        assert!(is_known_region("us-east-1"));
        assert!(is_known_region("us-gov-west-1"));
        assert!(is_known_region("cn-north-1"));
        assert!(is_known_region("ap-east-2"));
        assert!(!is_known_region("mars-north-1"));
    }
}
