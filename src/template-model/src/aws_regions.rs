//! Canonical mapping of AWS regions to their availability-zone suffixes.
//!
//! Single source of truth used by the resolver (`Fn::GetAZs`) and the rule
//! engines. Only generally-available (GA) regions are listed — opt-in regions
//! that have GA'd are included; pre-GA / private-preview regions are not.
//!
//! The canonical list is the AWS service-endpoints documentation:
//! <https://docs.aws.amazon.com/general/latest/gr/rande.html>. China regions
//! are documented separately at the same source.

/// Returns the AZ-letter suffixes for a region, or `None` if the region is
/// unknown / not GA.
///
/// `Fn::GetAZs` returns concrete AZ names of the form `<region><suffix>`
/// (e.g. `us-east-1a`). The suffix list captures the AZs actually exposed by
/// each region — most regions have three (a, b, c); a few legacy regions
/// have gaps (us-west-1 has two AZs, ca-central-1 skips "c").
pub fn availability_zone_suffixes(region: &str) -> Option<&'static [&'static str]> {
    match region {
        // US Commercial
        "us-east-1" => Some(&["a", "b", "c", "d", "e", "f"]),
        "us-east-2" => Some(&["a", "b", "c"]),
        "us-west-1" => Some(&["a", "b"]),
        "us-west-2" => Some(&["a", "b", "c", "d"]),

        // Canada
        "ca-central-1" => Some(&["a", "b", "d"]),
        "ca-west-1" => Some(&["a", "b", "d"]),

        // South America
        "sa-east-1" => Some(&["a", "b", "c"]),

        // Mexico
        "mx-central-1" => Some(&["a", "b", "c"]),

        // Europe
        "eu-central-1" => Some(&["a", "b", "c"]),
        "eu-central-2" => Some(&["a", "b", "c"]),
        "eu-west-1" => Some(&["a", "b", "c"]),
        "eu-west-2" => Some(&["a", "b", "c"]),
        "eu-west-3" => Some(&["a", "b", "c"]),
        "eu-north-1" => Some(&["a", "b", "c"]),
        "eu-south-1" => Some(&["a", "b", "c"]),
        "eu-south-2" => Some(&["a", "b", "c"]),

        // Africa
        "af-south-1" => Some(&["a", "b", "c"]),

        // Middle East
        "me-south-1" => Some(&["a", "b", "c"]),
        "me-central-1" => Some(&["a", "b", "c"]),

        // Israel
        "il-central-1" => Some(&["a", "b", "c"]),

        // Asia Pacific — North
        "ap-east-1" => Some(&["a", "b", "c"]),
        "ap-east-2" => Some(&["a", "b", "c"]),
        "ap-northeast-1" => Some(&["a", "b", "c", "d"]),
        "ap-northeast-2" => Some(&["a", "b", "c", "d"]),
        "ap-northeast-3" => Some(&["a", "b", "c"]),

        // Asia Pacific — South
        "ap-south-1" => Some(&["a", "b", "c"]),
        "ap-south-2" => Some(&["a", "b", "c"]),

        // Asia Pacific — Southeast
        "ap-southeast-1" => Some(&["a", "b", "c"]),
        "ap-southeast-2" => Some(&["a", "b", "c"]),
        "ap-southeast-3" => Some(&["a", "b", "c"]),
        "ap-southeast-4" => Some(&["a", "b", "c"]),
        "ap-southeast-5" => Some(&["a", "b", "c"]),
        "ap-southeast-6" => Some(&["a", "b", "c"]),
        "ap-southeast-7" => Some(&["a", "b", "c"]),

        // GovCloud
        "us-gov-east-1" => Some(&["a", "b", "c"]),
        "us-gov-west-1" => Some(&["a", "b", "c"]),

        // China — separate AWS partition, but GA
        "cn-north-1" => Some(&["a", "b", "c"]),
        "cn-northwest-1" => Some(&["a", "b", "c"]),

        _ => None,
    }
}

/// Returns fully-qualified AZ names for a region
/// (e.g. `["us-east-1a", "us-east-1b", ...]`), or `None` if the region is
/// unknown / not GA.
pub fn availability_zones_for_region(region: &str) -> Option<Vec<String>> {
    availability_zone_suffixes(region).map(|suffixes| suffixes.iter().map(|s| format!("{}{}", region, s)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_regions_return_azs() {
        assert_eq!(availability_zones_for_region("us-east-1").unwrap().len(), 6);
        assert!(availability_zones_for_region("eu-south-1").is_some());
        assert!(availability_zones_for_region("us-gov-west-1").is_some());
        assert!(availability_zones_for_region("cn-north-1").is_some());
    }

    #[test]
    fn unknown_region_returns_none() {
        assert!(availability_zones_for_region("xx-fantasy-1").is_none());
    }

    #[test]
    fn eu_south_1_returns_concrete_azs() {
        let azs = availability_zones_for_region("eu-south-1").unwrap();
        assert_eq!(azs.len(), 3);
        assert_eq!(azs[0], "eu-south-1a");
    }

    /// Newly-launched GA regions (Taipei, Kuala Lumpur, New Zealand, Thailand,
    /// Mexico) must resolve to concrete AZ enumerations rather than falling
    /// back to `Dynamic`. This test guards against regression.
    #[test]
    fn newly_added_ga_regions_resolve() {
        for region in ["ap-east-2", "ap-southeast-5", "ap-southeast-6", "ap-southeast-7", "mx-central-1"] {
            let azs = availability_zones_for_region(region)
                .unwrap_or_else(|| panic!("expected GA region '{}' to be supported", region));
            assert_eq!(azs.len(), 3, "expected 3 AZs for {}, got {:?}", region, azs);
            assert_eq!(azs[0], format!("{}a", region));
        }
    }

    /// us-west-1 only exposes two AZs (a, b) — many newer accounts can't see
    /// the historical "us-west-1c" zone. Lock the count to 2 to match the
    /// behaviour of `Fn::GetAZs` for typical accounts.
    #[test]
    fn us_west_1_has_two_azs() {
        let azs = availability_zones_for_region("us-west-1").unwrap();
        assert_eq!(azs.len(), 2);
        assert_eq!(azs, vec!["us-west-1a", "us-west-1b"]);
    }

    /// ca-central-1 skips the "c" suffix in CloudFormation `Fn::GetAZs`
    /// output — its three exposed AZs are a, b, d.
    #[test]
    fn ca_central_1_skips_c() {
        let azs = availability_zones_for_region("ca-central-1").unwrap();
        assert_eq!(azs, vec!["ca-central-1a", "ca-central-1b", "ca-central-1d"]);
    }

    /// Sanity-check that the entire AWS GA region set is covered. Whenever
    /// a new GA region launches, this list must be updated alongside the
    /// `match` in `availability_zone_suffixes`.
    #[test]
    fn all_ga_regions_covered() {
        let ga_regions = [
            // US
            "us-east-1", "us-east-2", "us-west-1", "us-west-2",
            // Canada
            "ca-central-1", "ca-west-1",
            // South America
            "sa-east-1",
            // Mexico
            "mx-central-1",
            // Europe
            "eu-central-1", "eu-central-2", "eu-west-1", "eu-west-2", "eu-west-3",
            "eu-north-1", "eu-south-1", "eu-south-2",
            // Africa
            "af-south-1",
            // Middle East
            "me-south-1", "me-central-1",
            // Israel
            "il-central-1",
            // Asia Pacific
            "ap-east-1", "ap-east-2",
            "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
            "ap-south-1", "ap-south-2",
            "ap-southeast-1", "ap-southeast-2", "ap-southeast-3",
            "ap-southeast-4", "ap-southeast-5", "ap-southeast-6", "ap-southeast-7",
            // GovCloud
            "us-gov-east-1", "us-gov-west-1",
            // China
            "cn-north-1", "cn-northwest-1",
        ];
        for r in ga_regions {
            assert!(
                availability_zones_for_region(r).is_some(),
                "GA region '{}' missing from availability_zone_suffixes",
                r
            );
        }
        assert_eq!(ga_regions.len(), 38);
    }
}
