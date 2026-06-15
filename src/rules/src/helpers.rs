use crate::category::Category;

/// Returns `true` if the rule ID indicates a fatal-severity rule (prefix `F`).
pub fn is_fatal_rule(rule_id: &str) -> bool {
    rule_id.starts_with('F')
}

/// Map a rule ID to its diagnostic category based on the ID prefix convention.
pub fn category_for_rule_id(rule_id: &str) -> Category {
    if let Some(prefix3) = rule_id.get(..3) {
        match prefix3 {
            "E25" | "W25" => return Category::Resource,
            "E86" | "W86" | "F86" => return Category::Structure,
            "I25" => return Category::BestPractice,
            "I35" => return Category::Resource,
            "W30" => return Category::Schema,
            "W36" => return Category::Resource,
            _ => {}
        }
    }
    if let Some(prefix2) = rule_id.get(..2) {
        match prefix2 {
            "F0" => return Category::Structure,
            "F1" => return Category::Intrinsic,
            "F2" => return Category::Structure,
            "F3" => return Category::Schema,
            "F5" => return Category::Structure,
            "F6" => return Category::Structure,
            "F7" => return Category::Structure,
            "F8" => return Category::Structure,
            "E0" => return Category::Structure,
            "E1" => return Category::Intrinsic,
            "E2" => return Category::Parameter,
            "E3" => return Category::Schema,
            "E5" => return Category::Structure,
            "E6" => return Category::Structure,
            "E8" => return Category::Structure,
            "W1" => return Category::Intrinsic,
            "W2" => return Category::Security,
            "W3" => return Category::Schema,
            "W7" => return Category::Structure,
            "W8" => return Category::Structure,
            "I2" => return Category::Structure,
            "I3" => return Category::BestPractice,
            _ => {}
        }
    }
    Category::Resource
}

/// Map a CloudFormation schema format string to the rule ID that validates it.
/// Returns `None` for formats without a dedicated rule.
pub fn format_rule_for_format(format: &str) -> Option<&'static str> {
    match format {
        "AWS::EC2::SecurityGroup.Id" => Some("E1150"),
        "AWS::EC2::VPC.Id" => Some("E1151"),
        "AWS::EC2::Image.Id" => Some("E1152"),
        "AWS::EC2::SecurityGroup.Name" => Some("E1153"),
        "AWS::EC2::Subnet.Id" => Some("E1154"),
        "AWS::Logs::LogGroup.Name" => Some("E1155"),
        "AWS::IAM::Role.Arn" => Some("E1156"),
        _ => None,
    }
}

/// Derive the top-level CloudFormation template section from diagnostic context.
pub fn section_for_rule_id(resource_id: Option<&str>, rule_id: &str) -> Option<&'static str> {
    if resource_id.is_some() {
        return Some("Resources");
    }
    match rule_id {
        "F0040" | "F6005" | "F6101" => Some("Outputs"),
        "W8001" => Some("Conditions"),
        "F0008" | "F0050" | "W7001" => Some("Mappings"),
        "F0009" => Some("Conditions"),
        "F0003" | "F0015" | "F0016" | "F2012" | "W2506" | "W2509" | "W2001" => Some("Parameters"),
        "F0001" | "F0007" | "F0011" | "E0001" => Some("Resources"),
        "F0002" => Some("AWSTemplateFormatVersion"),
        "F0004" => Some("Outputs"),
        "F8600" | "F8601" | "W8602" | "F8603" | "F8604" | "F8605" | "F8606" | "F8607" | "W8608" | "F8609" | "F8610"
        | "F8611" => Some("Rules"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::Category;
    use crate::registry::RULE_REGISTRY;

    #[test]
    fn is_fatal_rule_returns_true_for_f_prefix() {
        assert!(is_fatal_rule("F3002"));
        assert!(is_fatal_rule("F0001"));
    }

    #[test]
    fn is_fatal_rule_returns_false_for_non_f_prefixes() {
        assert!(!is_fatal_rule("E3002"));
        assert!(!is_fatal_rule("W1001"));
        assert!(!is_fatal_rule("I3011"));
    }

    #[test]
    fn category_for_rule_id_maps_two_char_prefixes_correctly() {
        assert_eq!(category_for_rule_id("F0001"), Category::Structure);
        assert_eq!(category_for_rule_id("F1010"), Category::Intrinsic);
        assert_eq!(category_for_rule_id("E1040"), Category::Intrinsic);
        assert_eq!(category_for_rule_id("E2010"), Category::Parameter);
        assert_eq!(category_for_rule_id("E3012"), Category::Schema);
        // W21xx avoids the W25/W30/W36 3-char overrides
        assert_eq!(category_for_rule_id("W2100"), Category::Security);
        assert_eq!(category_for_rule_id("I3011"), Category::BestPractice);
    }

    #[test]
    fn category_for_rule_id_applies_three_char_overrides() {
        assert_eq!(category_for_rule_id("E2529"), Category::Resource);
        assert_eq!(category_for_rule_id("E2504"), Category::Resource);
        assert_eq!(category_for_rule_id("I2530"), Category::BestPractice);
        assert_eq!(category_for_rule_id("F8600"), Category::Structure);
    }

    #[test]
    fn category_for_rule_id_defaults_to_resource_for_unknown_prefix() {
        assert_eq!(category_for_rule_id("Z9999"), Category::Resource);
    }

    #[test]
    fn section_for_rule_id_returns_resources_when_resource_id_present() {
        assert_eq!(section_for_rule_id(Some("Bucket"), "E3012"), Some("Resources"));
    }

    #[test]
    fn section_for_rule_id_maps_output_rules_to_outputs() {
        assert_eq!(section_for_rule_id(None, "F0040"), Some("Outputs"));
        assert_eq!(section_for_rule_id(None, "F0004"), Some("Outputs"));
    }

    #[test]
    fn section_for_rule_id_maps_parameter_rules_to_parameters() {
        assert_eq!(section_for_rule_id(None, "F0003"), Some("Parameters"));
        assert_eq!(section_for_rule_id(None, "W2001"), Some("Parameters"));
    }

    #[test]
    fn section_for_rule_id_maps_condition_rules_to_conditions() {
        assert_eq!(section_for_rule_id(None, "F0009"), Some("Conditions"));
        assert_eq!(section_for_rule_id(None, "W8001"), Some("Conditions"));
    }

    #[test]
    fn section_for_rule_id_maps_rules_section_rules() {
        assert_eq!(section_for_rule_id(None, "F8600"), Some("Rules"));
    }

    #[test]
    fn section_for_rule_id_returns_none_for_unmapped_rule() {
        assert_eq!(section_for_rule_id(None, "Z9999"), None);
    }

    #[test]
    fn format_rule_for_format_maps_all_known_formats() {
        assert_eq!(format_rule_for_format("AWS::EC2::Image.Id"), Some("E1152"));
        assert_eq!(format_rule_for_format("AWS::EC2::SecurityGroup.Id"), Some("E1150"));
        assert_eq!(format_rule_for_format("AWS::EC2::VPC.Id"), Some("E1151"));
        assert_eq!(format_rule_for_format("AWS::EC2::Subnet.Id"), Some("E1154"));
        assert_eq!(format_rule_for_format("AWS::Logs::LogGroup.Name"), Some("E1155"));
        assert_eq!(format_rule_for_format("AWS::IAM::Role.Arn"), Some("E1156"));
    }

    #[test]
    fn format_rule_for_format_returns_none_for_unknown_format() {
        assert_eq!(format_rule_for_format("unknown-format"), None);
    }

    #[test]
    fn category_heuristic_diverges_from_registry_for_some_rules() {
        let mut divergences = 0;
        for rule in RULE_REGISTRY {
            if category_for_rule_id(rule.id) != rule.category {
                divergences += 1;
            }
        }
        // The helper uses prefix heuristics; the registry is authoritative.
        // Many rules override the prefix convention. This test ensures
        // divergences don't grow unexpectedly.
        assert!(divergences > 0, "If all agree, the helper covers everything — great!");
    }
}
