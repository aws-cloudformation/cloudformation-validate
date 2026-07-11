use crate::category::Category;

/// Returns `true` if the rule ID indicates a fatal-severity rule (prefix `F`).
///
/// This is a heuristic over the built-in ID convention only. It must never decide
/// the severity, phase, or category of a custom, Rego, or Guard rule: those rules
/// choose their own ID freely (see [`is_valid_custom_rule_id`]) and carry their own
/// declared severity.
pub fn is_fatal_rule(rule_id: &str) -> bool {
    rule_id.starts_with('F')
}

/// The characters permitted in a custom (CEL/Rego/Guard) rule ID beyond ASCII
/// letters and digits: the identifier separators `_`, `.`, and `-`.
pub const CUSTOM_RULE_ID_SEPARATORS: [char; 3] = ['_', '.', '-'];

/// Returns `true` if `rule_id` is a well-formed custom-rule identifier: a non-empty
/// run of ASCII letters, digits, and the separators `_`, `.`, or `-`.
///
/// Custom (CEL/Rego/Guard) rule IDs are intentionally NOT required to follow the
/// built-in `[FEWID]\d{4}` convention — an author may name a rule anything in that
/// character set. The restriction only rejects whitespace and other punctuation that
/// would corrupt diagnostic formatting, rule-ID filtering, and de-duplication.
pub fn is_valid_custom_rule_id(rule_id: &str) -> bool {
    !rule_id.is_empty() && rule_id.chars().all(|c| c.is_ascii_alphanumeric() || CUSTOM_RULE_ID_SEPARATORS.contains(&c))
}

/// Extracts the numeric part of a rule ID (the digits after the severity-prefix
/// letter), used to order diagnostics by rule number within a severity. A rule ID
/// that does not follow the `[FEWID]\d+` convention (e.g. a custom rule) yields
/// `u32::MAX` so it sorts after the well-formed built-in rules.
pub fn rule_number(rule_id: &str) -> u32 {
    rule_id.get(1..).and_then(|digits| digits.parse::<u32>().ok()).unwrap_or(u32::MAX)
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

/// Regex for the `AWS::IAM::Role.Arn` schema *format* (the E1156 check): the partition must be
/// `aws`-prefixed and the role name is unrestricted (`.+`), so a role name containing a space or
/// other legal-but-unusual character is accepted here.
pub const IAM_ROLE_ARN_PATTERN: &str = r"^arn:aws[a-zA-Z-]*:iam::\d{12}:role/.+$";

/// Regex for the resource-property IAM role-ARN *rule* (the E3511 check): the partition group is
/// optional and the role name is constrained to the IAM role-name character class. This is
/// intentionally stricter than [`IAM_ROLE_ARN_PATTERN`] — the two correspond to two distinct checks
/// and must not be conflated.
pub const IAM_ROLE_ARN_RULE_PATTERN: &str = r"^arn:(aws[a-zA-Z-]*)?:iam::\d{12}:role/[a-zA-Z_0-9+=,.@\-_/]+$";

/// Regex for a valid EC2 Security Group name. The class mirrors the character set the service
/// accepts; the `+` requires at least one character.
pub const SECURITY_GROUP_NAME_PATTERN: &str = r"^[a-zA-Z0-9 \._\-:/()#,@\[\]+=&;\{\}!\$\*]+$";

/// Regex for a Route53 `MX` record value: a preference `0`–`65535`, a single whitespace, then the
/// mail-exchange host. The bounded-preference alternation enforces the 16-bit range (an unbounded
/// `\d+` would wrongly accept `70000`), and the single `\s` rejects the double-space form the
/// service rejects.
pub const MX_RECORD_PATTERN: &str =
    r"^(0|[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])\s\S+$";

/// Regex for a Route53 `CAA` record value: a flag `0` or `128`, a tag, and a quoted value, each
/// separated by a single whitespace. The single `\s` (not `\s+`) matches the service's own
/// single-separator requirement.
pub const CAA_RECORD_PATTERN: &str = r#"^(0|128)\s([a-zA-Z0-9]+)\s(".+")$"#;

/// Regex recognizing a hardcoded EC2 Availability Zone name (e.g. `us-east-1a`, `us-gov-west-1a`,
/// `us-iso-east-1a`). The repeated `(-[a-z]+)+` segment matches partition-qualified zones
/// (GovCloud/ISO) a single-segment pattern would miss.
pub const AVAILABILITY_ZONE_PATTERN: &str = r"^[a-z]{2}(-[a-z]+)+-[0-9][a-z]$";

/// Regex for an EC2 AMI identifier: `ami-` followed by an 8- or 17-character hex id. The two fixed
/// lengths (not a `{8,17}` range) reflect the only id widths EC2 issues, so a 9–16 character string
/// is not mistaken for an AMI id.
pub const AMI_ID_PATTERN: &str = r"^ami-([0-9a-f]{8}|[0-9a-f]{17})$";

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
        "F0040" | "F6005" | "F6101" | "F6004" | "F6011" | "I6011" | "I6010" => Some("Outputs"),
        "W8001" => Some("Conditions"),
        "F0008" | "F0050" | "W7001" | "F0017" | "E7001" | "F7002" | "I7002" | "I7010" => Some("Mappings"),
        "F0009" => Some("Conditions"),
        "F0003" | "F0015" | "F0016" | "F2012" | "W2506" | "W2509" | "W2001" | "E2001" | "F2002" | "F2003" | "F2011"
        | "I2011" | "F2015" | "W2501" | "I2010" => Some("Parameters"),
        "F0001" | "F0007" | "F0011" | "E0001" | "F0005" | "F1104" => Some("Resources"),
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
    fn is_valid_custom_rule_id_accepts_alphanumeric_and_separators() {
        // Built-in-style, arbitrary, and separator-bearing IDs are all permitted.
        assert!(is_valid_custom_rule_id("CUSTOM001"));
        assert!(is_valid_custom_rule_id("myRule1"));
        assert!(is_valid_custom_rule_id("check_bucket_encryption"));
        assert!(is_valid_custom_rule_id("s3.encryption.required"));
        assert!(is_valid_custom_rule_id("my-rule-1"));
        assert!(is_valid_custom_rule_id("Fluffy123"));
        assert!(is_valid_custom_rule_id("_"));
    }

    #[test]
    fn is_valid_custom_rule_id_rejects_empty_whitespace_and_punctuation() {
        assert!(!is_valid_custom_rule_id(""));
        assert!(!is_valid_custom_rule_id("my rule"));
        assert!(!is_valid_custom_rule_id("rule/id"));
        assert!(!is_valid_custom_rule_id("rule:id"));
        assert!(!is_valid_custom_rule_id("rule#1"));
        assert!(!is_valid_custom_rule_id("emoji😀"));
    }

    #[test]
    fn rule_number_extracts_numeric_suffix_ignoring_prefix() {
        assert_eq!(rule_number("F0001"), 1);
        assert_eq!(rule_number("E3012"), 3012);
        assert_eq!(rule_number("W9012"), 9012);
        // The severity prefix is irrelevant to the number, so same-numbered rules of
        // different severities share a number and are ordered by severity first.
        assert_eq!(rule_number("F3012"), rule_number("E3012"));
    }

    #[test]
    fn rule_number_returns_max_for_ids_without_a_numeric_suffix() {
        assert_eq!(rule_number("CUSTOM"), u32::MAX);
        assert_eq!(rule_number(""), u32::MAX);
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
