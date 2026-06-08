use std::fmt;

/// Built-in diagnostic categories for registered rules.
///
/// Custom and guard rules use freeform strings (e.g. `"guard:s3_versioning"`)
/// and do not use this enum. Public APIs expose categories as plain strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Category {
    Schema,
    Structure,
    Intrinsic,
    BestPractice,
    Resource,
    Security,
    Parameter,
    Reference,
    Deprecation,
    General,
}

impl Category {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Category::Schema => "Schema",
            Category::Structure => "Structure",
            Category::Intrinsic => "Intrinsic Function",
            Category::BestPractice => "Best Practice",
            Category::Resource => "Resource",
            Category::Security => "Security",
            Category::Parameter => "Parameter",
            Category::Reference => "Reference",
            Category::Deprecation => "Deprecation",
            Category::General => "General",
        }
    }

    pub fn from_str(s: &str) -> Category {
        match s.to_lowercase().as_str() {
            "schema" => Category::Schema,
            "structure" => Category::Structure,
            "intrinsic function" => Category::Intrinsic,
            "best practice" | "best-practice" | "best_practice" => Category::BestPractice,
            "resource" => Category::Resource,
            "security" => Category::Security,
            "parameter" => Category::Parameter,
            "reference" => Category::Reference,
            "deprecation" => Category::Deprecation,
            "general" => Category::General,
            _ => panic!("Invalid category: {}", s),
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_str_round_trips_through_from_str_for_all_variants() {
        let all = [
            Category::Schema,
            Category::Structure,
            Category::Intrinsic,
            Category::BestPractice,
            Category::Resource,
            Category::Security,
            Category::Parameter,
            Category::Reference,
            Category::Deprecation,
            Category::General,
        ];
        for cat in all {
            assert_eq!(
                Category::from_str(cat.as_str()),
                cat,
                "round-trip failed for {:?}",
                cat
            );
        }
    }

    #[test]
    fn from_str_parses_case_insensitively() {
        assert_eq!(Category::from_str("SCHEMA"), Category::Schema);
        assert_eq!(Category::from_str("Best Practice"), Category::BestPractice);
        assert_eq!(Category::from_str("BEST PRACTICE"), Category::BestPractice);
    }

    #[test]
    #[should_panic(expected = "Invalid category: guard:test")]
    fn from_str_panics_on_freeform_category_string() {
        Category::from_str("guard:test");
    }
}
