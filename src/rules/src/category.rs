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
}

impl std::str::FromStr for Category {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "schema" => Ok(Category::Schema),
            "structure" => Ok(Category::Structure),
            "intrinsic function" => Ok(Category::Intrinsic),
            "best practice" | "best-practice" | "best_practice" => Ok(Category::BestPractice),
            "resource" => Ok(Category::Resource),
            "security" => Ok(Category::Security),
            "parameter" => Ok(Category::Parameter),
            "reference" => Ok(Category::Reference),
            "deprecation" => Ok(Category::Deprecation),
            "general" => Ok(Category::General),
            _ => Err(format!("Invalid category: {}", s)),
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
    use std::str::FromStr;

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
            assert_eq!(Category::from_str(cat.as_str()).unwrap(), cat, "round-trip failed for {:?}", cat);
        }
    }

    #[test]
    fn from_str_parses_case_insensitively() {
        assert_eq!(Category::from_str("SCHEMA").unwrap(), Category::Schema);
        assert_eq!(Category::from_str("Best Practice").unwrap(), Category::BestPractice);
        assert_eq!(Category::from_str("BEST PRACTICE").unwrap(), Category::BestPractice);
    }

    #[test]
    fn from_str_errors_on_freeform_category_string() {
        let err = Category::from_str("guard:test").unwrap_err();
        assert_eq!(err, "Invalid category: guard:test");
    }
}
