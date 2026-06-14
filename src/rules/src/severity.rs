use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash, Default,
)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Enum))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Debug = 0,
    #[default]
    Info = 1,
    Warn = 2,
    Error = 3,
    Fatal = 4,
}

impl Severity {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Severity::Fatal => "FATAL",
            Severity::Error => "ERROR",
            Severity::Warn => "WARN",
            Severity::Info => "INFO",
            Severity::Debug => "DEBUG",
        }
    }

    pub fn from_prefix(c: char) -> Severity {
        match c.to_ascii_uppercase() {
            'F' => Severity::Fatal,
            'E' => Severity::Error,
            'W' => Severity::Warn,
            'I' => Severity::Info,
            'D' => Severity::Debug,
            _ => panic!("Invalid severity prefix: {}", c),
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "FATAL" => Ok(Severity::Fatal),
            "ERROR" => Ok(Severity::Error),
            "WARN" => Ok(Severity::Warn),
            "INFO" => Ok(Severity::Info),
            "DEBUG" => Ok(Severity::Debug),
            _ => Err(format!(
                "Invalid severity '{s}'; expected one of: fatal, error, warn, info, debug"
            )),
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use crate::Severity;

    #[test]
    fn as_str_returns_screaming_case_for_all_variants() {
        assert_eq!(Severity::Fatal.as_str(), "FATAL");
        assert_eq!(Severity::Error.as_str(), "ERROR");
        assert_eq!(Severity::Warn.as_str(), "WARN");
        assert_eq!(Severity::Info.as_str(), "INFO");
        assert_eq!(Severity::Debug.as_str(), "DEBUG");
    }

    #[test]
    fn from_str_parses_case_insensitively() {
        use std::str::FromStr;

        assert_eq!(Severity::from_str("fatal").unwrap(), Severity::Fatal);
        assert_eq!(Severity::from_str("FATAL").unwrap(), Severity::Fatal);

        assert_eq!(Severity::from_str("error").unwrap(), Severity::Error);
        assert_eq!(Severity::from_str("ERROR").unwrap(), Severity::Error);

        assert_eq!(Severity::from_str("warn").unwrap(), Severity::Warn);
        assert_eq!(Severity::from_str("WARN").unwrap(), Severity::Warn);

        assert_eq!(Severity::from_str("info").unwrap(), Severity::Info);
        assert_eq!(Severity::from_str("INFO").unwrap(), Severity::Info);

        assert_eq!(Severity::from_str("debug").unwrap(), Severity::Debug);
        assert_eq!(Severity::from_str("DEBUG").unwrap(), Severity::Debug);
    }

    #[test]
    fn from_str_errors_on_unknown_value() {
        use std::str::FromStr;

        let err = Severity::from_str("test").unwrap_err();
        assert_eq!(
            err,
            "Invalid severity 'test'; expected one of: fatal, error, warn, info, debug"
        );
    }

    #[test]
    fn from_prefix_maps_all_valid_chars_case_insensitively() {
        assert_eq!(Severity::from_prefix('f'), Severity::Fatal);
        assert_eq!(Severity::from_prefix('F'), Severity::Fatal);

        assert_eq!(Severity::from_prefix('e'), Severity::Error);
        assert_eq!(Severity::from_prefix('E'), Severity::Error);

        assert_eq!(Severity::from_prefix('w'), Severity::Warn);
        assert_eq!(Severity::from_prefix('W'), Severity::Warn);

        assert_eq!(Severity::from_prefix('i'), Severity::Info);
        assert_eq!(Severity::from_prefix('I'), Severity::Info);

        assert_eq!(Severity::from_prefix('d'), Severity::Debug);
        assert_eq!(Severity::from_prefix('D'), Severity::Debug);
    }

    #[test]
    #[should_panic(expected = "Invalid severity prefix: t")]
    fn from_prefix_panics_on_invalid_char() {
        Severity::from_prefix('t');
    }

    #[test]
    fn default() {
        assert_eq!(Severity::default(), Severity::Info);
    }

    #[test]
    fn ordering_ranks_debug_lowest_and_fatal_highest() {
        assert!(
            Severity::Debug < Severity::Info,
            "Debug should rank below Info"
        );
        assert!(
            Severity::Info < Severity::Warn,
            "Info should rank below Warn"
        );
        assert!(
            Severity::Warn < Severity::Error,
            "Warn should rank below Error"
        );
        assert!(
            Severity::Error < Severity::Fatal,
            "Error should rank below Fatal"
        );
    }
}
