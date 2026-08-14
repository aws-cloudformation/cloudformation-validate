//! Validation of `AWS::Events::Rule` `ScheduleExpression` values (`rate(...)` / `cron(...)`).
//!
//! The service accepts a `rate(Value Unit)` where `Value` is a positive integer and `Unit` agrees
//! in number with it (`minute`/`hour`/`day` when the value is 1, plural otherwise), or a
//! `cron(...)` of exactly six space-separated fields that does not pin both day-of-month and
//! day-of-week. Each returned string is a complete, human-readable reason a value is invalid.

/// Return every reason `expression` is an invalid `ScheduleExpression`, or an empty vector when it
/// is valid. More than one reason can apply at once (e.g. a zero value with a mismatched unit).
#[must_use]
pub fn schedule_expression_errors(expression: &str) -> Vec<String> {
    if let Some(inner) = wrapped_body(expression, "rate(") {
        check_rate(inner)
    } else if let Some(inner) = wrapped_body(expression, "cron(") {
        check_cron(inner)
    } else {
        vec![format!("'{expression}' has to be either 'cron()' or 'rate()'")]
    }
}

/// The text between the parentheses when `expression` is `prefix...)`, else `None`.
fn wrapped_body<'a>(expression: &'a str, prefix: &str) -> Option<&'a str> {
    expression.strip_prefix(prefix).and_then(|rest| rest.strip_suffix(')'))
}

fn check_rate(body: &str) -> Vec<String> {
    let mut errors = Vec::new();
    if body.is_empty() {
        errors.push("'' is not of type 'string'".to_string());
        return errors;
    }
    let items: Vec<&str> = body.split(' ').collect();
    if items.len() != 2 {
        errors.push(format!("'{body}' has to be of format rate(Value Unit)"));
        return errors;
    }
    let (value, unit) = (items[0], items[1]);
    if !is_ascii_digits(value) {
        errors.push(format!("'{value}' is not of type 'integer'"));
        return errors;
    }
    let amount: u64 = value.parse().unwrap_or(0);
    if amount == 0 {
        errors.push(format!("'{value}' is less than the minimum of 0"));
    }
    let valid_units: [&str; 3] = if amount <= 1 { ["minute", "hour", "day"] } else { ["minutes", "hours", "days"] };
    if !valid_units.contains(&unit) {
        errors.push(format!("'{unit}' is not one of {valid_units:?}"));
    }
    errors
}

fn check_cron(body: &str) -> Vec<String> {
    let mut errors = Vec::new();
    if body.is_empty() {
        errors.push("'' is not of type 'string'".to_string());
        return errors;
    }
    let fields: Vec<&str> = body.split(' ').collect();
    if fields.len() != 6 {
        errors.push(format!("'{}' is not of length 6. (Minutes Hours Day-of-month Month Day-of-week Year)", fields[0]));
        return errors;
    }
    let day_of_month = fields[2];
    let day_of_week = fields[4];
    if day_of_month != "?" && day_of_week != "?" {
        errors.push(format!(
            "'{}' specifies both Day-of-month and Day-of-week. (Minutes Hours Day-of-month Month Day-of-week Year)",
            body.chars().next().unwrap_or_default()
        ));
    }
    errors
}

/// A non-empty run of ASCII digits, matching Python's `str.isdigit` for the inputs that appear here
/// (it rejects signs, decimals and whitespace, so `1.5` and `-1` are not integers).
fn is_ascii_digits(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_rate_and_cron_have_no_errors() {
        assert!(schedule_expression_errors("rate(1 minute)").is_empty());
        assert!(schedule_expression_errors("rate(5 minutes)").is_empty());
        assert!(schedule_expression_errors("cron(0 12 * * ? *)").is_empty());
        assert!(schedule_expression_errors("cron(0 12 ? * MON *)").is_empty());
    }

    #[test]
    fn rate_unit_must_agree_in_number_with_value() {
        assert_eq!(
            schedule_expression_errors("rate(1 minutes)"),
            vec!["'minutes' is not one of [\"minute\", \"hour\", \"day\"]".to_string()]
        );
        assert_eq!(
            schedule_expression_errors("rate(5 minute)"),
            vec!["'minute' is not one of [\"minutes\", \"hours\", \"days\"]".to_string()]
        );
    }

    #[test]
    fn rate_value_must_be_positive_integer() {
        assert_eq!(schedule_expression_errors("rate(1.5 hours)"), vec!["'1.5' is not of type 'integer'".to_string()]);
        assert_eq!(
            schedule_expression_errors("rate(0 minutes)"),
            vec![
                "'0' is less than the minimum of 0".to_string(),
                "'minutes' is not one of [\"minute\", \"hour\", \"day\"]".to_string(),
            ]
        );
    }

    #[test]
    fn rate_must_have_two_space_separated_items() {
        assert_eq!(
            schedule_expression_errors("rate(10  minutes)"),
            vec!["'10  minutes' has to be of format rate(Value Unit)".to_string()]
        );
        assert_eq!(schedule_expression_errors("rate(5)"), vec!["'5' has to be of format rate(Value Unit)".to_string()]);
    }

    #[test]
    fn empty_rate_reports_missing_string() {
        assert_eq!(schedule_expression_errors("rate()"), vec!["'' is not of type 'string'".to_string()]);
    }

    #[test]
    fn cron_must_have_six_fields() {
        assert_eq!(
            schedule_expression_errors("cron(bad)"),
            vec!["'bad' is not of length 6. (Minutes Hours Day-of-month Month Day-of-week Year)".to_string()]
        );
    }

    #[test]
    fn cron_cannot_pin_both_day_of_month_and_day_of_week() {
        assert_eq!(
            schedule_expression_errors("cron(0 12 * * * *)"),
            vec![
                "'0' specifies both Day-of-month and Day-of-week. (Minutes Hours Day-of-month Month Day-of-week Year)"
                    .to_string()
            ]
        );
    }

    #[test]
    fn non_rate_non_cron_is_rejected() {
        assert_eq!(
            schedule_expression_errors("every minute"),
            vec!["'every minute' has to be either 'cron()' or 'rate()'".to_string()]
        );
    }
}
