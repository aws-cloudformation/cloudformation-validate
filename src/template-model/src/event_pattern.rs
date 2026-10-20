use std::collections::{BTreeSet, HashMap};
use std::net::Ipv6Addr;

use crate::SemanticModel;
use crate::resolver::ResolvedValue;

const EVENT_PATTERN_RESOURCE_TYPES: [&str; 2] = ["AWS::Events::Rule", "AWS::Events::Archive"];
const EVENT_PATTERN_PROPERTY_PATH: &str = "Properties.EventPattern";
const EVENT_PATTERN_ROOT_LABEL: &str = "EventPattern";
const OR_KEY: &str = "$or";

const EXACTLY_OPERATOR: &str = "exactly";
const PREFIX_OPERATOR: &str = "prefix";
const SUFFIX_OPERATOR: &str = "suffix";
const ANYTHING_BUT_OPERATOR: &str = "anything-but";
const NUMERIC_OPERATOR: &str = "numeric";
const EXISTS_OPERATOR: &str = "exists";
const CIDR_OPERATOR: &str = "cidr";
const WILDCARD_OPERATOR: &str = "wildcard";
const EQUALS_IGNORE_CASE_OPERATOR: &str = "equals-ignore-case";

const NUMERIC_COMPARISONS: [&str; 5] = ["<", "<=", "=", ">=", ">"];
const LOWER_BOUND_COMPARISONS: [&str; 2] = [">", ">="];
const UPPER_BOUND_COMPARISONS: [&str; 2] = ["<", "<="];
const ANYTHING_BUT_NESTED_OPERATORS: [&str; 4] =
    [PREFIX_OPERATOR, SUFFIX_OPERATOR, WILDCARD_OPERATOR, EQUALS_IGNORE_CASE_OPERATOR];
const MAX_EXACT_EVENTBRIDGE_INTEGER: u64 = 9_007_199_254_740_992;
const MIN_OR_BRANCHES: usize = 2;
const OR_BRANCH_RESERVED_FIELD_NAMES: &[&str] = &[
    EXACTLY_OPERATOR,
    EQUALS_IGNORE_CASE_OPERATOR,
    PREFIX_OPERATOR,
    SUFFIX_OPERATOR,
    ANYTHING_BUT_OPERATOR,
    EXISTS_OPERATOR,
    WILDCARD_OPERATOR,
    NUMERIC_OPERATOR,
    CIDR_OPERATOR,
    "=",
    "<",
    "<=",
    ">",
    ">=",
    "regex",
    "not-wildcard",
    "not-equals-ignore-case",
    "date-after",
    "date-on-or-after",
    "date-before",
    "date-on-or-before",
    "in-date-range",
    "ip-address-in-range",
    "ip-address-not-in-range",
];

const UNKNOWN_OPERATOR_FIX: &str =
    "Use one of exactly, prefix, suffix, anything-but, numeric, exists, cidr, wildcard or equals-ignore-case";
const INVALID_JSON_FIX: &str = "Provide a valid JSON object";
const OBJECT_PATTERN_FIX: &str = "Use a JSON object containing event fields";
const EMPTY_OBJECT_FIX: &str = "Add an event field, or remove the empty object";
const OR_BRANCHES_FIX: &str = "Give $or an array containing at least two objects";
const OR_RESERVED_FIELD_FIX: &str = "Rename the field so it is not reserved by $or matching";
const EMPTY_ARRAY_FIX: &str = "Give the key at least one value, or remove the key";
const SCALAR_VALUE_FIX: &str = "Wrap the value in an array";
const MATCH_VALUE_FIX: &str = "Use a scalar value or an object containing exactly one matcher operator";
const PREFIX_SUFFIX_FIX: &str = "Use a string or an object containing only equals-ignore-case with a string value";
const NUMERIC_FIX: &str = "Use [operator, number] or [>, number, <, number] with inclusive variants where allowed";
const ANYTHING_BUT_FIX: &str =
    "Give anything-but one string, one number, a homogeneous array, or one supported nested matcher";
const EXISTS_FIX: &str = "Set exists to an unquoted true or false";
const CIDR_FIX: &str = "Use a valid IPv4 or IPv6 CIDR string";
const WILDCARD_FIX: &str = "Use a string with non-consecutive wildcards and escape only * or \\";
const STRING_MATCHER_FIX: &str = "Give the matcher a string value";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EventPatternViolation {
    pub resource_id: String,
    pub property_path: String,
    pub message: String,
    pub suggested_fix: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PatternFinding {
    property_path: String,
    message: String,
    suggested_fix: String,
}

#[derive(Clone)]
struct PatternLocation {
    display_path: String,
    authored_path: Option<String>,
}

impl PatternLocation {
    fn authored_root() -> Self {
        Self {
            display_path: EVENT_PATTERN_ROOT_LABEL.to_string(),
            authored_path: Some(EVENT_PATTERN_PROPERTY_PATH.to_string()),
        }
    }

    fn parsed_string_root() -> Self {
        Self { display_path: EVENT_PATTERN_ROOT_LABEL.to_string(), authored_path: None }
    }

    fn field(&self, field_name: &str) -> Self {
        Self {
            display_path: format!("{}.{field_name}", self.display_path),
            authored_path: self.authored_path.as_ref().map(|path| format!("{path}.{field_name}")),
        }
    }

    fn item(&self, index: usize) -> Self {
        Self {
            display_path: format!("{}[{index}]", self.display_path),
            authored_path: self.authored_path.as_ref().map(|path| format!("{path}.{index}")),
        }
    }

    fn diagnostic_path(&self) -> String {
        self.authored_path.clone().unwrap_or_else(|| EVENT_PATTERN_PROPERTY_PATH.to_string())
    }
}

/// Event patterns that EventBridge rejects when the rule or archive is created.
///
/// Values controlled by an unresolved parameter or another deploy-time expression
/// are not judged. Concrete siblings remain subject to validation.
#[must_use]
pub fn event_pattern_violations(model: &SemanticModel) -> Vec<EventPatternViolation> {
    let mut violations = BTreeSet::new();
    let conditions = HashMap::new();
    for resource_type in EVENT_PATTERN_RESOURCE_TYPES {
        for resource_id in model.resources_of_type(resource_type) {
            let Some(pattern) = model.resolve(resource_id, EVENT_PATTERN_PROPERTY_PATH) else {
                continue;
            };
            let mut checker = EventPatternChecker::new(model, resource_id, &conditions);
            if checker.location_is_parameter_controlled(&PatternLocation::authored_root()) {
                continue;
            }
            match pattern {
                ResolvedValue::Concrete { value } => match &value.0 {
                    serde_json::Value::String(pattern_text) => match serde_json::from_str(pattern_text) {
                        Ok(parsed) => checker
                            .check_pattern_root(PatternValue::Json(&parsed), PatternLocation::parsed_string_root()),
                        Err(_) => checker.add_finding(
                            &PatternLocation::parsed_string_root(),
                            "EventPattern string is not valid JSON".to_string(),
                            INVALID_JSON_FIX,
                        ),
                    },
                    _ => checker.check_pattern_root(PatternValue::Resolved(pattern), PatternLocation::authored_root()),
                },
                _ => checker.check_pattern_root(PatternValue::Resolved(pattern), PatternLocation::authored_root()),
            }
            violations.extend(checker.findings.into_iter().map(|finding| EventPatternViolation {
                resource_id: resource_id.clone(),
                property_path: finding.property_path,
                message: finding.message,
                suggested_fix: finding.suggested_fix,
            }));
        }
    }
    violations.into_iter().collect()
}

#[derive(Clone, Copy)]
enum PatternValue<'a> {
    Json(&'a serde_json::Value),
    Resolved(&'a ResolvedValue),
}

enum PatternShape<'a> {
    Object(Vec<(&'a str, PatternValue<'a>)>),
    Array(Vec<PatternValue<'a>>),
    Scalar(&'a serde_json::Value),
    Unknown,
}

impl<'a> PatternValue<'a> {
    fn shape(self) -> PatternShape<'a> {
        match self {
            PatternValue::Json(serde_json::Value::Object(entries)) => PatternShape::Object(
                entries.iter().map(|(key, value)| (key.as_str(), PatternValue::Json(value))).collect(),
            ),
            PatternValue::Json(serde_json::Value::Array(items)) => {
                PatternShape::Array(items.iter().map(PatternValue::Json).collect())
            }
            PatternValue::Json(scalar) => PatternShape::Scalar(scalar),
            PatternValue::Resolved(ResolvedValue::Concrete { value }) => PatternValue::Json(&value.0).shape(),
            PatternValue::Resolved(ResolvedValue::Map { entries }) => PatternShape::Object(
                entries.iter().map(|entry| (entry.key.as_str(), PatternValue::Resolved(&entry.value))).collect(),
            ),
            PatternValue::Resolved(ResolvedValue::List { items }) => {
                PatternShape::Array(items.iter().map(PatternValue::Resolved).collect())
            }
            PatternValue::Resolved(
                ResolvedValue::Enum { .. }
                | ResolvedValue::Conditional { .. }
                | ResolvedValue::Reference { .. }
                | ResolvedValue::Dynamic { .. }
                | ResolvedValue::TypedDynamic { .. },
            ) => PatternShape::Unknown,
        }
    }
}

struct EventPatternChecker<'a> {
    model: &'a SemanticModel,
    resource_id: &'a str,
    conditions: &'a HashMap<String, bool>,
    findings: Vec<PatternFinding>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PatternObjectContext {
    Ordinary,
    OrBranch,
}

impl<'a> EventPatternChecker<'a> {
    fn new(model: &'a SemanticModel, resource_id: &'a str, conditions: &'a HashMap<String, bool>) -> Self {
        Self { model, resource_id, conditions, findings: Vec::new() }
    }

    fn check_pattern_root(&mut self, pattern: PatternValue<'_>, location: PatternLocation) {
        match self.shape_at(pattern, &location) {
            PatternShape::Object(entries) => {
                self.check_pattern_object(&location, &entries, PatternObjectContext::Ordinary)
            }
            PatternShape::Unknown => {}
            PatternShape::Array(_) | PatternShape::Scalar(_) => {
                self.add_finding(&location, "EventPattern must be a JSON object".to_string(), OBJECT_PATTERN_FIX)
            }
        }
    }

    fn check_pattern_object(
        &mut self,
        location: &PatternLocation,
        entries: &[(&str, PatternValue<'_>)],
        context: PatternObjectContext,
    ) {
        if entries.is_empty() {
            self.add_finding(
                location,
                format!("'{}' must not be an empty object", location.display_path),
                EMPTY_OBJECT_FIX,
            );
            return;
        }
        for (key, value) in entries {
            let field_location = location.field(key);
            if context == PatternObjectContext::OrBranch && OR_BRANCH_RESERVED_FIELD_NAMES.contains(key) {
                self.add_finding(
                    &field_location,
                    format!("'{}' is reserved and cannot be a field name inside $or", field_location.display_path),
                    OR_RESERVED_FIELD_FIX,
                );
                continue;
            }
            if *key == OR_KEY {
                self.check_or_branches(*value, &field_location);
                continue;
            }
            match self.shape_at(*value, &field_location) {
                PatternShape::Object(nested) => self.check_pattern_object(&field_location, &nested, context),
                PatternShape::Array(items) => self.check_match_values(&field_location, &items),
                PatternShape::Scalar(_) => self.add_finding(
                    &field_location,
                    format!("'{}' must be an array or an object", field_location.display_path),
                    SCALAR_VALUE_FIX,
                ),
                PatternShape::Unknown => {}
            }
        }
    }

    fn check_or_branches(&mut self, branches: PatternValue<'_>, location: &PatternLocation) {
        match self.shape_at(branches, location) {
            PatternShape::Array(branches) => {
                if branches.len() < MIN_OR_BRANCHES {
                    self.add_finding(
                        location,
                        format!("'{}' must contain at least {MIN_OR_BRANCHES} branch objects", location.display_path),
                        OR_BRANCHES_FIX,
                    );
                }
                for (index, branch) in branches.iter().enumerate() {
                    let branch_location = location.item(index);
                    match self.shape_at(*branch, &branch_location) {
                        PatternShape::Object(entries) => {
                            self.check_pattern_object(&branch_location, &entries, PatternObjectContext::OrBranch)
                        }
                        PatternShape::Unknown => {}
                        PatternShape::Array(_) | PatternShape::Scalar(_) => self.add_finding(
                            &branch_location,
                            format!("'{}' must be an object", branch_location.display_path),
                            OR_BRANCHES_FIX,
                        ),
                    }
                }
            }
            PatternShape::Unknown => {}
            PatternShape::Object(_) | PatternShape::Scalar(_) => self.add_finding(
                location,
                format!("'{}' must be an array of branch objects", location.display_path),
                OR_BRANCHES_FIX,
            ),
        }
    }

    fn check_match_values(&mut self, location: &PatternLocation, match_values: &[PatternValue<'_>]) {
        if match_values.is_empty() {
            self.add_finding(location, format!("'{}' is an empty array", location.display_path), EMPTY_ARRAY_FIX);
            return;
        }
        for (index, match_value) in match_values.iter().enumerate() {
            let match_location = location.item(index);
            match self.shape_at(*match_value, &match_location) {
                PatternShape::Object(operators) => self.check_match_expression(&match_location, &operators),
                PatternShape::Scalar(_) | PatternShape::Unknown => {}
                PatternShape::Array(_) => self.add_finding(
                    &match_location,
                    format!("'{}' must be a scalar value or a matcher object", match_location.display_path),
                    MATCH_VALUE_FIX,
                ),
            }
        }
    }

    fn check_match_expression(&mut self, location: &PatternLocation, operators: &[(&str, PatternValue<'_>)]) {
        if operators.len() != 1 {
            self.add_finding(
                location,
                format!("matcher in '{}' must contain exactly one operator", location.display_path),
                MATCH_VALUE_FIX,
            );
            return;
        }
        let (operator, operand) = operators[0];
        let operand_location = location.field(operator);
        match operator {
            PREFIX_OPERATOR | SUFFIX_OPERATOR => {
                self.check_prefix_or_suffix(operator, operand, location, &operand_location)
            }
            EXISTS_OPERATOR => self.check_exists(operand, location, &operand_location),
            NUMERIC_OPERATOR => self.check_numeric(operand, location, &operand_location),
            ANYTHING_BUT_OPERATOR => self.check_anything_but(operand, location, &operand_location),
            WILDCARD_OPERATOR => self.check_wildcard(operand, location, &operand_location),
            CIDR_OPERATOR => self.check_cidr(operand, location, &operand_location),
            EXACTLY_OPERATOR | EQUALS_IGNORE_CASE_OPERATOR => {
                self.check_string_matcher(operator, operand, location, &operand_location)
            }
            unknown_operator => self.add_finding(
                &operand_location,
                format!("'{unknown_operator}' in '{}' is not an event pattern operator", location.display_path),
                UNKNOWN_OPERATOR_FIX,
            ),
        }
    }

    fn check_prefix_or_suffix(
        &mut self,
        operator: &str,
        operand: PatternValue<'_>,
        match_location: &PatternLocation,
        operand_location: &PatternLocation,
    ) {
        let is_valid = match self.shape_at(operand, operand_location) {
            PatternShape::Scalar(serde_json::Value::String(_)) | PatternShape::Unknown => true,
            PatternShape::Object(entries) if entries.len() == 1 && entries[0].0 == EQUALS_IGNORE_CASE_OPERATOR => {
                let case_insensitive_location = operand_location.field(EQUALS_IGNORE_CASE_OPERATOR);
                matches!(
                    self.shape_at(entries[0].1, &case_insensitive_location),
                    PatternShape::Scalar(serde_json::Value::String(_)) | PatternShape::Unknown
                )
            }
            PatternShape::Object(_) | PatternShape::Array(_) | PatternShape::Scalar(_) => false,
        };
        if !is_valid {
            self.add_finding(
                operand_location,
                format!(
                    "{operator} in '{}' must be a string or an equals-ignore-case object containing one string",
                    match_location.display_path
                ),
                PREFIX_SUFFIX_FIX,
            );
        }
    }

    fn check_exists(
        &mut self,
        operand: PatternValue<'_>,
        match_location: &PatternLocation,
        operand_location: &PatternLocation,
    ) {
        if !matches!(
            self.shape_at(operand, operand_location),
            PatternShape::Scalar(serde_json::Value::Bool(_)) | PatternShape::Unknown
        ) {
            self.add_finding(
                operand_location,
                format!("exists in '{}' must be true or false", match_location.display_path),
                EXISTS_FIX,
            );
        }
    }

    fn check_numeric(
        &mut self,
        operand: PatternValue<'_>,
        match_location: &PatternLocation,
        operand_location: &PatternLocation,
    ) {
        match self.shape_at(operand, operand_location) {
            PatternShape::Array(bounds) => self.check_numeric_bounds(&bounds, match_location, operand_location),
            PatternShape::Unknown => {}
            PatternShape::Object(_) | PatternShape::Scalar(_) => self.add_finding(
                operand_location,
                format!("numeric in '{}' must be an array", match_location.display_path),
                NUMERIC_FIX,
            ),
        }
    }

    fn check_numeric_bounds(
        &mut self,
        bounds: &[PatternValue<'_>],
        match_location: &PatternLocation,
        operand_location: &PatternLocation,
    ) {
        if bounds.len() != 2 && bounds.len() != 4 {
            self.add_finding(
                operand_location,
                format!("numeric in '{}' must contain two or four elements", match_location.display_path),
                NUMERIC_FIX,
            );
            return;
        }
        let first_operator_location = operand_location.item(0);
        let Some(first_operator) = self.known_string(bounds[0], &first_operator_location) else {
            if !matches!(self.shape_at(bounds[0], &first_operator_location), PatternShape::Unknown) {
                self.add_finding(
                    &first_operator_location,
                    format!("numeric in '{}' must start with a comparison operator", match_location.display_path),
                    NUMERIC_FIX,
                );
            }
            return;
        };
        if !NUMERIC_COMPARISONS.contains(&first_operator) {
            self.add_finding(
                &first_operator_location,
                format!("'{first_operator}' in '{}' is not a numeric comparison operator", match_location.display_path),
                NUMERIC_FIX,
            );
            return;
        }
        let first_number_location = operand_location.item(1);
        let first_number = self.numeric_operand(bounds[1], &first_number_location);
        if first_number == NumericOperand::Invalid {
            self.add_finding(
                &first_number_location,
                format!("numeric comparison value in '{}' must be a representable number", match_location.display_path),
                NUMERIC_FIX,
            );
            return;
        }
        if bounds.len() == 2 {
            return;
        }
        if !LOWER_BOUND_COMPARISONS.contains(&first_operator) {
            self.add_finding(
                &first_operator_location,
                format!("four-part numeric range in '{}' must start with > or >=", match_location.display_path),
                NUMERIC_FIX,
            );
            return;
        }
        let second_operator_location = operand_location.item(2);
        let Some(second_operator) = self.known_string(bounds[2], &second_operator_location) else {
            if !matches!(self.shape_at(bounds[2], &second_operator_location), PatternShape::Unknown) {
                self.add_finding(
                    &second_operator_location,
                    format!("numeric range in '{}' must contain an upper-bound operator", match_location.display_path),
                    NUMERIC_FIX,
                );
            }
            return;
        };
        if !UPPER_BOUND_COMPARISONS.contains(&second_operator) {
            self.add_finding(
                &second_operator_location,
                format!("'{second_operator}' in '{}' is not a valid upper-bound operator", match_location.display_path),
                NUMERIC_FIX,
            );
            return;
        }
        let second_number_location = operand_location.item(3);
        let second_number = self.numeric_operand(bounds[3], &second_number_location);
        if second_number == NumericOperand::Invalid {
            self.add_finding(
                &second_number_location,
                format!("numeric comparison value in '{}' must be a representable number", match_location.display_path),
                NUMERIC_FIX,
            );
            return;
        }
        if let (NumericOperand::Known(lower), NumericOperand::Known(upper)) = (first_number, second_number) {
            let range_is_empty = lower >= upper;
            if range_is_empty {
                self.add_finding(
                    operand_location,
                    format!("numeric range in '{}' cannot match any value", match_location.display_path),
                    NUMERIC_FIX,
                );
            }
        }
    }

    fn check_anything_but(
        &mut self,
        operand: PatternValue<'_>,
        match_location: &PatternLocation,
        operand_location: &PatternLocation,
    ) {
        match self.shape_at(operand, operand_location) {
            PatternShape::Unknown | PatternShape::Scalar(serde_json::Value::String(_)) => {}
            PatternShape::Scalar(serde_json::Value::Number(number)) if comparable_number(number).is_some() => {}
            PatternShape::Array(values) => self.check_anything_but_values(&values, match_location, operand_location),
            PatternShape::Object(entries) => self.check_nested_anything_but(&entries, match_location, operand_location),
            PatternShape::Scalar(_) => self.add_finding(
                operand_location,
                format!("anything-but in '{}' has an unsupported value", match_location.display_path),
                ANYTHING_BUT_FIX,
            ),
        }
    }

    fn check_anything_but_values(
        &mut self,
        values: &[PatternValue<'_>],
        match_location: &PatternLocation,
        operand_location: &PatternLocation,
    ) {
        if values.is_empty() {
            self.add_finding(
                operand_location,
                format!("anything-but in '{}' must not use an empty array", match_location.display_path),
                ANYTHING_BUT_FIX,
            );
            return;
        }
        let mut value_kind = None;
        for (index, value) in values.iter().enumerate() {
            let value_location = operand_location.item(index);
            let current_kind = match self.shape_at(*value, &value_location) {
                PatternShape::Unknown => continue,
                PatternShape::Scalar(serde_json::Value::String(_)) => AnythingButValueKind::String,
                PatternShape::Scalar(serde_json::Value::Number(number)) if comparable_number(number).is_some() => {
                    AnythingButValueKind::Number
                }
                PatternShape::Object(_) | PatternShape::Array(_) | PatternShape::Scalar(_) => {
                    self.add_finding(
                        &value_location,
                        format!("anything-but in '{}' accepts only strings or numbers", match_location.display_path),
                        ANYTHING_BUT_FIX,
                    );
                    return;
                }
            };
            if value_kind.is_some_and(|existing| existing != current_kind) {
                self.add_finding(
                    operand_location,
                    format!("anything-but in '{}' cannot mix strings and numbers", match_location.display_path),
                    ANYTHING_BUT_FIX,
                );
                return;
            }
            value_kind = Some(current_kind);
        }
    }

    fn check_nested_anything_but(
        &mut self,
        entries: &[(&str, PatternValue<'_>)],
        match_location: &PatternLocation,
        operand_location: &PatternLocation,
    ) {
        if entries.len() != 1 {
            self.add_finding(
                operand_location,
                format!("anything-but in '{}' must contain exactly one nested operator", match_location.display_path),
                ANYTHING_BUT_FIX,
            );
            return;
        }
        let (nested_operator, nested_operand) = entries[0];
        let nested_location = operand_location.field(nested_operator);
        if !ANYTHING_BUT_NESTED_OPERATORS.contains(&nested_operator) {
            self.add_finding(
                &nested_location,
                format!("anything-but in '{}' cannot use '{nested_operator}'", match_location.display_path),
                ANYTHING_BUT_FIX,
            );
            return;
        }
        self.check_nested_string_values(nested_operator, nested_operand, match_location, &nested_location);
    }

    fn check_nested_string_values(
        &mut self,
        nested_operator: &str,
        operand: PatternValue<'_>,
        match_location: &PatternLocation,
        operand_location: &PatternLocation,
    ) {
        match self.shape_at(operand, operand_location) {
            PatternShape::Unknown => {}
            PatternShape::Scalar(serde_json::Value::String(value)) => {
                if matches!(nested_operator, PREFIX_OPERATOR | SUFFIX_OPERATOR) && value.is_empty() {
                    self.add_finding(
                        operand_location,
                        format!(
                            "anything-but {nested_operator} in '{}' must not be empty",
                            match_location.display_path
                        ),
                        ANYTHING_BUT_FIX,
                    );
                } else if nested_operator == WILDCARD_OPERATOR {
                    self.check_wildcard_text(value, match_location, operand_location);
                }
            }
            PatternShape::Array(values) => {
                for (index, value) in values.iter().enumerate() {
                    let value_location = operand_location.item(index);
                    match self.shape_at(*value, &value_location) {
                        PatternShape::Unknown => {}
                        PatternShape::Scalar(serde_json::Value::String(text)) => {
                            if matches!(nested_operator, PREFIX_OPERATOR | SUFFIX_OPERATOR) && text.is_empty() {
                                self.add_finding(
                                    &value_location,
                                    format!(
                                        "anything-but {nested_operator} in '{}' must not contain an empty string",
                                        match_location.display_path
                                    ),
                                    ANYTHING_BUT_FIX,
                                );
                                return;
                            }
                            if nested_operator == WILDCARD_OPERATOR
                                && self.check_wildcard_text(text, match_location, &value_location)
                            {
                                return;
                            }
                        }
                        PatternShape::Object(_) | PatternShape::Array(_) | PatternShape::Scalar(_) => {
                            self.add_finding(
                                &value_location,
                                format!(
                                    "anything-but {nested_operator} in '{}' accepts only strings",
                                    match_location.display_path
                                ),
                                ANYTHING_BUT_FIX,
                            );
                            return;
                        }
                    }
                }
            }
            PatternShape::Object(_) | PatternShape::Scalar(_) => self.add_finding(
                operand_location,
                format!("anything-but {nested_operator} in '{}' accepts only strings", match_location.display_path),
                ANYTHING_BUT_FIX,
            ),
        }
    }

    fn check_wildcard(
        &mut self,
        operand: PatternValue<'_>,
        match_location: &PatternLocation,
        operand_location: &PatternLocation,
    ) {
        match self.shape_at(operand, operand_location) {
            PatternShape::Unknown => {}
            PatternShape::Scalar(serde_json::Value::String(wildcard)) => {
                self.check_wildcard_text(wildcard, match_location, operand_location);
            }
            PatternShape::Object(_) | PatternShape::Array(_) | PatternShape::Scalar(_) => self.add_finding(
                operand_location,
                format!("wildcard in '{}' must be a string", match_location.display_path),
                WILDCARD_FIX,
            ),
        }
    }

    fn check_wildcard_text(
        &mut self,
        wildcard: &str,
        match_location: &PatternLocation,
        operand_location: &PatternLocation,
    ) -> bool {
        if let Some(problem) = wildcard_problem(wildcard) {
            self.add_finding(
                operand_location,
                format!("wildcard in '{}' {problem}", match_location.display_path),
                WILDCARD_FIX,
            );
            return true;
        }
        false
    }

    fn check_cidr(
        &mut self,
        operand: PatternValue<'_>,
        match_location: &PatternLocation,
        operand_location: &PatternLocation,
    ) {
        let is_valid = match self.shape_at(operand, operand_location) {
            PatternShape::Unknown => true,
            PatternShape::Scalar(serde_json::Value::String(cidr)) => is_valid_eventbridge_cidr(cidr),
            PatternShape::Object(_) | PatternShape::Array(_) | PatternShape::Scalar(_) => false,
        };
        if !is_valid {
            self.add_finding(
                operand_location,
                format!("cidr in '{}' must be a valid IPv4 or IPv6 network", match_location.display_path),
                CIDR_FIX,
            );
        }
    }

    fn check_string_matcher(
        &mut self,
        operator: &str,
        operand: PatternValue<'_>,
        match_location: &PatternLocation,
        operand_location: &PatternLocation,
    ) {
        if !matches!(
            self.shape_at(operand, operand_location),
            PatternShape::Unknown | PatternShape::Scalar(serde_json::Value::String(_))
        ) {
            self.add_finding(
                operand_location,
                format!("{operator} in '{}' must be a string", match_location.display_path),
                STRING_MATCHER_FIX,
            );
        }
    }

    fn shape_at<'value>(&self, value: PatternValue<'value>, location: &PatternLocation) -> PatternShape<'value> {
        if self.location_is_parameter_controlled(location) { PatternShape::Unknown } else { value.shape() }
    }

    fn location_is_parameter_controlled(&self, location: &PatternLocation) -> bool {
        location.authored_path.as_deref().is_some_and(|property_path| {
            self.model.scenario_value_uses_unresolved_parameter(self.resource_id, property_path, self.conditions)
        })
    }

    fn known_string<'value>(&self, value: PatternValue<'value>, location: &PatternLocation) -> Option<&'value str> {
        match self.shape_at(value, location) {
            PatternShape::Scalar(serde_json::Value::String(text)) => Some(text),
            PatternShape::Object(_) | PatternShape::Array(_) | PatternShape::Scalar(_) | PatternShape::Unknown => None,
        }
    }

    fn numeric_operand(&self, value: PatternValue<'_>, location: &PatternLocation) -> NumericOperand {
        match self.shape_at(value, location) {
            PatternShape::Unknown => NumericOperand::Unknown,
            PatternShape::Scalar(serde_json::Value::Number(number)) => {
                numeric_comparison_number(number).map_or(NumericOperand::Invalid, NumericOperand::Known)
            }
            PatternShape::Object(_) | PatternShape::Array(_) | PatternShape::Scalar(_) => NumericOperand::Invalid,
        }
    }

    fn add_finding(&mut self, location: &PatternLocation, message: String, suggested_fix: &str) {
        self.findings.push(PatternFinding {
            property_path: location.diagnostic_path(),
            message,
            suggested_fix: suggested_fix.to_string(),
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnythingButValueKind {
    String,
    Number,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum NumericOperand {
    Known(f64),
    Unknown,
    Invalid,
}

fn is_valid_eventbridge_cidr(cidr: &str) -> bool {
    let mut components = cidr.trim_end_matches('/').split('/');
    let (Some(address), Some(mask), None) = (components.next(), components.next(), components.next()) else {
        return false;
    };
    let Ok(mask_bits) = mask.parse::<i16>() else {
        return false;
    };
    if address.contains(':') {
        if address.contains('.') {
            return false;
        }
        let Ok(ipv6) = address.parse::<Ipv6Addr>() else {
            return false;
        };
        if ipv6.to_ipv4_mapped().is_some() { (0..32).contains(&mask_bits) } else { (0..128).contains(&mask_bits) }
    } else {
        is_valid_ipv4_literal(address) && (0..32).contains(&mask_bits)
    }
}

fn is_valid_ipv4_literal(address: &str) -> bool {
    let octets: Vec<&str> = address.split('.').collect();
    octets.len() == 4
        && octets.iter().all(|octet| {
            !octet.is_empty() && octet.bytes().all(|byte| byte.is_ascii_digit()) && octet.parse::<u8>().is_ok()
        })
}

#[derive(Debug, PartialEq, Eq)]
struct NormalizedDecimal {
    is_negative: bool,
    digits: String,
    exponent: i64,
}

fn comparable_number(number: &serde_json::Number) -> Option<f64> {
    let value = number.as_f64().filter(|value| value.is_finite())?;
    let authored = normalize_decimal(&number.to_string())?;
    let represented = normalize_decimal(&value.to_string())?;
    (authored == represented).then_some(value)
}

fn numeric_comparison_number(number: &serde_json::Number) -> Option<f64> {
    comparable_number(number)
        .filter(|value| value.fract() != 0.0 || value.abs() <= MAX_EXACT_EVENTBRIDGE_INTEGER as f64)
}

fn normalize_decimal(text: &str) -> Option<NormalizedDecimal> {
    let (is_negative, unsigned) = text.strip_prefix('-').map_or((false, text), |value| (true, value));
    let (mantissa, explicit_exponent) = match unsigned.find(['e', 'E']) {
        Some(index) => {
            let exponent_text = unsigned.get(index + 1..)?;
            if exponent_text.contains(['e', 'E']) {
                return None;
            }
            (unsigned.get(..index)?, exponent_text.parse::<i64>().ok()?)
        }
        None => (unsigned, 0),
    };
    let mut components = mantissa.split('.');
    let whole = components.next()?;
    let fraction = components.next().unwrap_or_default();
    if components.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let mut digits = format!("{whole}{fraction}").trim_start_matches('0').to_string();
    if digits.is_empty() {
        return Some(NormalizedDecimal { is_negative: false, digits: "0".to_string(), exponent: 0 });
    }
    let mut exponent = explicit_exponent.checked_sub(i64::try_from(fraction.len()).ok()?)?;
    while digits.ends_with('0') {
        digits.pop();
        exponent = exponent.checked_add(1)?;
    }
    Some(NormalizedDecimal { is_negative, digits, exponent })
}

fn wildcard_problem(wildcard: &str) -> Option<&'static str> {
    let mut characters = wildcard.chars();
    let mut previous_was_wildcard = false;
    while let Some(character) = characters.next() {
        match character {
            '\\' => match characters.next() {
                Some('*' | '\\') => previous_was_wildcard = false,
                Some(_) => return Some("uses an unsupported escape sequence"),
                None => return Some("ends with an incomplete escape sequence"),
            },
            '*' if previous_was_wildcard => return Some("has consecutive wildcard characters"),
            '*' => previous_was_wildcard = true,
            _ => previous_was_wildcard = false,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn violations(event_pattern_yaml: &str) -> Vec<EventPatternViolation> {
        let template = format!(
            "Resources:\n  Rule:\n    Type: AWS::Events::Rule\n    Properties:\n      EventPattern: {event_pattern_yaml}\n"
        );
        let model = SemanticModel::from_bytes(template.as_bytes()).expect("template parses");
        event_pattern_violations(&model)
    }

    fn messages(event_pattern_yaml: &str) -> Vec<String> {
        violations(event_pattern_yaml).into_iter().map(|violation| violation.message).collect()
    }

    #[test]
    fn matcher_objects_are_not_read_as_field_selectors() {
        assert!(messages(r#"{"detail": {"x": [{"prefix": "a"}, {"anything-but": {"prefix": "b"}}]}}"#).is_empty());
    }

    #[test]
    fn nested_field_selectors_are_checked_at_any_depth_with_precise_paths() {
        let findings = violations(r#"{"detail": {"a": {"b": {"c": {"d": "plain"}}}}}"#);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].property_path, "Properties.EventPattern.detail.a.b.c.d");
        assert_eq!(findings[0].message, "'EventPattern.detail.a.b.c.d' must be an array or an object");
    }

    #[test]
    fn or_accepts_siblings_and_checks_every_branch() {
        assert!(
            messages(r#"{"source": ["a"], "$or": [{"detail-type": ["one"]}, {"detail-type": ["two"]}]}"#).is_empty()
        );
        assert_eq!(
            messages(r#"{"$or": [{"source": ["a"]}, {"detail-type": []}]}"#),
            vec!["'EventPattern.$or[1].detail-type' is an empty array"]
        );
    }

    #[test]
    fn or_requires_an_array_with_at_least_two_object_branches() {
        for pattern in [
            r#"{"$or": {"source": ["a"]}}"#,
            r#"{"$or": [{"source": ["a"]}]}"#,
            r#"{"$or": ["not-an-object", {"source": ["a"]}]}"#,
        ] {
            assert_eq!(messages(pattern).len(), 1, "{pattern}");
        }
    }

    #[test]
    fn or_branches_reject_reserved_field_names_at_any_depth() {
        for pattern in [
            r#"{"$or": [{"prefix": ["a"]}, {"source": ["b"]}]}"#,
            r#"{"$or": [{"detail": {"numeric": ["1"]}}, {"source": ["b"]}]}"#,
        ] {
            assert_eq!(messages(pattern).len(), 1, "{pattern}");
        }
        assert!(messages(r#"{"prefix": ["a"], "source": ["b"]}"#).is_empty());
    }

    #[test]
    fn json_string_pattern_is_parsed_before_checking() {
        let findings = violations(r#"'{"source": [{"startsWith": "aws."}]}'"#);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].property_path, EVENT_PATTERN_PROPERTY_PATH);
        assert_eq!(findings[0].message, "'startsWith' in 'EventPattern.source[0]' is not an event pattern operator");
    }

    #[test]
    fn malformed_json_and_non_object_roots_are_reported() {
        assert_eq!(messages("'not json'"), vec!["EventPattern string is not valid JSON"]);
        assert_eq!(messages("'[]'"), vec!["EventPattern must be a JSON object"]);
        assert_eq!(messages("'null'"), vec!["EventPattern must be a JSON object"]);
    }

    #[test]
    fn pattern_from_overridable_parameter_is_not_judged() {
        let template = r#"
Parameters:
  Pattern:
    Type: String
    Default: '{"source": "aws.ec2"}'
Resources:
  Rule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern: !Ref Pattern
"#;
        let model = SemanticModel::from_bytes(template.as_bytes()).expect("template parses");
        let findings = event_pattern_violations(&model);
        assert!(findings.is_empty(), "a caller can override the parameter before deployment: {findings:?}");
    }

    #[test]
    fn parameter_controlled_value_does_not_hide_invalid_concrete_sibling() {
        let template = r#"
Parameters:
  Sources:
    Type: CommaDelimitedList
    Default: example.app
Resources:
  Rule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: !Ref Sources
        detail:
          state: []
"#;
        let model = SemanticModel::from_bytes(template.as_bytes()).expect("template parses");
        let findings = event_pattern_violations(&model);
        assert_eq!(findings.len(), 1, "the concrete sibling remains invalid: {findings:?}");
        assert_eq!(findings[0].property_path, "Properties.EventPattern.detail.state");
    }

    #[test]
    fn prefix_and_suffix_case_insensitive_forms_require_one_string() {
        assert!(messages(r#"{"x": [{"prefix": {"equals-ignore-case": "abc"}}, {"suffix": "xyz"}]}"#).is_empty());
        for pattern in [
            r#"{"x": [{"prefix": {"bogus": "abc"}}]}"#,
            r#"{"x": [{"prefix": {"equals-ignore-case": 5}}]}"#,
            r#"{"x": [{"suffix": {"equals-ignore-case": "abc", "extra": "x"}}]}"#,
        ] {
            assert_eq!(messages(pattern).len(), 1, "{pattern}");
        }
    }

    #[test]
    fn numeric_matchers_require_valid_comparison_structure() {
        for pattern in [
            r#"{"x": [{"numeric": ">"}]}"#,
            r#"{"x": [{"numeric": [">"]}]}"#,
            r#"{"x": [{"numeric": [">", true]}]}"#,
            r#"{"x": [{"numeric": ["<", 1, "<", 2]}]}"#,
            r#"{"x": [{"numeric": [">", 1, ">=", 2]}]}"#,
            r#"{"x": [{"numeric": [">", 2, "<", 1]}]}"#,
            r#"{"x": [{"numeric": [">=", 1, "<=", 1]}]}"#,
            r#"{"x": [{"numeric": [">=", -0.0, "<=", 0]}]}"#,
            r#"{"x": [{"numeric": ["=", 9007199254740993]}]}"#,
            r#"'{"x": [{"numeric": ["=", 9007199254740993.0]}]}'"#,
            r#"'{"x": [{"numeric": ["=", 0.30000000000000001]}]}'"#,
            r#"{"x": [{"numeric": ["=", 1e16]}]}"#,
        ] {
            assert_eq!(messages(pattern).len(), 1, "{pattern}");
        }
        for pattern in [
            r#"{"x": [{"numeric": ["=", 3.8]}]}"#,
            r#"'{"x": [{"numeric": ["=", 1E-320]}]}'"#,
            r#"{"x": [{"numeric": [">=", 0, "<=", 1]}]}"#,
            r#"{"x": [{"numeric": ["=", 9007199254740992.0]}]}"#,
        ] {
            assert!(messages(pattern).is_empty(), "{pattern}");
        }
    }

    #[test]
    fn anything_but_requires_supported_homogeneous_values() {
        for pattern in [
            r#"{"x": [{"anything-but": true}]}"#,
            r#"{"x": [{"anything-but": []}]}"#,
            r#"{"x": [{"anything-but": ["a", 1]}]}"#,
            r#"{"x": [{"anything-but": {"prefix": ""}}]}"#,
            r#"{"x": [{"anything-but": {"wildcard": 5}}]}"#,
            r#"{"x": [{"anything-but": {"prefix": "a", "suffix": "b"}}]}"#,
        ] {
            assert_eq!(messages(pattern).len(), 1, "{pattern}");
        }
        for pattern in [
            r#"{"x": [{"anything-but": ["a", "b"]}]}"#,
            r#"{"x": [{"anything-but": [1, 2]}]}"#,
            r#"{"x": [{"anything-but": 9007199254740994}]}"#,
            r#"{"x": [{"anything-but": 1e16}]}"#,
            r#"{"x": [{"anything-but": {"prefix": ["a", "b"]}}]}"#,
            r#"{"x": [{"anything-but": {"equals-ignore-case": ["a", ""]}}]}"#,
            r#"{"x": [{"anything-but": {"prefix": []}}]}"#,
            r#"{"x": [{"anything-but": {"wildcard": []}}]}"#,
        ] {
            assert!(messages(pattern).is_empty(), "{pattern}");
        }
    }

    #[test]
    fn wildcard_validation_distinguishes_escaped_literals_from_wildcards() {
        for pattern in [
            r#"{"x": [{"wildcard": "a*b"}]}"#,
            r#"{"x": [{"wildcard": "a\\**b"}]}"#,
            r#"{"x": [{"wildcard": "a\\\\*b"}]}"#,
        ] {
            assert!(messages(pattern).is_empty(), "{pattern}");
        }
        for pattern in [
            r#"{"x": [{"wildcard": "a**b"}]}"#,
            r#"{"x": [{"wildcard": "a\\qb"}]}"#,
            r#"{"x": [{"wildcard": "a\\"}]}"#,
            r#"{"x": [{"wildcard": 5}]}"#,
        ] {
            assert_eq!(messages(pattern).len(), 1, "{pattern}");
        }
    }

    #[test]
    fn nested_wildcard_list_reports_once_per_matcher() {
        for pattern in [
            r#"{"x": [{"anything-but": {"wildcard": ["a**", "b**"]}}]}"#,
            r#"'{"x": [{"anything-but": {"wildcard": ["a**", "b**"]}}]}'"#,
        ] {
            assert_eq!(messages(pattern).len(), 1, "{pattern}");
        }
    }

    #[test]
    fn cidr_and_string_matchers_follow_event_pattern_grammar() {
        for pattern in [
            r#"{"ip": [{"cidr": "10.0.0.0/24"}]}"#,
            r#"{"ip": [{"cidr": "10.0.0.0/24//"}]}"#,
            r#"{"ip": [{"cidr": "10.0.0.0/-0"}]}"#,
            r#"{"ip": [{"cidr": "10.0.0.0/31"}]}"#,
            r#"{"ip": [{"cidr": "2001:db8::/127"}]}"#,
            r#"{"ip": [{"cidr": "::ffff:a00:0/24"}]}"#,
            r#"{"name": [{"equals-ignore-case": "ABC"}, {"exactly": "abc"}]}"#,
        ] {
            assert!(messages(pattern).is_empty(), "{pattern}");
        }
        for pattern in [
            r#"{"x": [{"cidr": "not-a-network"}]}"#,
            r#"{"x": [{"cidr": "10.0.0.1"}]}"#,
            r#"{"x": [{"cidr": "10.0.0.0/32"}]}"#,
            r#"{"x": [{"cidr": "2001:db8::/128"}]}"#,
            r#"{"x": [{"cidr": "10.0.0.0/255.255.255.0"}]}"#,
            r#"{"x": [{"cidr": "::ffff:10.0.0.0/104"}]}"#,
            r#"{"x": [{"cidr": "::ffff:a00:0/104"}]}"#,
            r#"{"x": [{"cidr": 5}]}"#,
            r#"{"x": [{"equals-ignore-case": ["abc"]}]}"#,
            r#"{"x": [{"exactly": 5}]}"#,
        ] {
            assert_eq!(messages(pattern).len(), 1, "{pattern}");
        }
    }

    #[test]
    fn matcher_objects_require_exactly_one_operator() {
        for pattern in [r#"{"x": [{}]}"#, r#"{"x": [{"prefix": "a", "suffix": "b"}]}"#] {
            assert_eq!(messages(pattern).len(), 1, "{pattern}");
        }
    }

    #[test]
    fn field_selectors_reject_empty_objects_nested_arrays_and_bare_null() {
        for pattern in [r#"{}"#, r#"{"detail": {}}"#, r#"{"x": [["a"]]}"#, r#"{"x": null}"#] {
            assert_eq!(messages(pattern).len(), 1, "{pattern}");
        }
        assert!(messages(r#"{"x": [null, true, false, 1, 1e400, "a"]}"#).is_empty());
    }

    #[test]
    fn identical_invalid_matchers_keep_distinct_paths() {
        let findings = violations(r#"{"x": [{"startsWith": "a"}, {"startsWith": "b"}]}"#);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].property_path, "Properties.EventPattern.x.0.startsWith");
        assert_eq!(findings[1].property_path, "Properties.EventPattern.x.1.startsWith");
    }
}
