//! Regexes shared by more than one rule category. Category-local patterns stay
//! in their own module; only patterns validated identically by rules in
//! different modules live here so the pattern has a single definition.

use rules::AMI_ID_PATTERN;
use std::sync::LazyLock;

/// EC2 AMI identifier: `ami-` followed by an 8- or 17-character hex id. Shared
/// by the hardcoded-AMI best-practice check and the resolved-parameter AMI-type
/// check.
pub(super) static AMI_ID_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(AMI_ID_PATTERN).expect("Invalid AMI_ID_RE pattern"));
