//! Regexes for well-known AWS resource value formats (identifiers, record
//! values, names) shared by the schema validator and the rule engines.

/// Regex for the `AWS::IAM::Role.Arn` schema *format* check: the partition must be
/// `aws`-prefixed and the role name is unrestricted (`.+`), so a role name containing a space or
/// other legal-but-unusual character is accepted here.
pub const IAM_ROLE_ARN_PATTERN: &str = r"^arn:aws[a-zA-Z-]*:iam::\d{12}:role/.+$";

/// Regex for the resource-property IAM role-ARN *rule* check: the partition group is
/// optional and the role name is constrained to the IAM role-name character class. This is
/// intentionally stricter than [`IAM_ROLE_ARN_PATTERN`] - the two correspond to two distinct checks
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
