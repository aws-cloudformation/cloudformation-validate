//! Shared regex compilation for CloudFormation `pattern`/`AllowedPattern` constraints.
//!
//! CloudFormation validates patterns with a PCRE-style engine that supports lookaround,
//! backreferences, `\Z`, `\uXXXX` escapes, POSIX classes and possessive quantifiers. Rust's `regex`
//! crate is RE2-style and rejects those, so a provider-supplied pattern that is perfectly valid
//! service-side would fail to compile and - if the caller swallows the error - silently drop the
//! constraint (a false negative) or be treated as non-matching (a false positive).
//!
//! [`compile`] closes that gap. It tries, cheapest first: the `regex` crate with a raised
//! compiled-size limit, then a normalization pass that rewrites Rust-incompatible-but-equivalent
//! syntax, then the `fancy-regex` backtracking engine (which understands lookaround/backreferences)
//! on the raw and normalized forms. Every pattern shipped in the compiled schemas - and every
//! service-valid `AllowedPattern` - compiles through one of these paths, so a constraint is never
//! silently discarded. [`is_service_valid`] reports whether a pattern is enforceable this way, for
//! the rule that flags genuinely-malformed `AllowedPattern`s.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, RwLock};

/// Compiled-size ceiling for the `regex` crate. The crate's 10 MiB default rejects otherwise-simple
/// patterns whose Unicode-aware shorthands (`\w`, `\p{...}`) are multiplied by a large bounded
/// repetition (e.g. `^[\w.-]{1,255}$`); 64 MiB admits every schema pattern while still bounding a
/// pathological input.
const REGEX_SIZE_LIMIT_BYTES: usize = 64 << 20;

/// Process-wide cache of compiled patterns, keyed by the raw pattern string. Compiling a regex (and
/// especially the fancy-regex fallback) is far costlier than a map lookup, and the same schema/format
/// patterns are validated against many resources and values, so each distinct pattern is compiled
/// exactly once and the resulting [`CompiledPattern`] is shared thereafter. The `None` result for an
/// uncompilable pattern is cached too, so a bad pattern is not re-attempted on every call.
static PATTERN_CACHE: LazyLock<RwLock<HashMap<String, Option<Arc<CompiledPattern>>>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// A regex compiled from a CloudFormation constraint, backed by whichever engine could compile it.
///
/// The `regex`-crate variant is used for the common RE2-compatible case; the `fancy-regex` variant
/// handles lookaround/backreference patterns. Both expose a uniform [`CompiledPattern::is_match`].
#[derive(Debug)]
pub enum CompiledPattern {
    Fast(regex::Regex),
    Fancy(fancy_regex::Regex),
}

impl CompiledPattern {
    /// Whether `text` matches the pattern. A `fancy-regex` match that errors at runtime (e.g. its
    /// backtrack limit is hit on adversarial input) is reported as non-matching rather than
    /// propagating, mirroring the crate's own fallible contract; such inputs are not real template
    /// values and treating them as non-matching cannot mask a legitimate constraint violation.
    #[must_use]
    pub fn is_match(&self, text: &str) -> bool {
        match self {
            CompiledPattern::Fast(re) => re.is_match(text),
            CompiledPattern::Fancy(re) => re.is_match(text).unwrap_or(false),
        }
    }
}

/// Compile a CloudFormation `pattern`/`AllowedPattern` string, preserving its matched language.
///
/// The result is memoized: each distinct pattern is compiled once and the shared [`CompiledPattern`]
/// is returned on subsequent calls. Returns `None` only when the pattern cannot be made to compile by
/// any strategy - which, for the schemas shipped in this crate's consumers, does not occur (enforced
/// by a corpus test). Callers treat `None` as "constraint could not be enforced" and must not
/// silently accept the value.
#[must_use]
pub fn compile(pattern: &str) -> Option<Arc<CompiledPattern>> {
    if let Some(cached) = PATTERN_CACHE.read().expect("PATTERN_CACHE not poisoned").get(pattern) {
        return cached.clone();
    }
    let compiled = compile_uncached(pattern).map(Arc::new);
    PATTERN_CACHE.write().expect("PATTERN_CACHE not poisoned").insert(pattern.to_string(), compiled.clone());
    compiled
}

fn compile_uncached(pattern: &str) -> Option<CompiledPattern> {
    if let Ok(re) = build_fast(pattern) {
        return Some(CompiledPattern::Fast(re));
    }
    let normalized = normalize(pattern);
    if let Ok(re) = build_fast(&normalized) {
        return Some(CompiledPattern::Fast(re));
    }
    if let Ok(re) = fancy_regex::Regex::new(pattern) {
        return Some(CompiledPattern::Fancy(re));
    }
    if let Ok(re) = fancy_regex::Regex::new(&normalized) {
        return Some(CompiledPattern::Fancy(re));
    }
    None
}

/// Whether a pattern is a valid regular expression that this tool can enforce - i.e. it either
/// compiles directly or compiles after equivalence-preserving normalization / on the backtracking
/// engine. A pattern that is genuinely malformed (unbalanced groups, dangling quantifier the source
/// engine also rejects) returns `false`. Used by the rule that reports invalid `AllowedPattern`s so
/// it never fires on a pattern that is merely PCRE-flavored rather than broken.
#[must_use]
pub fn is_service_valid(pattern: &str) -> bool {
    compile(pattern).is_some()
}

/// Anchor an `AllowedPattern` the way CloudFormation does before matching: a pattern is implicitly
/// wrapped so it must match the whole value. A leading `^` and/or trailing `$` already present are
/// kept; missing anchors are added.
#[must_use]
pub fn anchor_allowed_pattern(pattern: &str) -> String {
    match (pattern.starts_with('^'), pattern.ends_with('$')) {
        (true, true) => pattern.to_string(),
        (true, false) => format!("{pattern}$"),
        (false, true) => format!("^{pattern}"),
        (false, false) => format!("^{pattern}$"),
    }
}

/// Whether every element of `value` matches `pattern` (auto-anchored). For a scalar parameter
/// `value` is the whole default; for a `CommaDelimitedList`/`List<>` parameter it is the raw default
/// and each comma-separated, trimmed element must match. Returns `None` when the pattern cannot be
/// compiled at all - the caller reports that as an invalid pattern rather than a match failure.
#[must_use]
pub fn default_matches_pattern(pattern: &str, value: &str, is_comma_delimited: bool) -> Option<bool> {
    let compiled = compile(&anchor_allowed_pattern(pattern))?;
    if is_comma_delimited {
        Some(value.split(',').all(|element| compiled.is_match(element.trim())))
    } else {
        Some(compiled.is_match(value))
    }
}

fn build_fast(pattern: &str) -> Result<regex::Regex, regex::Error> {
    regex::RegexBuilder::new(pattern).size_limit(REGEX_SIZE_LIMIT_BYTES).build()
}

static QUANTIFIED_LOOKAROUND: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"(\(\?[=!][^)]*\))[+*]").expect("QUANTIFIED_LOOKAROUND is a valid regex"));

/// Rewrite PCRE/Python constructs the Rust engines reject into an equivalent form, without ever
/// narrowing the set of real (UTF-8) strings that match - narrowing would turn a passing template
/// into a spurious violation, which is never acceptable.
fn normalize(pattern: &str) -> String {
    let mut out = pattern.replace(r"\Z", r"\z");
    out = convert_unicode_escapes(&out);
    out = expand_posix_classes(&out);
    out = rewrite_unicode_other_complement(&out);
    out = repair_char_classes(&out);
    QUANTIFIED_LOOKAROUND.replace_all(&out, "$1").into_owned()
}

/// `\Z` in Python matches at end-of-string or just before a trailing newline; `\z` in Rust matches
/// only at the absolute end. CloudFormation validates single-line scalar values that never carry a
/// trailing newline, so the two are equivalent for every real input.
///
/// Convert `\uXXXX` (JSON/Python) escapes to the `regex` crate's `\u{XXXX}` brace form. A UTF-16
/// surrogate code unit (`D800`–`DFFF`) is not a Unicode scalar value and cannot stand alone in a Rust
/// `&str`; schemas emit them only as surrogate-pair ranges (the XML `Char` production), which denote
/// the astral planes. A run of such escapes inside a character class is therefore collapsed to the
/// single scalar range `\u{10000}-\u{10FFFF}` those pairs encode - this compiles and matches every
/// astral character the pattern admits, whereas clamping each surrogate half to a BMP boundary would
/// both drop the astral planes (a spurious violation) and, when the low half precedes the high half,
/// invert the range into an uncompilable pattern.
fn convert_unicode_escapes(pattern: &str) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::with_capacity(pattern.len());
    let mut index = 0;
    let mut inside_class = false;
    while index < chars.len() {
        if let Some(code_point) = unicode_escape_at(&chars, index) {
            if inside_class && is_surrogate(code_point) {
                out.push_str(SURROGATE_PAIR_ASTRAL_RANGE);
                index = end_of_surrogate_run(&chars, index);
            } else {
                out.push_str(&format!(r"\u{{{:04X}}}", nearest_scalar(code_point)));
                index += UNICODE_ESCAPE_LEN;
            }
            continue;
        }
        let ch = chars[index];
        match ch {
            '\\' if index + 1 < chars.len() => {
                out.push('\\');
                out.push(chars[index + 1]);
                index += 2;
                continue;
            }
            '[' => inside_class = true,
            ']' => inside_class = false,
            _ => {}
        }
        out.push(ch);
        index += 1;
    }
    out
}

/// The scalar range a UTF-16 surrogate-pair range decodes to: the astral planes, U+10000–U+10FFFF.
const SURROGATE_PAIR_ASTRAL_RANGE: &str = r"\u{10000}-\u{10FFFF}";

/// Character length of a `\uXXXX` escape: backslash, `u`, four hex digits.
const UNICODE_ESCAPE_LEN: usize = 6;

fn is_surrogate(code_point: u32) -> bool {
    (0xD800..=0xDFFF).contains(&code_point)
}

/// The escape's own code point, or - for a lone surrogate half that reaches the single-escape path
/// rather than a surrogate-pair range - the nearest scalar boundary, since a surrogate cannot be
/// emitted as a `\u{...}` scalar. Clamping a single half rather than dropping it keeps the class
/// well-formed; a real surrogate-pair range is handled separately and never lands here.
fn nearest_scalar(code_point: u32) -> u32 {
    if !is_surrogate(code_point) {
        code_point
    } else if code_point <= 0xDBFF {
        0xD7FF
    } else {
        0xE000
    }
}

/// The code point of a `\uXXXX` escape starting at `index`, or `None` if no such escape is there.
fn unicode_escape_at(chars: &[char], index: usize) -> Option<u32> {
    if chars.get(index) != Some(&'\\') || chars.get(index + 1) != Some(&'u') {
        return None;
    }
    let hex: String = chars.get(index + 2..index + UNICODE_ESCAPE_LEN)?.iter().collect();
    if !hex.chars().all(|digit| digit.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(&hex, 16).ok()
}

/// Index just past a maximal run of surrogate `\uXXXX` escapes beginning at `index`, consuming the
/// `-` separators that join them into ranges (e.g. `𐀀-􏿿`). The whole run
/// denotes one astral scalar range regardless of how the halves are grouped or ordered.
fn end_of_surrogate_run(chars: &[char], mut index: usize) -> usize {
    loop {
        index += UNICODE_ESCAPE_LEN;
        if chars.get(index) == Some(&'-') && unicode_escape_at(chars, index + 1).is_some_and(is_surrogate) {
            index += 1;
        } else if !unicode_escape_at(chars, index).is_some_and(is_surrogate) {
            return index;
        }
    }
}

/// POSIX-shorthand character classes that PCRE-style engines accept but Rust does not. Each is
/// expanded to the exact set of Unicode general categories the class denotes, so no character the
/// service would accept is rejected and none it rejects is admitted. `\p{Graph}` is every visible
/// character - letters, marks, numbers, punctuation, symbols, plus format (`Cf`) and private-use
/// (`Co`) code points; `\p{Print}` additionally allows the space separator (`Zs`). The replacement
/// is emitted as class members so it works both bare and inside an existing `[...]`.
fn expand_posix_classes(pattern: &str) -> String {
    const GRAPH_TOKEN: &[char] = &['\\', 'p', '{', 'G', 'r', 'a', 'p', 'h', '}'];
    const PRINT_TOKEN: &[char] = &['\\', 'p', '{', 'P', 'r', 'i', 'n', 't', '}'];
    const GRAPH_MEMBERS: &str = r"\p{L}\p{M}\p{N}\p{P}\p{S}\p{Cf}\p{Co}";
    const PRINT_MEMBERS: &str = r"\p{L}\p{M}\p{N}\p{P}\p{S}\p{Cf}\p{Co}\p{Zs}\x20";
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::with_capacity(pattern.len());
    let mut index = 0;
    let mut inside_class = false;
    while index < chars.len() {
        if let Some(replacement) = posix_expansion(&chars, index, GRAPH_TOKEN, GRAPH_MEMBERS, inside_class) {
            out.push_str(&replacement);
            index += GRAPH_TOKEN.len();
            continue;
        }
        if let Some(replacement) = posix_expansion(&chars, index, PRINT_TOKEN, PRINT_MEMBERS, inside_class) {
            out.push_str(&replacement);
            index += PRINT_TOKEN.len();
            continue;
        }
        let ch = chars[index];
        match ch {
            '\\' if index + 1 < chars.len() => {
                out.push('\\');
                out.push(chars[index + 1]);
                index += 2;
                continue;
            }
            '[' => inside_class = true,
            ']' => inside_class = false,
            _ => {}
        }
        out.push(ch);
        index += 1;
    }
    out
}

/// If `token` (e.g. `\p{Graph}`) starts at `index` in `chars`, produce its expansion - wrapped in
/// `[...]` when it appears bare so it stays a single matchable unit, or as raw members when already
/// inside a character class.
fn posix_expansion(chars: &[char], index: usize, token: &[char], members: &str, inside_class: bool) -> Option<String> {
    if !chars[index..].starts_with(token) {
        return None;
    }
    Some(if inside_class { members.to_string() } else { format!("[{members}]") })
}

const UNICODE_OTHER_COMPLEMENT: &[char] = &['[', '^', '\\', 'p', '{', 'C', '}', ']'];
const UNICODE_OTHER_LOOKAHEAD: &str = r"(?:(?!\p{C})(?s:.))";

/// A large bounded repetition of `[^\p{C}]` expands beyond the `regex` crate's NFA size limit.
/// Expressing the same one-scalar predicate as a lookahead keeps the repetition compact in the
/// backtracking engine: the lookahead rejects Unicode Other and the dot-all atom consumes exactly
/// one scalar from every remaining general category.
fn rewrite_unicode_other_complement(pattern: &str) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::with_capacity(pattern.len());
    let mut index = 0;
    let mut inside_class = false;
    while index < chars.len() {
        if chars[index] == '\\' && index + 1 < chars.len() {
            out.push(chars[index]);
            out.push(chars[index + 1]);
            index += 2;
            continue;
        }
        if !inside_class && chars[index..].starts_with(UNICODE_OTHER_COMPLEMENT) {
            out.push_str(UNICODE_OTHER_LOOKAHEAD);
            index += UNICODE_OTHER_COMPLEMENT.len();
            continue;
        }
        match chars[index] {
            '[' => inside_class = true,
            ']' => inside_class = false,
            _ => {}
        }
        out.push(chars[index]);
        index += 1;
    }
    out
}

/// Repair character classes that Rust rejects but which are valid (or intended) service-side:
/// a `-` immediately after a shorthand (`\w`, `\d`, `\s`, `\p{...}`) or a `[` appearing literally
/// inside a class. Escaping the hyphen makes it a literal `-` (its only sensible meaning there), and
/// escaping the inner `[` makes it a literal `[`; neither changes which characters the class admits.
fn repair_char_classes(pattern: &str) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::with_capacity(pattern.len() + 8);
    let mut index = 0;
    let mut inside_class = false;
    let mut prev_was_shorthand = false;
    while index < chars.len() {
        let ch = chars[index];
        if ch == '\\' && index + 1 < chars.len() {
            let next = chars[index + 1];
            out.push('\\');
            out.push(next);
            if (next == 'p' || next == 'P') && index + 2 < chars.len() && chars[index + 2] == '{' {
                let mut end = index + 2;
                while end < chars.len() && chars[end] != '}' {
                    out.push(chars[end]);
                    end += 1;
                }
                if end < chars.len() {
                    out.push('}');
                }
                index = end + 1;
                prev_was_shorthand = inside_class;
                continue;
            }
            prev_was_shorthand = inside_class && matches!(next, 'w' | 'd' | 's' | 'W' | 'D' | 'S');
            index += 2;
            continue;
        }
        if ch == '[' {
            if inside_class {
                out.push_str(r"\[");
                index += 1;
                prev_was_shorthand = false;
                continue;
            }
            inside_class = true;
            prev_was_shorthand = false;
            out.push('[');
            index += 1;
            if index < chars.len() && chars[index] == '^' {
                out.push('^');
                index += 1;
            }
            if index < chars.len() && chars[index] == ']' {
                out.push(']');
                index += 1;
            }
            continue;
        }
        if ch == ']' && inside_class {
            inside_class = false;
            out.push(']');
            index += 1;
            prev_was_shorthand = false;
            continue;
        }
        if ch == '-' && inside_class && prev_was_shorthand {
            out.push_str(r"\-");
            index += 1;
            prev_was_shorthand = false;
            continue;
        }
        out.push(ch);
        prev_was_shorthand = false;
        index += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_pattern_compiles_on_fast_engine() {
        let compiled = compile(r"^ami-[0-9a-f]{8,17}$").expect("plain pattern compiles");
        assert!(matches!(*compiled, CompiledPattern::Fast(_)));
        assert!(compiled.is_match("ami-0123abcd"));
        assert!(!compiled.is_match("vpc-0123abcd"));
    }

    #[test]
    fn compile_is_memoized_and_returns_the_same_instance() {
        let first = compile(r"^cache-test-[0-9]+$").expect("compiles");
        let second = compile(r"^cache-test-[0-9]+$").expect("compiles");
        assert!(Arc::ptr_eq(&first, &second), "repeated compile must reuse the cached instance");
    }

    #[test]
    fn print_class_matches_format_and_private_use_characters() {
        // `\p{Print}` includes format (Cf) and private-use (Co) code points; the expansion must not
        // narrow them away or a valid value becomes a spurious violation.
        let compiled = compile(r"^\p{Print}+$").expect("\\p{Print} compiles");
        assert!(compiled.is_match("normal text"));
        assert!(compiled.is_match("zero\u{200B}width"), "U+200B (Cf) must match \\p{{Print}}");
        assert!(compiled.is_match("private\u{E000}use"), "U+E000 (Co) must match \\p{{Print}}");
    }

    #[test]
    fn negative_lookahead_compiles_and_matches_like_pcre() {
        let compiled = compile(r"^(?!aws:).+$").expect("lookahead pattern compiles");
        assert!(matches!(*compiled, CompiledPattern::Fancy(_)));
        assert!(compiled.is_match("my-tag"));
        assert!(!compiled.is_match("aws:reserved"));
    }

    #[test]
    fn uppercase_z_anchor_is_normalized_to_lowercase() {
        let compiled = compile(r"\A[0-9a-fA-F]+\Z").expect("\\A..\\Z pattern compiles");
        assert!(compiled.is_match("abc123"));
        assert!(!compiled.is_match("xyz"));
    }

    #[test]
    fn size_limit_pattern_compiles_without_rewrite() {
        let compiled = compile(r"^[\w.-]{1,255}$").expect("size-limit pattern compiles");
        assert!(matches!(*compiled, CompiledPattern::Fast(_)));
        assert!(compiled.is_match("valid.name-1"));
    }

    #[test]
    fn bounded_unicode_other_complement_preserves_category_and_length_constraints() {
        let compiled = compile(r"^[^\p{C}]{1,2048}$").expect("bounded Unicode category pattern compiles");

        assert!(compiled.is_match("cafe\u{301} 123 ☃!"));
        assert!(!compiled.is_match(""), "the lower length boundary must be enforced");
        for (category, value) in [
            ("Control", "line\nbreak"),
            ("Format", "zero\u{200B}width"),
            ("Private Use", "private\u{E000}use"),
            ("Unassigned", "unassigned\u{0378}"),
        ] {
            assert!(!compiled.is_match(value), "Unicode {category} characters must be rejected");
        }

        let maximum_length = "a".repeat(2048);
        let above_maximum_length = "a".repeat(2049);
        assert!(compiled.is_match(&maximum_length), "the upper length boundary must be accepted");
        assert!(!compiled.is_match(&above_maximum_length), "values above the upper length boundary must be rejected");
    }

    #[test]
    fn print_class_still_matches_ordinary_text() {
        let compiled = compile(r"^\p{Print}+$").expect("\\p{Print} pattern compiles");
        for value in ["abc", "Hello World", "aws:reserved", "café", "a.b.c/x"] {
            assert!(compiled.is_match(value), "\\p{{Print}} must match {value:?}");
        }
        assert!(!compiled.is_match(""));
    }

    #[test]
    fn graph_class_inside_existing_class_compiles() {
        let compiled = compile(r"^[\p{Graph}\x20]*$").expect("\\p{Graph} in class compiles");
        assert!(compiled.is_match("visible text"));
    }

    #[test]
    fn surrogate_pair_range_admits_astral_characters() {
        // The XML `Char` production shipped in schemas encodes the astral planes as a UTF-16
        // surrogate-pair range. Collapsing it to the scalar astral range must keep those characters
        // matchable - dropping them would make a value the service accepts fail spuriously.
        let compiled = compile(r"^[ -퟿-�𐀀-􏿿\r\n\t]*$").expect("surrogate pattern compiles");
        assert!(compiled.is_match("normal text"));
        assert!(
            compiled.is_match("emoji \u{1F600} and \u{10FFFF}"),
            "astral characters must match the surrogate-pair range"
        );
    }

    #[test]
    fn low_then_high_surrogate_range_still_compiles() {
        // The same class also ships with the surrogate halves ordered low-before-high; clamping each
        // half independently would invert the range (E000..D7FF) and fail to compile.
        let compiled =
            compile(r"^[ -퟿-�\uD800\uDBFF-\uDC00\uDFFF\t]*$").expect("reordered surrogate pattern compiles");
        assert!(compiled.is_match("normal text"));
        assert!(compiled.is_match("astral \u{1F4A9}"), "astral characters must match regardless of surrogate ordering");
    }

    #[test]
    fn lone_surrogate_escape_outside_class_is_clamped_not_inverted() {
        // A `\uXXXX` escape outside a character class is a single code point, not a range endpoint;
        // a surrogate there is clamped to the nearest scalar so the pattern still compiles.
        assert!(is_service_valid(r"^\uD800$"));
    }

    #[test]
    fn hyphen_after_shorthand_is_treated_as_literal() {
        let compiled = compile(r"[\w-.~]+").expect("hyphen-range pattern compiles");
        assert!(compiled.is_match("a-b.c"));
    }

    #[test]
    fn genuinely_malformed_pattern_is_not_service_valid() {
        assert!(!is_service_valid(r"^(unbalanced"));
        assert!(!is_service_valid(r"a{2,1}"));
    }

    #[test]
    fn pcre_flavored_patterns_are_service_valid() {
        assert!(is_service_valid(r"^(?!aws:).+$"));
        assert!(is_service_valid(r"\A[0-9]+\Z"));
        assert!(is_service_valid(r"^\p{Print}+$"));
        assert!(is_service_valid(r"^[\w.-]{1,255}$"));
    }

    #[test]
    fn normalize_preserves_plain_pattern_unchanged() {
        assert_eq!(normalize(r"^[a-z0-9]+$"), r"^[a-z0-9]+$");
    }

    #[test]
    fn anchor_allowed_pattern_adds_missing_anchors() {
        assert_eq!(anchor_allowed_pattern("[a-z]+"), "^[a-z]+$");
        assert_eq!(anchor_allowed_pattern("^[a-z]+"), "^[a-z]+$");
        assert_eq!(anchor_allowed_pattern("[a-z]+$"), "^[a-z]+$");
        assert_eq!(anchor_allowed_pattern("^[a-z]+$"), "^[a-z]+$");
    }

    #[test]
    fn default_matches_pattern_scalar() {
        assert_eq!(default_matches_pattern(r"[0-9]+", "123", false), Some(true));
        assert_eq!(default_matches_pattern(r"[0-9]+", "12a", false), Some(false));
    }

    #[test]
    fn default_matches_pattern_honors_pcre_syntax() {
        // \A..\Z is valid service-side; "abc123" matches, so no violation should be reported.
        assert_eq!(default_matches_pattern(r"\A[0-9a-fA-F]+\Z", "abc123", false), Some(true));
    }

    #[test]
    fn default_matches_pattern_comma_delimited_checks_each_element() {
        assert_eq!(default_matches_pattern(r"[a-z]+", "abc, def ,ghi", true), Some(true));
        assert_eq!(default_matches_pattern(r"[a-z]+", "abc, DEF", true), Some(false));
    }

    #[test]
    fn default_matches_pattern_returns_none_for_uncompilable() {
        assert_eq!(default_matches_pattern(r"^(unbalanced", "x", false), None);
    }
}
