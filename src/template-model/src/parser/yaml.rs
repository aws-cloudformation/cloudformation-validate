use crate::consts::*;
use crate::ir::*;
use crate::parser::builder::{Builder, TemplateSections};
use crate::parser::value::{ParseValue, ValueKind};
use log::{debug, info, warn};
use std::collections::{BTreeMap, HashMap};
use std::mem;
use std::str::from_utf8;
use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser, Tag};
use yaml_rust2::scanner::Marker;
use yaml_rust2::yaml::{Hash, Yaml};

/// Output of the YAML event-stream load: the document tree, source spans for each
/// path, and any duplicate-key diagnostics found during the load.
struct LoadedYaml {
    docs: Vec<Yaml>,
    span_map: HashMap<String, (u32, u32)>,
    dup_key_diagnostics: Vec<ParseDefect>,
    merge_key_spans: Vec<SourceSpan>,
}

/// The tag handle of the YAML core schema (`!!str` scans as this handle plus the
/// bare suffix, e.g. `str`).
const CORE_TAG_HANDLE: &str = "tag:yaml.org,2002:";

/// Base for the synthetic alias ids used as mapping keys for *plain* `<<` merge
/// keys. A plain `<<` scalar in key position is the YAML 1.1 merge indicator, but a
/// quoted `'<<'` is an ordinary key - the two must stay distinguishable through the
/// loaded tree, and `Yaml::Alias` never otherwise appears as a key (aliases resolve
/// to their anchored value at load time). Each merge key gets a unique id so several
/// merge entries in one mapping neither collide in the hash nor lose their order.
const MERGE_KEY_SENTINEL_BASE: usize = usize::MAX / 2;

/// Whether a mapping key is the sentinel for a plain `<<` merge key.
fn is_merge_sentinel(key: &Yaml) -> bool {
    matches!(key, Yaml::Alias(id) if *id >= MERGE_KEY_SENTINEL_BASE)
}

/// Splits an optional leading sign off a numeric token: `(negative, rest)`.
fn split_sign(v: &str) -> (bool, &str) {
    match v.as_bytes().first() {
        Some(b'-') => (true, &v[1..]),
        Some(b'+') => (false, &v[1..]),
        _ => (false, v),
    }
}

/// Parses the digits of `body` in `radix` after stripping YAML 1.1 `_` separators.
/// `None` when no digit remains or a digit is invalid for the radix. Values beyond
/// `i64` fall out as `None` and the token resolves as a string.
fn radix_int(body: &str, radix: u32, negative: bool) -> Option<i64> {
    let digits: String = body.chars().filter(|c| *c != '_').collect();
    if digits.is_empty() {
        return None;
    }
    let magnitude = i64::from_str_radix(&digits, radix).ok()?;
    Some(if negative { -magnitude } else { magnitude })
}

/// A YAML 1.1 sexagesimal segment after the first colon: one digit, or two digits
/// where the first is 0-5 (i.e. a value 0-59).
fn sexagesimal_segment(seg: &str) -> Option<i64> {
    match seg.as_bytes() {
        [d @ b'0'..=b'9'] => Some((d - b'0') as i64),
        [h @ b'0'..=b'5', l @ b'0'..=b'9'] => Some(((h - b'0') * 10 + (l - b'0')) as i64),
        _ => None,
    }
}

/// Parses a YAML 1.1 integer: binary (`0b…`), octal (leading `0`), decimal,
/// hexadecimal (`0x…`), or sexagesimal (`1:30` = 90), with `_` separators.
/// This is the resolution CloudFormation's own YAML parser applies, which differs
/// from YAML 1.2: a leading zero means octal, and `0o…` is *not* an integer form.
fn parse_yaml11_int(v: &str) -> Option<i64> {
    let (negative, body) = split_sign(v);
    if body.is_empty() {
        return None;
    }
    if let Some(hex) = body.strip_prefix("0x") {
        return if hex.bytes().all(|b| b.is_ascii_hexdigit() || b == b'_') {
            radix_int(hex, 16, negative)
        } else {
            None
        };
    }
    if let Some(bin) = body.strip_prefix("0b") {
        return if bin.bytes().all(|b| matches!(b, b'0' | b'1' | b'_')) { radix_int(bin, 2, negative) } else { None };
    }
    if body.contains(':') {
        // Sexagesimal: first segment `[1-9][0-9_]*`, then `:` separated 0-59 segments.
        let mut segments = body.split(':');
        let first = segments.next()?;
        if !first.as_bytes().first().is_some_and(|b| (b'1'..=b'9').contains(b))
            || !first.bytes().all(|b| b.is_ascii_digit() || b == b'_')
        {
            return None;
        }
        let mut acc = radix_int(first, 10, false)?;
        for seg in segments {
            acc = acc.checked_mul(60)?.checked_add(sexagesimal_segment(seg)?)?;
        }
        return Some(if negative { -acc } else { acc });
    }
    if body.len() > 1 && body.starts_with('0') {
        // Leading zero is octal; a non-octal digit (e.g. `012345678`) is a string.
        return if body.bytes().all(|b| matches!(b, b'0'..=b'7' | b'_')) { radix_int(body, 8, negative) } else { None };
    }
    if !body.bytes().all(|b| b.is_ascii_digit() || b == b'_') || body.starts_with('_') {
        return None;
    }
    radix_int(body, 10, negative)
}

/// Matches `[0-9][0-9_]*` (a YAML 1.1 digit run that must start with a digit).
fn digit_run(s: &str) -> bool {
    s.as_bytes().first().is_some_and(u8::is_ascii_digit) && s.bytes().all(|b| b.is_ascii_digit() || b == b'_')
}

/// Matches `[0-9_]*` (the fraction part, which may be empty).
fn digit_run_or_empty(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_digit() || b == b'_')
}

/// Matches a YAML 1.1 float exponent: `[eE][-+][0-9]+`. The sign is mandatory -
/// `1e5` and `1.5e10` are *strings* in YAML 1.1, unlike YAML 1.2.
fn signed_exponent(s: &str) -> bool {
    let rest = match s.strip_prefix('e').or_else(|| s.strip_prefix('E')) {
        Some(r) => r,
        None => return s.is_empty(),
    };
    let rest = match rest.strip_prefix('+').or_else(|| rest.strip_prefix('-')) {
        Some(r) => r,
        None => return false,
    };
    !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit())
}

/// Splits `body` at its exponent marker, returning `(mantissa, tail)` where tail
/// includes the `e`/`E`. When no marker exists the tail is empty.
fn split_exponent(body: &str) -> (&str, &str) {
    match body.find(['e', 'E']) {
        Some(idx) => (&body[..idx], &body[idx..]),
        None => (body, ""),
    }
}

/// Parses a YAML 1.1 float, returning the token to store in [`Yaml::Real`] -
/// normalized (separators stripped, sexagesimal evaluated) so `Yaml::as_f64` can
/// re-parse it. Mirrors the YAML 1.1 resolver CloudFormation's parser uses:
/// the exponent requires a sign, `.5` has no signed form, and `.inf`/`.nan`
/// spellings are the only infinity/NaN tokens.
fn parse_yaml11_float(v: &str) -> Option<String> {
    match v {
        ".inf" | ".Inf" | ".INF" | "+.inf" | "+.Inf" | "+.INF" | "-.inf" | "-.Inf" | "-.INF" | ".nan" | ".NaN"
        | ".NAN" => return Some(v.to_string()),
        _ => {}
    }
    let (negative, body) = split_sign(v);
    // `.5`/`.5e+3`: no sign is permitted on this form in YAML 1.1 (`-.5` is a string).
    if let Some(after_dot) = v.strip_prefix('.') {
        let (mantissa, exp) = split_exponent(after_dot);
        if digit_run(mantissa) && signed_exponent(exp) {
            return Some(v.replace('_', ""));
        }
        return None;
    }
    // Sexagesimal float: `[-+]?[0-9][0-9_]*(:[0-5]?[0-9])+\.[0-9_]*`.
    if body.contains(':') {
        let (int_part, frac_part) = body.split_once('.')?;
        let mut segments = int_part.split(':');
        let first = segments.next()?;
        if !digit_run(first) || !digit_run_or_empty(frac_part) {
            return None;
        }
        let mut acc = radix_int(first, 10, false)? as f64;
        for seg in segments {
            acc = acc * 60.0 + sexagesimal_segment(seg)? as f64;
        }
        let frac: String = frac_part.chars().filter(|c| *c != '_').collect();
        acc += format!("0.{}", if frac.is_empty() { "0" } else { &frac }).parse::<f64>().ok()?;
        if negative {
            acc = -acc;
        }
        return Some(format!("{}", acc));
    }
    // `12.34e+5` / `12.`: digits, a mandatory dot, optional fraction and exponent.
    let (mantissa, exp) = split_exponent(body);
    let (int_part, frac_part) = mantissa.split_once('.')?;
    if digit_run(int_part) && digit_run_or_empty(frac_part) && signed_exponent(exp) {
        let mut normalized: String = v.chars().filter(|c| *c != '_').collect();
        // Rust's float parser rejects a bare trailing dot before an exponent
        // (`10.e+3`); give it an explicit zero fraction.
        if frac_part.is_empty() && !exp.is_empty() {
            normalized = normalized.replacen('.', ".0", 1);
        }
        return Some(normalized);
    }
    None
}

/// Resolves a plain (unquoted, untagged) YAML scalar per the YAML 1.1 schema -
/// the resolution CloudFormation's template parser applies. Notable differences
/// from YAML 1.2: `yes`/`no`/`on`/`off` (and case variants) are booleans, a
/// leading zero means octal, `_` separates digits, `1:30` is the integer 90, and
/// a float exponent requires an explicit sign (`1e5` is a string).
/// Timestamps (`2010-09-09`) stay strings: CloudFormation treats them as opaque
/// scalar text, and every template consumer here needs the source spelling.
fn resolve_plain_scalar(v: &str) -> Yaml {
    match v {
        "" | "~" | "null" | "Null" | "NULL" => return Yaml::Null,
        "yes" | "Yes" | "YES" | "true" | "True" | "TRUE" | "on" | "On" | "ON" => return Yaml::Boolean(true),
        "no" | "No" | "NO" | "false" | "False" | "FALSE" | "off" | "Off" | "OFF" => return Yaml::Boolean(false),
        _ => {}
    }
    if let Some(i) = parse_yaml11_int(v) {
        return Yaml::Integer(i);
    }
    if let Some(f) = parse_yaml11_float(v) {
        return Yaml::Real(f);
    }
    Yaml::String(v.to_string())
}

/// Resolves a scalar carrying an explicit core-schema tag (`!!str`, `!!int`, etc.).
/// The tag overrides both style and content-based resolution. A recognized tag
/// whose lexical value is invalid fails the parse rather than being silently
/// reinterpreted as a string.
fn resolve_core_tagged_scalar(suffix: &str, value: &str) -> Result<Option<Yaml>, String> {
    let invalid = || format!("'{}' is not a valid value for !!{}", value, suffix);
    match suffix {
        "str" => Ok(Some(Yaml::String(value.to_string()))),
        "null" => match resolve_plain_scalar(value) {
            Yaml::Null => Ok(Some(Yaml::Null)),
            _ => Err(invalid()),
        },
        "bool" => match resolve_plain_scalar(value) {
            boolean @ Yaml::Boolean(_) => Ok(Some(boolean)),
            _ => Err(invalid()),
        },
        "int" => parse_yaml11_int(value).map(Yaml::Integer).map(Some).ok_or_else(invalid),
        "float" => parse_yaml11_float(value)
            .map(Yaml::Real)
            .or_else(|| parse_yaml11_int(value).map(|integer| Yaml::Real(format!("{}", integer as f64))))
            .map(Some)
            .ok_or_else(invalid),
        _ => Ok(None),
    }
}

/// One open container while the event stream is being consumed. The frame stack
/// runs parallel to `doc_stack`, and each frame records the slot the *next* child
/// value will occupy: a mapping's current key, or a sequence's next index. Joining
/// every frame's slot yields the canonical `/`-separated path the shared builder
/// assigns each node - so a span keyed here (e.g. `Ingress/0/SourceSecurityGroupId`)
/// lands on exactly the node the builder produces, array indices included.
enum PathFrame {
    /// The key currently awaiting its value, or `None` while awaiting a key.
    Map(Option<String>),
    /// The index the next sequence element will occupy.
    Seq(usize),
}

/// See [`CfnYamlLoader::current_path`]. A free function over the frames so the
/// path can be computed while a sibling field of the loader is mutably
/// borrowed (as during duplicate-key detection inside `insert_new_node`).
fn path_from_frames(frames: &[PathFrame]) -> String {
    let mut path = String::new();
    for frame in frames {
        let segment = match frame {
            PathFrame::Map(Some(key)) => key.as_str(),
            PathFrame::Map(None) => continue,
            PathFrame::Seq(idx) => {
                if !path.is_empty() {
                    path.push('/');
                }
                path.push_str(&idx.to_string());
                continue;
            }
        };
        if !path.is_empty() {
            path.push('/');
        }
        path.push_str(segment);
    }
    path
}

/// Converts YAML shorthand tags (!Ref, !Sub, etc.) into map-form intrinsics.
struct CfnYamlLoader {
    docs: Vec<Yaml>,
    doc_stack: Vec<(Yaml, usize)>,
    key_stack: Vec<Yaml>,
    anchor_map: BTreeMap<usize, Yaml>,
    /// Stack of tags to apply when sequences/mappings complete.
    /// Each entry is (tag_name, stack_depth_when_set).
    /// A stack is needed because nested tags (e.g. `!Or [!Equals [...]]`)
    /// would otherwise overwrite the outer tag.
    pending_tags: Vec<(String, usize)>,
    /// One frame per open container, parallel to `doc_stack`; see [`PathFrame`].
    path_frames: Vec<PathFrame>,
    span_map: HashMap<String, (u32, u32)>,
    /// Source position of the key currently awaiting its value, one entry per open
    /// mapping (parallel to `key_stack`). Used to anchor duplicate-key diagnostics.
    key_marks: Vec<Option<(u32, u32)>>,
    /// Every key committed so far in each open mapping (parallel to `key_stack`),
    /// with its first occurrence's position and whether that first occurrence has
    /// already been diagnosed. A duplicated key is flagged at *every* occurrence -
    /// the first duplicate retroactively flags the original occurrence too, so a
    /// reader sees all the colliding definitions, not just the later ones.
    seen_keys: Vec<Vec<(Yaml, Option<(u32, u32)>, bool)>>,
    /// Duplicate-key diagnostics found while a mapping is still open, one buffer per
    /// open mapping (parallel to `key_stack`). Flushed to `dup_key_diagnostics` when
    /// the mapping closes - unless that mapping used a YAML merge key (`<<`), in which
    /// case the buffer is dropped. A mapping that merges is not required to have unique
    /// keys, so its duplicate check is suppressed for the whole mapping.
    pending_dup_diagnostics: Vec<Vec<ParseDefect>>,
    /// Whether the correspondingly-open mapping contains a `<<` merge key (parallel to
    /// `key_stack`). Set from any position in the mapping - before or after a
    /// duplicate - so the suppression covers every ordering.
    mapping_uses_merge: Vec<bool>,
    /// `yaml_rust2` silently keeps the last value for a duplicate key, so duplicates
    /// are detected here at load time. Every colliding occurrence is diagnosed,
    /// matching the JSON front-end's byte pre-scan.
    dup_key_diagnostics: Vec<ParseDefect>,
    /// Source positions of YAML merge keys (`<<`) encountered during loading.
    merge_key_spans: Vec<SourceSpan>,
    /// Count of plain `<<` merge keys seen, used to mint unique sentinel key ids.
    merge_key_count: usize,
    /// Set after a structural nesting-depth violation. All later events are
    /// ignored, so no deeper `Yaml` tree is constructed; `load` returns the
    /// located parse error before consulting the incomplete document state.
    suppress_tree_construction: bool,
    /// First structurally-fatal defect found while loading (a null or non-scalar
    /// mapping key). CloudFormation cannot represent such a template as JSON, so
    /// the whole parse fails - mirroring the scanner's own hard errors.
    load_error: Option<ParseError>,
    /// Where a second YAML document begins, when the stream has more than one.
    /// A CloudFormation template is a single document; extra documents fail the
    /// parse rather than being silently dropped.
    second_doc_mark: Option<(u32, u32)>,
}

impl CfnYamlLoader {
    fn new() -> Self {
        Self {
            docs: Vec::new(),
            doc_stack: Vec::new(),
            key_stack: Vec::new(),
            anchor_map: BTreeMap::new(),
            pending_tags: Vec::new(),
            path_frames: Vec::new(),
            span_map: HashMap::new(),
            key_marks: Vec::new(),
            seen_keys: Vec::new(),
            pending_dup_diagnostics: Vec::new(),
            mapping_uses_merge: Vec::new(),
            dup_key_diagnostics: Vec::new(),
            merge_key_spans: Vec::new(),
            merge_key_count: 0,
            suppress_tree_construction: false,
            load_error: None,
            second_doc_mark: None,
        }
    }

    fn load(text: &str) -> Result<LoadedYaml, ParseError> {
        let mut loader = Self::new();
        let mut parser = Parser::new_from_str(text);
        // The scanner error carries a Marker locating the failure; surface it so the
        // resulting F1101 diagnostic is anchored at the offending position instead of
        // being left without a location.
        parser.load(&mut loader, true).map_err(|e| {
            let (line, column) = Self::mark_position(*e.marker());
            ParseError { message: format!("YAML parse error: {}", e), line: Some(line), column: Some(column) }
        })?;
        // A structural defect found while building the tree (null/unhashable key)
        // fails the parse outright: the document has no JSON equivalent.
        if let Some(error) = loader.load_error {
            return Err(error);
        }
        // A template is one YAML document; refuse streams carrying more instead of
        // validating only the first and silently ignoring the rest.
        if let Some((line, column)) = loader.second_doc_mark {
            return Err(ParseError {
                message: "expected a single document in the stream but found another document".to_string(),
                line: Some(line),
                column: Some(column),
            });
        }
        Ok(LoadedYaml {
            docs: loader.docs,
            span_map: loader.span_map,
            dup_key_diagnostics: loader.dup_key_diagnostics,
            merge_key_spans: loader.merge_key_spans,
        })
    }

    /// The canonical `/`-separated path of the value the innermost frame is about to
    /// receive: every enclosing frame's committed slot, then this frame's own slot.
    /// A mapping frame still awaiting its key contributes nothing (that key becomes the
    /// slot once seen), so the path names the value node the builder will allocate.
    fn current_path(&self) -> String {
        path_from_frames(&self.path_frames)
    }

    /// The `(line, column)` a Marker points at, in the 1-based/1-based convention the
    /// rest of the diagnostics pipeline uses. yaml_rust2 already reports the line
    /// 1-based but the column 0-based, so only the column is incremented. This is the
    /// single place that conversion happens.
    fn mark_position(mark: Marker) -> (u32, u32) {
        (mark.line() as u32, mark.col() as u32 + 1)
    }

    /// Anchors a mapping value at its key's position, overwriting any earlier entry so
    /// a duplicate key resolves to the surviving (last) occurrence - matching how the
    /// loaded `Hash` keeps the last value written for a repeated key. Object-property
    /// diagnostics anchor at the key, so this is where the value's span lives.
    fn record_key_span(&mut self, mark: Marker) {
        let path = self.current_path();
        if !path.is_empty() {
            self.span_map.insert(path, Self::mark_position(mark));
        }
    }

    /// Anchors a value that no key precedes - a sequence element, or a container opened
    /// directly inside a sequence - at its own position. Never overwrites a span a key
    /// already assigned to the same path (a container that is a mapping *value* is
    /// reached here too, but its key recorded the authoritative position first).
    fn record_value_span(&mut self, mark: Marker) {
        let path = self.current_path();
        if !path.is_empty() {
            self.span_map.entry(path).or_insert_with(|| Self::mark_position(mark));
        }
    }

    /// Advances the innermost frame's slot once a value has been placed into it, so the
    /// next child resolves to the correct path: a mapping again awaits a key, and a
    /// sequence moves to the next index. A no-op for a mapping still awaiting its key
    /// (the placed node was that key, not a value).
    fn advance_after_value(&mut self) {
        match self.path_frames.last_mut() {
            Some(PathFrame::Map(slot @ Some(_))) => *slot = None,
            Some(PathFrame::Seq(idx)) => *idx += 1,
            _ => {}
        }
    }

    /// Whether a node about to be placed is a mapping key still awaiting its value,
    /// rather than a value or sequence element. Read from the tree builder's own
    /// `key_stack` so path tracking stays in lockstep with node construction.
    fn placing_map_key(&self) -> bool {
        matches!(self.doc_stack.last(), Some((Yaml::Hash(_), _))) && self.key_stack.last() == Some(&Yaml::BadValue)
    }

    /// The bare suffix of a primary (`!`-handle) YAML tag, or `None` for
    /// secondary-handle (`!!type`) tags and untagged nodes. Every primary tag is a
    /// candidate intrinsic shorthand: recognized suffixes map through
    /// [`SHORT_TAG_TO_FN_KEY`], and an unrecognized suffix is still wrapped as
    /// `{ Fn::<suffix>: value }` by [`Self::wrap_with_tag`] so the shared builder can
    /// flag it as an unsupported function - mirroring how a typo'd `Fn::` key is
    /// caught in the long form and in JSON, instead of silently dropping the tag.
    fn cfn_tag_name(tag: &Option<Tag>) -> Option<String> {
        let tag = tag.as_ref()?;
        if tag.handle != "!" {
            return None;
        }
        Some(tag.suffix.clone())
    }

    /// Wraps `value` in the single-key mapping the shared builder recognizes, given
    /// the bare suffix of a `!Tag`. A recognized suffix uses its canonical key from
    /// [`SHORT_TAG_TO_FN_KEY`] (`GetAtt` → `Fn::GetAtt`, `Ref`/`Condition` map to
    /// themselves); any other suffix becomes `{ Fn::<suffix>: value }` so a
    /// misspelled or unknown tag surfaces as an unsupported function rather than
    /// being silently discarded.
    /// Emits the unknown-function warning when a shorthand tag does not name a
    /// known intrinsic (after the short-name mapping, e.g. `!GetAtt` →
    /// `Fn::GetAtt`). `Condition` and the `ForEach::<id>` loop tags are valid
    /// non-`Fn::` forms.
    fn warn_unknown_tag(&mut self, tag_name: &str) {
        let fn_key = SHORT_TAG_TO_FN_KEY
            .iter()
            .find(|(short, _)| *short == tag_name)
            .map(|(_, fn_key)| (*fn_key).to_string())
            .unwrap_or_else(|| format!("{}{}", FN_PREFIX, tag_name));
        let known = crate::consts::INTRINSIC_FN_PATH_SEGMENTS.contains(&fn_key.as_str())
            || fn_key == FN_REF
            || fn_key == crate::consts::FN_CONDITION
            || fn_key.starts_with(crate::consts::FN_FOR_EACH_KEY_PREFIX);
        // A near-miss of a known function is warned (with a suggestion) by the
        // builder when it sees the wrapped map, so only warn here for names far
        // from every function - otherwise the same tag would warn twice.
        if !known && super::builder::closest_function_name(&fn_key).is_none() {
            self.dup_key_diagnostics.push(crate::make_parse_defect(
                "W1103",
                format!("'!{}' is not a supported function", tag_name),
                UNKNOWN_SPAN,
            ));
        }
    }

    fn cfn_tag_key(tag_name: &str) -> String {
        SHORT_TAG_TO_FN_KEY
            .iter()
            .find(|(short, _)| *short == tag_name)
            .map(|(_, fn_key)| (*fn_key).to_string())
            .unwrap_or_else(|| format!("{}{}", FN_PREFIX, tag_name))
    }

    fn record_tagged_spans(&mut self, tag_name: &str) {
        let base_path = self.current_path();
        if base_path.is_empty() {
            return;
        }

        let tagged_path = format!("{}/{}", base_path, Self::cfn_tag_key(tag_name));
        if let Some(span) = self.span_map.get(&base_path).copied() {
            self.span_map.entry(tagged_path.clone()).or_insert(span);
        }

        let descendant_prefix = format!("{}/", base_path);
        let descendant_spans: Vec<(String, (u32, u32))> = self
            .span_map
            .iter()
            .filter_map(|(path, span)| {
                path.strip_prefix(&descendant_prefix).map(|suffix| (format!("{}/{}", tagged_path, suffix), *span))
            })
            .collect();
        for (path, span) in descendant_spans {
            self.span_map.entry(path).or_insert(span);
        }
    }

    fn wrap_with_tag(tag_name: &str, value: Yaml) -> Yaml {
        let mut hash = Hash::new();
        hash.insert(Yaml::String(Self::cfn_tag_key(tag_name)), value);
        Yaml::Hash(hash)
    }

    fn insert_new_node(&mut self, node: (Yaml, usize), mark: Marker) {
        let (mut node_val, aid) = node;
        if let Some((_, depth)) = self.pending_tags.last()
            && self.doc_stack.len() == *depth
        {
            let (tag_name, _) = self.pending_tags.pop().unwrap();
            // A `!Name` shorthand tag is unambiguously a function invocation -
            // unlike a long-form `Fn::Name` map key, which may be a data key -
            // so any unknown tag warrants the unknown-function warning here,
            // where the tag context still exists.
            self.warn_unknown_tag(&tag_name);
            self.record_tagged_spans(&tag_name);
            let wrapped = Self::wrap_with_tag(&tag_name, node_val);
            node_val = wrapped;
        }

        if aid > 0 {
            self.anchor_map.insert(aid, node_val.clone());
        }

        if self.doc_stack.is_empty() {
            self.doc_stack.push((node_val, 0));
            return;
        }

        let parent = self.doc_stack.last_mut().unwrap();
        match parent.0 {
            Yaml::Array(ref mut v) => v.push(node_val),
            Yaml::Hash(ref mut h) => {
                let cur_key = self.key_stack.last_mut().unwrap();
                if cur_key == &Yaml::BadValue {
                    // The node becomes this mapping's pending key. CloudFormation
                    // sections and properties are JSON objects, so a key must be a
                    // scalar: a null key or a collection key has no JSON form and
                    // fails the parse (first offender wins).
                    if self.load_error.is_none() {
                        let (line, column) = Self::mark_position(mark);
                        match &node_val {
                            Yaml::Null | Yaml::BadValue => {
                                self.load_error = Some(ParseError {
                                    message: format!("Null key not supported (line {})", line),
                                    line: Some(line),
                                    column: Some(column),
                                });
                            }
                            Yaml::Hash(_) | Yaml::Array(_) => {
                                self.load_error = Some(ParseError {
                                    message: format!("Complex key not supported (line {})", line),
                                    line: Some(line),
                                    column: Some(column),
                                });
                            }
                            _ => {}
                        }
                    }
                    *cur_key = node_val;
                } else {
                    let key = mem::replace(cur_key, Yaml::BadValue);
                    let key_mark = self.key_marks.last_mut().and_then(|m| m.take());
                    // A plain `<<` key (carried as a merge sentinel) merges the aliased
                    // mapping(s) into this one (resolved in a post-load pass). Its
                    // presence suppresses this mapping's duplicate-key check, matching
                    // how the resolved merge is treated.
                    if is_merge_sentinel(&key)
                        && let Some(flag) = self.mapping_uses_merge.last_mut()
                    {
                        *flag = true;
                        // Use the mark captured above; `self.key_marks.last()` was
                        // already emptied by the `.take()` on the line that set
                        // `key_mark`, so re-reading it here would never match.
                        if let Some((line, col)) = key_mark {
                            self.merge_key_spans.push(SourceSpan {
                                start_line: line,
                                start_column: col,
                                end_line: line,
                                end_column: col + 2,
                            });
                        }
                    }
                    // A repeated key would be silently overwritten by yaml_rust2, so
                    // duplicates are flagged here - at every occurrence, the original
                    // included (it is flagged retroactively when the first duplicate
                    // appears). Buffered per mapping so the whole set can be dropped
                    // if the mapping turns out to merge.
                    let dup_span = |mark: Option<(u32, u32)>, name: &str| {
                        mark.map(|(line, col)| SourceSpan {
                            start_line: line,
                            start_column: col,
                            end_line: line,
                            end_column: col + name.len() as u32,
                        })
                        .unwrap_or(UNKNOWN_SPAN)
                    };
                    // At this point every enclosing frame's slot is committed and
                    // the innermost slot holds the duplicated key, so the path
                    // names the duplicated entry itself - anchoring the diagnostic
                    // at the entity it duplicates.
                    let duplicated_path = path_from_frames(&self.path_frames);
                    if h.insert(key.clone(), node_val).is_some() {
                        if let Some(name) = yaml_key_as_string(&key)
                            && let Some(buffer) = self.pending_dup_diagnostics.last_mut()
                        {
                            // First duplicate: flag the original occurrence too.
                            if let Some(entry) =
                                self.seen_keys.last_mut().and_then(|keys| keys.iter_mut().find(|(k, _, _)| *k == key))
                                && !entry.2
                            {
                                entry.2 = true;
                                buffer.push(crate::make_parse_defect_at(
                                    "F0000",
                                    format!("Duplicate key '{}'", name),
                                    dup_span(entry.1, &name),
                                    &duplicated_path,
                                ));
                            }
                            buffer.push(crate::make_parse_defect_at(
                                "F0000",
                                format!("Duplicate key '{}'", name),
                                dup_span(key_mark, &name),
                                &duplicated_path,
                            ));
                        }
                    } else if let Some(keys) = self.seen_keys.last_mut() {
                        keys.push((key, key_mark, false));
                    }
                }
            }
            _ => unreachable!(),
        }
    }
    /// Returns whether another container may be opened. On the first overrun,
    /// records a located parse error and suppresses every subsequent event so
    /// the loader never constructs a tree deeper than the deterministic bound.
    fn allow_container(&mut self, mark: Marker) -> bool {
        if self.doc_stack.len() < crate::consts::MAX_YAML_NESTING_DEPTH {
            return true;
        }

        if self.load_error.is_none() {
            let (line, column) = Self::mark_position(mark);
            self.load_error = Some(ParseError {
                message: format!(
                    "Template exceeds the maximum structural nesting depth of {} at line {}",
                    crate::consts::MAX_YAML_NESTING_DEPTH,
                    line
                ),
                line: Some(line),
                column: Some(column),
            });
        }
        self.suppress_tree_construction = true;
        false
    }
}

impl MarkedEventReceiver for CfnYamlLoader {
    fn on_event(&mut self, ev: Event, mark: Marker) {
        if self.suppress_tree_construction {
            return;
        }
        match ev {
            Event::DocumentStart => {
                // The first document is the template; any further document has no
                // meaning for CloudFormation and fails the parse after loading.
                if !self.docs.is_empty() && self.second_doc_mark.is_none() {
                    self.second_doc_mark = Some(Self::mark_position(mark));
                }
            }
            Event::Nothing | Event::StreamStart | Event::StreamEnd => {}
            Event::DocumentEnd => match self.doc_stack.len() {
                0 => self.docs.push(Yaml::BadValue),
                1 => self.docs.push(self.doc_stack.pop().unwrap().0),
                _ => {}
            },
            Event::SequenceStart(aid, ref tag) => {
                if !self.allow_container(mark) {
                    return;
                }
                if let Some(tag_name) = Self::cfn_tag_name(tag) {
                    self.pending_tags.push((tag_name, self.doc_stack.len()));
                }
                // Anchor the sequence at its slot in the parent before opening a frame
                // for its elements. As a mapping value this is a no-op (the key already
                // recorded the authoritative position); as a nested element it records
                // the sequence's own start.
                self.record_value_span(mark);
                self.doc_stack.push((Yaml::Array(Vec::new()), aid));
                self.path_frames.push(PathFrame::Seq(0));
            }
            Event::SequenceEnd => {
                self.path_frames.pop();
                let node = self.doc_stack.pop().unwrap();
                self.insert_new_node(node, mark);
                self.advance_after_value();
            }
            Event::MappingStart(aid, ref tag) => {
                if !self.allow_container(mark) {
                    return;
                }
                if let Some(tag_name) = Self::cfn_tag_name(tag) {
                    self.pending_tags.push((tag_name, self.doc_stack.len()));
                }
                self.record_value_span(mark);
                self.doc_stack.push((Yaml::Hash(Hash::new()), aid));
                self.key_stack.push(Yaml::BadValue);
                self.key_marks.push(None);
                self.seen_keys.push(Vec::new());
                self.pending_dup_diagnostics.push(Vec::new());
                self.mapping_uses_merge.push(false);
                self.path_frames.push(PathFrame::Map(None));
            }
            Event::MappingEnd => {
                self.key_stack.pop();
                self.key_marks.pop();
                self.seen_keys.pop();
                // Keep this mapping's buffered duplicate diagnostics only if it did not
                // use a merge key; a merge-bearing mapping suppresses its dup check.
                let buffered = self.pending_dup_diagnostics.pop().unwrap_or_default();
                if !self.mapping_uses_merge.pop().unwrap_or(false) {
                    self.dup_key_diagnostics.extend(buffered);
                }
                self.path_frames.pop();
                let node = self.doc_stack.pop().unwrap();
                self.insert_new_node(node, mark);
                self.advance_after_value();
            }
            Event::Scalar(v, style, aid, ref tag) => {
                let cfn_tag = Self::cfn_tag_name(tag);
                let is_key = self.placing_map_key();
                // A recognized explicit core-schema tag overrides both style and
                // content. Invalid lexical content records a hard parse error at
                // the tagged scalar; unknown core tags retain their prior scalar
                // handling because this parser does not assign them a type.
                let core_tagged = tag
                    .as_ref()
                    .filter(|tag| tag.handle == CORE_TAG_HANDLE)
                    .map(|tag| resolve_core_tagged_scalar(&tag.suffix, &v));
                let node = match core_tagged {
                    Some(Ok(Some(resolved))) => resolved,
                    Some(Err(message)) => {
                        if self.load_error.is_none() {
                            let (line, column) = Self::mark_position(mark);
                            self.load_error = Some(ParseError {
                                message: format!("YAML parse error: {}", message),
                                line: Some(line),
                                column: Some(column),
                            });
                        }
                        Yaml::BadValue
                    }
                    Some(Ok(None)) | None if style != yaml_rust2::scanner::TScalarStyle::Plain => {
                        Yaml::String(v.clone())
                    }
                    Some(Ok(None)) | None => resolve_plain_scalar(&v),
                };
                // Only a *plain*, untagged `<<` in key position is the YAML 1.1 merge
                // indicator; a quoted `'<<'` is an ordinary key. Carry the merge as a
                // unique sentinel so the two stay distinguishable downstream.
                let is_merge_key =
                    is_key && style == yaml_rust2::scanner::TScalarStyle::Plain && tag.is_none() && v == YAML_MERGE_KEY;
                let node = if is_merge_key {
                    self.merge_key_count += 1;
                    Yaml::Alias(MERGE_KEY_SENTINEL_BASE + self.merge_key_count)
                } else {
                    node
                };

                if is_key {
                    // This scalar names the slot its sibling value will occupy; put it in
                    // the frame so the value's path is complete, then anchor the property
                    // at the key (object-property diagnostics anchor at the key). The
                    // slot uses the key's *coerced string form* - the same string
                    // [`yaml_key_as_string`] later gives the builder - so a key that
                    // resolves to a non-string scalar (`On:`, `010:`) is anchored at the
                    // path the builder actually produces.
                    let slot_name = yaml_key_as_string(&node).unwrap_or_else(|| v.clone());
                    if let Some(PathFrame::Map(slot)) = self.path_frames.last_mut() {
                        *slot = Some(slot_name);
                    }
                    self.record_key_span(mark);
                    // Remember this key's position so a later duplicate of it can be
                    // anchored at the offending occurrence.
                    if let Some(slot) = self.key_marks.last_mut() {
                        *slot = Some(Self::mark_position(mark));
                    }
                } else if matches!(self.doc_stack.last(), Some((Yaml::Array(_), _))) {
                    // A sequence element: no key precedes it, so anchor it at itself.
                    self.record_value_span(mark);
                }

                if let Some(tag_name) = cfn_tag {
                    self.warn_unknown_tag(&tag_name);
                    self.record_tagged_spans(&tag_name);
                    let wrapped = Self::wrap_with_tag(&tag_name, node);
                    self.insert_new_node((wrapped, aid), mark);
                } else {
                    self.insert_new_node((node, aid), mark);
                }
                if !is_key {
                    self.advance_after_value();
                }
            }
            Event::Alias(id) => {
                let n = self.anchor_map.get(&id).cloned().unwrap_or(Yaml::BadValue);
                // An alias resolves to an anchored value, so it is always a value or
                // sequence element (never a key); anchor a sequence element at itself.
                if matches!(self.doc_stack.last(), Some((Yaml::Array(_), _))) {
                    self.record_value_span(mark);
                }
                self.insert_new_node((n, 0), mark);
                self.advance_after_value();
            }
        }
    }
}

/// A borrowed view over a `yaml_rust2::Yaml` implementing the format-agnostic
/// [`ParseValue`] so the shared [`Builder`] can construct the IR.
///
/// A YAML mapping key may be a non-string scalar; such entries are dropped by
/// [`ParseValue::as_object`] since CloudFormation section/property keys are strings.
#[derive(Clone, Copy)]
struct YamlValue<'a>(&'a Yaml);

impl<'a> ParseValue for YamlValue<'a> {
    fn kind(&self) -> ValueKind {
        match self.0 {
            Yaml::Null | Yaml::BadValue => ValueKind::Null,
            Yaml::Boolean(_) => ValueKind::Bool,
            Yaml::Integer(_) | Yaml::Real(_) => ValueKind::Number,
            Yaml::String(_) => ValueKind::String,
            Yaml::Array(_) => ValueKind::Array,
            Yaml::Hash(_) => ValueKind::Object,
            // Aliases are resolved to their anchored value at load time, so a
            // surviving Alias is a dangling reference; treat as null.
            Yaml::Alias(_) => ValueKind::Null,
        }
    }

    fn as_coerced_str(&self) -> Option<String> {
        match self.0 {
            Yaml::String(s) => Some(s.clone()),
            Yaml::Integer(i) => Some(i.to_string()),
            Yaml::Real(s) => Some(s.clone()),
            Yaml::Boolean(b) => Some(b.to_string()),
            _ => None,
        }
    }

    fn as_array(&self) -> Option<Vec<Self>> {
        self.0.as_vec().map(|arr| arr.iter().map(YamlValue).collect())
    }

    fn as_object(&self) -> Option<Vec<(String, Self)>> {
        let hash = self.0.as_hash()?;
        // Distinct YAML scalar keys can coerce to the same string (e.g. the bare
        // integer `1` and the quoted `"1"`). CloudFormation, JSON, and every
        // downstream consumer treat a mapping as string-keyed with the last entry
        // winning, so collapse such collisions here - keeping the last occurrence -
        // rather than emit a `Node::Map` carrying two identical string keys. This is
        // purely structural: it changes no diagnostic (duplicate-key detection runs
        // over the raw YAML keys at load time, where `1` and `"1"` are already
        // distinct and correctly not flagged).
        let mut entries: Vec<(String, Self)> = Vec::with_capacity(hash.len());
        for (k, v) in hash.iter() {
            let Some(key) = yaml_key_as_string(k) else {
                continue;
            };
            if let Some(existing) = entries.iter_mut().find(|(ek, _)| *ek == key) {
                existing.1 = YamlValue(v);
            } else {
                entries.push((key, YamlValue(v)));
            }
        }
        Some(entries)
    }

    fn as_integer(&self) -> Option<i64> {
        match self.0 {
            Yaml::Integer(i) => Some(*i),
            _ => None,
        }
    }

    fn describe_scalar(&self) -> String {
        match self.0 {
            Yaml::Null | Yaml::BadValue => "null".to_string(),
            Yaml::Boolean(b) => b.to_string(),
            Yaml::Integer(i) => i.to_string(),
            Yaml::Real(r) => r.clone(),
            Yaml::String(s) => format!("'{}'", s),
            Yaml::Alias(_) => "null".to_string(),
            // Composites are handled by describe_value; unreachable for scalars.
            Yaml::Array(_) | Yaml::Hash(_) => String::new(),
        }
    }

    fn scalar_node(&self) -> Node {
        match self.0 {
            Yaml::Null | Yaml::BadValue | Yaml::Alias(_) => Node::Null,
            Yaml::Boolean(b) => Node::Bool(*b),
            Yaml::Integer(i) => Node::Int(*i),
            // Reuse yaml_rust2's own float parser so the numeric value matches the
            // source token that as_coerced_str/describe_scalar report - it maps the
            // YAML float spellings `.inf`/`.nan`/`-.inf` that Rust's std parser
            // rejects. A Yaml::Real is only produced when that parser accepted the
            // string, so as_f64 is always Some here; NAN (never a silently-plausible
            // value like 0.0) is the sentinel if that invariant were ever broken.
            Yaml::Real(_) => Node::Float(self.0.as_f64().unwrap_or(f64::NAN)),
            Yaml::String(s) => Node::String(s.clone()),
            // Composites are built by Builder::build; unreachable for scalars.
            Yaml::Array(_) | Yaml::Hash(_) => Node::Null,
        }
    }
}

/// A mapping key coerced to its string form (CloudFormation keys are strings, but
/// YAML permits integer/bool scalar keys).
fn yaml_key_as_string(y: &Yaml) -> Option<String> {
    match y {
        Yaml::String(s) => Some(s.clone()),
        Yaml::Integer(i) => Some(i.to_string()),
        Yaml::Real(s) => Some(s.clone()),
        Yaml::Boolean(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Resolves YAML 1.1 merge keys (`<<`) throughout the tree, in place.
///
/// `yaml_rust2` does not implement merge keys, so a `<<: <alias>` entry survives to
/// this pass as a merge-sentinel key whose value is the already-resolved aliased
/// mapping (or a sequence of them). Left alone this both injects a spurious
/// property and hides the aliased members. Here each merge entry is spliced into
/// its enclosing mapping: explicit keys always win over merged ones, and among
/// multiple merge sources the earlier one wins over the later (YAML 1.1). Explicit
/// keys keep their original positions; merged-only members are appended after them.
/// A quoted `'<<'` is an ordinary key (no sentinel) and survives as a property.
fn resolve_merge_keys(node: &mut Yaml) {
    match node {
        Yaml::Hash(hash) => {
            let original = std::mem::take(hash);
            let mut merge_sources: Vec<Yaml> = Vec::new();
            let mut resolved = Hash::new();
            for (key, value) in original {
                if is_merge_sentinel(&key) {
                    merge_sources.push(value);
                } else {
                    // Explicit keys win: a genuine duplicate explicit key keeps
                    // yaml_rust2's last-wins behavior (already flagged as F0000).
                    resolved.insert(key, value);
                }
            }
            // Earlier merge sources win over later ones, so only insert a merged
            // member when neither an explicit key nor an earlier merge supplied it.
            // Each source is a load-time clone of the anchored mapping, so any merge
            // key the anchor itself used is still unresolved inside it; resolve the
            // source first so nested `<<` is flattened before its members are spliced.
            for mut source in merge_sources {
                resolve_merge_keys(&mut source);
                match source {
                    Yaml::Hash(members) => merge_members(&mut resolved, members),
                    // A `<<: [*a, *b]` sequence merges each mapping in order.
                    Yaml::Array(items) => {
                        for item in items {
                            if let Yaml::Hash(members) = item {
                                merge_members(&mut resolved, members);
                            }
                        }
                    }
                    // A non-mapping merge value is malformed YAML; drop it (removing
                    // the spurious `<<` property) rather than inject a bogus member.
                    _ => {}
                }
            }
            // Resolve merges nested inside the explicit values. Merged-in values were
            // already resolved above, so re-visiting them here is a harmless no-op.
            for (_, value) in resolved.iter_mut() {
                resolve_merge_keys(value);
            }
            *hash = resolved;
        }
        Yaml::Array(items) => {
            for item in items.iter_mut() {
                resolve_merge_keys(item);
            }
        }
        _ => {}
    }
}

/// Inserts each member of a merge source into `target`, skipping keys already
/// present so explicit keys and earlier merge sources take precedence.
fn merge_members(target: &mut Hash, members: Hash) {
    for (key, value) in members {
        if !target.contains_key(&key) {
            target.insert(key, value);
        }
    }
}

pub fn parse_yaml(bytes: &[u8]) -> Result<TemplateIR, ParseError> {
    let text = from_utf8(bytes).map_err(|e| ParseError {
        message: format!("Invalid UTF-8: {}", e),
        line: None,
        column: None,
    })?;

    let LoadedYaml { mut docs, span_map: raw_spans, dup_key_diagnostics, merge_key_spans } = CfnYamlLoader::load(text)?;

    if docs.is_empty() {
        return Err(ParseError { message: "Empty YAML document".into(), line: Some(1), column: Some(1) });
    }

    if docs[0].as_hash().is_none() {
        return Err(ParseError {
            message: "Template root must be a YAML mapping".into(),
            line: Some(1),
            column: Some(1),
        });
    }

    // Splice any YAML merge keys (`<<`) into their enclosing mappings before building
    // the IR, so aliased members appear inline and no spurious `<<` property remains.
    resolve_merge_keys(&mut docs[0]);

    let mut builder = Builder::new();
    builder.diagnostics = dup_key_diagnostics;
    for span in merge_key_spans {
        builder.diagnostics.push(crate::make_parse_defect(
            "W1100",
            "YAML merge key '<<' is not supported by CloudFormation - use 'aws cloudformation package' to pre-process"
                .to_string(),
            span,
        ));
    }
    let root = builder.build_map(&YamlValue(&docs[0]), "");

    let sections = TemplateSections::extract(&builder.arena, root);

    for (path, (line, col)) in &raw_spans {
        builder.span_index.insert(
            path.clone(),
            SourceSpan {
                start_line: *line,
                start_column: *col,
                end_line: *line,
                end_column: *col + path.rsplit('/').next().unwrap_or(path).len() as u32,
            },
        );
    }
    info!("YAML span assignment complete: {} entries from marker tracking", builder.span_index.len());

    debug!(
        "YAML IR built: {} resources, {} parameters, {} mappings, {} conditions, {} outputs, {} span entries",
        builder.arena.as_map(sections.resources).map(|m| m.len()).unwrap_or(0),
        builder.arena.as_map(sections.parameters).map(|m| m.len()).unwrap_or(0),
        builder.arena.as_map(sections.mappings).map(|m| m.len()).unwrap_or(0),
        builder.arena.as_map(sections.conditions).map(|m| m.len()).unwrap_or(0),
        builder.arena.as_map(sections.outputs).map(|m| m.len()).unwrap_or(0),
        builder.span_index.len()
    );
    if !builder.diagnostics.is_empty() {
        warn!("{} parse diagnostics from YAML (malformed intrinsics)", builder.diagnostics.len());
    }

    Ok(sections.into_ir(builder))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A genuine same-string-key duplicate produces the identical F0000 message in
    /// both formats - the two duplicate detectors (JSON byte scan, YAML load-time
    /// Hash) must agree on which duplicates fire.
    #[test]
    fn duplicate_string_key_matches_across_formats() {
        let json = crate::parser::json::parse_json(b"{\n\"Resources\":{\n\"A\":{},\n\"A\":{}\n}\n}\n").unwrap();
        let yaml = parse_yaml(b"Resources:\n  A: {}\n  A: {}\n").unwrap();
        let entries = |ir: &TemplateIR| -> Vec<(String, u32)> {
            ir.diagnostics
                .iter()
                .filter(|d| d.rule_id == "F0000")
                .map(|d| (d.message.clone(), d.span.start_line))
                .collect()
        };
        // Both occurrences are flagged - the original line and the duplicate line.
        assert_eq!(entries(&json), [("Duplicate key 'A'".to_string(), 3), ("Duplicate key 'A'".to_string(), 4)]);
        assert_eq!(entries(&yaml), [("Duplicate key 'A'".to_string(), 2), ("Duplicate key 'A'".to_string(), 3)]);
    }

    #[test]
    fn integer_key_and_string_key_are_not_duplicates() {
        let input = "Resources:\n  R:\n    Type: AWS::S3::Bucket\n    Metadata:\n      1: a\n      \"1\": b\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        assert!(
            ir.diagnostics.iter().all(|d| d.rule_id != "F0000"),
            "a bare int key and a quoted string key must not be flagged as duplicates"
        );
    }

    #[test]
    fn parse_minimal_yaml() {
        let input = "AWSTemplateFormatVersion: \"2010-09-09\"\nResources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: my-bucket\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        assert_eq!(ir.format_version.as_deref(), Some("2010-09-09"));
        assert_eq!(ir.arena.as_map(ir.resources).unwrap().len(), 1);
    }

    /// Span-index paths must carry the array index, matching the paths the shared
    /// builder assigns. A key inside an array element (`Ingress/1/Port`) and a scalar
    /// array element (`Cidrs/1`) each get their own span, so a diagnostic on them
    /// anchors at the offending line rather than walking up to the enclosing array.
    #[test]
    fn array_element_spans_include_index() {
        //             1          2       3      4              5           6            7             8              9
        let input = "Resources:\n  R:\n    Type: T\n    Properties:\n      Ingress:\n      - Port: 80\n      - Port: 443\n      Cidrs:\n      - 10.0.0.0/16\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let line = |path: &str| ir.span_index.get(path).map(|s| s.start_line);
        // Keys inside distinct array elements resolve to distinct element lines,
        // never collapsing onto a single index-less `Ingress/Port` key.
        assert_eq!(line("Resources/R/Properties/Ingress/0/Port"), Some(6));
        assert_eq!(line("Resources/R/Properties/Ingress/1/Port"), Some(7));
        assert!(line("Resources/R/Properties/Ingress/Port").is_none(), "index-less array key must not exist");
        // A scalar array element is anchored at itself.
        assert_eq!(line("Resources/R/Properties/Cidrs/0"), Some(9));
    }

    #[test]
    fn shorthand_intrinsic_sequence_child_spans_include_function_path() {
        let input = "Resources:\n  R:\n    Type: T\n    Properties:\n      AvailabilityZone: !Select\n      - invalid-index\n      - !GetAZs ''\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let line = |path: &str| ir.span_index.get(path).map(|span| span.start_line);

        assert_eq!(line("Resources/R/Properties/AvailabilityZone/Fn::Select/0"), Some(6));
        assert_eq!(line("Resources/R/Properties/AvailabilityZone/Fn::Select/1/Fn::GetAZs"), Some(7));
    }

    #[test]
    fn parse_tag_form_ref() {
        let input = "Resources:\n  R:\n    Type: T\n    Properties:\n      VpcId: !Ref myVpcId\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let res = ir.arena.as_map(ir.resources).unwrap();
        let props = ir.arena.map_get(res[0].1, "Properties").unwrap();
        let v = ir.arena.map_get(props, "VpcId").unwrap();
        match ir.arena.node(v) {
            Node::Intrinsic(IntrinsicFn::Ref(t)) => assert_eq!(t, "myVpcId"),
            o => panic!("Expected Ref, got {:?}", o),
        }
    }

    #[test]
    fn parse_tag_form_getatt() {
        let input = "Resources:\n  R:\n    Type: T\n    Properties:\n      Role: !GetAtt LambdaRole.Arn\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let res = ir.arena.as_map(ir.resources).unwrap();
        let props = ir.arena.map_get(res[0].1, "Properties").unwrap();
        let v = ir.arena.map_get(props, "Role").unwrap();
        match ir.arena.node(v) {
            Node::Intrinsic(IntrinsicFn::GetAtt(r, a)) => {
                assert_eq!(r, "LambdaRole");
                assert_eq!(a, "Arn");
            }
            o => panic!("Expected GetAtt, got {:?}", o),
        }
    }

    #[test]
    fn parse_if_intrinsic() {
        let input = "Resources:\n  R:\n    Type: T\n    Properties:\n      Val:\n        Fn::If:\n          - IsProd\n          - prod\n          - dev\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let res = ir.arena.as_map(ir.resources).unwrap();
        let props = ir.arena.map_get(res[0].1, "Properties").unwrap();
        let v = ir.arena.map_get(props, "Val").unwrap();
        match ir.arena.node(v) {
            Node::Intrinsic(IntrinsicFn::If(c, _, _)) => assert_eq!(c, "IsProd"),
            o => panic!("Expected If, got {:?}", o),
        }
    }

    #[test]
    fn parse_invalid_yaml() {
        parse_yaml(b"{{invalid").unwrap_err();
    }

    #[test]
    fn yaml_json_equivalence() {
        let y = parse_yaml(b"Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: test\n")
            .unwrap();
        let j = super::super::json::parse_json(
            br#"{"Resources":{"B":{"Type":"AWS::S3::Bucket","Properties":{"BucketName":"test"}}}}"#,
        )
        .unwrap();
        assert_eq!(y.arena.as_map(y.resources).unwrap().len(), j.arena.as_map(j.resources).unwrap().len());
    }

    #[test]
    fn parse_inline_ref_in_flow_sequence() {
        let input = "Conditions:\n  C:\n    Fn::Equals: [!Ref Env, Prod]\nResources:\n  R:\n    Type: T\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let conds = ir.arena.as_map(ir.conditions).unwrap();
        match ir.arena.node(conds[0].1) {
            Node::Intrinsic(IntrinsicFn::Equals(a, _)) => match ir.arena.node(*a) {
                Node::Intrinsic(IntrinsicFn::Ref(t)) => assert_eq!(t, "Env"),
                o => panic!("Expected Ref, got {:?}", o),
            },
            o => panic!("Expected Equals, got {:?}", o),
        }
    }

    #[test]
    fn parse_sub_block_scalar() {
        let input = "Resources:\n  R:\n    Type: T\n    Properties:\n      UserData: !Sub |\n        yum install pkg\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let res = ir.arena.as_map(ir.resources).unwrap();
        let props = ir.arena.map_get(res[0].1, "Properties").unwrap();
        let v = ir.arena.map_get(props, "UserData").unwrap();
        match ir.arena.node(v) {
            Node::Intrinsic(IntrinsicFn::Sub(t, _)) => assert!(t.contains("yum")),
            o => panic!("Expected Sub, got {:?}", o),
        }
    }

    /// YAML object keys are preserved in source order, matching the JSON parser.
    #[test]
    fn yaml_object_key_order_preserved() {
        let input = "Resources:\n  Zebra:\n    Type: AWS::S3::Bucket\n  Apple:\n    Type: AWS::S3::Bucket\n  Mango:\n    Type: AWS::S3::Bucket\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let res = ir.arena.as_map(ir.resources).unwrap();
        let names: Vec<&str> = res.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(names, vec!["Zebra", "Apple", "Mango"]);
    }

    /// Full-form `Fn::Not: [{Fn::Contains: ...}]` in YAML must not produce
    /// a type error - `Fn::Contains` is a boolean-producing Rules-section
    /// intrinsic, not a non-boolean expression.
    #[test]
    fn fn_not_accepts_fn_contains_argument_no_e8005() {
        let input = "Parameters:\n  BootstrapVersion:\n    Type: String\nResources:\n  B:\n    Type: AWS::S3::Bucket\nRules:\n  CheckBootstrapVersion:\n    Assertions:\n      - Assert:\n          Fn::Not:\n            - Fn::Contains:\n                - [\"1\", \"2\", \"3\", \"4\", \"5\"]\n                - Ref: BootstrapVersion\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let shape_errors: Vec<_> = ir.diagnostics.iter().filter(|d| d.rule_id == "E8005").collect();
        assert!(shape_errors.is_empty(), "Expected no E8005 for Fn::Not(Fn::Contains), got: {:?}", shape_errors);
    }

    #[test]
    fn fn_not_with_string_argument_produces_e8005() {
        let input = "Resources:\n  B:\n    Type: AWS::S3::Bucket\nConditions:\n  Bad:\n    Fn::Not:\n      - definitely-not-boolean\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        assert!(
            ir.diagnostics.iter().any(|d| d.rule_id == "E8005"
                && d.message.contains("Fn::Not")
                && d.message.contains("is not of type 'boolean'")),
            "Expected E8005 for Fn::Not with string arg, got: {:?}",
            ir.diagnostics
        );
    }

    /// Collects the E1033 messages a parsed template produced, in source order.
    fn e1033_messages(ir: &TemplateIR) -> Vec<&str> {
        ir.diagnostics.iter().filter(|d| d.rule_id == "E1033").map(|d| d.message.as_str()).collect()
    }

    #[test]
    fn parse_get_stack_output_full_form_builds_intrinsic() {
        let input = "Resources:\n  R:\n    Type: AWS::SNS::Topic\n    Properties:\n      DisplayName:\n        Fn::GetStackOutput:\n          StackName: s\n          OutputName: o\n          Region: us-east-1\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let res = ir.arena.as_map(ir.resources).unwrap();
        let props = ir.arena.map_get(res[0].1, "Properties").unwrap();
        let name = ir.arena.map_get(props, "DisplayName").unwrap();
        match ir.arena.node(name) {
            Node::Intrinsic(IntrinsicFn::GetStackOutput(args)) => {
                let keys: Vec<&str> = args.iter().map(|(k, _)| k.as_str()).collect();
                assert_eq!(keys, ["StackName", "OutputName", "Region"]);
            }
            o => panic!("Expected GetStackOutput, got {:?}", o),
        }
        assert!(e1033_messages(&ir).is_empty(), "well-formed call must not emit E1033");
    }

    /// The YAML-only `!GetStackOutput` shorthand tag with a block-mapping argument
    /// must build the same intrinsic as the full `Fn::GetStackOutput` form.
    #[test]
    fn parse_get_stack_output_short_tag_block_mapping() {
        let input = "Resources:\n  R:\n    Type: AWS::SNS::Topic\n    Properties:\n      DisplayName: !GetStackOutput\n        StackName: s\n        OutputName: o\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let res = ir.arena.as_map(ir.resources).unwrap();
        let props = ir.arena.map_get(res[0].1, "Properties").unwrap();
        let name = ir.arena.map_get(props, "DisplayName").unwrap();
        match ir.arena.node(name) {
            Node::Intrinsic(IntrinsicFn::GetStackOutput(args)) => {
                let keys: Vec<&str> = args.iter().map(|(k, _)| k.as_str()).collect();
                assert_eq!(keys, ["StackName", "OutputName"]);
            }
            o => panic!("Expected GetStackOutput from short tag, got {:?}", o),
        }
        assert!(e1033_messages(&ir).is_empty(), "well-formed short-tag call must not emit E1033");
    }

    /// The `!GetStackOutput` shorthand with a flow-mapping argument (`{...}`).
    #[test]
    fn parse_get_stack_output_short_tag_flow_mapping() {
        let input = "Resources:\n  R:\n    Type: AWS::SNS::Topic\n    Properties:\n      DisplayName: !GetStackOutput {StackName: s, OutputName: o}\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let res = ir.arena.as_map(ir.resources).unwrap();
        let props = ir.arena.map_get(res[0].1, "Properties").unwrap();
        let name = ir.arena.map_get(props, "DisplayName").unwrap();
        assert!(
            matches!(ir.arena.node(name), Node::Intrinsic(IntrinsicFn::GetStackOutput(_))),
            "flow-mapping short tag should build GetStackOutput, got {:?}",
            ir.arena.node(name)
        );
        assert!(e1033_messages(&ir).is_empty(), "well-formed flow-mapping call must not emit E1033");
    }

    #[test]
    fn parse_get_stack_output_full_form_missing_required_emits_e1033() {
        let input = "Resources:\n  R:\n    Type: AWS::SNS::Topic\n    Properties:\n      DisplayName:\n        Fn::GetStackOutput:\n          StackName: s\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        assert_eq!(e1033_messages(&ir), ["'OutputName' is a required property"]);
    }

    #[test]
    fn parse_get_stack_output_short_tag_missing_required_emits_e1033() {
        let input = "Resources:\n  R:\n    Type: AWS::SNS::Topic\n    Properties:\n      DisplayName: !GetStackOutput\n        OutputName: o\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        assert_eq!(e1033_messages(&ir), ["'StackName' is a required property"]);
    }

    #[test]
    fn parse_get_stack_output_short_tag_additional_property_emits_e1033() {
        let input = "Resources:\n  R:\n    Type: AWS::SNS::Topic\n    Properties:\n      DisplayName: !GetStackOutput\n        StackName: s\n        OutputName: o\n        Bad: v\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        assert_eq!(e1033_messages(&ir), ["Additional properties are not allowed ('Bad' was unexpected)"]);
    }

    #[test]
    fn parse_get_stack_output_short_tag_non_object_emits_e1033_and_falls_through() {
        let input = "Resources:\n  R:\n    Type: AWS::SNS::Topic\n    Properties:\n      DisplayName: !GetStackOutput invalid\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        assert_eq!(e1033_messages(&ir), ["'invalid' is not of type 'object'"]);
        // A malformed (non-object) argument cannot form the intrinsic, so the node
        // stays a plain scalar rather than becoming an IntrinsicFn::GetStackOutput.
        let res = ir.arena.as_map(ir.resources).unwrap();
        let props = ir.arena.map_get(res[0].1, "Properties").unwrap();
        let name = ir.arena.map_get(props, "DisplayName").unwrap();
        assert!(
            !matches!(ir.arena.node(name), Node::Intrinsic(_)),
            "non-object arg should not build an intrinsic, got {:?}",
            ir.arena.node(name)
        );
    }

    #[test]
    fn parse_get_stack_output_in_resource_metadata_emits_e1033() {
        let input = "Resources:\n  R:\n    Type: AWS::SNS::Topic\n    Properties:\n      DisplayName: ok\n    Metadata:\n      M:\n        Fn::GetStackOutput:\n          StackName: s\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        assert_eq!(e1033_messages(&ir), ["'OutputName' is a required property"]);
    }

    #[test]
    fn parse_get_stack_output_in_parameter_default_does_not_emit_e1033() {
        // As with JSON: CloudFormation never evaluates intrinsics in a parameter
        // Default, so E1033 must not fire there (E2001 covers it instead).
        let input = "Parameters:\n  P:\n    Type: String\n    Default: !GetStackOutput\n      StackName: s\nResources:\n  R:\n    Type: AWS::SNS::Topic\n    Properties:\n      DisplayName: !Ref P\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        assert!(e1033_messages(&ir).is_empty(), "E1033 must not fire for a call in a parameter Default");
    }

    #[test]
    fn parse_get_stack_output_nested_in_join_does_not_emit_e1033() {
        let input = "Resources:\n  R:\n    Type: AWS::SNS::Topic\n    Properties:\n      DisplayName: !Join\n        - '-'\n        - - x\n          - !GetStackOutput\n            StackName: s\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        assert!(e1033_messages(&ir).is_empty(), "E1033 must not fire for a call nested inside another function");
    }

    /// The full `Fn::GetStackOutput` form and the `!GetStackOutput` shorthand must
    /// build the identical IR - the shared builder guarantees JSON/YAML parity, and
    /// this pins that the YAML tag path funnels through it too.
    #[test]
    fn parse_get_stack_output_short_tag_matches_full_form() {
        let tag = parse_yaml(
            "Resources:\n  R:\n    Type: AWS::SNS::Topic\n    Properties:\n      DisplayName: !GetStackOutput\n        StackName: s\n        OutputName: o\n"
                .as_bytes(),
        )
        .unwrap();
        let full = parse_yaml(
            "Resources:\n  R:\n    Type: AWS::SNS::Topic\n    Properties:\n      DisplayName:\n        Fn::GetStackOutput:\n          StackName: s\n          OutputName: o\n"
                .as_bytes(),
        )
        .unwrap();
        for ir in [&tag, &full] {
            let res = ir.arena.as_map(ir.resources).unwrap();
            let props = ir.arena.map_get(res[0].1, "Properties").unwrap();
            let name = ir.arena.map_get(props, "DisplayName").unwrap();
            match ir.arena.node(name) {
                Node::Intrinsic(IntrinsicFn::GetStackOutput(args)) => {
                    let keys: Vec<&str> = args.iter().map(|(k, _)| k.as_str()).collect();
                    assert_eq!(keys, ["StackName", "OutputName"]);
                }
                o => panic!("Expected GetStackOutput, got {:?}", o),
            }
            assert!(e1033_messages(ir).is_empty());
        }
    }

    #[test]
    fn unknown_fn_long_form_far_from_any_function_is_data() {
        // The long map-key form is ambiguous (it may be a data key), so only
        // near-miss typos warn; `Fn::Bogus` is left to schema validation.
        let input = "Resources:\n  R:\n    Type: T\n    Properties:\n      P:\n        Fn::Bogus: hello\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let w1103: Vec<&str> =
            ir.diagnostics.iter().filter(|d| d.rule_id == "W1103").map(|d| d.message.as_str()).collect();
        assert!(w1103.is_empty(), "got: {:?}", w1103);
    }

    /// A misspelled or unknown `!`-shorthand tag (`!Bogus`) is wrapped into
    /// `{ Fn::Bogus: ... }` exactly like the long form and JSON, so the shared
    /// unsupported-function check fires. Silently dropping the tag (the previous
    /// behavior) would hide a real authoring mistake.
    #[test]
    fn unknown_fn_short_tag_form_emits_w1103() {
        // A `!Name` tag is unambiguously a function attempt, so any unknown
        // tag warns - unlike the ambiguous long map-key form.
        let input = "Resources:\n  R:\n    Type: T\n    Properties:\n      P: !Bogus hello\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let w1103: Vec<&str> =
            ir.diagnostics.iter().filter(|d| d.rule_id == "W1103").map(|d| d.message.as_str()).collect();
        assert_eq!(w1103, ["'!Bogus' is not a supported function"]);
    }

    /// A wrong-case shorthand tag (`!GetAttt`, a typo of `!GetAtt`) is not in the
    /// recognized-tag table, so it is wrapped as `{ Fn::GetAttt: ... }` and flagged
    /// as unsupported - matching both the long `Fn::GetAttt` form and JSON.
    #[test]
    fn wrong_case_short_tag_emits_w1103() {
        let input =
            "Resources:\n  R:\n    Type: AWS::SNS::Topic\n    Properties:\n      TopicName: !GetAttt [R, Arn]\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let w1103: Vec<&str> =
            ir.diagnostics.iter().filter(|d| d.rule_id == "W1103").map(|d| d.message.as_str()).collect();
        assert_eq!(w1103, ["'Fn::GetAttt' is not a supported function - did you mean 'Fn::GetAtt'?"]);
    }

    /// The unknown-tag YAML shorthand and the equivalent JSON long form emit the
    /// identical W1103 - the shared builder guarantees the diagnostic cannot drift
    /// between formats once the tag is wrapped.
    #[test]
    fn unknown_short_tag_warns_where_long_form_is_data() {
        // The tag form is unambiguous function syntax and warns; the long
        // map-key form is potentially a data key and stays silent (schema
        // validation owns any type mismatch there).
        let tag_input = "Resources:\n  R:\n    Type: T\n    Properties:\n      P: !Bogus x\n";
        let tag_ir = parse_yaml(tag_input.as_bytes()).unwrap();
        assert!(tag_ir.diagnostics.iter().any(|d| d.rule_id == "W1103"), "tag form warns");
        let long_input = "Resources:\n  R:\n    Type: T\n    Properties:\n      P:\n        Fn::Bogus: x\n";
        let long_ir = parse_yaml(long_input.as_bytes()).unwrap();
        assert!(long_ir.diagnostics.iter().all(|d| d.rule_id != "W1103"), "long form is data");
    }

    /// A secondary-handle tag (`!!str`) is not a CloudFormation intrinsic shorthand
    /// and must not be wrapped into an `Fn::` map or trigger W1103 - only primary
    /// (`!`-handle) tags are intrinsic candidates.
    #[test]
    fn secondary_handle_tag_is_not_wrapped() {
        let input = "Resources:\n  R:\n    Type: AWS::SNS::Topic\n    Properties:\n      TopicName: !!str hello\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        assert!(ir.diagnostics.iter().all(|d| d.rule_id != "W1103"), "a `!!`-handle tag must not trigger W1103");
        let res = ir.arena.as_map(ir.resources).unwrap();
        let props = ir.arena.map_get(res[0].1, "Properties").unwrap();
        let name = ir.arena.map_get(props, "TopicName").unwrap();
        assert_eq!(ir.arena.as_str(name), Some("hello"), "`!!str hello` must stay the plain string 'hello'");
    }

    /// Builds the scalar `Node` for a bare plain YAML scalar the way the loader
    /// does (`Yaml::from_str`), so float-spelling handling in `scalar_node` can be
    /// asserted directly.
    fn scalar_node_of(token: &str) -> Node {
        let y = Yaml::from_str(token);
        YamlValue(&y).scalar_node()
    }

    /// The IEEE float spellings YAML accepts (`.inf`/`.nan`/`-.inf`) must map to the
    /// real IEEE values, not a silently-wrong 0.0, and the numeric `Node` must agree
    /// with the verbatim token `as_coerced_str` returns.
    #[test]
    fn scalar_node_yaml_infinity_matches_source_token() {
        let y = Yaml::from_str(".inf");
        assert!(matches!(y, Yaml::Real(_)), "`.inf` must scan as a Real, got {:?}", y);
        let v = YamlValue(&y);
        match v.scalar_node() {
            Node::Float(f) => assert!(f.is_infinite() && f.is_sign_positive(), "expected +inf, got {}", f),
            o => panic!("expected Node::Float(inf), got {:?}", o),
        }
        assert_eq!(v.as_coerced_str().as_deref(), Some(".inf"), "coerced string must be the source token");
    }

    #[test]
    fn scalar_node_yaml_negative_infinity() {
        match scalar_node_of("-.inf") {
            Node::Float(f) => assert!(f.is_infinite() && f.is_sign_negative(), "expected -inf, got {}", f),
            o => panic!("expected Node::Float(-inf), got {:?}", o),
        }
    }

    #[test]
    fn scalar_node_yaml_nan() {
        let y = Yaml::from_str(".nan");
        assert!(matches!(y, Yaml::Real(_)), "`.nan` must scan as a Real, got {:?}", y);
        let v = YamlValue(&y);
        match v.scalar_node() {
            Node::Float(f) => assert!(f.is_nan(), "expected NaN, got {}", f),
            o => panic!("expected Node::Float(NaN), got {:?}", o),
        }
        assert_eq!(v.as_coerced_str().as_deref(), Some(".nan"), "coerced string must be the source token");
    }

    #[test]
    fn scalar_node_ordinary_float_unchanged() {
        match scalar_node_of("3.14") {
            Node::Float(f) => assert!((f - 3.14).abs() < f64::EPSILON, "expected 3.14, got {}", f),
            o => panic!("expected Node::Float(3.14), got {:?}", o),
        }
    }

    #[test]
    fn scalar_node_exponent_float_unchanged() {
        match scalar_node_of("1e6") {
            Node::Float(f) => assert!((f - 1_000_000.0).abs() < f64::EPSILON, "expected 1e6, got {}", f),
            o => panic!("expected Node::Float(1e6), got {:?}", o),
        }
    }

    /// A `<<` merge key inlines the aliased mapping's members, leaves no spurious
    /// `<<` property behind, and lets `map_get` find the merged members.
    #[test]
    fn yaml_merge_key_inlines_aliased_members() {
        let input = "Resources:\n  Base: &base\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: from-base\n  Derived:\n    <<: *base\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let res = ir.arena.as_map(ir.resources).unwrap();
        let (_, derived) = res.iter().find(|(k, _)| k == "Derived").expect("Derived resource present");
        // No spurious "<<" property remains.
        assert!(ir.arena.map_get(*derived, YAML_MERGE_KEY).is_none(), "the '<<' key must not survive as a property");
        // The merged members are visible via map_get.
        assert_eq!(ir.arena.as_str(ir.arena.map_get(*derived, "Type").unwrap()), Some("AWS::S3::Bucket"));
        let props = ir.arena.map_get(*derived, "Properties").unwrap();
        assert_eq!(ir.arena.as_str(ir.arena.map_get(props, "BucketName").unwrap()), Some("from-base"));
    }

    /// An explicit key in the merging mapping wins over the merged value.
    #[test]
    fn yaml_merge_key_explicit_key_overrides_merged() {
        let input = "Anchors:\n  Base: &base\n    Type: AWS::S3::Bucket\n    Foo: from-base\nResources:\n  Derived:\n    <<: *base\n    Foo: explicit\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let res = ir.arena.as_map(ir.resources).unwrap();
        let (_, derived) = res.iter().find(|(k, _)| k == "Derived").expect("Derived resource present");
        assert!(ir.arena.map_get(*derived, YAML_MERGE_KEY).is_none(), "the '<<' key must not survive as a property");
        // Explicit key wins over merged; merged-only key still present.
        assert_eq!(ir.arena.as_str(ir.arena.map_get(*derived, "Foo").unwrap()), Some("explicit"));
        assert_eq!(ir.arena.as_str(ir.arena.map_get(*derived, "Type").unwrap()), Some("AWS::S3::Bucket"));
    }

    /// A sequence of merge sources (`<<: [*a, *b]`) merges each in order, with the
    /// earlier source winning over the later one (YAML 1.1).
    #[test]
    fn yaml_merge_key_sequence_earlier_source_wins() {
        let input = "Anchors:\n  A: &a\n    Shared: from-a\n    OnlyA: a\n  B: &b\n    Shared: from-b\n    OnlyB: b\nResources:\n  Derived:\n    Type: AWS::S3::Bucket\n    <<: [*a, *b]\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let res = ir.arena.as_map(ir.resources).unwrap();
        let (_, derived) = res.iter().find(|(k, _)| k == "Derived").expect("Derived resource present");
        assert!(ir.arena.map_get(*derived, YAML_MERGE_KEY).is_none(), "the '<<' key must not survive as a property");
        // Earlier source (*a) wins on the shared key; both sources' unique keys land.
        assert_eq!(ir.arena.as_str(ir.arena.map_get(*derived, "Shared").unwrap()), Some("from-a"));
        assert_eq!(ir.arena.as_str(ir.arena.map_get(*derived, "OnlyA").unwrap()), Some("a"));
        assert_eq!(ir.arena.as_str(ir.arena.map_get(*derived, "OnlyB").unwrap()), Some("b"));
    }

    /// A merge whose aliased member collides with an explicit key must NOT emit
    /// F0000 - the two are distinct source keys (`<<` vs the explicit name), and a
    /// merge-bearing mapping suppresses the duplicate-key check entirely.
    #[test]
    fn yaml_merge_key_collision_emits_no_f0000() {
        let input = "Anchors:\n  Base: &base\n    Foo: from-base\nResources:\n  Derived:\n    Type: AWS::S3::Bucket\n    <<: *base\n    Foo: explicit\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        assert!(
            ir.diagnostics.iter().all(|d| d.rule_id != "F0000"),
            "a merge-introduced collision must not be flagged as a duplicate key"
        );
    }

    #[test]
    fn yaml_merge_key_suppresses_literal_duplicate_in_same_mapping() {
        let input = "Anchors:\n  Base: &base\n    X: 1\nResources:\n  Derived:\n    Type: AWS::S3::Bucket\n    Dup: 1\n    Dup: 2\n    <<: *base\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        assert!(
            ir.diagnostics.iter().all(|d| d.rule_id != "F0000"),
            "a mapping that uses a merge key suppresses its duplicate-key check"
        );
    }

    /// The merge fix must not weaken duplicate detection in mappings that do NOT
    /// merge: a genuine literal duplicate elsewhere is still flagged - at both the
    /// original and the duplicate occurrence.
    #[test]
    fn yaml_literal_duplicate_without_merge_still_emits_f0000() {
        let input = "Resources:\n  R:\n    Type: AWS::S3::Bucket\n    Type: AWS::SNS::Topic\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let f0000: Vec<(&str, u32)> = ir
            .diagnostics
            .iter()
            .filter(|d| d.rule_id == "F0000")
            .map(|d| (d.message.as_str(), d.span.start_line))
            .collect();
        assert_eq!(
            f0000,
            [("Duplicate key 'Type'", 3), ("Duplicate key 'Type'", 4)],
            "a literal duplicate in a non-merging mapping must be flagged at every occurrence"
        );
    }

    fn defect_messages(ir: &TemplateIR, rule_id: &str) -> Vec<String> {
        ir.diagnostics.iter().filter(|d| d.rule_id == rule_id).map(|d| d.message.clone()).collect()
    }

    #[test]
    fn object_form_transform_contributes_its_name() {
        let input = "Transform:\n  Name: AWS::Include\n  Parameters:\n    Location: s3://b/k.yaml\nResources:\n  R:\n    Type: AWS::S3::Bucket\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        assert_eq!(ir.transforms, ["AWS::Include"]);
        assert!(defect_messages(&ir, "E1005").is_empty(), "a well-formed transform object is not a defect");
    }

    #[test]
    fn mixed_transform_list_keeps_strings_and_object_names() {
        let input = "Transform:\n  - AWS::LanguageExtensions\n  - Name: AWS::Include\n    Parameters:\n      Location: s3://b/k.yaml\nResources:\n  R:\n    Type: AWS::S3::Bucket\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        assert_eq!(ir.transforms, ["AWS::LanguageExtensions", "AWS::Include"]);
    }

    #[test]
    fn transform_object_without_name_is_a_defect() {
        let input =
            "Transform:\n  Parameters:\n    Location: s3://b/k.yaml\nResources:\n  R:\n    Type: AWS::S3::Bucket\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        assert_eq!(defect_messages(&ir, "E1005"), ["Transform object is missing required 'Name' property"]);
        assert!(ir.transforms.is_empty(), "an object without a Name contributes no transform");
    }

    #[test]
    fn transform_scalar_non_string_is_a_defect_anchored_at_the_section_key() {
        let input = "Transform: 42\nResources:\n  R:\n    Type: AWS::S3::Bucket\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let defects: Vec<&crate::ParseDefect> = ir.diagnostics.iter().filter(|d| d.rule_id == "E1005").collect();
        assert_eq!(defects.len(), 1);
        assert_eq!(
            defects[0].message,
            "Transform must be a transform name, a list of transforms, or a {Name, Parameters} object, got a number"
        );
        assert_eq!(defects[0].span.start_line, 1, "the defect anchors at the Transform key");
    }

    #[test]
    fn transform_object_with_unknown_key_and_bad_parameters_is_a_defect_per_violation() {
        let input = "Transform:\n  - Name: AWS::Include\n    Parameters: not-an-object\n    Extra: true\nResources:\n  R:\n    Type: AWS::S3::Bucket\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let messages = defect_messages(&ir, "E1005");
        assert_eq!(messages.len(), 2, "one defect per violation: {messages:?}");
        assert!(messages.contains(&"Transform 'Parameters' must be an object, got a string".to_string()));
        assert!(messages.contains(
            &"Transform object has unknown property 'Extra' - expected one of 'Name', 'Parameters'".to_string()
        ));
    }

    #[test]
    fn non_object_entity_sections_are_shape_defects() {
        let input = "Parameters:\nMappings:\n  - M\nConditions: scalar\nOutputs:\n  - Out\nResources:\n  R:\n    Type: AWS::S3::Bucket\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        assert_eq!(defect_messages(&ir, "E2001"), ["Parameters section must be an object, got null"]);
        assert_eq!(defect_messages(&ir, "E7001"), ["Mappings section must be an object, got a list"]);
        assert_eq!(defect_messages(&ir, "E8001"), ["Conditions section must be an object, got a string"]);
        assert_eq!(defect_messages(&ir, "E6003"), ["Outputs section must be an object, got a list"]);
    }

    #[test]
    fn well_formed_sections_produce_no_shape_defects() {
        let input = "Parameters:\n  P:\n    Type: String\nConditions:\n  C: !Equals [!Ref P, x]\nOutputs:\n  O:\n    Value: v\nResources:\n  R:\n    Type: AWS::S3::Bucket\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        for rule_id in ["E2001", "E7001", "E8001", "E6003", "F1004", "F0002", "E1005"] {
            assert_eq!(defect_messages(&ir, rule_id), Vec::<String>::new(), "no {rule_id} on well-formed sections");
        }
    }

    #[test]
    fn non_string_description_is_a_shape_defect() {
        let input = "Description:\n  Not: a string\nResources:\n  R:\n    Type: AWS::S3::Bucket\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        assert_eq!(defect_messages(&ir, "F1004"), ["Description must be a string, got an object"]);
    }

    #[test]
    fn non_string_format_version_is_a_shape_defect() {
        let input = "AWSTemplateFormatVersion:\n  bad: true\nResources:\n  R:\n    Type: AWS::S3::Bucket\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        assert_eq!(defect_messages(&ir, "F0002"), ["AWSTemplateFormatVersion must be '2010-09-09', got an object"]);
    }

    #[test]
    fn unquoted_date_format_version_is_not_a_shape_defect() {
        let input = "AWSTemplateFormatVersion: 2010-09-09\nResources:\n  R:\n    Type: AWS::S3::Bucket\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        assert_eq!(ir.format_version.as_deref(), Some("2010-09-09"));
        assert_eq!(defect_messages(&ir, "F0002"), Vec::<String>::new());
    }

    /// The property value a scalar spelling resolves to, as the arena node.
    fn scalar_property_node(yaml_scalar: &str) -> Node {
        let input = format!("Resources:\n  R:\n    Type: T\n    Properties:\n      V: {}\n", yaml_scalar);
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let res = ir.arena.as_map(ir.resources).unwrap();
        let props = ir.arena.map_get(res[0].1, "Properties").unwrap();
        let v = ir.arena.map_get(props, "V").unwrap();
        ir.arena.node(v).clone()
    }

    /// Plain scalars resolve per the YAML 1.1 schema - the resolution
    /// CloudFormation's own parser applies. `yes`/`no`/`on`/`off` variants are
    /// booleans; single letters `y`/`n` are not.
    #[test]
    fn yaml11_bool_spellings_resolve_to_booleans() {
        for s in ["yes", "Yes", "YES", "on", "On", "ON", "true", "True", "TRUE"] {
            assert_eq!(scalar_property_node(s), Node::Bool(true), "{s} must resolve to true");
        }
        for s in ["no", "No", "NO", "off", "Off", "OFF", "false", "False", "FALSE"] {
            assert_eq!(scalar_property_node(s), Node::Bool(false), "{s} must resolve to false");
        }
        for s in ["y", "Y", "n", "N", "yEs", "tRue"] {
            assert_eq!(scalar_property_node(s), Node::String(s.to_string()), "{s} must stay a string");
        }
    }

    /// YAML 1.1 integer forms: octal via leading zero, binary, hex, `_`
    /// separators, and sexagesimal - and the strings YAML 1.1 does *not*
    /// treat as numbers (`0o10`, invalid octal digits).
    #[test]
    fn yaml11_integer_forms_resolve() {
        assert_eq!(scalar_property_node("010"), Node::Int(8), "leading zero is octal");
        assert_eq!(scalar_property_node("0b1010"), Node::Int(10));
        assert_eq!(scalar_property_node("0x1A"), Node::Int(26));
        assert_eq!(scalar_property_node("1_024"), Node::Int(1024));
        assert_eq!(scalar_property_node("+12"), Node::Int(12));
        assert_eq!(scalar_property_node("-0"), Node::Int(0));
        assert_eq!(scalar_property_node("1:30"), Node::Int(90), "sexagesimal");
        assert_eq!(scalar_property_node("-1:30"), Node::Int(-90));
        assert_eq!(scalar_property_node("60:30"), Node::Int(3630));
        assert_eq!(scalar_property_node("0o10"), Node::String("0o10".into()), "0o is not a YAML 1.1 form");
        assert_eq!(scalar_property_node("012345678"), Node::String("012345678".into()), "8 is not octal");
        assert_eq!(scalar_property_node("1:60"), Node::String("1:60".into()), "60 exceeds a sexagesimal digit");
        assert_eq!(scalar_property_node("0:59"), Node::String("0:59".into()), "first segment cannot start with 0");
    }

    /// YAML 1.1 float forms: the exponent requires an explicit sign, the
    /// leading-dot form takes no sign, and `_` separators are stripped.
    #[test]
    fn yaml11_float_forms_resolve() {
        assert_eq!(scalar_property_node("1.5"), Node::Float(1.5));
        assert_eq!(scalar_property_node("10."), Node::Float(10.0));
        assert_eq!(scalar_property_node(".5"), Node::Float(0.5));
        assert_eq!(scalar_property_node(".5e+3"), Node::Float(500.0));
        assert_eq!(scalar_property_node("1.5e+10"), Node::Float(1.5e10));
        assert_eq!(scalar_property_node("1_0.5_5"), Node::Float(10.55));
        assert_eq!(scalar_property_node("1e5"), Node::String("1e5".into()), "exponent without sign is a string");
        assert_eq!(scalar_property_node("1.5e10"), Node::String("1.5e10".into()), "exponent needs a sign");
        assert_eq!(scalar_property_node("-.5"), Node::String("-.5".into()), "leading-dot form takes no sign");
        assert_eq!(scalar_property_node("1:30.5"), Node::Float(90.5), "sexagesimal float");
        assert_eq!(scalar_property_node(".inf"), Node::Float(f64::INFINITY));
        match scalar_property_node(".nan") {
            Node::Float(f) => assert!(f.is_nan()),
            other => panic!("expected NaN float, got {:?}", other),
        }
    }

    /// Timestamps stay strings: CloudFormation treats them as opaque scalar text.
    #[test]
    fn dates_and_timestamps_stay_strings() {
        assert_eq!(scalar_property_node("2010-09-09"), Node::String("2010-09-09".into()));
        assert_eq!(scalar_property_node("2001-12-14 21:59:43.10 -5"), Node::String("2001-12-14 21:59:43.10 -5".into()));
    }

    /// An explicit core-schema tag overrides both style and content.
    #[test]
    fn core_schema_tags_override_resolution() {
        assert_eq!(scalar_property_node("!!str 123"), Node::String("123".into()));
        assert_eq!(scalar_property_node("!!str yes"), Node::String("yes".into()));
        assert_eq!(scalar_property_node("!!int '5'"), Node::Int(5));
        assert_eq!(scalar_property_node("!!bool 'yes'"), Node::Bool(true));
        assert_eq!(scalar_property_node("!!float '2'"), Node::Float(2.0));
        assert_eq!(scalar_property_node("!!null ~"), Node::Null);
    }

    #[test]
    fn malformed_recognized_core_tags_fail_at_the_scalar() {
        for (tagged_value, expected_column) in [
            ("!!bool definitely", 26),
            ("!!int not_an_integer", 25),
            ("!!float not_a_float", 27),
            ("!!null not_null", 26),
        ] {
            let template = format!(
                "Resources:\n  R:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: {tagged_value}\n"
            );
            let error = parse_yaml(template.as_bytes()).expect_err("malformed explicit tag must fail parsing");
            assert!(error.message.contains("not a valid value"), "{tagged_value}: {}", error.message);
            assert_eq!(error.line, Some(5), "{tagged_value}");
            assert_eq!(error.column, Some(expected_column), "{tagged_value}");
        }
    }

    /// Mapping keys resolve like values, then coerce to their string form - so a
    /// key spelled `On:` is the property "true" and its span lands on the path the
    /// builder produces.
    #[test]
    fn non_string_scalar_keys_coerce_to_resolved_string_form() {
        let input = "Resources:\n  R:\n    Type: T\n    Metadata:\n      On: a\n      010: b\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let res = ir.arena.as_map(ir.resources).unwrap();
        let meta = ir.arena.map_get(res[0].1, "Metadata").unwrap();
        let keys: Vec<String> = ir.arena.as_map(meta).unwrap().iter().map(|(k, _)| k.clone()).collect();
        assert_eq!(keys, ["true", "8"], "keys resolve per YAML 1.1 then coerce to strings");
        assert!(
            ir.span_index.contains_key("Resources/R/Metadata/true"),
            "the span is keyed at the coerced key the builder uses"
        );
    }

    /// A stream with more than one document fails the parse: a template is one
    /// document, and validating just the first would silently ignore the rest.
    #[test]
    fn multiple_documents_fail_the_parse() {
        let input = "Resources:\n  A:\n    Type: T\n---\nResources:\n  B:\n    Type: T\n";
        let err = parse_yaml(input.as_bytes()).unwrap_err();
        assert!(err.message.contains("single document"), "unexpected message: {}", err.message);
        assert_eq!(err.line, Some(4), "anchored at the start of the second document");
    }

    /// Null and non-scalar mapping keys have no JSON form; the parse fails the
    /// way it does for any structurally invalid document.
    #[test]
    fn null_and_complex_keys_fail_the_parse() {
        let null_key = "Resources:\n  R:\n    Type: T\n    Metadata:\n      ~: v\n";
        let err = parse_yaml(null_key.as_bytes()).unwrap_err();
        assert!(err.message.contains("Null key"), "unexpected message: {}", err.message);
        assert_eq!(err.line, Some(5));

        let complex_key = "Resources:\n  R:\n    Type: T\n    Metadata:\n      ? [a, b]\n      : v\n";
        let err = parse_yaml(complex_key.as_bytes()).unwrap_err();
        assert!(err.message.contains("Complex key"), "unexpected message: {}", err.message);
    }

    /// Only a *plain* `<<` is the merge indicator; a quoted `'<<'` is an ordinary
    /// key that survives as a property (and no merge warning fires).
    #[test]
    fn quoted_merge_key_is_an_ordinary_property() {
        let input = "Resources:\n  R:\n    Type: T\n    Properties:\n      \"<<\": literal\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let res = ir.arena.as_map(ir.resources).unwrap();
        let props = ir.arena.map_get(res[0].1, "Properties").unwrap();
        let v = ir.arena.map_get(props, YAML_MERGE_KEY).expect("the quoted '<<' key must survive");
        assert_eq!(ir.arena.node(v), &Node::String("literal".into()));
        assert!(ir.diagnostics.iter().all(|d| d.rule_id != "W1100"), "no merge warning for a literal '<<' key");
    }

    /// Two plain `<<` entries in one mapping both merge, earlier source first -
    /// the second must not silently replace the first.
    #[test]
    fn multiple_merge_keys_in_one_mapping_all_merge() {
        let input = "Defaults:\n  A: &a\n    X: from-a\n  B: &b\n    X: from-b\n    Y: from-b\nResources:\n  R:\n    Type: T\n    Properties:\n      <<: *a\n      <<: *b\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let res = ir.arena.as_map(ir.resources).unwrap();
        let props = ir.arena.map_get(res[0].1, "Properties").unwrap();
        let x = ir.arena.map_get(props, "X").expect("X merged");
        let y = ir.arena.map_get(props, "Y").expect("Y merged");
        assert_eq!(ir.arena.node(x), &Node::String("from-a".into()), "the earlier merge source wins");
        assert_eq!(ir.arena.node(y), &Node::String("from-b".into()));
    }

    /// A YAML template at exactly the nesting-depth boundary must parse cleanly.
    #[test]
    fn yaml_nesting_at_boundary_parses() {
        let limit = crate::consts::MAX_YAML_NESTING_DEPTH;
        // Build a YAML with exactly `limit` nested mappings.
        let mut yaml = String::new();
        for i in 0..limit {
            let indent = "  ".repeat(i);
            yaml.push_str(&format!("{}L{}:\n", indent, i));
        }
        let indent = "  ".repeat(limit);
        yaml.push_str(&format!("{}leaf\n", indent));

        let result = parse_yaml(yaml.as_bytes());
        assert!(result.is_ok(), "template at exactly the nesting-depth boundary must parse: {:?}", result.err());
    }

    /// A YAML template one level above the boundary must fail with a structural error.
    #[test]
    fn yaml_nesting_one_over_boundary_fails() {
        let limit = crate::consts::MAX_YAML_NESTING_DEPTH;
        // Build a YAML with limit+1 nested mappings. Each `key:\n` at increased
        // indent opens a new mapping in the event stream, pushing one MappingStart.
        let mut yaml = String::new();
        for i in 0..=limit {
            let indent = "  ".repeat(i);
            yaml.push_str(&format!("{}L{}:\n", indent, i));
        }
        let indent = "  ".repeat(limit + 1);
        yaml.push_str(&format!("{}leaf\n", indent));

        let result = parse_yaml(yaml.as_bytes());
        assert!(result.is_err(), "template exceeding the nesting-depth boundary must be rejected");
        let error = result.unwrap_err();
        let msg = error.message.to_lowercase();
        assert!(msg.contains("nesting depth"), "error must reference nesting depth, got: {}", error.message);
        assert!(error.line.is_some(), "error must carry a source line");
    }
}
