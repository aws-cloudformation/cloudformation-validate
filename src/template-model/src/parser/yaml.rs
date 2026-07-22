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
    dup_key_diagnostics: Vec<diagnostics::Diagnostic>,
}

/// One open container while the event stream is being consumed. The frame stack
/// runs parallel to `doc_stack`, and each frame records the slot the *next* child
/// value will occupy: a mapping's current key, or a sequence's next index. Joining
/// every frame's slot yields the canonical `/`-separated path the shared builder
/// assigns each node — so a span keyed here (e.g. `Ingress/0/SourceSecurityGroupId`)
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
    /// Duplicate-key diagnostics found while a mapping is still open, one buffer per
    /// open mapping (parallel to `key_stack`). Flushed to `dup_key_diagnostics` when
    /// the mapping closes — unless that mapping used a YAML merge key (`<<`), in which
    /// case the buffer is dropped. A mapping that merges is not required to have unique
    /// keys, so its duplicate check is suppressed for the whole mapping.
    pending_dup_diagnostics: Vec<Vec<diagnostics::Diagnostic>>,
    /// Whether the correspondingly-open mapping contains a `<<` merge key (parallel to
    /// `key_stack`). Set from any position in the mapping — before or after a
    /// duplicate — so the suppression covers every ordering.
    mapping_uses_merge: Vec<bool>,
    /// `yaml_rust2` silently keeps the last value for a duplicate key, so duplicates
    /// are detected here at load time — matching how the JSON front-end pre-scans for
    /// them. One diagnostic per occurrence after the first, like the JSON path.
    dup_key_diagnostics: Vec<diagnostics::Diagnostic>,
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
            pending_dup_diagnostics: Vec::new(),
            mapping_uses_merge: Vec::new(),
            dup_key_diagnostics: Vec::new(),
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
        Ok(LoadedYaml { docs: loader.docs, span_map: loader.span_map, dup_key_diagnostics: loader.dup_key_diagnostics })
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
    /// a duplicate key resolves to the surviving (last) occurrence — matching how the
    /// loaded `Hash` keeps the last value written for a repeated key. cfn-lint anchors
    /// object-property diagnostics at the key, so this is where the value's span lives.
    fn record_key_span(&mut self, mark: Marker) {
        let path = self.current_path();
        if !path.is_empty() {
            self.span_map.insert(path, Self::mark_position(mark));
        }
    }

    /// Anchors a value that no key precedes — a sequence element, or a container opened
    /// directly inside a sequence — at its own position. Never overwrites a span a key
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
    /// flag it as an unsupported function — mirroring how a typo'd `Fn::` key is
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
    fn wrap_with_tag(tag_name: &str, value: Yaml) -> Yaml {
        let fn_key = SHORT_TAG_TO_FN_KEY
            .iter()
            .find(|(short, _)| *short == tag_name)
            .map(|(_, fn_key)| (*fn_key).to_string())
            .unwrap_or_else(|| format!("{}{}", FN_PREFIX, tag_name));
        let mut hash = Hash::new();
        hash.insert(Yaml::String(fn_key), value);
        Yaml::Hash(hash)
    }

    fn insert_new_node(&mut self, node: (Yaml, usize), _mark: Marker) {
        let (mut node_val, aid) = node;
        if let Some((_, depth)) = self.pending_tags.last()
            && self.doc_stack.len() == *depth
        {
            let (tag_name, _) = self.pending_tags.pop().unwrap();
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
                    *cur_key = node_val;
                } else {
                    let key = mem::replace(cur_key, Yaml::BadValue);
                    let key_mark = self.key_marks.last_mut().and_then(|m| m.take());
                    // A `<<` key merges the aliased mapping(s) into this one (resolved
                    // in a post-load pass). Its presence suppresses this mapping's
                    // duplicate-key check, matching how the resolved merge is treated.
                    if key == Yaml::String(YAML_MERGE_KEY.to_string())
                        && let Some(flag) = self.mapping_uses_merge.last_mut()
                    {
                        *flag = true;
                    }
                    // A returned old value means this key already existed: yaml_rust2
                    // would silently overwrite it, so flag the duplicate (one per
                    // occurrence after the first, like the JSON pre-scan). Buffered per
                    // mapping so it can be dropped if the mapping turns out to merge.
                    if h.insert(key.clone(), node_val).is_some()
                        && let Some(name) = yaml_key_as_string(&key)
                    {
                        let span = key_mark
                            .map(|(line, col)| SourceSpan {
                                start_line: line,
                                start_column: col,
                                end_line: line,
                                end_column: col + name.len() as u32,
                            })
                            .unwrap_or(UNKNOWN_SPAN);
                        // At this point every enclosing frame's slot is committed and
                        // the innermost slot holds the duplicated key, so the path
                        // names the duplicated entry itself — anchoring the diagnostic
                        // at the entity it duplicates.
                        let duplicated_path = path_from_frames(&self.path_frames);
                        let diagnostic = crate::make_parse_diagnostic_at(
                            "F0000",
                            format!("Duplicate key '{}'", name),
                            span,
                            &duplicated_path,
                        );
                        if let Some(buffer) = self.pending_dup_diagnostics.last_mut() {
                            buffer.push(diagnostic);
                        }
                    }
                }
            }
            _ => unreachable!(),
        }
    }
}

impl MarkedEventReceiver for CfnYamlLoader {
    fn on_event(&mut self, ev: Event, mark: Marker) {
        match ev {
            Event::DocumentStart | Event::Nothing | Event::StreamStart | Event::StreamEnd => {}
            Event::DocumentEnd => match self.doc_stack.len() {
                0 => self.docs.push(Yaml::BadValue),
                1 => self.docs.push(self.doc_stack.pop().unwrap().0),
                _ => {}
            },
            Event::SequenceStart(aid, ref tag) => {
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
                if let Some(tag_name) = Self::cfn_tag_name(tag) {
                    self.pending_tags.push((tag_name, self.doc_stack.len()));
                }
                self.record_value_span(mark);
                self.doc_stack.push((Yaml::Hash(Hash::new()), aid));
                self.key_stack.push(Yaml::BadValue);
                self.key_marks.push(None);
                self.pending_dup_diagnostics.push(Vec::new());
                self.mapping_uses_merge.push(false);
                self.path_frames.push(PathFrame::Map(None));
            }
            Event::MappingEnd => {
                self.key_stack.pop();
                self.key_marks.pop();
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
                let node = if style != yaml_rust2::scanner::TScalarStyle::Plain {
                    Yaml::String(v.clone())
                } else {
                    Yaml::from_str(&v)
                };

                let is_key = self.placing_map_key();
                if is_key {
                    // This scalar names the slot its sibling value will occupy; put it in
                    // the frame so the value's path is complete, then anchor the property
                    // at the key (cfn-lint anchors object-property diagnostics at the key).
                    if let Some(PathFrame::Map(slot)) = self.path_frames.last_mut() {
                        *slot = Some(v.clone());
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
        // winning, so collapse such collisions here — keeping the last occurrence —
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
            // source token that as_coerced_str/describe_scalar report — it maps the
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
/// `yaml_rust2` does not implement merge keys, so a `<<: <alias>` entry survives as
/// a literal `<<` key whose value is the already-resolved aliased mapping (or a
/// sequence of them). Left alone this both injects a spurious `<<` property and
/// hides the aliased members. Here each `<<` entry is spliced into its enclosing
/// mapping: explicit keys always win over merged ones, and among multiple merge
/// sources the earlier one wins over the later (YAML 1.1). Explicit keys keep their
/// original positions; merged-only members are appended after them.
fn resolve_merge_keys(node: &mut Yaml) {
    match node {
        Yaml::Hash(hash) => {
            let original = std::mem::take(hash);
            let mut merge_sources: Vec<Yaml> = Vec::new();
            let mut resolved = Hash::new();
            for (key, value) in original {
                if key == Yaml::String(YAML_MERGE_KEY.to_string()) {
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

    let LoadedYaml { mut docs, span_map: raw_spans, dup_key_diagnostics } = CfnYamlLoader::load(text)?;

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
    /// both formats — the two duplicate detectors (JSON byte scan, YAML load-time
    /// Hash) must agree on which duplicates fire.
    #[test]
    fn duplicate_string_key_matches_across_formats() {
        let json = crate::parser::json::parse_json(b"{\n\"Resources\":{\n\"A\":{},\n\"A\":{}\n}\n}\n").unwrap();
        let yaml = parse_yaml(b"Resources:\n  A: {}\n  A: {}\n").unwrap();
        let messages = |ir: &TemplateIR| -> Vec<String> {
            ir.diagnostics.iter().filter(|d| d.rule_id == "F0000").map(|d| d.message.clone()).collect()
        };
        assert_eq!(messages(&json), ["Duplicate key 'A'"]);
        assert_eq!(messages(&yaml), messages(&json));
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
    /// a type error — `Fn::Contains` is a boolean-producing Rules-section
    /// intrinsic, not a non-boolean expression.
    #[test]
    fn fn_not_accepts_fn_contains_argument_no_f0014() {
        let input = "Parameters:\n  BootstrapVersion:\n    Type: String\nResources:\n  B:\n    Type: AWS::S3::Bucket\nRules:\n  CheckBootstrapVersion:\n    Assertions:\n      - Assert:\n          Fn::Not:\n            - Fn::Contains:\n                - [\"1\", \"2\", \"3\", \"4\", \"5\"]\n                - Ref: BootstrapVersion\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let f0014: Vec<_> = ir.diagnostics.iter().filter(|d| d.rule_id == "F0014").collect();
        assert!(f0014.is_empty(), "Expected no F0014 for Fn::Not(Fn::Contains), got: {:?}", f0014);
    }

    #[test]
    fn fn_not_with_string_argument_still_produces_f0014() {
        let input = "Resources:\n  B:\n    Type: AWS::S3::Bucket\nConditions:\n  Bad:\n    Fn::Not:\n      - definitely-not-boolean\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        assert!(
            ir.diagnostics.iter().any(|d| d.rule_id == "F0014"
                && d.message.contains("Fn::Not")
                && d.message.contains("is not of type 'boolean'")),
            "Expected F0014 for Fn::Not with string arg, got: {:?}",
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
    /// build the identical IR — the shared builder guarantees JSON/YAML parity, and
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
    fn unknown_fn_long_form_emits_w1103() {
        let input = "Resources:\n  R:\n    Type: AWS::SNS::Topic\n    Properties:\n      TopicName:\n        Fn::Bogus: hello\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let w1103: Vec<&str> =
            ir.diagnostics.iter().filter(|d| d.rule_id == "W1103").map(|d| d.message.as_str()).collect();
        assert_eq!(w1103, ["'Fn::Bogus' is not a supported function"]);
    }

    /// A misspelled or unknown `!`-shorthand tag (`!Bogus`) is wrapped into
    /// `{ Fn::Bogus: ... }` exactly like the long form and JSON, so the shared
    /// unsupported-function check fires. Silently dropping the tag (the previous
    /// behavior) would hide a real authoring mistake.
    #[test]
    fn unknown_fn_short_tag_form_emits_w1103() {
        let input = "Resources:\n  R:\n    Type: AWS::SNS::Topic\n    Properties:\n      TopicName: !Bogus hello\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let w1103: Vec<&str> =
            ir.diagnostics.iter().filter(|d| d.rule_id == "W1103").map(|d| d.message.as_str()).collect();
        assert_eq!(w1103, ["'Fn::Bogus' is not a supported function"]);
    }

    /// A wrong-case shorthand tag (`!GetAttt`, a typo of `!GetAtt`) is not in the
    /// recognized-tag table, so it is wrapped as `{ Fn::GetAttt: ... }` and flagged
    /// as unsupported — matching both the long `Fn::GetAttt` form and JSON.
    #[test]
    fn wrong_case_short_tag_emits_w1103() {
        let input =
            "Resources:\n  R:\n    Type: AWS::SNS::Topic\n    Properties:\n      TopicName: !GetAttt [R, Arn]\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let w1103: Vec<&str> =
            ir.diagnostics.iter().filter(|d| d.rule_id == "W1103").map(|d| d.message.as_str()).collect();
        assert_eq!(w1103, ["'Fn::GetAttt' is not a supported function"]);
    }

    /// The unknown-tag YAML shorthand and the equivalent JSON long form emit the
    /// identical W1103 — the shared builder guarantees the diagnostic cannot drift
    /// between formats once the tag is wrapped.
    #[test]
    fn unknown_short_tag_matches_json_long_form_w1103() {
        let yaml = parse_yaml(
            "Resources:\n  R:\n    Type: AWS::SNS::Topic\n    Properties:\n      TopicName: !Bogus hello\n".as_bytes(),
        )
        .unwrap();
        let json = super::super::json::parse_json(
            br#"{"Resources":{"R":{"Type":"AWS::SNS::Topic","Properties":{"TopicName":{"Fn::Bogus":"hello"}}}}}"#,
        )
        .unwrap();
        let w1103 = |ir: &TemplateIR| -> Vec<String> {
            ir.diagnostics.iter().filter(|d| d.rule_id == "W1103").map(|d| d.message.clone()).collect()
        };
        assert_eq!(w1103(&yaml), w1103(&json));
        assert_eq!(w1103(&yaml), ["'Fn::Bogus' is not a supported function"]);
    }

    /// A secondary-handle tag (`!!str`) is not a CloudFormation intrinsic shorthand
    /// and must not be wrapped into an `Fn::` map or trigger W1103 — only primary
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
    /// F0000 — the two are distinct source keys (`<<` vs the explicit name), and a
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
    /// merge: a genuine literal duplicate elsewhere is still flagged.
    #[test]
    fn yaml_literal_duplicate_without_merge_still_emits_f0000() {
        let input = "Resources:\n  R:\n    Type: AWS::S3::Bucket\n    Type: AWS::SNS::Topic\n";
        let ir = parse_yaml(input.as_bytes()).unwrap();
        let f0000: Vec<&str> =
            ir.diagnostics.iter().filter(|d| d.rule_id == "F0000").map(|d| d.message.as_str()).collect();
        assert_eq!(
            f0000,
            ["Duplicate key 'Type'"],
            "a literal duplicate in a non-merging mapping must still be flagged"
        );
    }
}
