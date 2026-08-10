pub mod builder;
mod condition_shape;
pub mod json;
mod resource_shape;
pub mod value;
pub mod yaml;

use crate::ir::{ParseError, TemplateIR};
use log::{debug, error, info};

pub fn parse(bytes: &[u8]) -> Result<TemplateIR, ParseError> {
    let trimmed = bytes.iter().position(|&b| !b.is_ascii_whitespace());
    let result = match trimmed {
        Some(pos) if bytes[pos] == b'{' => json::parse_json(bytes),
        _ => yaml::parse_yaml(bytes),
    };
    match &result {
        Ok(ir) => {
            let format = if trimmed.map(|p| bytes[p]) == Some(b'{') { "JSON" } else { "YAML" };
            info!(
                "Parsed {} template ({} bytes): {} arena nodes, {} global index paths, {} diagnostics",
                format,
                bytes.len(),
                ir.arena.len(),
                ir.global_index.len(),
                ir.diagnostics.len()
            );
            debug!(
                "Template sections: format={:?} transforms={:?} description={:?}",
                ir.format_version,
                ir.transforms,
                ir.description.as_deref().map(|d| &d[..d.floor_char_boundary(d.len().min(60))])
            );
        }
        Err(e) => error!("Parse failed on {} byte input: {}", bytes.len(), e),
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A non-object root is rejected in both formats. The dispatch heuristic routes
    /// only a leading `{` to the JSON front-end, so a JSON array root is parsed as
    /// YAML and reports the YAML-worded error; either way the outcome is the same -
    /// a `ParseError` at 1:1 with no model.
    #[test]
    fn non_object_root_is_rejected_in_both_formats() {
        let json_array = parse(br#"[{"Type":"AWS::S3::Bucket"}]"#);
        let yaml_seq = parse(b"- Type: AWS::S3::Bucket\n");
        assert!(json_array.is_err(), "a JSON array root must be rejected");
        assert!(yaml_seq.is_err(), "a YAML sequence root must be rejected");
    }

    /// A leading `{` (after optional whitespace) dispatches to the JSON front-end; a
    /// well-formed JSON object template parses successfully through it.
    #[test]
    fn leading_brace_dispatches_to_json() {
        let ir = parse(b"  {\"Resources\":{\"R\":{\"Type\":\"AWS::S3::Bucket\"}}}").unwrap();
        assert_eq!(ir.arena.as_map(ir.resources).unwrap().len(), 1);
    }
}
