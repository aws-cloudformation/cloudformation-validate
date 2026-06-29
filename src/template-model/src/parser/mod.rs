pub mod builder;
pub mod json;
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
