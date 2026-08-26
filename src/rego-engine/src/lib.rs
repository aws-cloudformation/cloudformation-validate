pub(crate) mod builtins;
pub(crate) mod engine;
pub(crate) mod guard_to_rego;
pub(crate) mod policies {
    include!(concat!(env!("OUT_DIR"), "/handwritten_rego.rs"));
}

pub use engine::RegoEngine;
