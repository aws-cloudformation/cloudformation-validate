pub(crate) mod builtins;
pub(crate) mod engine;
pub(crate) mod eval_context;
pub(crate) mod guard_to_rego;
#[cfg(test)]
mod policy_guard_coverage;
pub(crate) mod policies {
    include!(concat!(env!("OUT_DIR"), "/handwritten_rego.rs"));
}

pub use engine::RegoEngine;
