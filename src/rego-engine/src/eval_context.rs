use std::cell::RefCell;
use std::collections::HashSet;
use std::sync::Arc;
use template_model::SemanticModel;

/// Per-evaluation state the Rego builtins read while a single `evaluate_rules`
/// call runs on the current thread: the model under validation, the region
/// override the region-scoped rules resolve against, and the built-in rule IDs
/// that global filtering has already proven cannot survive.
///
/// The state lives in thread-local storage rather than a holder shared by the
/// engine, so one engine can evaluate distinct templates on many threads at once
/// without one thread observing another's model or region.
pub(crate) struct EvaluationContext {
    model: Arc<SemanticModel>,
    region: Option<String>,
    suppressed_builtin_rules: Arc<HashSet<String>>,
}

impl EvaluationContext {
    pub(crate) fn new(
        model: Arc<SemanticModel>,
        region: Option<String>,
        suppressed_builtin_rules: Arc<HashSet<String>>,
    ) -> Self {
        Self { model, region, suppressed_builtin_rules }
    }
}

thread_local! {
    /// A stack, not a single slot: a nested evaluation on the same thread restores
    /// the enclosing context when it finishes instead of clearing the state the
    /// outer evaluation still depends on.
    static CONTEXT_STACK: RefCell<Vec<EvaluationContext>> = const { RefCell::new(Vec::new()) };
}

/// Installs an [`EvaluationContext`] for the current thread until it is dropped.
///
/// Entering pushes onto the thread-local stack and dropping pops it, so the stack
/// stays balanced even when evaluation unwinds through the scope on error. Scopes
/// must be dropped in reverse order of creation, which the RAII binding guarantees.
#[must_use = "the context is only installed while the scope is held"]
pub(crate) struct EvaluationScope {
    _guard: (),
}

impl EvaluationScope {
    pub(crate) fn enter(context: EvaluationContext) -> Self {
        CONTEXT_STACK.with(|stack| stack.borrow_mut().push(context));
        Self { _guard: () }
    }
}

impl Drop for EvaluationScope {
    fn drop(&mut self) {
        CONTEXT_STACK.with(|stack| {
            stack.borrow_mut().pop();
        });
    }
}

fn with_current_context<R>(read: impl FnOnce(&EvaluationContext) -> R) -> Option<R> {
    CONTEXT_STACK.with(|stack| stack.borrow().last().map(read))
}

/// The model of the innermost active evaluation, or `None` when no evaluation is
/// in progress on this thread (for example during engine warm-up).
pub(crate) fn current_model() -> Option<Arc<SemanticModel>> {
    with_current_context(|context| context.model.clone())
}

/// The region override of the innermost active evaluation, or `None` when there
/// is no active evaluation or the caller supplied no region.
pub(crate) fn current_region() -> Option<String> {
    with_current_context(|context| context.region.clone()).flatten()
}

/// Whether global filtering has proven that no diagnostic from `rule_id` can
/// survive, so its handwritten clauses can stop before doing any work. Absent an
/// active evaluation nothing is suppressed, which keeps engine warm-up unfiltered.
pub(crate) fn is_builtin_rule_suppressed(rule_id: &str) -> bool {
    with_current_context(|context| context.suppressed_builtin_rules.contains(rule_id)).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_model() -> Arc<SemanticModel> {
        Arc::new(SemanticModel::from_bytes(b"AWSTemplateFormatVersion: '2010-09-09'\nResources: {}").unwrap())
    }

    #[test]
    fn no_scope_exposes_no_model_or_region_and_suppresses_nothing() {
        assert!(current_model().is_none());
        assert!(current_region().is_none());
        assert!(!is_builtin_rule_suppressed("W9010"));
    }

    #[test]
    fn scope_exposes_its_model_region_and_suppressed_rules() {
        let suppressed = Arc::new(HashSet::from(["W9010".to_string()]));
        let _scope =
            EvaluationScope::enter(EvaluationContext::new(empty_model(), Some("eu-west-1".to_string()), suppressed));

        assert!(current_model().is_some());
        assert_eq!(current_region(), Some("eu-west-1".to_string()));
        assert!(is_builtin_rule_suppressed("W9010"));
        assert!(!is_builtin_rule_suppressed("W9011"));
    }

    #[test]
    fn dropping_the_scope_clears_the_context() {
        {
            let _scope = EvaluationScope::enter(EvaluationContext::new(empty_model(), None, Arc::default()));
            assert!(current_model().is_some());
        }
        assert!(current_model().is_none());
    }

    #[test]
    fn nested_scope_restores_the_enclosing_context_on_exit() {
        let outer = Arc::new(HashSet::from(["OUTER".to_string()]));
        let inner = Arc::new(HashSet::from(["INNER".to_string()]));

        let _outer_scope =
            EvaluationScope::enter(EvaluationContext::new(empty_model(), Some("us-east-1".to_string()), outer));
        {
            let _inner_scope =
                EvaluationScope::enter(EvaluationContext::new(empty_model(), Some("ap-south-1".to_string()), inner));
            assert_eq!(current_region(), Some("ap-south-1".to_string()));
            assert!(is_builtin_rule_suppressed("INNER"));
            assert!(!is_builtin_rule_suppressed("OUTER"));
        }
        assert_eq!(current_region(), Some("us-east-1".to_string()));
        assert!(is_builtin_rule_suppressed("OUTER"));
        assert!(!is_builtin_rule_suppressed("INNER"));
    }
}
