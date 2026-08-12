use crate::consts::{
    CONDITION_REF_PREFIX, FN_AND, FN_CONDITION, FN_EQUALS, FN_NOT, FN_OR, MAX_PARAM_COMBINATIONS, MAX_SAT_ITERATIONS,
    MAX_TOTAL_SAT_ITERATIONS, PARAM_UNKNOWN_SENTINEL, PSEUDO_PREFIX, PSEUDO_REGION,
};
use crate::ir::*;
use crate::model::PseudoParameterOverrides;
use crate::resolver::{MappingData, ParameterInfo};
use log::{debug, info};
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// How many budget-exhausted satisfiability queries are retained for the
/// advisory diagnostic. The advisory tells an author that analysis of their
/// condition set was cut short; a handful of examples conveys that, while
/// retaining every query on a pathological template would itself grow unbounded.
const MAX_REPORTED_BUDGET_EXHAUSTED_QUERIES: usize = 5;

/// How the advisory describes analysis cut short by the cumulative budget rather
/// than by one expensive query: from that point on, every remaining question about
/// the condition set gets the conservative answer.
const WHOLE_CONDITION_SET_DESCRIPTION: &str =
    "this template's condition set as a whole (remaining conditions were assumed compatible)";

#[derive(Debug, Clone)]
pub enum ConditionExpr {
    Equals(ValueExpr, ValueExpr),
    And(Vec<ConditionExpr>),
    Or(Vec<ConditionExpr>),
    Not(Box<ConditionExpr>),
    ConditionRef(String),
    /// A condition body that does not produce a boolean (e.g. a bare `Fn::Ref`,
    /// a scalar, or a value-producing function). CloudFormation rejects it; it is
    /// reported as a not-a-boolean error and is deliberately opaque to the SAT
    /// model and to the undefined-reference check (it is not a condition
    /// reference).
    Invalid,
}

#[derive(Debug, Clone)]
pub enum ValueExpr {
    ParamRef(String),
    Literal(String),
    PseudoParam(String),
    MappingLookup { map_name: String, key1: Box<ValueExpr>, key2: Box<ValueExpr> },
    Other,
}

#[derive(Debug, Clone)]
pub struct MutexGroup {
    pub conditions: Vec<String>,
    pub parameter: String,
    pub values: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Implication {
    pub antecedent: String,
    pub consequent: String,
}

#[derive(Debug)]
pub struct ConditionModel {
    pub conditions: HashMap<String, ConditionExpr>,
    pub parameters: HashMap<String, ParameterInfo>,
    pub mutex_groups: Vec<MutexGroup>,
    pub implications: Vec<Implication>,
    /// Constraints a `Rules` section imposes on the parameters, as
    /// `rule condition => assertion` pairs over synthetic conditions. Kept apart
    /// from `implications` - which the `And`/`Or` structure of the conditions
    /// entails and satisfiability therefore rederives on its own - because these
    /// are external restrictions on what a deployment may supply and are the only
    /// constraints the satisfiability search has to apply itself. Separate
    /// storage also means recomputing the derived `implications` cannot discard
    /// them.
    rule_implications: Vec<Implication>,
    pseudo_overrides: PseudoParameterOverrides,
    mappings: MappingData,
    /// Cumulative satisfiability search steps consumed across every query for
    /// this model. Shared (the model is reached through one `Arc`) so the
    /// quadratic compatibility pass, scenario resolution, and rule-evaluation
    /// builtins all draw down a single per-validation budget.
    sat_iterations_used: AtomicU64,
    /// Referenced parameters and their candidate values, derived from the
    /// condition set and parameter definitions. Every satisfiability query reads
    /// the candidate values of the parameters it depends on, so caching this
    /// avoids rederiving the same map across queries. Computed once on first use
    /// and invalidated by `register_inline` - the only path that mutates the
    /// condition set after construction.
    referenced_param_values: OnceLock<HashMap<String, Vec<String>>>,
    budget_exhausted_queries: std::sync::Mutex<Vec<String>>,
}

pub fn format_condition_expr(expr: &ConditionExpr) -> String {
    match expr {
        ConditionExpr::Equals(a, b) => {
            format!("Equals({}, {})", format_value_expr(a), format_value_expr(b))
        }
        ConditionExpr::And(exprs) => {
            let items: Vec<String> = exprs.iter().map(format_condition_expr).collect();
            format!("And({})", items.join(", "))
        }
        ConditionExpr::Or(exprs) => {
            let items: Vec<String> = exprs.iter().map(format_condition_expr).collect();
            format!("Or({})", items.join(", "))
        }
        ConditionExpr::Not(e) => format!("Not({})", format_condition_expr(e)),
        ConditionExpr::ConditionRef(name) => format!("Condition({})", name),
        ConditionExpr::Invalid => "Invalid".to_string(),
    }
}

fn format_value_expr(expr: &ValueExpr) -> String {
    match expr {
        ValueExpr::ParamRef(name) => format!("Param({})", name),
        ValueExpr::Literal(s) => format!("\"{}\"", s),
        ValueExpr::PseudoParam(name) => name.clone(),
        ValueExpr::MappingLookup { map_name, key1, key2 } => {
            format!("FindInMap({}, {}, {})", map_name, format_value_expr(key1), format_value_expr(key2))
        }
        ValueExpr::Other => "?".into(),
    }
}

impl ConditionModel {
    pub fn from_ir(
        ir: &TemplateIR,
        parameters: &HashMap<String, ParameterInfo>,
        pseudo_overrides: &PseudoParameterOverrides,
        mappings: &MappingData,
    ) -> Self {
        let mut conditions = HashMap::new();

        if ir.conditions != NULL_REF
            && let Some(entries) = ir.arena.as_map(ir.conditions)
        {
            for (name, node_ref) in entries {
                let expr = parse_condition_expr(&ir.arena, *node_ref, parameters);
                conditions.insert(name.clone(), expr);
            }
        }

        let mutex_groups = extract_mutex_groups(&conditions);
        let implications = extract_implications(&conditions);

        info!(
            "Condition model: {} conditions, {} mutex groups (params: {:?}), {} implications",
            conditions.len(),
            mutex_groups.len(),
            mutex_groups.iter().map(|g| g.parameter.as_str()).collect::<Vec<_>>(),
            implications.len()
        );
        ConditionModel {
            conditions,
            parameters: parameters.clone(),
            mutex_groups,
            implications,
            rule_implications: Vec::new(),
            pseudo_overrides: pseudo_overrides.clone(),
            mappings: mappings.clone(),
            sat_iterations_used: AtomicU64::new(0),
            referenced_param_values: OnceLock::new(),
            budget_exhausted_queries: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Decides whether the given condition assumptions can hold simultaneously.
    ///
    /// A condition is a pure function of the template's parameters,
    /// pseudo-parameters, and mappings, so the assumptions hold exactly when some
    /// assignment of concrete values to the parameters they read makes every
    /// assumed condition take its assumed value. The search is over those
    /// parameter assignments, which is why its cost tracks how many independent
    /// inputs a template really has rather than how many conditions are layered
    /// over them.
    ///
    /// On inputs that exhaust a search budget this degrades to a conservative
    /// `true` (assume satisfiable). Whether that conservative answer *adds* or
    /// *suppresses* a diagnostic depends on how each caller uses the result, so
    /// "conservative" is not safe in one fixed direction. The callers below are
    /// examples, not an exhaustive list:
    ///
    /// - Used directly (`conditions_compatible`, `resources_compatible`, and the
    ///   scenario-reachability filters in `resolve_scenarios_json` and the schema
    ///   validator) a conservative `true` treats two conditions as able to
    ///   coexist / a scenario as reachable, so it keeps a pair or scenario a full
    ///   search might have eliminated - at worst surfacing an extra
    ///   (false-positive) diagnostic.
    /// - Used negated to prove *unreachability* (`find_unreachable_branches`,
    ///   which emits when `!is_satisfiable(branch_assumptions)`) a conservative
    ///   `true` makes the branch look reachable and therefore *suppresses* an
    ///   unreachable-branch diagnostic - a false negative, the opposite
    ///   direction.
    /// - Used negated to prove *implication* (`condition_implies`, i.e.
    ///   `!is_satisfiable(a = true, b = false)`; the conditional-reference guard
    ///   uses the same shape) a conservative `true` flips the result to "does not
    ///   imply", which can surface an extra (false-positive) diagnostic.
    ///
    /// All of these occur only on adversarial inputs that exhaust the budget;
    /// valid templates resolve well within budget and are unaffected. Reaching a
    /// budget is recorded (see [`Self::budget_exhausted_queries`]) so a curtailed
    /// analysis is reported rather than silently narrowing what validation proves.
    ///
    /// A condition the parameters cannot decide - one comparing a value the model
    /// cannot resolve, or sitting on a reference cycle - is treated as compatible
    /// with any assumption about it, the same conservative direction.
    #[must_use]
    pub fn is_satisfiable(&self, assumptions: &[(String, bool)]) -> bool {
        self.is_satisfiable_with_param_overrides(assumptions, &HashMap::new())
    }

    /// Like [`Self::is_satisfiable`], but with the target region pinned as the
    /// only candidate value for the `AWS::Region` pseudo-parameter - a per-region
    /// satisfiability query that asks whether a condition can hold *in that
    /// region*, not whether the region could be anything. Used by the
    /// region-availability check so a resource guarded by a
    /// condition that cannot hold in the target region (e.g.
    /// `!Equals [AWS::Region, other-region]`) is correctly treated as never
    /// created there - even when no explicit `--region` override pins the
    /// pseudo-parameter globally (where it stays a free variable to avoid
    /// false unreachable-branch diagnostics).
    #[must_use]
    pub fn is_satisfiable_in_region(&self, assumptions: &[(String, bool)], region: &str) -> bool {
        let overrides = HashMap::from([(PSEUDO_REGION.to_string(), vec![region.to_string()])]);
        self.is_satisfiable_with_param_overrides(assumptions, &overrides)
    }

    /// Satisfiability with a set of parameter/pseudo-parameter candidate-value
    /// overrides applied on top of the model's derived candidate values. An
    /// override restricts a parameter to exactly the given values for this query
    /// only; a parameter not referenced by any relevant condition is unaffected.
    #[must_use]
    fn is_satisfiable_with_param_overrides<'model>(
        &'model self,
        assumptions: &[(String, bool)],
        param_overrides: &'model HashMap<String, Vec<String>>,
    ) -> bool {
        // Once the cumulative search budget for this model is spent, assume
        // satisfiable instead of searching further (the conservative-`true`
        // contract documented above). Checked before any per-query setup so an
        // exhausted query costs O(1) - this is what keeps a template with a huge
        // number of conditions (a quadratic flood of queries) bounded.
        if self.satisfiability_budget_exhausted() {
            return true;
        }

        let mut assumed: HashMap<&'model str, bool> = HashMap::with_capacity(assumptions.len());
        for (name, expected) in assumptions {
            // A name that names no condition of this template fixes no
            // expression's value, so it constrains nothing.
            let Some((condition_name, _)) = self.conditions.get_key_value(name.as_str()) else {
                continue;
            };
            if let Some(&already_assumed) = assumed.get(condition_name.as_str())
                && already_assumed != *expected
            {
                return false;
            }
            assumed.insert(condition_name.as_str(), *expected);
        }
        if assumed.is_empty() {
            return true;
        }
        debug!("Checking satisfiability of {:?} against {} conditions", assumptions, self.conditions.len());

        let mut query = SatisfiabilityQuery::prepare(self, &assumed, param_overrides);

        // If even the restricted parameter space this query depends on is too
        // large to enumerate, assume satisfiable instead of exploring it (the
        // conservative-`true` contract documented on `is_satisfiable`). The
        // preparation already walked the query's dependency closure; charging
        // that work keeps a flood of cap-tripped queries drawing the cumulative
        // budget down in proportion to the work performed.
        if query.parameter_point_count() > MAX_PARAM_COMBINATIONS {
            self.charge_satisfiability_work(query.steps);
            return true;
        }

        let satisfiable = query.some_point_satisfies(&assumed);
        let steps = query.steps;
        self.charge_satisfiability_work(steps);
        if steps > MAX_SAT_ITERATIONS {
            // Synthetic condition names (inline Fn::If expressions and
            // Rules-section conditions) are internal; describe them generically
            // rather than leaking `__`-prefixed identifiers into the advisory.
            let describe = |name: &str| -> String {
                if name.starts_with("__") { "<inline condition>".to_string() } else { name.to_string() }
            };
            let query_desc =
                assumptions.iter().map(|(n, v)| format!("{}={}", describe(n), v)).collect::<Vec<_>>().join(", ");
            self.record_curtailed_analysis(query_desc);
        }
        satisfiable
    }

    /// Charges satisfiability work to this model's cumulative budget, reporting the
    /// crossing so an analysis that silently stops deciding conditions cannot go
    /// unnoticed by the author of the template that caused it.
    fn charge_satisfiability_work(&self, steps: u64) {
        let before = self.sat_iterations_used.fetch_add(steps, Ordering::Relaxed);
        if before < MAX_TOTAL_SAT_ITERATIONS && before.saturating_add(steps) >= MAX_TOTAL_SAT_ITERATIONS {
            self.record_curtailed_analysis(WHOLE_CONDITION_SET_DESCRIPTION.to_string());
        }
    }

    /// Records what a spent budget stopped short of deciding, for the advisory
    /// diagnostic the validation reports.
    fn record_curtailed_analysis(&self, description: String) {
        if let Ok(mut curtailed) = self.budget_exhausted_queries.lock()
            && curtailed.len() < MAX_REPORTED_BUDGET_EXHAUSTED_QUERIES
        {
            curtailed.push(description);
        }
    }

    /// Whether this model has spent its cumulative satisfiability search budget.
    /// Callers that drive many queries (the pairwise compatibility pass) check
    /// this to stop early once further queries would only return the
    /// conservative answer.
    #[must_use]
    pub fn satisfiability_budget_exhausted(&self) -> bool {
        self.sat_iterations_used.load(Ordering::Relaxed) >= MAX_TOTAL_SAT_ITERATIONS
    }

    /// Cumulative satisfiability search steps consumed by this model so far.
    #[must_use]
    pub fn sat_iterations_used(&self) -> u64 {
        self.sat_iterations_used.load(Ordering::Relaxed)
    }

    pub fn budget_exhausted_queries(&self) -> Vec<String> {
        self.budget_exhausted_queries.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Test-only: advance the cumulative satisfiability counter directly, so the
    /// budget threshold and short-circuit behavior can be exercised without
    /// burning `MAX_TOTAL_SAT_ITERATIONS` of real search work (which would be
    /// pointless seconds of computation). Charged through the same path as real
    /// work so the reporting that accompanies exhaustion is exercised too.
    #[cfg(test)]
    fn add_sat_iterations_for_test(&self, count: u64) {
        self.charge_satisfiability_work(count);
    }

    /// Builds, per parameter the conditions reference, the candidate values to
    /// enumerate during satisfiability search. The set used for each parameter
    /// is:
    ///
    /// - **User parameter with `AllowedValues`**: those values exactly.
    /// - **User parameter without `AllowedValues`**: every literal it is
    ///   compared against in any condition, plus a sentinel
    ///   (`PARAM_UNKNOWN_SENTINEL`) standing for "any other value".
    /// - **Pseudo-parameter pinned by an explicit override** (e.g. user passed
    ///   `--region us-east-1`): the override value as the only candidate, so
    ///   the solver treats the pseudo-parameter as a constant.
    /// - **Pseudo-parameter without an explicit override**: literals plus the
    ///   `__unknown__` sentinel, treating it as a free variable. Without this,
    ///   `Fn::Equals[AWS::Partition, "aws"]` would always evaluate true (the
    ///   default partition is "aws"), incorrectly marking the false branch
    ///   unreachable on templates that deploy to non-commercial partitions.
    ///
    /// Comparing a parameter against only the literals it is actually compared
    /// against (plus the sentinel) is exact: two values a condition set never
    /// distinguishes produce identical truth assignments, so one representative
    /// of the "any other value" class suffices.
    ///
    /// Derived purely from the immutable condition set, parameter definitions,
    /// and pseudo-parameter overrides, so it is computed once and cached.
    fn collect_referenced_param_values(&self) -> HashMap<String, Vec<String>> {
        let mut compared_literals: HashMap<String, Vec<String>> = HashMap::new();
        for expr in self.conditions.values() {
            collect_equals_pairs(expr, &mut compared_literals);
        }
        let mut param_values: HashMap<String, Vec<String>> = HashMap::new();
        for (param_name, literals) in &compared_literals {
            if let Some(fixed) = self.pseudo_overrides.fixed_value(param_name) {
                param_values.insert(param_name.clone(), vec![fixed]);
                continue;
            }
            if let Some(allowed_values) = self.parameters.get(param_name).and_then(|p| p.allowed_values.clone()) {
                param_values.insert(param_name.clone(), allowed_values);
                continue;
            }
            let mut values = literals.clone();
            values.push(PARAM_UNKNOWN_SENTINEL.to_string());
            values.sort();
            values.dedup();
            param_values.insert(param_name.clone(), values);
        }
        param_values
    }

    /// The candidate values of every parameter any condition references,
    /// computed once and cached (see [`Self::collect_referenced_param_values`]).
    fn referenced_param_values(&self) -> &HashMap<String, Vec<String>> {
        self.referenced_param_values.get_or_init(|| self.collect_referenced_param_values())
    }

    #[must_use]
    pub fn conditions_compatible(&self, cond_a: &str, cond_b: &str) -> bool {
        self.is_satisfiable(&[(cond_a.into(), true), (cond_b.into(), true)])
    }

    #[must_use]
    pub fn condition_implies(&self, cond_a: &str, cond_b: &str) -> bool {
        // A implies B iff (A=true, B=false) is unsatisfiable
        // Fast path: same condition always implies itself
        if cond_a == cond_b {
            return true;
        }
        !self.is_satisfiable(&[(cond_a.into(), true), (cond_b.into(), false)])
    }

    pub fn resources_compatible(&self, cond_a: Option<&str>, cond_b: Option<&str>) -> bool {
        match (cond_a, cond_b) {
            (None, _) | (_, None) => true,
            (Some(a), Some(b)) => self.conditions_compatible(a, b),
        }
    }

    pub fn get(&self, name: &str) -> Option<&ConditionExpr> {
        self.conditions.get(name)
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.conditions.keys().map(|s| s.as_str())
    }

    pub fn tautological_equals(&self) -> Vec<(String, bool)> {
        let mut result = Vec::new();
        for (name, expr) in &self.conditions {
            Self::find_tautological(expr, name, &mut result);
        }
        result
    }

    fn find_tautological(expr: &ConditionExpr, cond_name: &str, out: &mut Vec<(String, bool)>) {
        match expr {
            ConditionExpr::Equals(a, b) => {
                let always_equal = match (a, b) {
                    (ValueExpr::Literal(la), ValueExpr::Literal(lb)) => Some(la == lb),
                    (ValueExpr::ParamRef(pa), ValueExpr::ParamRef(pb)) => Some(pa == pb),
                    (ValueExpr::PseudoParam(pa), ValueExpr::PseudoParam(pb)) => Some(pa == pb),
                    _ => None,
                };
                if let Some(equal) = always_equal {
                    out.push((cond_name.to_string(), equal));
                }
            }
            ConditionExpr::And(children) | ConditionExpr::Or(children) => {
                for c in children {
                    Self::find_tautological(c, cond_name, out);
                }
            }
            ConditionExpr::Not(child) => Self::find_tautological(child, cond_name, out),
            ConditionExpr::ConditionRef(_) | ConditionExpr::Invalid => {}
        }
    }

    pub fn referenced_params(&self) -> Vec<String> {
        let mut params = Vec::new();
        for expr in self.conditions.values() {
            collect_param_refs_from_expr(expr, &mut params);
        }
        params.sort();
        params.dedup();
        params
    }

    pub fn register_inline(&mut self, name: String, expr: ConditionExpr) {
        self.register_inline_batch(std::iter::once((name, expr)));
    }

    /// Registers many inline conditions at once, recomputing the derived mutex
    /// groups and implications a single time. Registering a large batch through
    /// `register_inline` would recompute them per insertion (quadratic).
    pub fn register_inline_batch(&mut self, items: impl IntoIterator<Item = (String, ConditionExpr)>) {
        for (name, expr) in items {
            self.conditions.insert(name, expr);
        }
        self.mutex_groups = extract_mutex_groups(&self.conditions);
        self.implications = extract_implications(&self.conditions);
        // Inserting a condition can introduce parameter references the cached
        // map omits, so invalidate it; it is rebuilt lazily on the next
        // satisfiability query. The cumulative iteration counter is deliberately
        // left untouched - it is a per-validation work budget, not state derived
        // from the condition set, and resetting it would hand adversarial input a
        // way to refill the budget.
        self.referenced_param_values = OnceLock::new();
    }

    pub fn register_rule_implications(&mut self, arena: &Arena, rules: &[(String, NodeRef, Vec<NodeRef>)]) {
        // A Rules-section `RuleCondition => Assertions` relationship becomes a set
        // of constraints `__rule_cond_<rule> => __rule_assert_<rule>_<i>`. They are
        // kept in their own list because they restrict what a deployment may
        // supply rather than following from the conditions' structure, so
        // satisfiability has to apply them explicitly (see `rule_implications`).
        let mut rule_implications: Vec<Implication> = Vec::new();
        for (rule_name, condition_node, assertion_nodes) in rules {
            let antecedent = if *condition_node != NULL_REF {
                let expr = parse_condition_expr(arena, *condition_node, &self.parameters);
                let synth_name = format!("__rule_cond_{}", rule_name);
                self.conditions.insert(synth_name.clone(), expr);
                Some(synth_name)
            } else {
                None
            };

            for (idx, assert_node) in assertion_nodes.iter().enumerate() {
                if *assert_node == NULL_REF {
                    continue;
                }
                let assert_expr = parse_condition_expr(arena, *assert_node, &self.parameters);
                let assert_name = format!("__rule_assert_{}_{}", rule_name, idx);
                self.conditions.insert(assert_name.clone(), assert_expr);

                if let Some(ref ante) = antecedent {
                    rule_implications.push(Implication { antecedent: ante.clone(), consequent: assert_name });
                }
            }
        }

        self.mutex_groups = extract_mutex_groups(&self.conditions);
        self.implications = extract_implications(&self.conditions);
        self.rule_implications = rule_implications;
        self.referenced_param_values = OnceLock::new();
    }

    pub fn undefined_condition_refs(&self) -> Vec<(String, String)> {
        let mut result = Vec::new();
        for (owner, expr) in &self.conditions {
            let mut refs = Vec::new();
            collect_condition_refs(expr, &mut refs);
            for r in refs {
                if !self.conditions.contains_key(&r) {
                    result.push((owner.clone(), r));
                }
            }
        }
        // The conditions map iterates in arbitrary order; sort so diagnostic
        // emission order is deterministic across runs.
        result.sort();
        result
    }

    /// Names of top-level conditions whose body does not produce a boolean
    /// (e.g. a bare `Fn::Ref`), for the not-a-boolean condition diagnostic.
    /// Synthetic conditions (`__`-prefixed) are excluded - they are never
    /// user-visible. Returned sorted for deterministic diagnostic ordering.
    pub fn invalid_condition_bodies(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .conditions
            .iter()
            .filter(|(name, expr)| matches!(expr, ConditionExpr::Invalid) && !name.starts_with("__"))
            .map(|(name, _)| name.clone())
            .collect();
        names.sort();
        names
    }

    pub fn detect_cycles(&self) -> Vec<Vec<String>> {
        let mut adj: HashMap<String, Vec<String>> = HashMap::new();
        for (name, expr) in &self.conditions {
            let mut refs = Vec::new();
            collect_condition_refs(expr, &mut refs);
            let mut targets: Vec<String> = refs.into_iter().filter(|r| self.conditions.contains_key(r)).collect();
            targets.sort();
            adj.insert(name.clone(), targets);
        }

        let mut sorted_names: Vec<&String> = self.conditions.keys().collect();
        sorted_names.sort();

        let mut cycles = Vec::new();
        let mut visited: HashSet<String> = HashSet::new();
        let mut on_stack: HashSet<String> = HashSet::new();
        let mut path: Vec<String> = Vec::new();

        for name in &sorted_names {
            if !visited.contains(name.as_str()) {
                Self::dfs_cycles(name, &adj, &mut visited, &mut on_stack, &mut path, &mut cycles);
            }
        }
        cycles
    }

    fn dfs_cycles(
        node: &str,
        adj: &HashMap<String, Vec<String>>,
        visited: &mut HashSet<String>,
        on_stack: &mut HashSet<String>,
        path: &mut Vec<String>,
        cycles: &mut Vec<Vec<String>>,
    ) {
        visited.insert(node.to_string());
        on_stack.insert(node.to_string());
        path.push(node.to_string());

        if let Some(neighbors) = adj.get(node) {
            for neighbor in neighbors {
                if !visited.contains(neighbor.as_str()) {
                    Self::dfs_cycles(neighbor, adj, visited, on_stack, path, cycles);
                } else if on_stack.contains(neighbor.as_str()) {
                    let cycle_start = path.iter().position(|n| n == neighbor).unwrap();
                    let cycle: Vec<String> = path[cycle_start..].to_vec();
                    cycles.push(cycle);
                }
            }
        }

        path.pop();
        on_stack.remove(node);
    }

    pub fn detect_equivalent_conditions(&self) -> Vec<(String, String)> {
        let mut canonical_groups: HashMap<String, Vec<&str>> = HashMap::new();
        for (name, expr) in &self.conditions {
            if name.starts_with("__") {
                continue;
            }
            if expr_has_opaque_value(expr) {
                continue;
            }
            let canonical = canonical_form(expr);
            canonical_groups.entry(canonical).or_default().push(name.as_str());
        }

        let mut pairs = Vec::new();
        for (_, mut group) in canonical_groups {
            if group.len() < 2 {
                continue;
            }
            group.sort();
            for other in &group[1..] {
                pairs.push((group[0].to_string(), other.to_string()));
            }
        }
        pairs
    }
}

fn expr_has_opaque_value(expr: &ConditionExpr) -> bool {
    match expr {
        ConditionExpr::Equals(a, b) => value_is_opaque(a) || value_is_opaque(b),
        ConditionExpr::And(items) | ConditionExpr::Or(items) => items.iter().any(expr_has_opaque_value),
        ConditionExpr::Not(inner) => expr_has_opaque_value(inner),
        // An invalid (non-boolean) body is reported by its own diagnostic and
        // never participates in equivalence detection, so treat it as opaque to
        // exclude it.
        ConditionExpr::Invalid => true,
        ConditionExpr::ConditionRef(_) => false,
    }
}

fn value_is_opaque(val: &ValueExpr) -> bool {
    match val {
        ValueExpr::Other => true,
        // A mapping lookup whose keys contain an opaque sub-expression cannot be
        // compared for equivalence: two lookups that differ only in an opaque key
        // (e.g. `Fn::Select` over different indices) would otherwise canonicalize
        // to the same "?" and be wrongly reported as equivalent.
        ValueExpr::MappingLookup { key1, key2, .. } => value_is_opaque(key1) || value_is_opaque(key2),
        _ => false,
    }
}

fn canonical_form(expr: &ConditionExpr) -> String {
    match expr {
        ConditionExpr::Equals(a, b) => {
            let ca = canonical_value(a);
            let cb = canonical_value(b);
            let (left, right) = if ca <= cb { (ca, cb) } else { (cb, ca) };
            format!("EQ({},{})", left, right)
        }
        ConditionExpr::And(items) => {
            let mut parts: Vec<String> = items.iter().map(canonical_form).collect();
            parts.sort();
            format!("AND({})", parts.join(","))
        }
        ConditionExpr::Or(items) => {
            let mut parts: Vec<String> = items.iter().map(canonical_form).collect();
            parts.sort();
            format!("OR({})", parts.join(","))
        }
        ConditionExpr::Not(inner) => {
            format!("NOT({})", canonical_form(inner))
        }
        ConditionExpr::ConditionRef(name) => {
            format!("CREF({})", name)
        }
        ConditionExpr::Invalid => "INVALID".to_string(),
    }
}

fn canonical_value(val: &ValueExpr) -> String {
    match val {
        ValueExpr::ParamRef(name) => format!("P({})", name),
        ValueExpr::Literal(s) => format!("L({})", s),
        ValueExpr::PseudoParam(name) => format!("PP({})", name),
        ValueExpr::MappingLookup { map_name, key1, key2 } => {
            format!("MAP({},{},{})", map_name, canonical_value(key1), canonical_value(key2))
        }
        ValueExpr::Other => "?".to_string(),
    }
}

fn collect_param_refs_from_expr(expr: &ConditionExpr, out: &mut Vec<String>) {
    match expr {
        ConditionExpr::Equals(a, b) => {
            collect_param_refs_from_value(a, out);
            collect_param_refs_from_value(b, out);
        }
        ConditionExpr::And(exprs) | ConditionExpr::Or(exprs) => {
            for e in exprs {
                collect_param_refs_from_expr(e, out);
            }
        }
        ConditionExpr::Not(e) => collect_param_refs_from_expr(e, out),
        ConditionExpr::ConditionRef(_) | ConditionExpr::Invalid => {}
    }
}

fn collect_param_refs_from_value(expr: &ValueExpr, out: &mut Vec<String>) {
    match expr {
        ValueExpr::ParamRef(n) => out.push(n.clone()),
        ValueExpr::MappingLookup { key1, key2, .. } => {
            collect_param_refs_from_value(key1, out);
            collect_param_refs_from_value(key2, out);
        }
        _ => {}
    }
}

pub fn parse_condition_expr(
    arena: &Arena,
    node_ref: NodeRef,
    parameters: &HashMap<String, ParameterInfo>,
) -> ConditionExpr {
    match arena.node(node_ref) {
        Node::Intrinsic(IntrinsicFn::Equals(a, b)) => {
            let va = parse_value_expr(arena, *a, parameters);
            let vb = parse_value_expr(arena, *b, parameters);
            ConditionExpr::Equals(va, vb)
        }
        Node::Intrinsic(IntrinsicFn::And(children)) => {
            let exprs = children.iter().map(|c| parse_condition_expr(arena, *c, parameters)).collect();
            ConditionExpr::And(exprs)
        }
        Node::Intrinsic(IntrinsicFn::Or(children)) => {
            let exprs = children.iter().map(|c| parse_condition_expr(arena, *c, parameters)).collect();
            ConditionExpr::Or(exprs)
        }
        Node::Intrinsic(IntrinsicFn::Not(child)) => {
            let expr = parse_condition_expr(arena, *child, parameters);
            ConditionExpr::Not(Box::new(expr))
        }
        Node::Intrinsic(IntrinsicFn::Ref(target)) => {
            if let Some(name) = target.strip_prefix(CONDITION_REF_PREFIX) {
                ConditionExpr::ConditionRef(name.to_string())
            } else {
                // A bare `Fn::Ref` (to a parameter, resource, or pseudo-parameter)
                // is not a boolean and is not a condition reference, so it is an
                // invalid condition body.
                ConditionExpr::Invalid
            }
        }
        _ => {
            // Try to parse as a map with intrinsic keys
            if let Some(entries) = arena.as_map(node_ref)
                && entries.len() == 1
            {
                let (key, val) = &entries[0];
                match key.as_str() {
                    FN_EQUALS => {
                        if let Some(arr) = arena.as_list(*val)
                            && arr.len() == 2
                        {
                            let va = parse_value_expr(arena, arr[0], parameters);
                            let vb = parse_value_expr(arena, arr[1], parameters);
                            return ConditionExpr::Equals(va, vb);
                        }
                    }
                    FN_AND => {
                        if let Some(arr) = arena.as_list(*val) {
                            let exprs = arr.iter().map(|c| parse_condition_expr(arena, *c, parameters)).collect();
                            return ConditionExpr::And(exprs);
                        }
                    }
                    FN_OR => {
                        if let Some(arr) = arena.as_list(*val) {
                            let exprs = arr.iter().map(|c| parse_condition_expr(arena, *c, parameters)).collect();
                            return ConditionExpr::Or(exprs);
                        }
                    }
                    FN_NOT => {
                        if let Some(arr) = arena.as_list(*val)
                            && !arr.is_empty()
                        {
                            let expr = parse_condition_expr(arena, arr[0], parameters);
                            return ConditionExpr::Not(Box::new(expr));
                        }
                    }
                    FN_CONDITION => {
                        if let Some(name) = arena.as_str(*val) {
                            return ConditionExpr::ConditionRef(name.to_string());
                        }
                    }
                    _ => {}
                }
            }
            ConditionExpr::Invalid
        }
    }
}

fn parse_value_expr(arena: &Arena, node_ref: NodeRef, parameters: &HashMap<String, ParameterInfo>) -> ValueExpr {
    match arena.node(node_ref) {
        Node::String(s) => ValueExpr::Literal(s.clone()),
        Node::Int(i) => ValueExpr::Literal(i.to_string()),
        Node::Bool(b) => ValueExpr::Literal(b.to_string()),
        Node::Intrinsic(IntrinsicFn::Ref(target)) => {
            if target.starts_with(PSEUDO_PREFIX) {
                ValueExpr::PseudoParam(target.clone())
            } else if parameters.contains_key(target) {
                ValueExpr::ParamRef(target.clone())
            } else {
                ValueExpr::Other
            }
        }
        // FindInMap can resolve to a concrete value, so it gets a dedicated
        // variant the SAT solver understands. Every other intrinsic produces
        // a value that cannot be known statically - it must be treated as an
        // opaque unknown (`Other`), never a comparable literal. Treating, say,
        // `Fn::Sub(...)` as the literal string "Sub(...)" would make
        // `Fn::Equals[!Sub ..., "x"]` look like a literal-vs-literal compare and
        // spuriously fire the always-true/false tautology check.
        Node::Intrinsic(IntrinsicFn::FindInMap(m, k1, k2, _)) => {
            let map_name = arena.as_str(*m).unwrap_or("?").to_string();
            let key1 = parse_value_expr(arena, *k1, parameters);
            let key2 = parse_value_expr(arena, *k2, parameters);
            ValueExpr::MappingLookup { map_name, key1: Box::new(key1), key2: Box::new(key2) }
        }
        _ => ValueExpr::Other,
    }
}

/// Walks a condition expression and collects, per parameter or pseudo-parameter
/// it references, every literal it is compared against in an `Fn::Equals`.
/// Pseudo-parameters (`AWS::Partition`, `AWS::Region`, …) are collected the same
/// way as user parameters; the SAT solver treats both as named symbols whose
/// candidate values are enumerated during satisfiability search.
fn collect_equals_pairs(expr: &ConditionExpr, out: &mut HashMap<String, Vec<String>>) {
    match expr {
        ConditionExpr::Equals(a, b) => {
            if let Some((symbol, literal)) = match_symbol_literal_pair(a, b) {
                out.entry(symbol).or_default().push(literal);
            } else {
                collect_param_refs_from_value_into_pairs(a, out);
                collect_param_refs_from_value_into_pairs(b, out);
            }
        }
        ConditionExpr::And(exprs) | ConditionExpr::Or(exprs) => {
            for e in exprs {
                collect_equals_pairs(e, out);
            }
        }
        ConditionExpr::Not(e) => collect_equals_pairs(e, out),
        ConditionExpr::ConditionRef(_) | ConditionExpr::Invalid => {}
    }
}

/// Returns the `(symbol_name, compared_literal)` when `a` and `b` are an
/// `Fn::Equals` pair of a parameter (or pseudo-parameter) and a literal in
/// either order. Returns `None` otherwise.
fn match_symbol_literal_pair(a: &ValueExpr, b: &ValueExpr) -> Option<(String, String)> {
    match (a, b) {
        (ValueExpr::ParamRef(p), ValueExpr::Literal(v)) | (ValueExpr::Literal(v), ValueExpr::ParamRef(p)) => {
            Some((p.clone(), v.clone()))
        }
        (ValueExpr::PseudoParam(p), ValueExpr::Literal(v)) | (ValueExpr::Literal(v), ValueExpr::PseudoParam(p)) => {
            Some((p.clone(), v.clone()))
        }
        _ => None,
    }
}

fn collect_param_refs_from_value_into_pairs(expr: &ValueExpr, out: &mut HashMap<String, Vec<String>>) {
    match expr {
        ValueExpr::ParamRef(p) | ValueExpr::PseudoParam(p) => {
            out.entry(p.clone()).or_default();
        }
        ValueExpr::MappingLookup { key1, key2, .. } => {
            collect_param_refs_from_value_into_pairs(key1, out);
            collect_param_refs_from_value_into_pairs(key2, out);
        }
        _ => {}
    }
}

fn collect_condition_refs(expr: &ConditionExpr, out: &mut Vec<String>) {
    let mut borrowed = Vec::new();
    condition_ref_names(expr, &mut borrowed);
    out.extend(borrowed.into_iter().map(str::to_string));
}

pub fn collect_condition_deps(expr: &ConditionExpr, out: &mut Vec<String>) {
    collect_condition_refs(expr, out);
}

fn extract_mutex_groups(conditions: &HashMap<String, ConditionExpr>) -> Vec<MutexGroup> {
    // Find conditions that test the same parameter with different literal values.
    // Handles both Equals(Param, Lit) and Not(Equals(Param, Lit)).
    let mut param_tests: HashMap<String, Vec<(String, String)>> = HashMap::new(); // param → [(cond_name, literal)]

    for (name, expr) in conditions {
        if let Some((param, _lit, is_positive)) = extract_equals_test(expr) {
            // Only positive tests (Equals) form mutex groups - two conditions
            // testing Equals(Param, "X") and Equals(Param, "Y") are mutex.
            // Not(Equals(Param, "X")) is compatible with Equals(Param, "Y").
            if is_positive {
                param_tests.entry(param).or_default().push((name.clone(), _lit));
            }
        }
    }

    param_tests
        .into_iter()
        .filter(|(_, tests)| tests.len() > 1)
        .map(|(param, tests)| {
            let conditions = tests.iter().map(|(n, _)| n.clone()).collect();
            let values = tests.iter().map(|(_, v)| v.clone()).collect();
            MutexGroup { conditions, parameter: param, values }
        })
        .collect()
}

fn extract_equals_test(expr: &ConditionExpr) -> Option<(String, String, bool)> {
    match expr {
        ConditionExpr::Equals(a, b) => {
            if let (ValueExpr::ParamRef(p), ValueExpr::Literal(v)) | (ValueExpr::Literal(v), ValueExpr::ParamRef(p)) =
                (a, b)
            {
                return Some((p.clone(), v.clone(), true));
            }
            None
        }
        ConditionExpr::Not(inner) => {
            if let Some((param, lit, positive)) = extract_equals_test(inner) {
                Some((param, lit, !positive))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// One satisfiability query, prepared for enumeration.
///
/// A CloudFormation condition is a pure function of the template's parameters,
/// pseudo-parameters, and mappings - a condition has no truth value of its own
/// to choose. So "can these conditions hold simultaneously?" is decided over the
/// *parameter* space: the assumptions hold exactly when some assignment of
/// concrete values to the parameters they depend on makes every assumed
/// condition take its assumed value.
///
/// Searching parameter assignments rather than condition assignments is what
/// keeps the cost proportional to a template's real degrees of freedom. The
/// number of parameter points is the product of a few candidate values per
/// referenced parameter, while the space of condition truth assignments is
/// exponential in the number of conditions - so a template that layers many
/// conditions over a few shared inputs (a partition or region check reused
/// across dozens of conditions) stays cheap no matter how many conditions are
/// built on top of those inputs.
///
/// Enumerating points also removes the need to enforce derived constraints
/// separately: a parameter takes exactly one value at a point, so mutually
/// exclusive conditions cannot both hold there, and evaluating a condition at a
/// point yields exactly the value its `And`/`Or`/`Not` structure entails. Only
/// Rules-section constraints, which no condition expression entails, are applied
/// as a filter on admissible points.
struct SatisfiabilityQuery<'model> {
    model: &'model ConditionModel,
    /// Conditions whose value this query depends on: the assumed conditions, the
    /// conditions reachable from them through condition references, and the
    /// endpoints of every applicable Rules-section constraint. Positions in this
    /// list index `value_at_point` and `being_evaluated`.
    dependencies: Vec<&'model str>,
    position_of_dependency: HashMap<&'model str, usize>,
    /// Parameters the dependencies reference, each with the candidate values to
    /// enumerate. Held in a deterministic order so the work charged to the
    /// budget - and therefore which query first trips an exhausted budget - does
    /// not depend on hash iteration order.
    parameters: Vec<(&'model str, &'model [String])>,
    position_of_parameter: HashMap<&'model str, usize>,
    /// Which candidate value each parameter takes at the current point.
    selected_value: Vec<usize>,
    /// How many parameters are bound while the descent explores points: those at
    /// positions below it have a value, those at or above it are still free and
    /// read as undetermined.
    bound_depth: usize,
    /// Rules-section constraints to honor, as `(antecedent, consequent)` pairs of
    /// dependency positions.
    rule_constraints: Vec<(usize, usize)>,
    value_at_point: Vec<PointValue>,
    /// The value a condition is forced to take by the assumptions, for conditions
    /// the point itself leaves undetermined. Such a condition acts as a free
    /// choice - its value turns on data the model cannot resolve - and the
    /// assumptions constrain that choice: assuming `And(a, b)` holds forces both
    /// `a` and `b` to hold however little is known about them. Cleared for every
    /// point.
    forced_value: Vec<Option<bool>>,
    /// How many values the assumptions have forced. Propagation repeats while this
    /// keeps growing, so a value forced late still constrains what was examined
    /// earlier.
    forcings_made: u64,
    being_evaluated: Vec<bool>,
    /// How many reads returned something other than a property of the point alone:
    /// a reference cut because it closes a cycle, or a value the assumptions forced.
    /// Comparing this count before and after an evaluation is how that evaluation
    /// detects its result must not be cached as the point's own value.
    provisional_reads: u64,
    /// Satisfiability work performed, charged to the model's per-query and
    /// cumulative budgets by the caller.
    steps: u64,
}

/// Cached value of one dependency at the current parameter point.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PointValue {
    NotEvaluated,
    Determined(bool),
    /// The point does not determine the condition: it compares a value the model
    /// cannot resolve, references a condition the template does not define, or
    /// sits on a condition-reference cycle.
    Undetermined,
}

/// The precomputed inputs of one point enumeration, bundled so the recursive
/// descent carries a single reference rather than three slices.
struct PointEnumeration<'query> {
    /// The value each assumed condition must take, by dependency position.
    expectations: &'query [(usize, bool)],
    /// The parameters each dependency's value depends on.
    dependency_masks: &'query [u64],
    /// The parameters still free at each depth, so the condition values that read
    /// them can be discarded before a new value is tried.
    unbound_masks: &'query [u64],
}

impl<'model> SatisfiabilityQuery<'model> {
    fn prepare(
        model: &'model ConditionModel,
        assumed: &HashMap<&'model str, bool>,
        param_overrides: &'model HashMap<String, Vec<String>>,
    ) -> Self {
        let mut assumed_names: Vec<&'model str> = assumed.keys().copied().collect();
        assumed_names.sort_unstable();

        let mut query = SatisfiabilityQuery {
            model,
            dependencies: Vec::new(),
            position_of_dependency: HashMap::new(),
            parameters: Vec::new(),
            position_of_parameter: HashMap::new(),
            selected_value: Vec::new(),
            bound_depth: 0,
            rule_constraints: Vec::new(),
            value_at_point: Vec::new(),
            forced_value: Vec::new(),
            forcings_made: 0,
            being_evaluated: Vec::new(),
            provisional_reads: 0,
            steps: 0,
        };
        query.add_dependencies_reachable_from(&assumed_names);
        query.add_parameters_of_dependencies(param_overrides);
        query.add_applicable_rule_constraints(param_overrides);
        query.order_parameters_by_reader_count();
        query.selected_value = vec![0; query.parameters.len()];
        query.value_at_point = vec![PointValue::NotEvaluated; query.dependencies.len()];
        query.forced_value = vec![None; query.dependencies.len()];
        query.being_evaluated = vec![false; query.dependencies.len()];
        query
    }

    /// Orders the parameters for the descent: those pinned to a single candidate
    /// value first, since binding them can never branch, and the rest so that the
    /// one the fewest conditions read is bound last. The descent re-evaluates only
    /// conditions that read a parameter it just rebound, so varying the least-read
    /// parameter innermost keeps the largest number of condition values valid.
    fn order_parameters_by_reader_count(&mut self) {
        if self.parameters.len() < 2 {
            return;
        }
        let model = self.model;
        let mut reader_count: HashMap<&'model str, usize> = HashMap::new();
        let mut names: Vec<&'model str> = Vec::new();
        for dependency in &self.dependencies {
            let Some(expr) = model.conditions.get(*dependency) else {
                continue;
            };
            names.clear();
            parameter_names(expr, &mut names);
            names.sort_unstable();
            names.dedup();
            for name in &names {
                *reader_count.entry(name).or_default() += 1;
            }
        }
        self.steps += self.dependencies.len() as u64;
        // Ties break on the parameter name so the enumeration order - and with it
        // the work charged before a budget trips - never depends on hash
        // iteration order.
        self.parameters.sort_by(|(left, left_candidates), (right, right_candidates)| {
            (left_candidates.len() > 1)
                .cmp(&(right_candidates.len() > 1))
                .then_with(|| {
                    let left_readers = reader_count.get(left).copied().unwrap_or_default();
                    let right_readers = reader_count.get(right).copied().unwrap_or_default();
                    right_readers.cmp(&left_readers)
                })
                .then_with(|| left.cmp(right))
        });
        self.position_of_parameter = self.parameters.iter().enumerate().map(|(at, (name, _))| (*name, at)).collect();
    }

    /// Adds `seeds` and every condition reachable from them through condition
    /// references. Reachability is what makes the parameter search exact: a
    /// condition no assumed condition can reach cannot influence the answer, and
    /// a parameter only that condition reads is therefore irrelevant too.
    fn add_dependencies_reachable_from(&mut self, seeds: &[&'model str]) {
        let conditions = &self.model.conditions;
        let mut pending: Vec<&'model str> = seeds.to_vec();
        while let Some(name) = pending.pop() {
            let Some((dependency, expr)) = conditions.get_key_value(name) else {
                continue;
            };
            let dependency = dependency.as_str();
            if self.position_of_dependency.contains_key(dependency) {
                continue;
            }
            self.position_of_dependency.insert(dependency, self.dependencies.len());
            self.dependencies.push(dependency);
            self.steps += 1;
            condition_ref_names(expr, &mut pending);
        }
    }

    /// Registers the parameters the current dependencies read, with the candidate
    /// values to enumerate for each.
    fn add_parameters_of_dependencies(&mut self, param_overrides: &'model HashMap<String, Vec<String>>) {
        let conditions = &self.model.conditions;
        let mut names: Vec<&'model str> = Vec::new();
        for dependency in &self.dependencies {
            if let Some(expr) = conditions.get(*dependency) {
                parameter_names(expr, &mut names);
            }
        }
        names.sort_unstable();
        names.dedup();
        for name in names {
            self.add_parameter(name, param_overrides);
        }
    }

    /// Registers one parameter and the values the query will try for it. A
    /// per-query override (e.g. a pinned target region) replaces the model's
    /// derived candidates. A parameter with no candidate values is left out: it
    /// is then undetermined at every point, which keeps the query conservative
    /// rather than silently making every condition that reads it unsatisfiable.
    fn add_parameter(&mut self, name: &'model str, param_overrides: &'model HashMap<String, Vec<String>>) {
        if self.position_of_parameter.contains_key(name) {
            return;
        }
        let candidates = param_overrides
            .get(name)
            .or_else(|| self.model.referenced_param_values().get(name))
            .map_or(&[][..], Vec::as_slice);
        if candidates.is_empty() {
            return;
        }
        self.position_of_parameter.insert(name, self.parameters.len());
        self.parameters.push((name, candidates));
        self.steps += 1;
    }

    /// Adds the Rules-section constraints this query must honor. A Rules
    /// assertion restricts which parameter values a deployment can supply, and no
    /// condition expression entails it, so a point that violates one must be
    /// excluded rather than accepted.
    ///
    /// A constraint applies once it reads a parameter this query already varies;
    /// pulling it in can introduce further parameters, which can bring in further
    /// constraints, so this runs to a fixpoint. A constraint over parameters the
    /// query does not vary is left unenforced - its antecedent is undetermined at
    /// every point, so enforcing it could only reject points the template allows.
    fn add_applicable_rule_constraints(&mut self, param_overrides: &'model HashMap<String, Vec<String>>) {
        let model = self.model;
        if model.rule_implications.is_empty() {
            return;
        }
        let mut applied = vec![false; model.rule_implications.len()];
        loop {
            let mut newly_applied = false;
            for (position, implication) in model.rule_implications.iter().enumerate() {
                if applied[position] {
                    continue;
                }
                let (Some((antecedent, _)), Some((consequent, _))) = (
                    model.conditions.get_key_value(implication.antecedent.as_str()),
                    model.conditions.get_key_value(implication.consequent.as_str()),
                ) else {
                    applied[position] = true;
                    continue;
                };
                let endpoints = [antecedent.as_str(), consequent.as_str()];
                let mut steps = 0;
                let constrained_parameters = reachable_parameter_names(&model.conditions, &endpoints, &mut steps);
                self.steps += steps;
                if !constrained_parameters.iter().any(|name| self.position_of_parameter.contains_key(name)) {
                    continue;
                }
                applied[position] = true;
                newly_applied = true;
                self.add_dependencies_reachable_from(&endpoints);
                self.add_parameters_of_dependencies(param_overrides);
                self.rule_constraints
                    .push((self.position_of_dependency[endpoints[0]], self.position_of_dependency[endpoints[1]]));
            }
            if !newly_applied {
                return;
            }
        }
    }

    /// How many distinct parameter points this query would enumerate.
    fn parameter_point_count(&self) -> u64 {
        self.parameters.iter().fold(1u64, |points, (_, candidates)| points.saturating_mul(candidates.len() as u64))
    }

    /// Whether some parameter point makes every assumed condition take its
    /// assumed value.
    ///
    /// Parameters are bound one at a time and the descent continues only while the
    /// assumptions can still hold: a condition the parameters bound so far already
    /// decide against its assumption cannot be rescued by the parameters still
    /// unbound, so every point below that branch is skipped. That is what keeps a
    /// wide parameter space affordable - the branches that could satisfy the query
    /// are explored, the rest are cut at the level that decided them.
    fn some_point_satisfies(&mut self, assumed: &HashMap<&'model str, bool>) -> bool {
        let mut expectations: Vec<(usize, bool)> = assumed
            .iter()
            .filter_map(|(name, expected)| self.position_of_dependency.get(name).map(|&at| (at, *expected)))
            .collect();
        expectations.sort_unstable();
        let parameter_masks = self.varying_parameter_masks();
        let dependency_masks = self.dependency_parameter_masks(&parameter_masks);
        let mut unbound_masks = vec![0u64; self.parameters.len() + 1];
        for at in (0..self.parameters.len()).rev() {
            unbound_masks[at] = unbound_masks[at + 1] | parameter_masks[at];
        }
        // Parameters pinned to a single candidate value are ordered first and are
        // bound for the whole enumeration: their value cannot vary, so descending
        // through them would only deepen the recursion without branching.
        self.bound_depth = self.parameters.iter().take_while(|(_, candidates)| candidates.len() < 2).count();
        let enumeration = PointEnumeration {
            expectations: &expectations,
            dependency_masks: &dependency_masks,
            unbound_masks: &unbound_masks,
        };
        self.extend_point(&enumeration)
    }

    /// Explores the points that agree with the parameters bound so far, returning
    /// whether any of them satisfies the query.
    fn extend_point(&mut self, enumeration: &PointEnumeration<'_>) -> bool {
        self.steps += 1;
        if self.steps > MAX_SAT_ITERATIONS {
            // The number of points is the product of the candidate values of every
            // parameter the query reads, so it grows exponentially in that
            // parameter count. Once the per-query budget is spent, assume
            // satisfiable rather than explore further - the conservative-`true`
            // contract documented on `is_satisfiable`.
            return true;
        }
        if !self.assumptions_can_still_hold(enumeration.expectations) {
            return false;
        }
        let at = self.bound_depth;
        if at == self.parameters.len() {
            return true;
        }
        for candidate in 0..self.parameters[at].1.len() {
            self.selected_value[at] = candidate;
            // Everything from this parameter inward is about to take a new value,
            // so the condition values that read any of them no longer hold.
            self.discard_values_affected_by(enumeration.unbound_masks[at], enumeration.dependency_masks);
            self.bound_depth = at + 1;
            let satisfied = self.extend_point(enumeration);
            self.bound_depth = at;
            if satisfied {
                return true;
            }
        }
        false
    }

    /// Whether the assumptions and the applicable Rules-section constraints can
    /// still hold given the parameters bound so far. A condition that is already
    /// determined against its assumption stays that way however the unbound
    /// parameters are chosen, which is what makes cutting the branch sound.
    ///
    /// A condition the parameters leave undetermined is not simply accepted:
    /// assuming it holds also constrains the conditions it is built from, so the
    /// assumptions are propagated into those and any contradiction they force is a
    /// contradiction of the assumptions. Propagation repeats while it keeps forcing
    /// new values, so a value forced late still contradicts an assumption examined
    /// earlier. Only contradictions that must hold are derived - where two operands
    /// could each be the one satisfying a disjunction, nothing is forced - so the
    /// answer degrades to the conservative "can still hold" rather than to a wrong
    /// rejection.
    fn assumptions_can_still_hold(&mut self, expectations: &[(usize, bool)]) -> bool {
        self.forced_value.fill(None);
        loop {
            let forcings_before = self.forcings_made;
            for &(dependency, expected) in expectations {
                if !self.require_dependency(dependency, expected) {
                    return false;
                }
            }
            if !self.rule_constraints_hold() {
                return false;
            }
            if self.forcings_made == forcings_before {
                return true;
            }
        }
    }

    /// Requires a dependency to take a value, propagating into the conditions it is
    /// built from when the point leaves it undetermined. Returns `false` when that
    /// contradicts what the point determines or what the assumptions already forced.
    fn require_dependency(&mut self, dependency: usize, expected: bool) -> bool {
        self.steps += 1;
        if let Some(determined) = self.dependency_value(dependency) {
            return determined == expected;
        }
        match self.forced_value[dependency] {
            Some(already_forced) => return already_forced == expected,
            None => {
                self.forced_value[dependency] = Some(expected);
                self.forcings_made += 1;
            }
        }
        let Some(expr) = self.model.conditions.get(self.dependencies[dependency]) else {
            return true;
        };
        self.require(expr, expected)
    }

    /// Requires an expression to take a value, deriving the values its operands
    /// must take. A conjunction that must hold requires every operand to hold, a
    /// disjunction that must not hold requires every operand not to hold, and a
    /// negation inverts the requirement; the remaining shapes need at least one
    /// operand to comply, which forces nothing until only one candidate is left.
    fn require(&mut self, expr: &'model ConditionExpr, expected: bool) -> bool {
        self.steps += 1;
        match expr {
            ConditionExpr::ConditionRef(name) => match self.position_of_dependency.get(name.as_str()).copied() {
                Some(dependency) => self.require_dependency(dependency, expected),
                // A reference the template does not define constrains nothing.
                None => true,
            },
            ConditionExpr::Not(operand) => self.require(operand, !expected),
            ConditionExpr::And(operands) if expected => operands.iter().all(|operand| self.require(operand, true)),
            ConditionExpr::Or(operands) if !expected => operands.iter().all(|operand| self.require(operand, false)),
            ConditionExpr::And(operands) => self.require_any(operands, false),
            ConditionExpr::Or(operands) => self.require_any(operands, true),
            // A comparison is a leaf: when the point cannot decide it, the values it
            // reads are simply unknown, and any requirement on it can be met.
            ConditionExpr::Equals(_, _) | ConditionExpr::Invalid => true,
        }
    }

    /// Requires at least one operand to take `satisfying`. Nothing is forced while
    /// more than one operand could be the one that does - only the two certainties
    /// are derived: a contradiction when every operand already rules it out, and the
    /// value of the last operand that could still comply.
    fn require_any(&mut self, operands: &'model [ConditionExpr], satisfying: bool) -> bool {
        let mut undecided: Option<&'model ConditionExpr> = None;
        let mut undecided_operands = 0usize;
        for operand in operands {
            match self.evaluate(operand) {
                Some(value) if value == satisfying => return true,
                Some(_) => {}
                None => {
                    undecided_operands += 1;
                    undecided = Some(operand);
                }
            }
        }
        match (undecided_operands, undecided) {
            (0, _) => false,
            (1, Some(last_candidate)) => self.require(last_candidate, satisfying),
            _ => true,
        }
    }

    /// Whether the applicable Rules-section constraints hold, forcing what they
    /// entail: a constraint whose antecedent holds requires its consequent to hold,
    /// and one whose consequent cannot hold requires its antecedent not to.
    fn rule_constraints_hold(&mut self) -> bool {
        for at in 0..self.rule_constraints.len() {
            let (antecedent, consequent) = self.rule_constraints[at];
            if self.dependency_belief(antecedent) == Some(true) && !self.require_dependency(consequent, true) {
                return false;
            }
            if self.dependency_belief(consequent) == Some(false) && !self.require_dependency(antecedent, false) {
                return false;
            }
        }
        true
    }

    /// One bit per parameter whose value varies across points. A parameter with a
    /// single candidate value gets an empty mask because its value never changes.
    /// Parameters past the width of the mask share its last bit, which
    /// over-invalidates rather than under-invalidates.
    fn varying_parameter_masks(&self) -> Vec<u64> {
        let mut masks = Vec::with_capacity(self.parameters.len());
        let mut next_bit = 0u32;
        for (_, candidates) in &self.parameters {
            if candidates.len() < 2 {
                masks.push(0);
                continue;
            }
            masks.push(1u64 << next_bit);
            next_bit = (next_bit + 1).min(u64::BITS - 1);
        }
        masks
    }

    /// For each dependency, the parameters its value can depend on: those it reads
    /// itself and those read by everything it references. Enumeration consults
    /// this to keep the values a parameter change cannot have affected, which is
    /// what makes the cost of a point proportional to the conditions that
    /// actually moved rather than to the whole dependency closure.
    fn dependency_parameter_masks(&mut self, parameter_masks: &[u64]) -> Vec<u64> {
        let model = self.model;
        let mut masks = vec![0u64; self.dependencies.len()];
        let mut references: Vec<Vec<usize>> = vec![Vec::new(); self.dependencies.len()];
        let mut names: Vec<&'model str> = Vec::new();
        let mut referenced: Vec<&'model str> = Vec::new();
        for (at, dependency) in self.dependencies.iter().enumerate() {
            let Some(expr) = model.conditions.get(*dependency) else {
                continue;
            };
            names.clear();
            parameter_names(expr, &mut names);
            for name in &names {
                if let Some(&position) = self.position_of_parameter.get(*name) {
                    masks[at] |= parameter_masks[position];
                }
            }
            referenced.clear();
            condition_ref_names(expr, &mut referenced);
            references[at] =
                referenced.iter().filter_map(|name| self.position_of_dependency.get(*name).copied()).collect();
        }
        self.steps += self.dependencies.len() as u64;

        // Propagate to a fixpoint: masks only grow, so this terminates even when
        // the references form a cycle.
        loop {
            let mut grew = false;
            for at in 0..masks.len() {
                let propagated = references[at].iter().fold(masks[at], |mask, &reference| mask | masks[reference]);
                if propagated != masks[at] {
                    masks[at] = propagated;
                    grew = true;
                }
            }
            self.steps += masks.len() as u64;
            if !grew {
                return masks;
            }
        }
    }

    /// Drops the cached values of every dependency that reads one of the
    /// parameters that just changed.
    fn discard_values_affected_by(&mut self, changed_parameters: u64, dependency_masks: &[u64]) {
        for (at, value) in self.value_at_point.iter_mut().enumerate() {
            if dependency_masks[at] & changed_parameters != 0 {
                *value = PointValue::NotEvaluated;
            }
        }
    }

    /// The value of one dependency at the current point, memoized for the rest of
    /// this point's evaluation. Only what the point itself determines is cached;
    /// values that came from a cut cycle or from what the assumptions forced are
    /// left out, because they hold for one reference rather than for the point.
    fn dependency_value(&mut self, dependency: usize) -> Option<bool> {
        match self.value_at_point[dependency] {
            PointValue::Determined(value) => return Some(value),
            PointValue::Undetermined => return None,
            PointValue::NotEvaluated => {}
        }
        if self.being_evaluated[dependency] {
            // A condition that transitively references itself has no value to
            // read here; leaving this reference undetermined keeps evaluation
            // total and terminating. The cycle itself is reported as a template
            // defect by the reference-graph analysis.
            self.provisional_reads += 1;
            return None;
        }
        let Some(expr) = self.model.conditions.get(self.dependencies[dependency]) else {
            self.value_at_point[dependency] = PointValue::Undetermined;
            return None;
        };
        self.being_evaluated[dependency] = true;
        let provisional_reads_before = self.provisional_reads;
        let value = self.evaluate(expr);
        self.being_evaluated[dependency] = false;
        if self.provisional_reads == provisional_reads_before {
            self.value_at_point[dependency] = value.map_or(PointValue::Undetermined, PointValue::Determined);
        }
        value
    }

    /// What is currently believed about a dependency: the value the point
    /// determines, or failing that the value the assumptions have forced on it.
    fn dependency_belief(&mut self, dependency: usize) -> Option<bool> {
        if let Some(determined) = self.dependency_value(dependency) {
            return Some(determined);
        }
        let forced = self.forced_value[dependency];
        if forced.is_some() {
            self.provisional_reads += 1;
        }
        forced
    }

    /// Evaluates a condition expression at the current point. `None` means the
    /// point does not determine the expression; it propagates except where an
    /// operand already decides the result - a false operand of `And`, a true
    /// operand of `Or` - so an unresolvable comparison in one branch does not
    /// discard what the rest of the expression proves.
    fn evaluate(&mut self, expr: &'model ConditionExpr) -> Option<bool> {
        // Each evaluation step is one unit of satisfiability work. Counting here,
        // in the recursive core, keeps the budget proportional to real effort: a
        // deep condition closure draws the budget down faster than a shallow one,
        // so the budget bounds actual work uniformly regardless of how the
        // conditions are shaped.
        self.steps += 1;
        match expr {
            ConditionExpr::Equals(left, right) => {
                let left = self.value_at_current_point(left)?;
                let right = self.value_at_current_point(right)?;
                Some(left == right)
            }
            ConditionExpr::And(operands) => {
                let mut all_determined = true;
                for operand in operands {
                    match self.evaluate(operand) {
                        Some(false) => return Some(false),
                        Some(true) => {}
                        None => all_determined = false,
                    }
                }
                all_determined.then_some(true)
            }
            ConditionExpr::Or(operands) => {
                let mut all_determined = true;
                for operand in operands {
                    match self.evaluate(operand) {
                        Some(true) => return Some(true),
                        Some(false) => {}
                        None => all_determined = false,
                    }
                }
                all_determined.then_some(false)
            }
            ConditionExpr::Not(operand) => self.evaluate(operand).map(|value| !value),
            ConditionExpr::ConditionRef(name) => {
                // A reference to a condition the template does not define has no
                // value; it is reported as an undefined reference elsewhere.
                let dependency = self.position_of_dependency.get(name.as_str()).copied()?;
                self.dependency_belief(dependency)
            }
            // A condition body that is not a boolean has no truth value, so it
            // never decides a query.
            ConditionExpr::Invalid => None,
        }
    }

    /// The concrete value of a value expression at the current point, or `None`
    /// when the point does not determine it.
    fn value_at_current_point(&mut self, expr: &'model ValueExpr) -> Option<String> {
        match expr {
            ValueExpr::Literal(literal) => Some(literal.clone()),
            ValueExpr::ParamRef(name) => self.selected_parameter_value(name).map(str::to_string),
            ValueExpr::PseudoParam(name) => self
                .selected_parameter_value(name)
                .map(str::to_string)
                .or_else(|| self.model.pseudo_overrides.fixed_value(name)),
            ValueExpr::MappingLookup { map_name, key1, key2 } => {
                let top_level_key = self.value_at_current_point(key1)?;
                let second_level_key = self.value_at_current_point(key2)?;
                let mapped = self.model.mappings.get(map_name)?.get(&top_level_key)?.get(&second_level_key)?;
                match mapped {
                    serde_json::Value::String(text) => Some(text.clone()),
                    other => Some(other.to_string()),
                }
            }
            ValueExpr::Other => None,
        }
    }

    /// The value the parameters bound so far assign to a parameter, or `None` when
    /// the query does not vary it or has not bound it yet.
    fn selected_parameter_value(&self, name: &str) -> Option<&'model str> {
        let position = *self.position_of_parameter.get(name)?;
        if position >= self.bound_depth {
            return None;
        }
        self.parameters[position].1.get(self.selected_value[position]).map(String::as_str)
    }
}

/// Names of the conditions `expr` references, borrowed from `expr` so the
/// satisfiability hot path collects them without allocating.
fn condition_ref_names<'expr>(expr: &'expr ConditionExpr, out: &mut Vec<&'expr str>) {
    match expr {
        ConditionExpr::ConditionRef(name) => out.push(name.as_str()),
        ConditionExpr::And(operands) | ConditionExpr::Or(operands) => {
            for operand in operands {
                condition_ref_names(operand, out);
            }
        }
        ConditionExpr::Not(operand) => condition_ref_names(operand, out),
        ConditionExpr::Equals(_, _) | ConditionExpr::Invalid => {}
    }
}

/// Names of the parameters and pseudo-parameters `expr` reads directly - not
/// those read by the conditions it references.
fn parameter_names<'expr>(expr: &'expr ConditionExpr, out: &mut Vec<&'expr str>) {
    match expr {
        ConditionExpr::Equals(left, right) => {
            parameter_names_of_value(left, out);
            parameter_names_of_value(right, out);
        }
        ConditionExpr::And(operands) | ConditionExpr::Or(operands) => {
            for operand in operands {
                parameter_names(operand, out);
            }
        }
        ConditionExpr::Not(operand) => parameter_names(operand, out),
        ConditionExpr::ConditionRef(_) | ConditionExpr::Invalid => {}
    }
}

fn parameter_names_of_value<'expr>(expr: &'expr ValueExpr, out: &mut Vec<&'expr str>) {
    match expr {
        ValueExpr::ParamRef(name) | ValueExpr::PseudoParam(name) => out.push(name.as_str()),
        ValueExpr::MappingLookup { key1, key2, .. } => {
            parameter_names_of_value(key1, out);
            parameter_names_of_value(key2, out);
        }
        ValueExpr::Literal(_) | ValueExpr::Other => {}
    }
}

/// Names of the parameters and pseudo-parameters reachable from `seeds` through
/// condition references, with the traversal cost added to `steps`.
fn reachable_parameter_names<'conditions>(
    conditions: &'conditions HashMap<String, ConditionExpr>,
    seeds: &[&'conditions str],
    steps: &mut u64,
) -> Vec<&'conditions str> {
    let mut visited: HashSet<&'conditions str> = HashSet::new();
    let mut pending: Vec<&'conditions str> = seeds.to_vec();
    let mut names = Vec::new();
    while let Some(name) = pending.pop() {
        if !visited.insert(name) {
            continue;
        }
        *steps += 1;
        if let Some(expr) = conditions.get(name) {
            parameter_names(expr, &mut names);
            condition_ref_names(expr, &mut pending);
        }
    }
    names.sort_unstable();
    names.dedup();
    names
}

/// Derives `antecedent => consequent` pairs from `And`/`Or` condition
/// structure. These are *enforced* by the satisfiability search, so only
/// logically sound pairs may be produced:
///
/// * `X = And(...)` implies each condition reference reachable through nested
///   `And`s (`And(And(A, B), C)` implies `A`, `B`, and `C`) - but nothing
///   under an `Or` or `Not` child, whose references are not individually
///   entailed.
/// * Symmetrically, each condition reference reachable through nested `Or`s
///   implies `X = Or(...)`, and nothing under an `And` or `Not` child does.
fn extract_implications(conditions: &HashMap<String, ConditionExpr>) -> Vec<Implication> {
    let mut implications = Vec::new();

    for (name, expr) in conditions {
        match expr {
            ConditionExpr::And(children) => {
                let mut refs = Vec::new();
                collect_same_operator_refs(children, true, &mut refs);
                for ref_name in refs {
                    implications.push(Implication { antecedent: name.clone(), consequent: ref_name });
                }
            }
            ConditionExpr::Or(children) => {
                let mut refs = Vec::new();
                collect_same_operator_refs(children, false, &mut refs);
                for ref_name in refs {
                    implications.push(Implication { antecedent: ref_name, consequent: name.clone() });
                }
            }
            _ => {}
        }
    }

    implications
}

/// Collects condition references reachable through nested operators of the
/// *same* kind only (`in_and` selects which). Crossing into the other operator
/// or a `Not` breaks entailment, so those subtrees are skipped.
fn collect_same_operator_refs(exprs: &[ConditionExpr], in_and: bool, out: &mut Vec<String>) {
    for child in exprs {
        match child {
            ConditionExpr::ConditionRef(name) => out.push(name.clone()),
            ConditionExpr::And(children) if in_and => collect_same_operator_refs(children, in_and, out),
            ConditionExpr::Or(children) if !in_and => collect_same_operator_refs(children, in_and, out),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::PseudoParameterOverrides;
    use crate::parser;
    use crate::resolver::{extract_mappings, extract_parameters};
    use std::fmt::Write;

    fn build_condition_model(input: &str) -> ConditionModel {
        let ir = parser::parse(input.as_bytes()).unwrap();
        let (params, _) = extract_parameters(&ir);
        let (mappings, _) = extract_mappings(&ir);
        let pseudo = PseudoParameterOverrides::default();
        ConditionModel::from_ir(&ir, &params, &pseudo, &mappings)
    }

    #[test]
    fn parse_simple_conditions() {
        let input = r#"
Parameters:
  Env:
    Type: String
    AllowedValues:
      - Prod
      - Dev
Conditions:
  isProduction:
    Fn::Equals:
      - !Ref Env
      - Prod
  isDevelopment:
    Fn::Equals:
      - !Ref Env
      - Dev
Resources:
  R:
    Type: T
"#;
        let model = build_condition_model(input);
        assert_eq!(model.conditions.len(), 2);
        assert!(model.conditions.contains_key("isProduction"));
        assert!(model.conditions.contains_key("isDevelopment"));
    }

    #[test]
    fn mutex_group_extraction() {
        let input = r#"
Parameters:
  Env:
    Type: String
    AllowedValues: [Prod, Dev]
Conditions:
  isProduction:
    Fn::Equals: [!Ref Env, Prod]
  isDevelopment:
    Fn::Equals: [!Ref Env, Dev]
Resources:
  R:
    Type: T
"#;
        let model = build_condition_model(input);
        assert!(!model.mutex_groups.is_empty());
        assert_eq!(model.mutex_groups[0].conditions.len(), 2);
    }

    #[test]
    fn satisfiable_single_true() {
        let input = r#"
Parameters:
  Env:
    Type: String
    AllowedValues: [Prod, Dev]
Conditions:
  isProduction:
    Fn::Equals: [!Ref Env, Prod]
  isDevelopment:
    Fn::Equals: [!Ref Env, Dev]
Resources:
  R:
    Type: T
"#;
        let model = build_condition_model(input);
        assert!(model.is_satisfiable(&[("isProduction".into(), true)]));
    }

    #[test]
    fn satisfiable_mutex_violation() {
        let input = r#"
Parameters:
  Env:
    Type: String
    AllowedValues: [Prod, Dev]
Conditions:
  isProduction:
    Fn::Equals: [!Ref Env, Prod]
  isDevelopment:
    Fn::Equals: [!Ref Env, Dev]
Resources:
  R:
    Type: T
"#;
        let model = build_condition_model(input);
        assert!(!model.conditions_compatible("isProduction", "isDevelopment"));
    }

    #[test]
    fn resources_compatible_both_unconditional() {
        let input = r#"
Resources:
  R:
    Type: T
"#;
        let model = build_condition_model(input);
        assert!(model.resources_compatible(None, None));
    }

    #[test]
    fn no_conditions_template() {
        let input = r#"{"Resources":{"R":{"Type":"T"}}}"#;
        let model = build_condition_model(input);
        assert!(model.conditions.is_empty());
        assert!(model.is_satisfiable(&[]));
    }

    #[test]
    fn condition_implies_same_condition() {
        let input = r#"
Parameters:
  Env:
    Type: String
    AllowedValues: [Prod, Dev]
Conditions:
  isProduction:
    Fn::Equals: [!Ref Env, Prod]
Resources:
  R:
    Type: T
"#;
        let model = build_condition_model(input);
        // A condition always implies itself
        assert!(model.condition_implies("isProduction", "isProduction"));
    }

    #[test]
    fn is_satisfiable_contradictory_assumptions() {
        let input = r#"
Parameters:
  Env:
    Type: String
    AllowedValues: [Prod, Dev]
Conditions:
  isProduction:
    Fn::Equals: [!Ref Env, Prod]
Resources:
  R:
    Type: T
"#;
        let model = build_condition_model(input);
        // Same condition assumed both true and false is unsatisfiable
        assert!(!model.is_satisfiable(&[("isProduction".into(), true), ("isProduction".into(), false),]));
    }

    #[test]
    fn condition_implies_mutex_conditions() {
        let input = r#"
Parameters:
  Env:
    Type: String
    AllowedValues: [Prod, Dev]
Conditions:
  isProduction:
    Fn::Equals: [!Ref Env, Prod]
  isDevelopment:
    Fn::Equals: [!Ref Env, Dev]
Resources:
  R:
    Type: T
"#;
        let model = build_condition_model(input);
        // Mutex conditions do not imply each other
        assert!(!model.condition_implies("isProduction", "isDevelopment"));
        assert!(!model.condition_implies("isDevelopment", "isProduction"));
    }

    #[test]
    fn compatible_or_condition_without_allowed_values() {
        let input = r#"
Parameters:
  Env:
    Type: String
Conditions:
  IsProd:
    Fn::Equals: [!Ref Env, Prod]
  IsProdOrStage:
    Fn::Or:
      - Condition: IsProd
      - Fn::Equals: [!Ref Env, Stage]
Resources:
  R:
    Type: T
"#;
        let model = build_condition_model(input);
        assert!(model.conditions_compatible("IsProd", "IsProdOrStage"));
        assert!(model.condition_implies("IsProd", "IsProdOrStage"));
        assert!(!model.condition_implies("IsProdOrStage", "IsProd"));
    }

    #[test]
    fn tautological_equals_literal_match() {
        let input = r#"
Conditions:
  AlwaysTrue:
    Fn::Equals: ["same", "same"]
  AlwaysFalse:
    Fn::Equals: ["a", "b"]
Resources:
  R:
    Type: T
"#;
        let model = build_condition_model(input);
        let taut = model.tautological_equals();
        assert!(taut.iter().any(|(n, v)| n == "AlwaysTrue" && *v));
        assert!(taut.iter().any(|(n, v)| n == "AlwaysFalse" && !*v));
    }

    #[test]
    fn tautological_equals_nested_in_and() {
        let input = r#"
Parameters:
  Env:
    Type: String
Conditions:
  Nested:
    Fn::And:
      - Fn::Equals: ["x", "x"]
      - Fn::Equals: [!Ref Env, Prod]
Resources:
  R:
    Type: T
"#;
        let model = build_condition_model(input);
        let taut = model.tautological_equals();
        assert!(
            taut.iter().any(|(n, v)| n == "Nested" && *v),
            "should detect tautological Equals inside And: {:?}",
            taut
        );
    }

    #[test]
    fn referenced_params_collected() {
        let input = r#"
Parameters:
  Env:
    Type: String
  Region:
    Type: String
Conditions:
  IsProd:
    Fn::Equals: [!Ref Env, Prod]
  IsUsEast:
    Fn::Equals: [!Ref Region, us-east-1]
Resources:
  R:
    Type: T
"#;
        let model = build_condition_model(input);
        let refs = model.referenced_params();
        assert!(refs.contains(&"Env".to_string()));
        assert!(refs.contains(&"Region".to_string()));
        assert_eq!(refs.len(), 2);
    }

    #[test]
    fn and_implication_extracted() {
        let input = r#"
Parameters:
  Env:
    Type: String
  DB:
    Type: String
    AllowedValues: [yes, no]
Conditions:
  IsProd:
    Fn::Equals: [!Ref Env, Prod]
  CreateDB:
    Fn::Equals: [!Ref DB, yes]
  ProdAndDB:
    Fn::And:
      - Condition: IsProd
      - Condition: CreateDB
Resources:
  R:
    Type: T
"#;
        let model = build_condition_model(input);
        // ProdAndDB = And(IsProd, CreateDB) → ProdAndDB implies IsProd and CreateDB
        assert!(model.implications.iter().any(|i| i.antecedent == "ProdAndDB" && i.consequent == "IsProd"));
        assert!(model.implications.iter().any(|i| i.antecedent == "ProdAndDB" && i.consequent == "CreateDB"));
    }

    #[test]
    fn or_implication_extracted() {
        let input = r#"
Parameters:
  Env:
    Type: String
    AllowedValues: [Prod, Dev, Stage]
Conditions:
  IsProd:
    Fn::Equals: [!Ref Env, Prod]
  IsDev:
    Fn::Equals: [!Ref Env, Dev]
  ProdOrDev:
    Fn::Or:
      - Condition: IsProd
      - Condition: IsDev
Resources:
  R:
    Type: T
"#;
        let model = build_condition_model(input);
        // Or(IsProd, IsDev) → IsProd implies ProdOrDev, IsDev implies ProdOrDev
        assert!(model.implications.iter().any(|i| i.antecedent == "IsProd" && i.consequent == "ProdOrDev"));
        assert!(model.implications.iter().any(|i| i.antecedent == "IsDev" && i.consequent == "ProdOrDev"));
    }

    #[test]
    fn three_way_mutex_group() {
        let input = r#"
Parameters:
  Env:
    Type: String
    AllowedValues: [Prod, Dev, Stage]
Conditions:
  IsProd:
    Fn::Equals: [!Ref Env, Prod]
  IsDev:
    Fn::Equals: [!Ref Env, Dev]
  IsStage:
    Fn::Equals: [!Ref Env, Stage]
Resources:
  R:
    Type: T
"#;
        let model = build_condition_model(input);
        assert_eq!(model.mutex_groups.len(), 1);
        assert_eq!(model.mutex_groups[0].conditions.len(), 3);
        assert!(!model.conditions_compatible("IsProd", "IsDev"));
        assert!(!model.conditions_compatible("IsProd", "IsStage"));
        assert!(!model.conditions_compatible("IsDev", "IsStage"));
    }

    #[test]
    fn resources_compatible_one_unconditional() {
        let input = r#"
Parameters:
  Env:
    Type: String
    AllowedValues: [Prod, Dev]
Conditions:
  IsProd:
    Fn::Equals: [!Ref Env, Prod]
Resources:
  R:
    Type: T
"#;
        let model = build_condition_model(input);
        assert!(model.resources_compatible(Some("IsProd"), None));
        assert!(model.resources_compatible(None, Some("IsProd")));
    }

    #[test]
    fn condition_names_iterator() {
        let input = r#"
Conditions:
  A:
    Fn::Equals: ["x", "x"]
  B:
    Fn::Equals: ["y", "y"]
Resources:
  R:
    Type: T
"#;
        let model = build_condition_model(input);
        let mut names: Vec<&str> = model.names().collect();
        names.sort();
        assert_eq!(names, vec!["A", "B"]);
    }

    #[test]
    fn get_returns_none_for_unknown_condition() {
        let input = r#"{"Resources":{"R":{"Type":"T"}}}"#;
        let model = build_condition_model(input);
        assert!(model.get("NonExistent").is_none(), "unknown condition should return None");
    }

    #[test]
    fn not_condition_parsed() {
        let input = r#"
Parameters:
  Env:
    Type: String
    AllowedValues: [Prod, Dev]
Conditions:
  IsProd:
    Fn::Equals: [!Ref Env, Prod]
  NotProd:
    Fn::Not:
      - Condition: IsProd
Resources:
  R:
    Type: T
"#;
        let model = build_condition_model(input);
        assert!(!model.conditions_compatible("IsProd", "NotProd"));
        assert!(!model.condition_implies("IsProd", "NotProd"));
    }

    #[test]
    fn pseudo_param_without_override_is_a_free_variable_in_sat_solver() {
        let input = r#"
Parameters:
  Env:
    Type: String
    AllowedValues: [Prod, Dev]
Conditions:
  IsUsEast1:
    Fn::Equals: [!Ref "AWS::Region", us-east-1]
  IsProd:
    Fn::Equals: [!Ref Env, Prod]
Resources:
  R:
    Type: T
"#;
        let model = build_condition_model(input);
        assert!(
            model.is_satisfiable(&[("IsUsEast1".into(), true)]),
            "IsUsEast1=true must be reachable: AWS::Region can equal 'us-east-1'"
        );
        assert!(
            model.is_satisfiable(&[("IsUsEast1".into(), false)]),
            "IsUsEast1=false must be reachable: AWS::Region can equal anything other than 'us-east-1' \
             (the auto-derived default region must not pin the pseudo-parameter to a constant - that \
             produced false-positive W1028 unreachable-branch diagnostics on partition/region branches)"
        );
        assert!(
            model.is_satisfiable(&[("IsProd".into(), true)]),
            "IsProd=true must be reachable: Env can equal 'Prod'"
        );
        assert!(
            model.is_satisfiable(&[("IsProd".into(), false)]),
            "IsProd=false must be reachable: Env can equal 'Dev'"
        );
    }

    #[test]
    fn is_satisfiable_in_region_pins_aws_region() {
        let input = r#"
Conditions:
  IsUsEast1:
    Fn::Equals: [!Ref "AWS::Region", us-east-1]
Resources:
  R:
    Type: T
"#;
        let model = build_condition_model(input);
        // With AWS::Region left free, the region-equals condition can hold either
        // way; pinning the region resolves it. This is what the region-availability
        // check relies on to skip a resource whose condition cannot hold in the
        // target region - even when no explicit --region override is set.
        assert!(
            model.is_satisfiable_in_region(&[("IsUsEast1".into(), true)], "us-east-1"),
            "IsUsEast1=true must hold when the target region IS us-east-1"
        );
        assert!(
            !model.is_satisfiable_in_region(&[("IsUsEast1".into(), true)], "us-west-2"),
            "IsUsEast1=true must be unsatisfiable when the target region is us-west-2"
        );
        // A condition that does not reference AWS::Region is unaffected by the pin.
        assert!(
            model.is_satisfiable_in_region(&[("IsUsEast1".into(), false)], "us-west-2"),
            "IsUsEast1=false must hold at us-west-2"
        );
    }

    #[test]
    fn pseudo_param_explicit_override_pins_value_in_sat_solver() {
        let ir = parser::parse(
            r#"
Conditions:
  IsAwsPartition:
    Fn::Equals: [!Ref "AWS::Partition", aws]
Resources:
  R:
    Type: T
"#
            .as_bytes(),
        )
        .unwrap();
        let (params, _) = extract_parameters(&ir);
        let (mappings, _) = extract_mappings(&ir);
        let pseudo = PseudoParameterOverrides { partition: Some("aws-cn".to_string()), ..Default::default() };

        let model = ConditionModel::from_ir(&ir, &params, &pseudo, &mappings);

        assert!(
            !model.is_satisfiable(&[("IsAwsPartition".into(), true)]),
            "with partition pinned to aws-cn, IsAwsPartition=true must be unsatisfiable"
        );
        assert!(
            model.is_satisfiable(&[("IsAwsPartition".into(), false)]),
            "with partition pinned to aws-cn, IsAwsPartition=false must hold"
        );
    }

    #[test]
    fn pseudo_param_custom_region_changes_satisfiability() {
        let ir = parser::parse(
            r#"
Conditions:
  IsUsEast1:
    Fn::Equals: [!Ref "AWS::Region", us-east-1]
Resources:
  R:
    Type: T
"#
            .as_bytes(),
        )
        .unwrap();
        let (params, _) = extract_parameters(&ir);
        let (mappings, _) = extract_mappings(&ir);
        let pseudo = PseudoParameterOverrides { region: Some("eu-west-1".to_string()), ..Default::default() };
        let model = ConditionModel::from_ir(&ir, &params, &pseudo, &mappings);
        // With eu-west-1, IsUsEast1=true should be unsatisfiable
        assert!(!model.is_satisfiable(&[("IsUsEast1".into(), true)]));
        assert!(model.is_satisfiable(&[("IsUsEast1".into(), false)]));
    }

    #[test]
    fn pseudo_param_partition_false_branch_is_reachable_without_override() {
        let input = r#"
Conditions:
  HasEcrPublic:
    Fn::Equals: [!Ref "AWS::Partition", aws]
Resources:
  R:
    Type: T
"#;
        let model = build_condition_model(input);

        assert!(
            model.is_satisfiable(&[("HasEcrPublic".into(), true)]),
            "HasEcrPublic=true must be reachable: AWS::Partition can equal 'aws'"
        );
        assert!(
            model.is_satisfiable(&[("HasEcrPublic".into(), false)]),
            "HasEcrPublic=false must be reachable: AWS::Partition can equal 'aws-cn' or 'aws-us-gov'"
        );
    }

    #[test]
    fn mapping_lookup_resolves_in_condition() {
        let input = r#"
Parameters:
  Env:
    Type: String
    AllowedValues: [Prod, Dev]
Mappings:
  EnvMap:
    Prod:
      Label: production
    Dev:
      Label: development
Conditions:
  IsProdLabel:
    Fn::Equals:
      - !FindInMap [EnvMap, !Ref Env, Label]
      - production
Resources:
  R:
    Type: T
"#;
        let model = build_condition_model(input);
        // When Env=Prod, FindInMap returns "production" → IsProdLabel=true
        // When Env=Dev, FindInMap returns "development" → IsProdLabel=false
        assert!(model.is_satisfiable(&[("IsProdLabel".into(), true)]));
        assert!(model.is_satisfiable(&[("IsProdLabel".into(), false)]));
    }

    #[test]
    fn mapping_lookup_format_value_expr_readable() {
        let expr = ValueExpr::MappingLookup {
            map_name: "MyMap".to_string(),
            key1: Box::new(ValueExpr::ParamRef("Env".to_string())),
            key2: Box::new(ValueExpr::Literal("Label".to_string())),
        };
        let formatted = format_value_expr(&expr);
        assert!(formatted.contains("FindInMap"));
        assert!(formatted.contains("MyMap"));
    }

    #[test]
    fn mapping_lookup_param_refs_collected() {
        let input = r#"
Parameters:
  Env:
    Type: String
    AllowedValues: [Prod, Dev]
Mappings:
  EnvMap:
    Prod:
      Label: production
    Dev:
      Label: development
Conditions:
  IsProdLabel:
    Fn::Equals:
      - !FindInMap [EnvMap, !Ref Env, Label]
      - production
Resources:
  R:
    Type: T
"#;
        let model = build_condition_model(input);
        let refs = model.referenced_params();
        assert!(refs.contains(&"Env".to_string()));
    }

    #[test]
    fn extract_equals_test_unwraps_not() {
        let expr = ConditionExpr::Not(Box::new(ConditionExpr::Equals(
            ValueExpr::ParamRef("Env".into()),
            ValueExpr::Literal("Prod".into()),
        )));
        let result = extract_equals_test(&expr);
        let (param, lit, positive) = result.expect("extract_equals_test should return Some for Not(Equals)");
        assert_eq!(param, "Env");
        assert_eq!(lit, "Prod");
        assert!(!positive);
    }

    #[test]
    fn nested_and_implication_extracts_deep_condition_refs() {
        let input = r#"
Parameters:
  A:
    Type: String
    AllowedValues: [yes, no]
  B:
    Type: String
    AllowedValues: [yes, no]
  C:
    Type: String
    AllowedValues: [yes, no]
Conditions:
  CondA:
    Fn::Equals: [!Ref A, yes]
  CondB:
    Fn::Equals: [!Ref B, yes]
  CondC:
    Fn::Equals: [!Ref C, yes]
  NestedAnd:
    Fn::And:
      - Fn::And:
          - Condition: CondA
          - Condition: CondB
      - Condition: CondC
Resources:
  R:
    Type: T
"#;
        let model = build_condition_model(input);
        // NestedAnd = And(And(CondA, CondB), CondC) should imply all three
        assert!(model.implications.iter().any(|i| i.antecedent == "NestedAnd" && i.consequent == "CondA"));
        assert!(model.implications.iter().any(|i| i.antecedent == "NestedAnd" && i.consequent == "CondB"));
        assert!(model.implications.iter().any(|i| i.antecedent == "NestedAnd" && i.consequent == "CondC"));
    }

    #[test]
    fn nested_or_implication_extracts_deep_condition_refs() {
        let input = r#"
Parameters:
  A:
    Type: String
    AllowedValues: [yes, no]
  B:
    Type: String
    AllowedValues: [yes, no]
Conditions:
  CondA:
    Fn::Equals: [!Ref A, yes]
  CondB:
    Fn::Equals: [!Ref B, yes]
  NestedOr:
    Fn::Or:
      - Fn::Or:
          - Condition: CondA
          - Condition: CondB
Resources:
  R:
    Type: T
"#;
        let model = build_condition_model(input);
        // CondA implies NestedOr, CondB implies NestedOr (through nested Or)
        assert!(model.implications.iter().any(|i| i.antecedent == "CondA" && i.consequent == "NestedOr"));
        assert!(model.implications.iter().any(|i| i.antecedent == "CondB" && i.consequent == "NestedOr"));
    }

    #[test]
    fn register_inline_adds_condition_and_rebuilds_mutex() {
        let input = r#"
Parameters:
  Env:
    Type: String
    AllowedValues: [Prod, Dev]
Conditions:
  IsProd:
    Fn::Equals: [!Ref Env, Prod]
Resources:
  R:
    Type: T
"#;
        let mut model = build_condition_model(input);
        assert_eq!(model.conditions.len(), 1);
        // Register an inline condition that tests the same param
        model.register_inline(
            "__inline_1".to_string(),
            ConditionExpr::Equals(ValueExpr::ParamRef("Env".to_string()), ValueExpr::Literal("Dev".to_string())),
        );
        assert_eq!(model.conditions.len(), 2);
        // Mutex groups should be rebuilt to include the new condition
        assert!(!model.mutex_groups.is_empty());
        assert!(!model.conditions_compatible("IsProd", "__inline_1"));
    }

    #[test]
    fn ifexpr_literal_equals_eagerly_evaluated() {
        // When IfExpr has Equals("a", "a"), it should resolve to the true branch directly
        let input = r#"{
  "Conditions": {"C": {"Fn::Equals": ["x", "x"]}},
  "Resources": {
    "R": {
      "Type": "T",
      "Properties": {
        "V": {"Fn::If": [{"Fn::Equals": ["same", "same"]}, "yes", "no"]}
      }
    }
  }
}"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        // Literal Equals("same","same") is true → should resolve to "yes" directly
        match model.resolve("R", "Properties.V") {
            Some(crate::resolver::ResolvedValue::Concrete { value: v }) => {
                assert_eq!(v.as_str().unwrap(), "yes");
            }
            other => panic!("Expected Concrete(\"yes\") from eager eval, got {:?}", other),
        }
    }

    #[test]
    fn ifexpr_literal_not_equals_eagerly_evaluated_to_false_branch() {
        let input = r#"{
  "Conditions": {"C": {"Fn::Equals": ["x", "x"]}},
  "Resources": {
    "R": {
      "Type": "T",
      "Properties": {
        "V": {"Fn::If": [{"Fn::Equals": ["a", "b"]}, "yes", "no"]}
      }
    }
  }
}"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        match model.resolve("R", "Properties.V") {
            Some(crate::resolver::ResolvedValue::Concrete { value: v }) => {
                assert_eq!(v.as_str().unwrap(), "no");
            }
            other => panic!("Expected Concrete(\"no\") from eager eval, got {:?}", other),
        }
    }

    #[test]
    fn ifexpr_non_literal_registers_inline_condition() {
        // When IfExpr has a non-trivial condition, it should register as inline
        let input = r#"
Parameters:
  Env:
    Type: String
    AllowedValues: [Prod, Dev]
Resources:
  R:
    Type: T
    Properties:
      V:
        Fn::If:
          - Fn::Equals: [!Ref Env, Prod]
          - big
          - small
"#;
        let model = crate::model::SemanticModel::from_bytes(input.as_bytes()).unwrap();
        // Should have registered an inline condition
        let inline_count = model.conditions.conditions.keys().filter(|k| k.starts_with("__inline_cond_")).count();
        assert!(inline_count > 0, "Expected at least one inline condition registered");
    }

    /// Builds a template whose conditions form a chain `chain_len` long, topped
    /// by an unsatisfiable `Contra = And(Top, Not(Top))`. `Top` transitively
    /// depends on the whole chain, so deciding `Contra` forces the solver to
    /// reason over every condition in the chain.
    ///
    /// Each link is written in De Morgan form (`Not(Or(Not(a), Not(b)))` for
    /// `And`, `Not(And(Not(a), Not(b)))` for `Or`) so the implication extractor
    /// (which only reads top-level `And`/`Or` structure) derives nothing from
    /// the chain. That keeps implication pruning out of the search, which is
    /// the point: this test exercises the *raw iteration budget*, not the
    /// implication constraints (covered by their own tests).
    fn chain_with_contradiction(chain_len: usize) -> String {
        let mut s = String::from(
            "Parameters:\n  P0:\n    Type: String\n    AllowedValues: [yes, no]\n  \
             P1:\n    Type: String\n    AllowedValues: [yes, no]\n\
             Conditions:\n  C000:\n    Fn::Equals: [!Ref P0, yes]\n  \
             C001:\n    Fn::Equals: [!Ref P1, yes]\n",
        );
        for i in 2..chain_len {
            // De Morgan: even links are And(a, b), odd links are Or(a, b).
            let outer_inner = if i % 2 == 0 { "Fn::Or" } else { "Fn::And" };
            let _ = write!(
                s,
                "  C{:03}:\n    Fn::Not:\n      - {}:\n          - Fn::Not:\n              - Condition: C{:03}\n          - Fn::Not:\n              - Condition: C{:03}\n",
                i,
                outer_inner,
                i - 1,
                i - 2
            );
        }
        let top = format!("C{:03}", chain_len - 1);
        let _ = write!(
            s,
            "  Contra:\n    Fn::And:\n      - Condition: {top}\n      \
             - Fn::Not:\n          - Condition: {top}\n\
             Resources:\n  R:\n    Type: T\n",
        );
        s
    }

    #[test]
    fn contradiction_over_a_long_condition_chain_is_decided_exactly_and_cheaply() {
        // `Contra = And(Top, Not(Top))` is unsatisfiable, and Top depends on the
        // whole chain, so deciding it requires reasoning over every condition in
        // the chain. The chain is built over two binary parameters no matter how
        // long it gets, so the answer is decided by four parameter assignments -
        // the work must therefore grow with the chain's length, not with the
        // number of truth assignments its conditions could take.
        //
        // This is the shape that made a real build hang: conditions layered over a
        // handful of shared inputs, where searching condition assignments costs
        // exponentially more than searching the inputs themselves.
        const SHORT_CHAIN: usize = 8;
        const LONG_CHAIN: usize = 32;
        const DOUBLED_CHAIN: usize = 64;

        for chain_length in [SHORT_CHAIN, LONG_CHAIN, DOUBLED_CHAIN] {
            let model = build_condition_model(&chain_with_contradiction(chain_length));
            assert!(
                !model.is_satisfiable(&[("Contra".to_string(), true)]),
                "a contradiction over a {chain_length}-condition chain must be proven \
                 unsatisfiable, not conceded as satisfiable because the search was too expensive"
            );
        }

        // Doubling the chain may at most double the work a few times over -
        // anything exponential in the condition count would exceed this by orders
        // of magnitude. Iteration counts are deterministic and machine-independent,
        // so this is a stable bound rather than a timing assertion.
        const MAX_GROWTH_FROM_DOUBLING: u64 = 4;
        let long_model = build_condition_model(&chain_with_contradiction(LONG_CHAIN));
        let _ = long_model.is_satisfiable(&[("Contra".to_string(), true)]);
        let doubled_model = build_condition_model(&chain_with_contradiction(DOUBLED_CHAIN));
        let _ = doubled_model.is_satisfiable(&[("Contra".to_string(), true)]);
        let long_chain_work = long_model.sat_iterations_used();
        let doubled_chain_work = doubled_model.sat_iterations_used();
        assert!(
            doubled_chain_work <= long_chain_work * MAX_GROWTH_FROM_DOUBLING,
            "doubling the chain length must not multiply the work by more than \
             {MAX_GROWTH_FROM_DOUBLING}x; {LONG_CHAIN} conditions cost {long_chain_work} steps and \
             {DOUBLED_CHAIN} cost {doubled_chain_work}"
        );
        assert!(
            doubled_chain_work < MAX_SAT_ITERATIONS,
            "deciding a chain of {DOUBLED_CHAIN} conditions over two binary parameters must stay \
             far inside the per-query budget; cost {doubled_chain_work} of {MAX_SAT_ITERATIONS}"
        );
    }

    /// Builds a template shaped like the deployment templates that made CDK's
    /// default validation hang: `layered` conditions, each an `And`/`Or` over
    /// conditions that all test the same few pseudo-parameters, so every condition
    /// is reachable from every other through the inputs they share.
    fn conditions_layered_over_shared_pseudo_parameters(layered: usize) -> String {
        const PARTITIONS: [&str; 4] = ["aws", "aws-us-gov", "aws-cn", "aws-iso"];
        const REGIONS: [&str; 4] = ["us-east-1", "us-west-2", "us-gov-west-1", "cn-north-1"];
        let mut template = String::from("Parameters:\n  Stage:\n    Type: String\nConditions:\n");
        let mut base_names = Vec::new();
        for (index, partition) in PARTITIONS.iter().enumerate() {
            let _ = write!(template, "  IsPartition{index}:\n    Fn::Equals: [!Ref 'AWS::Partition', {partition}]\n");
            base_names.push(format!("IsPartition{index}"));
        }
        for (index, region) in REGIONS.iter().enumerate() {
            let _ = write!(template, "  IsRegion{index}:\n    Fn::Equals: [!Ref 'AWS::Region', {region}]\n");
            base_names.push(format!("IsRegion{index}"));
        }
        let _ = write!(template, "  IsProd:\n    Fn::Equals: [!Ref Stage, prod]\n");
        base_names.push("IsProd".to_string());

        let mut names = base_names.clone();
        for index in 0..layered {
            let operator = if index % 2 == 0 { "Fn::And" } else { "Fn::Or" };
            let operands: Vec<&String> = (0..3).map(|offset| &names[(index * 7 + offset * 3) % names.len()]).collect();
            let _ = write!(template, "  Layered{index:03}:\n    {operator}:\n");
            for operand in operands {
                let _ = writeln!(template, "      - Condition: {operand}");
            }
            names.push(format!("Layered{index:03}"));
        }
        let _ = write!(
            template,
            "Resources:\n  R:\n    Type: AWS::SNS::Topic\n    Condition: {}\n",
            names[names.len() - 1]
        );
        template
    }

    #[test]
    fn conditions_layered_over_shared_inputs_are_analyzed_in_full() {
        // The regression guard for the incident: a hundred conditions built over
        // nine base conditions that test three shared inputs. Analyzing this by
        // searching condition assignments cost so much that the cumulative budget
        // ran out partway through the pairwise pass, silently leaving most
        // condition pairs undecided. Searching parameter assignments instead must
        // decide every pair well inside the budget. The same shape at the
        // two-hundred-condition CloudFormation maximum is covered end to end by the
        // security fixtures.
        const LAYERED_CONDITIONS: usize = 91;
        let model = build_condition_model(&conditions_layered_over_shared_pseudo_parameters(LAYERED_CONDITIONS));

        let mut names: Vec<&str> = model.names().collect();
        names.sort_unstable();
        assert_eq!(names.len(), LAYERED_CONDITIONS + 9, "the fixture must reach the scale under test");

        let mut decided_pairs = 0u64;
        for (offset, first) in names.iter().enumerate() {
            for second in &names[offset + 1..] {
                let _ = model.conditions_compatible(first, second);
                decided_pairs += 1;
            }
        }

        assert!(
            !model.satisfiability_budget_exhausted(),
            "the full pairwise pass over {} conditions must fit in the cumulative budget; it spent \
             {} of {MAX_TOTAL_SAT_ITERATIONS} deciding {decided_pairs} pairs",
            names.len(),
            model.sat_iterations_used()
        );
        assert!(
            model.budget_exhausted_queries().is_empty(),
            "no query over conditions layered on shared inputs may exceed its budget: {:?}",
            model.budget_exhausted_queries()
        );
        // Two conditions testing the same pseudo-parameter against different values
        // can never hold together. Proving that is what the pass exists for, and
        // what a budget-exhausted analysis silently stopped doing.
        assert!(
            !model.conditions_compatible("IsPartition0", "IsPartition1"),
            "conditions comparing the same pseudo-parameter with different values must be proven \
             incompatible"
        );
    }

    #[test]
    fn cumulative_budget_exhaustion_is_reported_rather_than_silently_narrowing_analysis() {
        // Exhausting the cumulative budget makes every later question about the
        // condition set take the conservative answer, so the template's author has
        // to be told the analysis was curtailed - the failure that made a
        // multi-hour hang produce no output at all.
        let model = build_condition_model(&chain_with_contradiction(8));
        assert!(model.budget_exhausted_queries().is_empty(), "nothing is curtailed before any work is charged");

        model.add_sat_iterations_for_test(MAX_TOTAL_SAT_ITERATIONS);

        assert!(model.satisfiability_budget_exhausted(), "the budget must register as spent");
        assert!(
            !model.budget_exhausted_queries().is_empty(),
            "spending the cumulative budget must be reported so a curtailed analysis is never silent"
        );
    }

    #[test]
    fn self_referential_conditions_are_undetermined_rather_than_looping() {
        // Two conditions that reference each other have no value to read. Deciding
        // a query over them must terminate - treating the cycle as undetermined,
        // the conservative direction - rather than recurse forever. The cycle
        // itself is reported by the reference-graph analysis.
        let model = build_condition_model(
            "Parameters:\n  Env:\n    Type: String\n    AllowedValues: [prod, dev]\n\
             Conditions:\n  Looping:\n    Fn::And:\n      - Condition: AlsoLooping\n      \
             - Fn::Equals: [!Ref Env, prod]\n  \
             AlsoLooping:\n    Fn::Or:\n      - Condition: Looping\n      \
             - Fn::Equals: [!Ref Env, dev]\n\
             Resources:\n  R:\n    Type: T\n",
        );
        assert!(
            model.is_satisfiable(&[("Looping".to_string(), true)]),
            "a condition on a reference cycle cannot be decided, so it must be assumed satisfiable"
        );
        assert!(model.is_satisfiable(&[("Looping".to_string(), false)]), "the same holds for the negated assumption");
        assert!(
            model.sat_iterations_used() < MAX_SAT_ITERATIONS,
            "a cycle must be cut immediately, not explored until the budget runs out; cost {}",
            model.sat_iterations_used()
        );
    }

    #[test]
    fn condition_over_an_unresolvable_value_does_not_constrain_a_query() {
        // A condition comparing something the model cannot resolve has no value at
        // any parameter assignment. It must not falsify a query - that would
        // suppress diagnostics for resources it guards - and must not make the
        // conditions it is combined with undecidable either.
        let model = build_condition_model(
            "Parameters:\n  Subnets:\n    Type: CommaDelimitedList\n  \
             Env:\n    Type: String\n    AllowedValues: [prod, dev]\n\
             Conditions:\n  \
             FirstSubnetIsReserved:\n    Fn::Equals: [!Select [0, !Ref Subnets], reserved]\n  \
             IsProd:\n    Fn::Equals: [!Ref Env, prod]\n  \
             IsDev:\n    Fn::Equals: [!Ref Env, dev]\n  \
             ReservedInProd:\n    Fn::And:\n      - Condition: FirstSubnetIsReserved\n      \
             - Condition: IsProd\n\
             Resources:\n  R:\n    Type: T\n",
        );
        assert!(
            model.is_satisfiable(&[("FirstSubnetIsReserved".to_string(), true)]),
            "an unresolvable comparison must be assumed able to hold"
        );
        assert!(
            model.conditions_compatible("ReservedInProd", "IsProd"),
            "an unresolvable operand must not make a combined condition look impossible"
        );
        assert!(
            !model.conditions_compatible("ReservedInProd", "IsDev"),
            "the resolvable operand must still constrain the combination: the And requires prod, \
             which excludes dev"
        );
    }

    #[test]
    fn conditions_sharing_a_parameter_through_derived_conditions_stay_exact() {
        // Two derived conditions that reach the same parameter through different
        // chains of references. Their compatibility follows only from the values
        // that parameter can take, so it must be decided exactly however deeply the
        // conditions are layered.
        let model = build_condition_model(
            "Parameters:\n  Env:\n    Type: String\n    AllowedValues: [prod, gamma, dev]\n  \
             Feature:\n    Type: String\n    AllowedValues: ['on', 'off']\n\
             Conditions:\n  \
             IsProd:\n    Fn::Equals: [!Ref Env, prod]\n  \
             IsDev:\n    Fn::Equals: [!Ref Env, dev]\n  \
             FeatureOn:\n    Fn::Equals: [!Ref Feature, 'on']\n  \
             ProdWithFeature:\n    Fn::And:\n      - Condition: IsProd\n      - Condition: FeatureOn\n  \
             DevWithFeature:\n    Fn::And:\n      - Condition: IsDev\n      - Condition: FeatureOn\n  \
             EitherWithFeature:\n    Fn::Or:\n      - Condition: ProdWithFeature\n      \
             - Condition: DevWithFeature\n\
             Resources:\n  R:\n    Type: T\n",
        );
        assert!(
            !model.conditions_compatible("ProdWithFeature", "DevWithFeature"),
            "conditions requiring different values of the same parameter cannot both hold, however \
             many references separate them from that parameter"
        );
        assert!(
            model.conditions_compatible("ProdWithFeature", "EitherWithFeature"),
            "a condition and a disjunction it satisfies must remain compatible"
        );
        assert!(
            model.condition_implies("ProdWithFeature", "FeatureOn"),
            "a conjunction must be proven to imply its operand"
        );
        assert!(
            !model.condition_implies("EitherWithFeature", "IsProd"),
            "a disjunction must not be proven to imply only one of its branches"
        );
    }

    /// Builds a model with `param_count` binary parameters, one base condition
    /// per parameter, and a `Wide` condition that is the conjunction of every
    /// base - so a query over `Wide` has a dependency closure spanning all of
    /// the parameters.
    fn wide_parameter_closure(param_count: usize) -> String {
        let mut s = String::from("Parameters:\n");
        for i in 0..param_count {
            let _ = write!(s, "  P{i:02}:\n    Type: String\n    AllowedValues: [yes, no]\n");
        }
        s.push_str("Conditions:\n");
        for i in 0..param_count {
            let _ = write!(s, "  Base{i:02}:\n    Fn::Equals: [!Ref P{i:02}, yes]\n");
        }
        s.push_str("  Wide:\n    Fn::And:\n");
        for i in 0..param_count {
            let _ = writeln!(s, "      - Condition: Base{i:02}");
        }
        s.push_str("Resources:\n  R:\n    Type: T\n");
        s
    }

    #[test]
    fn satisfiability_with_wide_parameter_closure_is_capped_conservatively() {
        // 24 binary parameters means 2^24 value combinations - far above
        // MAX_PARAM_COMBINATIONS. Enumerating them at every search leaf is the
        // denial-of-service shape the parameter cap defends against.
        const WIDE_PARAMS: usize = 24;
        let model = build_condition_model(&wide_parameter_closure(WIDE_PARAMS));

        // The query must return the conservative "satisfiable" answer rather
        // than enumerate the cartesian product.
        assert!(
            model.is_satisfiable(&[("Wide".to_string(), true)]),
            "a condition whose closure references more parameters than the cap must be \
             assumed satisfiable, not enumerated"
        );

        // And it must do so cheaply: the cap short-circuits before the search,
        // so the work charged stays far below the combination count that a full
        // enumeration would have cost.
        assert!(
            model.sat_iterations_used() < MAX_PARAM_COMBINATIONS,
            "the parameter cap must short-circuit before enumerating the cartesian product; \
             charged {} iterations, expected well under {MAX_PARAM_COMBINATIONS}",
            model.sat_iterations_used()
        );
    }

    #[test]
    fn satisfiability_with_narrow_parameter_closure_stays_exact() {
        // A contradiction over a single parameter is well under the cap, so the
        // solver must still prove it unsatisfiable rather than fall back to the
        // conservative answer - proving the cap does not over-trigger.
        let model = build_condition_model(
            "Parameters:\n  Env:\n    Type: String\n    AllowedValues: [prod, dev]\n\
             Conditions:\n  IsProd:\n    Fn::Equals: [!Ref Env, prod]\n  \
             IsDev:\n    Fn::Equals: [!Ref Env, dev]\n\
             Resources:\n  R:\n    Type: T\n",
        );
        assert!(
            !model.conditions_compatible("IsProd", "IsDev"),
            "mutually exclusive conditions over a small parameter space must remain provably \
             incompatible"
        );
    }

    #[test]
    fn cumulative_satisfiability_budget_accumulates_across_queries_then_halts_search() {
        // A small contradiction chain whose query completes exactly and cheaply
        // while still charging a non-zero, deterministic amount to the model's
        // shared cumulative counter - enough to prove queries accumulate without
        // spending the full per-query budget on every call.
        const CHAIN: usize = 8;
        let model = build_condition_model(&chain_with_contradiction(CHAIN));

        assert_eq!(model.sat_iterations_used(), 0, "a freshly built model has spent none of its cumulative budget");
        assert!(!model.satisfiability_budget_exhausted(), "a freshly built model's cumulative budget is not exhausted");

        // (1) Real queries accumulate across queries - a per-query reset would
        // be a silent denial-of-service regression. Issuing the same saturating
        // query repeatedly must strictly increase the shared counter.
        let mut previous = 0u64;
        for _ in 0..3 {
            let _ = model.is_satisfiable(&[("Contra".to_string(), true)]);
            let used = model.sat_iterations_used();
            assert!(
                used > previous,
                "each query while under budget must add to the shared cumulative counter; a \
                 per-query reset would be a silent denial-of-service regression. was {previous}, \
                 now {used}"
            );
            previous = used;
        }
        assert!(
            !model.satisfiability_budget_exhausted(),
            "a handful of queries must not exhaust the (large) cumulative budget"
        );

        // (2) The exhausted flag trips exactly at the cumulative threshold.
        // Fast-forward to one iteration short of the cap rather than burning
        // ~MAX_TOTAL_SAT_ITERATIONS of real search (pointless seconds of work);
        // the accumulation checked in (1) already proves real queries feed this
        // same counter.
        let to_threshold = MAX_TOTAL_SAT_ITERATIONS - model.sat_iterations_used() - 1;
        model.add_sat_iterations_for_test(to_threshold);
        assert!(
            !model.satisfiability_budget_exhausted(),
            "one iteration short of the cap must not be exhausted; counter is {}",
            model.sat_iterations_used()
        );
        model.add_sat_iterations_for_test(1);
        assert!(
            model.satisfiability_budget_exhausted(),
            "reaching MAX_TOTAL_SAT_ITERATIONS must trip the exhausted flag; counter is {}",
            model.sat_iterations_used()
        );

        // (3) Once exhausted, further queries must short-circuit in O(1): they
        // return the conservative satisfiable answer and charge no further work.
        let before_short_circuit = model.sat_iterations_used();
        let conservative = model.is_satisfiable(&[("Contra".to_string(), true)]);
        assert!(
            conservative,
            "a query issued after the cumulative budget is exhausted must return the conservative \
             satisfiable answer"
        );
        assert_eq!(
            model.sat_iterations_used(),
            before_short_circuit,
            "an exhausted-budget query must short-circuit without performing or charging further \
             search work"
        );
    }

    #[test]
    fn rules_section_implication_eliminates_impossible_scenario() {
        // Rules: when Env == prod, an assertion requires Env == dev - so a
        // condition equivalent to Env == prod can never hold. The implication
        // must actually constrain the SAT search, not merely be recorded.
        let yaml = b"
Parameters:
  Env:
    Type: String
Conditions:
  IsProd: !Equals [!Ref Env, prod]
Rules:
  RejectProd:
    RuleCondition: !Equals [!Ref Env, prod]
    Assertions:
      - Assert: !Equals [!Ref Env, dev]
Resources:
  B:
    Type: AWS::S3::Bucket
    Condition: IsProd
";
        let model = crate::SemanticModel::from_bytes(yaml).expect("model builds");
        assert!(
            !model.conditions.is_satisfiable(&[("IsProd".to_string(), true)]),
            "IsProd=true contradicts the Rules assertion and must be unsatisfiable"
        );
        assert!(model.conditions.is_satisfiable(&[("IsProd".to_string(), false)]), "IsProd=false remains satisfiable");
    }

    #[test]
    fn rules_without_rule_condition_do_not_constrain_unrelated_queries() {
        // An unconditional assertion has no antecedent implication; unrelated
        // conditions stay satisfiable both ways.
        let yaml = b"
Parameters:
  Env:
    Type: String
  Other:
    Type: String
Conditions:
  UsesOther: !Equals [!Ref Other, x]
Rules:
  AlwaysDev:
    Assertions:
      - Assert: !Equals [!Ref Env, dev]
Resources:
  B:
    Type: AWS::S3::Bucket
    Condition: UsesOther
";
        let model = crate::SemanticModel::from_bytes(yaml).expect("model builds");
        assert!(model.conditions.is_satisfiable(&[("UsesOther".to_string(), true)]));
        assert!(model.conditions.is_satisfiable(&[("UsesOther".to_string(), false)]));
    }

    #[test]
    fn mixed_nesting_produces_no_unsound_implications() {
        // `Complex = And(Or(A, B), Not(C))` entails none of A, B, C
        // individually, and none of them entails Complex. An unsound
        // implication here would be enforced by the search and wrongly prune
        // satisfiable scenarios (a real false-positive source for the
        // unreachable-branch rule).
        let yaml = b"
Parameters:
  Env:
    Type: String
    AllowedValues: [dev, prod]
  Flag:
    Type: String
    AllowedValues: ['true', 'false']
Conditions:
  A: !Equals [!Ref Env, prod]
  B: !Equals [!Ref Env, dev]
  C: !Equals [!Ref Flag, 'true']
  Complex: !And [!Or [!Condition A, !Condition B], !Not [!Condition C]]
  Inline: !And [!Condition B, !Condition C]
  NotA: !Not [!Condition A]
Resources:
  R:
    Type: AWS::S3::Bucket
    Condition: NotA
";
        let model = crate::SemanticModel::from_bytes(yaml).expect("model builds");
        assert!(
            !model.conditions.implications.iter().any(|i| i.antecedent == "Complex" || i.consequent == "Complex"),
            "no implication may involve the mixed-nesting condition: {:?}",
            model.conditions.implications
        );
        // Env=dev, Flag=false satisfies NotA=true with Inline=false.
        assert!(
            model.conditions.is_satisfiable(&[("NotA".to_string(), true), ("Inline".to_string(), false)]),
            "sound implications must not prune this satisfiable scenario"
        );
    }
}
