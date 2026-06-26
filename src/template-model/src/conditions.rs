use crate::consts::{
    CONDITION_REF_PREFIX, MAX_PARAM_COMBINATIONS, MAX_SAT_ITERATIONS, MAX_TOTAL_SAT_ITERATIONS, PARAM_UNKNOWN_SENTINEL,
    PSEUDO_PREFIX,
};
use crate::ir::*;
use crate::model::PseudoParameterOverrides;
use crate::resolver::{MappingData, ParameterInfo};
use log::{debug, info};
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone)]
pub enum ConditionExpr {
    Equals(ValueExpr, ValueExpr),
    And(Vec<ConditionExpr>),
    Or(Vec<ConditionExpr>),
    Not(Box<ConditionExpr>),
    ConditionRef(String),
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
    pseudo_overrides: PseudoParameterOverrides,
    mappings: MappingData,
    /// Cumulative satisfiability search steps consumed across every query for
    /// this model. Shared (the model is reached through one `Arc`) so the
    /// quadratic compatibility pass, scenario resolution, and rule-evaluation
    /// builtins all draw down a single per-validation budget.
    sat_iterations_used: AtomicU64,
    /// Referenced parameters and their candidate values, derived from the
    /// condition set and parameter definitions. The satisfiability consistency
    /// check enumerates this map at every search leaf, so caching it avoids
    /// recomputing the same map across leaves and queries. Computed once on
    /// first use and invalidated by `register_inline` — the only path that
    /// mutates the condition set after construction.
    referenced_param_values: OnceLock<HashMap<String, Vec<String>>>,
    /// Condition names in a stable (sorted) order, cached for reuse. The
    /// satisfiability search assigns each condition an index by this order, and
    /// the order in which assignments are explored drives how fast the per-query
    /// and cumulative budgets draw down. `HashMap` key order is randomized per
    /// instance, so without a stable order the iteration charged per query — and
    /// thus which pair the budget trips at under exhaustion — would differ
    /// between runs and between the rego and cel engines' separate model
    /// instances. A sorted order makes search order, budget draw-down, and
    /// budget-truncated output reproducible. Computed once on first use and
    /// invalidated by `register_inline`.
    sorted_condition_names: OnceLock<Vec<String>>,
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
            pseudo_overrides: pseudo_overrides.clone(),
            mappings: mappings.clone(),
            sat_iterations_used: AtomicU64::new(0),
            referenced_param_values: OnceLock::new(),
            sorted_condition_names: OnceLock::new(),
        }
    }

    /// Decides whether the given condition assumptions can hold simultaneously.
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
    ///   search might have eliminated — at worst surfacing an extra
    ///   (false-positive) diagnostic.
    /// - Used negated to prove *unreachability* (`find_unreachable_branches`,
    ///   which emits when `!is_satisfiable(branch_assumptions)`) a conservative
    ///   `true` makes the branch look reachable and therefore *suppresses* an
    ///   unreachable-branch diagnostic — a false negative, the opposite
    ///   direction.
    /// - Used negated to prove *implication* (`condition_implies`, i.e.
    ///   `!is_satisfiable(a = true, b = false)`; the conditional-reference guard
    ///   uses the same shape) a conservative `true` flips the result to "does not
    ///   imply", which can surface an extra (false-positive) diagnostic.
    ///
    /// All of these occur only on adversarial inputs that exhaust the budget;
    /// valid templates resolve well within budget and are unaffected.
    #[must_use]
    pub fn is_satisfiable(&self, assumptions: &[(String, bool)]) -> bool {
        // Once the cumulative search budget for this model is spent, assume
        // satisfiable instead of searching further (the conservative-`true`
        // contract documented above). Checked before any per-query setup so an
        // exhausted query costs O(1) — this is what keeps a template with a huge
        // number of conditions (a quadratic flood of queries) bounded.
        if self.satisfiability_budget_exhausted() {
            return true;
        }
        let cond_names: &[String] = self.sorted_condition_names.get_or_init(|| {
            let mut names: Vec<String> = self.conditions.keys().cloned().collect();
            names.sort();
            names
        });
        let n = cond_names.len();
        if n == 0 {
            return true;
        }
        debug!("Checking satisfiability of {:?} against {} conditions", assumptions, n);

        let name_to_idx: HashMap<&str, usize> = cond_names.iter().enumerate().map(|(i, n)| (n.as_str(), i)).collect();

        let mut assumption_map: HashMap<usize, bool> = HashMap::new();
        for (name, val) in assumptions {
            if let Some(&idx) = name_to_idx.get(name.as_str()) {
                if let Some(&existing) = assumption_map.get(&idx)
                    && existing != *val
                {
                    return false;
                }
                assumption_map.insert(idx, *val);
            }
        }

        let relevant = self.find_relevant_conditions(assumptions);
        let mut relevant_indices: Vec<usize> =
            relevant.iter().filter_map(|name| name_to_idx.get(name.as_str()).copied()).collect();
        // `find_relevant_conditions` returns a HashSet, whose iteration order is
        // randomized per process. The satisfiability result is order-independent,
        // but the number of search steps charged to the cumulative budget before
        // a satisfying assignment is found is not. Sort so per-query budget
        // draw-down is deterministic across runs and identical between the rego
        // and cel engines, which build separate models with different hash seeds;
        // otherwise budget exhaustion would trip at a different query per run and
        // diverge the budget-truncated diagnostics.
        relevant_indices.sort_unstable();

        // Enumerate only the parameters the relevant conditions actually
        // reference. Varying any other parameter cannot change a relevant
        // condition, so the satisfiability result is identical with far fewer
        // combinations.
        let relevant_param_values = self.relevant_param_values(&relevant_indices, cond_names);

        // If even that restricted parameter space is too large to enumerate,
        // assume satisfiable instead of exploring it (the conservative-`true`
        // contract documented on this method). This is the main guard against a
        // condition whose closure references many parameters. The closure size
        // is still charged to the budget so a flood of such queries stays
        // bounded too.
        let mut parameter_combinations: u64 = 1;
        for values in relevant_param_values.values() {
            parameter_combinations = parameter_combinations.saturating_mul(values.len() as u64);
        }
        if parameter_combinations > MAX_PARAM_COMBINATIONS {
            // The cap short-circuits before the search, but the query has
            // already walked the relevant closure: find_relevant_conditions
            // (closure BFS) and relevant_param_values (which re-walks every
            // relevant condition's expression). Charge that work — the condition
            // count plus the relevant-closure size — so a flood of cap-tripped
            // queries over a large condition graph draws the cumulative budget
            // down in proportion to the work performed, not merely by `n`.
            self.sat_iterations_used.fetch_add(n as u64 + relevant_indices.len() as u64, Ordering::Relaxed);
            return true;
        }

        let mut assignment = vec![false; n];
        for (&idx, &val) in &assumption_map {
            assignment[idx] = val;
        }
        let mut iterations = 0u64;
        let satisfiable = self.search_relevant(
            0,
            &mut assignment,
            cond_names,
            &name_to_idx,
            &assumption_map,
            &relevant_indices,
            &relevant_param_values,
            &mut iterations,
        );
        self.sat_iterations_used.fetch_add(iterations + n as u64, Ordering::Relaxed);
        satisfiable
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

    /// Test-only: advance the cumulative satisfiability counter directly, so the
    /// budget threshold and short-circuit behavior can be exercised without
    /// burning `MAX_TOTAL_SAT_ITERATIONS` of real search work (which would be
    /// pointless seconds of computation).
    #[cfg(test)]
    fn add_sat_iterations_for_test(&self, count: u64) {
        self.sat_iterations_used.fetch_add(count, Ordering::Relaxed);
    }

    fn find_relevant_conditions(&self, assumptions: &[(String, bool)]) -> HashSet<String> {
        let mut relevant = HashSet::new();
        let mut queue: Vec<String> = assumptions.iter().map(|(n, _)| n.clone()).collect();
        while let Some(name) = queue.pop() {
            if !relevant.insert(name.clone()) {
                continue;
            }
            if let Some(expr) = self.conditions.get(&name) {
                collect_condition_refs(expr, &mut queue);
            }
            // Also add conditions in the same mutex group
            for group in &self.mutex_groups {
                if group.conditions.contains(&name) {
                    for c in &group.conditions {
                        if !relevant.contains(c) {
                            queue.push(c.clone());
                        }
                    }
                }
            }
        }
        relevant
    }

    #[allow(clippy::too_many_arguments)]
    fn search_relevant(
        &self,
        rel_idx: usize,
        assignment: &mut Vec<bool>,
        cond_names: &[String],
        name_to_idx: &HashMap<&str, usize>,
        assumptions: &HashMap<usize, bool>,
        relevant: &[usize],
        param_values: &HashMap<String, Vec<String>>,
        iterations: &mut u64,
    ) -> bool {
        *iterations += 1;
        if *iterations > MAX_SAT_ITERATIONS {
            // Assume satisfiable to avoid false "unsatisfiable" which would suppress valid diagnostics
            return true;
        }

        if rel_idx == relevant.len() {
            return self.assignment_consistent_with_parameters(
                assignment,
                cond_names,
                name_to_idx,
                relevant,
                param_values,
                iterations,
            );
        }

        let idx = relevant[rel_idx];

        for &val in &[false, true] {
            if let Some(&required) = assumptions.get(&idx)
                && val != required
            {
                continue;
            }

            assignment[idx] = val;

            // Check mutex constraints
            if val {
                let mut violated = false;
                for group in &self.mutex_groups {
                    // A parameter can equal at most one value, so the conditions
                    // that are simultaneously true may reference at most one
                    // distinct value. Conditions that test the same value are
                    // equivalent and may all hold together.
                    let mut true_values: HashSet<&str> = HashSet::new();
                    for (position, condition_name) in group.conditions.iter().enumerate() {
                        let condition_holds = name_to_idx
                            .get(condition_name.as_str())
                            .map(|&i| relevant[..=rel_idx].contains(&i) && assignment[i])
                            .unwrap_or(false);
                        if condition_holds {
                            true_values.insert(group.values[position].as_str());
                        }
                    }
                    if true_values.len() > 1 {
                        violated = true;
                        break;
                    }
                }
                if violated {
                    continue;
                }
            }

            if self.search_relevant(
                rel_idx + 1,
                assignment,
                cond_names,
                name_to_idx,
                assumptions,
                relevant,
                param_values,
                iterations,
            ) {
                return true;
            }
        }

        false
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

    /// The parameters referenced by the given relevant conditions, paired with
    /// their candidate values. Restricting the satisfiability search to these
    /// parameters is exact — a parameter no relevant condition references cannot
    /// change any relevant condition's value — and keeps the enumerated space as
    /// small as the query actually requires.
    fn relevant_param_values(&self, relevant_indices: &[usize], cond_names: &[String]) -> HashMap<String, Vec<String>> {
        let all_values = self.referenced_param_values.get_or_init(|| self.collect_referenced_param_values());
        let mut referenced: HashMap<String, Vec<String>> = HashMap::new();
        for &i in relevant_indices {
            collect_equals_pairs(&self.conditions[&cond_names[i]], &mut referenced);
        }
        referenced
            .into_keys()
            .filter_map(|param| all_values.get(&param).map(|values| (param, values.clone())))
            .collect()
    }

    fn assignment_consistent_with_parameters(
        &self,
        assignment: &[bool],
        cond_names: &[String],
        name_to_idx: &HashMap<&str, usize>,
        relevant: &[usize],
        param_values: &HashMap<String, Vec<String>>,
        iterations: &mut u64,
    ) -> bool {
        if param_values.is_empty() {
            // No parameters — evaluate the relevant conditions directly. Other
            // conditions are unconstrained for this query and their assignment
            // entry is a placeholder, not a real value.
            for &i in relevant {
                let expr = &self.conditions[&cond_names[i]];
                let evaluated =
                    self.eval_expr_concrete(expr, &HashMap::new(), assignment, cond_names, name_to_idx, iterations);
                // None means can't evaluate (e.g., depends on a pseudo-parameter) — treat as compatible
                if let Some(eval_val) = evaluated
                    && eval_val != assignment[i]
                {
                    return false;
                }
            }
            return true;
        }

        // Try all combinations of parameter values. Sort the parameter names:
        // they come from a HashMap, and although the consistency result does not
        // depend on enumeration order, the number of steps charged before a
        // consistent assignment is found does. A stable order keeps per-query
        // budget draw-down deterministic and engine-identical (see the matching
        // sort of `relevant_indices` in `is_satisfiable`).
        let mut param_names: Vec<String> = param_values.keys().cloned().collect();
        param_names.sort_unstable();
        let param_vals: Vec<Vec<String>> = param_names.iter().map(|n| param_values[n].clone()).collect();

        let mut indices = vec![0usize; param_names.len()];
        loop {
            *iterations += 1;
            if *iterations > MAX_SAT_ITERATIONS {
                // The parameter cartesian product is exponential in the number
                // of referenced parameters. Once the per-query search budget is
                // spent, assume this assignment is consistent (satisfiable)
                // instead of enumerating further — the conservative-`true`
                // contract documented on `is_satisfiable`, which bounds the
                // work.
                return true;
            }
            // Build parameter assignment
            let mut param_assignment: HashMap<String, String> = HashMap::new();
            for (i, name) in param_names.iter().enumerate() {
                if indices[i] < param_vals[i].len() {
                    param_assignment.insert(name.clone(), param_vals[i][indices[i]].clone());
                }
            }

            // Check if the relevant conditions evaluate consistently. Other
            // conditions are unconstrained in this query and their default
            // assignment is a placeholder, not a real value.
            let mut consistent = true;
            for &i in relevant {
                let expr = &self.conditions[&cond_names[i]];
                let evaluated =
                    self.eval_expr_concrete(expr, &param_assignment, assignment, cond_names, name_to_idx, iterations);
                // None means can't evaluate (e.g., depends on a pseudo-parameter) — treat as compatible
                if let Some(eval_val) = evaluated
                    && eval_val != assignment[i]
                {
                    consistent = false;
                    break;
                }
            }
            if consistent {
                return true;
            }

            // Increment indices
            let mut carry = true;
            for i in (0..indices.len()).rev() {
                if carry {
                    indices[i] += 1;
                    if indices[i] < param_vals[i].len() {
                        carry = false;
                    } else {
                        indices[i] = 0;
                    }
                }
            }
            if carry {
                break; // exhausted all combinations
            }
        }

        false
    }

    fn eval_expr_concrete(
        &self,
        expr: &ConditionExpr,
        param_assignment: &HashMap<String, String>,
        cond_assignment: &[bool],
        _cond_names: &[String],
        name_to_idx: &HashMap<&str, usize>,
        iterations: &mut u64,
    ) -> Option<bool> {
        // Each evaluation is one unit of satisfiability work. Counting here, in
        // the recursive core, keeps the search budget proportional to real
        // effort: a deep condition closure draws the budget down faster than a
        // shallow one, so the budget bounds actual work uniformly regardless of
        // how the conditions are shaped.
        *iterations += 1;
        match expr {
            ConditionExpr::Equals(a, b) => {
                let av = self.eval_value_concrete(a, param_assignment)?;
                let bv = self.eval_value_concrete(b, param_assignment)?;
                Some(av == bv)
            }
            ConditionExpr::And(exprs) => {
                let mut result = true;
                for e in exprs {
                    result = result
                        && self.eval_expr_concrete(
                            e,
                            param_assignment,
                            cond_assignment,
                            _cond_names,
                            name_to_idx,
                            iterations,
                        )?;
                }
                Some(result)
            }
            ConditionExpr::Or(exprs) => {
                let mut result = false;
                for e in exprs {
                    result = result
                        || self.eval_expr_concrete(
                            e,
                            param_assignment,
                            cond_assignment,
                            _cond_names,
                            name_to_idx,
                            iterations,
                        )?;
                }
                Some(result)
            }
            ConditionExpr::Not(e) => Some(!self.eval_expr_concrete(
                e,
                param_assignment,
                cond_assignment,
                _cond_names,
                name_to_idx,
                iterations,
            )?),
            ConditionExpr::ConditionRef(name) => name_to_idx.get(name.as_str()).map(|&i| cond_assignment[i]),
        }
    }

    fn eval_value_concrete(&self, expr: &ValueExpr, param_assignment: &HashMap<String, String>) -> Option<String> {
        match expr {
            ValueExpr::Literal(s) => Some(s.clone()),
            ValueExpr::ParamRef(name) => param_assignment.get(name).cloned(),
            ValueExpr::PseudoParam(name) => {
                param_assignment.get(name).cloned().or_else(|| self.pseudo_overrides.fixed_value(name))
            }
            ValueExpr::MappingLookup { map_name, key1, key2 } => {
                let k1 = self.eval_value_concrete(key1, param_assignment)?;
                let k2 = self.eval_value_concrete(key2, param_assignment)?;
                let value = self.mappings.get(map_name)?.get(&k1)?.get(&k2)?;
                // Convert JSON value to string for condition comparison
                match value {
                    serde_json::Value::String(s) => Some(s.clone()),
                    other => Some(other.to_string()),
                }
            }
            ValueExpr::Other => None,
        }
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
            ConditionExpr::ConditionRef(_) => {}
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
        self.conditions.insert(name, expr);
        self.mutex_groups = extract_mutex_groups(&self.conditions);
        self.implications = extract_implications(&self.conditions);
        // Inserting a condition can introduce parameter references the cached
        // map omits and changes the set of condition names, so invalidate both
        // derived caches; they are rebuilt lazily on the next satisfiability
        // query. The cumulative iteration counter is deliberately left untouched
        // — it is a per-validation work budget, not state derived from the
        // condition set, and resetting it would hand adversarial input a way to
        // refill the budget.
        self.referenced_param_values = OnceLock::new();
        self.sorted_condition_names = OnceLock::new();
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
        ConditionExpr::ConditionRef(_) => {}
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
                // Treat as a value expression wrapped in an implicit Equals(Ref, "true")
                ConditionExpr::ConditionRef(target.clone())
            }
        }
        _ => {
            // Try to parse as a map with intrinsic keys
            if let Some(entries) = arena.as_map(node_ref)
                && entries.len() == 1
            {
                let (key, val) = &entries[0];
                match key.as_str() {
                    "Fn::Equals" => {
                        if let Some(arr) = arena.as_list(*val)
                            && arr.len() == 2
                        {
                            let va = parse_value_expr(arena, arr[0], parameters);
                            let vb = parse_value_expr(arena, arr[1], parameters);
                            return ConditionExpr::Equals(va, vb);
                        }
                    }
                    "Fn::And" => {
                        if let Some(arr) = arena.as_list(*val) {
                            let exprs = arr.iter().map(|c| parse_condition_expr(arena, *c, parameters)).collect();
                            return ConditionExpr::And(exprs);
                        }
                    }
                    "Fn::Or" => {
                        if let Some(arr) = arena.as_list(*val) {
                            let exprs = arr.iter().map(|c| parse_condition_expr(arena, *c, parameters)).collect();
                            return ConditionExpr::Or(exprs);
                        }
                    }
                    "Fn::Not" => {
                        if let Some(arr) = arena.as_list(*val)
                            && !arr.is_empty()
                        {
                            let expr = parse_condition_expr(arena, arr[0], parameters);
                            return ConditionExpr::Not(Box::new(expr));
                        }
                    }
                    "Condition" => {
                        if let Some(name) = arena.as_str(*val) {
                            return ConditionExpr::ConditionRef(name.to_string());
                        }
                    }
                    _ => {}
                }
            }
            // Fallback
            ConditionExpr::Equals(ValueExpr::Other, ValueExpr::Other)
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
        // a value that cannot be known statically — it must be treated as an
        // opaque unknown (`Other`), never a comparable literal. Treating, say,
        // `Fn::Sub(...)` as the literal string "Sub(...)" would make
        // `Fn::Equals[!Sub ..., "x"]` look like a literal-vs-literal compare and
        // spuriously fire the always-true/false check (W8003).
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
        ConditionExpr::ConditionRef(_) => {}
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
    match expr {
        ConditionExpr::ConditionRef(name) => out.push(name.clone()),
        ConditionExpr::And(exprs) | ConditionExpr::Or(exprs) => {
            for e in exprs {
                collect_condition_refs(e, out);
            }
        }
        ConditionExpr::Not(e) => collect_condition_refs(e, out),
        ConditionExpr::Equals(_, _) => {}
    }
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
            // Only positive tests (Equals) form mutex groups — two conditions
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

fn extract_implications(conditions: &HashMap<String, ConditionExpr>) -> Vec<Implication> {
    let mut implications = Vec::new();

    for (name, expr) in conditions {
        match expr {
            ConditionExpr::And(children) => {
                // And(A, B, ...) = true implies each child is true
                let mut refs = Vec::new();
                collect_nested_condition_refs_from_list(children, &mut refs);
                for ref_name in refs {
                    implications.push(Implication { antecedent: name.clone(), consequent: ref_name });
                }
            }
            ConditionExpr::Or(children) => {
                // If any child is true, the Or is true — each child implies the Or
                let mut refs = Vec::new();
                collect_nested_condition_refs_from_list(children, &mut refs);
                for ref_name in refs {
                    implications.push(Implication { antecedent: ref_name, consequent: name.clone() });
                }
            }
            _ => {}
        }
    }

    implications
}

fn collect_nested_condition_refs_from_list(exprs: &[ConditionExpr], out: &mut Vec<String>) {
    for child in exprs {
        collect_nested_condition_refs(child, out);
    }
}

fn collect_nested_condition_refs(expr: &ConditionExpr, out: &mut Vec<String>) {
    match expr {
        ConditionExpr::ConditionRef(name) => out.push(name.clone()),
        ConditionExpr::And(children) | ConditionExpr::Or(children) => {
            for child in children {
                collect_nested_condition_refs(child, out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::PseudoParameterOverrides;
    use crate::parser;
    use crate::resolver::{extract_mappings, extract_parameters};

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
             (the auto-derived default region must not pin the pseudo-parameter to a constant — that \
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

    /// Regression test for a W1028 false positive: when an `Fn::Equals`
    /// compares a pseudo-parameter to a literal and no override pins that
    /// pseudo-parameter, both branches of an `Fn::If` keyed on that condition
    /// must remain reachable. Before this was fixed, the SAT solver resolved
    /// `AWS::Partition` to its auto-derived default (`"aws"`), making
    /// `Fn::Equals[Ref AWS::Partition, "aws"]` deterministically true and the
    /// `Fn::If` false branch (the `Ref AWS::NoValue` arm) appear unreachable.
    /// At deploy time `AWS::Partition` ranges over `aws`, `aws-cn`,
    /// `aws-us-gov`, etc. — so without an explicit pin it has to behave as a
    /// free variable.
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
    fn chain_with_contradiction(chain_len: usize) -> String {
        use std::fmt::Write;
        let mut s = String::from(
            "Parameters:\n  P0:\n    Type: String\n    AllowedValues: [yes, no]\n  \
             P1:\n    Type: String\n    AllowedValues: [yes, no]\n\
             Conditions:\n  C000:\n    Fn::Equals: [!Ref P0, yes]\n  \
             C001:\n    Fn::Equals: [!Ref P1, yes]\n",
        );
        for i in 2..chain_len {
            let op = if i % 2 == 0 { "Fn::And" } else { "Fn::Or" };
            let _ = write!(
                s,
                "  C{:03}:\n    {}:\n      - Condition: C{:03}\n      - Condition: C{:03}\n",
                i,
                op,
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
    fn satisfiability_search_is_bounded_by_iteration_budget() {
        // `Contra = And(Top, Not(Top))` is unsatisfiable. Proving that requires
        // exhausting the assignment space of Top's dependency closure, which is
        // exponential in the chain length.
        //
        // Over a short chain the solver explores the whole space within the
        // iteration budget and returns the correct answer: unsatisfiable.
        const SHORT_CHAIN: usize = 8;
        let short_model = build_condition_model(&chain_with_contradiction(SHORT_CHAIN));
        assert!(
            !short_model.is_satisfiable(&[("Contra".to_string(), true)]),
            "a contradiction over a short chain must be proven unsatisfiable within the budget"
        );

        // Over a long chain the space is astronomically large (2^len). Without a
        // budget the search would run effectively forever; the MAX_SAT_ITERATIONS
        // cap cuts it off and the solver returns its conservative answer
        // (satisfiable). The flip from `false` to `true` for the same kind of
        // (still unsatisfiable) query is the observable signature of the budget
        // engaging. The query runs on a worker thread so that a regression which
        // removed the budget fails this test by timing out rather than hanging
        // the whole suite.
        const LONG_CHAIN: usize = 32;
        const SEARCH_CEILING: std::time::Duration = std::time::Duration::from_secs(30);
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let long_model = build_condition_model(&chain_with_contradiction(LONG_CHAIN));
            let _ = sender.send(long_model.is_satisfiable(&[("Contra".to_string(), true)]));
        });
        match receiver.recv_timeout(SEARCH_CEILING) {
            Ok(conservative_result) => assert!(
                conservative_result,
                "once the iteration budget is exceeded the solver must return the conservative \
                 satisfiable result, not the (correct but unaffordable) unsatisfiable one"
            ),
            Err(_) => panic!(
                "satisfiability search did not finish within {SEARCH_CEILING:?}; the iteration \
                 budget is not bounding the search"
            ),
        }
    }

    /// Builds a model with `param_count` binary parameters, one base condition
    /// per parameter, and a `Wide` condition that is the conjunction of every
    /// base — so a query over `Wide` has a dependency closure spanning all of
    /// the parameters.
    fn wide_parameter_closure(param_count: usize) -> String {
        use std::fmt::Write;
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
        // 24 binary parameters means 2^24 value combinations — far above
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
        // conservative answer — proving the cap does not over-trigger.
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
        // shared cumulative counter — enough to prove queries accumulate without
        // spending the full per-query budget on every call.
        const CHAIN: usize = 8;
        let model = build_condition_model(&chain_with_contradiction(CHAIN));

        assert_eq!(model.sat_iterations_used(), 0, "a freshly built model has spent none of its cumulative budget");
        assert!(!model.satisfiability_budget_exhausted(), "a freshly built model's cumulative budget is not exhausted");

        // (1) Real queries accumulate across queries — a per-query reset would
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
}
