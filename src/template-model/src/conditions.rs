use crate::consts::{CONDITION_REF_PREFIX, MAX_SAT_ITERATIONS, PSEUDO_PREFIX};
use crate::ir::*;
use crate::model::PseudoParameterOverrides;
use crate::resolver::{MappingData, ParameterInfo};
use log::{debug, info};
use std::collections::{HashMap, HashSet};

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
    MappingLookup {
        map_name: String,
        key1: Box<ValueExpr>,
        key2: Box<ValueExpr>,
    },
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
}

pub fn format_condition_expr(expr: &ConditionExpr) -> String {
    match expr {
        ConditionExpr::Equals(a, b) => {
            format!("Equals({}, {})", format_value_expr(a), format_value_expr(b))
        }
        ConditionExpr::And(exprs) => {
            let items: Vec<String> = exprs.iter().map(|e| format_condition_expr(e)).collect();
            format!("And({})", items.join(", "))
        }
        ConditionExpr::Or(exprs) => {
            let items: Vec<String> = exprs.iter().map(|e| format_condition_expr(e)).collect();
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
        ValueExpr::MappingLookup {
            map_name,
            key1,
            key2,
        } => format!(
            "FindInMap({}, {}, {})",
            map_name,
            format_value_expr(key1),
            format_value_expr(key2)
        ),
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

        if ir.conditions != NULL_REF {
            if let Some(entries) = ir.arena.as_map(ir.conditions) {
                for (name, node_ref) in entries {
                    let expr = parse_condition_expr(&ir.arena, *node_ref, parameters);
                    conditions.insert(name.clone(), expr);
                }
            }
        }

        let mutex_groups = extract_mutex_groups(&conditions);
        let implications = extract_implications(&conditions);

        info!(
            "Condition model: {} conditions, {} mutex groups (params: {:?}), {} implications",
            conditions.len(),
            mutex_groups.len(),
            mutex_groups
                .iter()
                .map(|g| g.parameter.as_str())
                .collect::<Vec<_>>(),
            implications.len()
        );
        ConditionModel {
            conditions,
            parameters: parameters.clone(),
            mutex_groups,
            implications,
            pseudo_overrides: pseudo_overrides.clone(),
            mappings: mappings.clone(),
        }
    }

    #[must_use]
    pub fn is_satisfiable(&self, assumptions: &[(String, bool)]) -> bool {
        let cond_names: Vec<String> = self.conditions.keys().cloned().collect();
        let n = cond_names.len();
        if n == 0 {
            return true;
        }
        debug!(
            "Checking satisfiability of {:?} against {} conditions",
            assumptions, n
        );

        let name_to_idx: HashMap<&str, usize> = cond_names
            .iter()
            .enumerate()
            .map(|(i, n)| (n.as_str(), i))
            .collect();

        let mut assumption_map: HashMap<usize, bool> = HashMap::new();
        for (name, val) in assumptions {
            if let Some(&idx) = name_to_idx.get(name.as_str()) {
                if let Some(&existing) = assumption_map.get(&idx) {
                    if existing != *val {
                        return false;
                    }
                }
                assumption_map.insert(idx, *val);
            }
        }

        let relevant = self.find_relevant_conditions(assumptions);
        let relevant_indices: Vec<usize> = relevant
            .iter()
            .filter_map(|name| name_to_idx.get(name.as_str()).copied())
            .collect();

        let mut assignment = vec![false; n];
        for (&idx, &val) in &assumption_map {
            assignment[idx] = val;
        }
        let mut iterations = 0u64;
        self.search_relevant(
            0,
            &mut assignment,
            &cond_names,
            &name_to_idx,
            &assumption_map,
            &relevant_indices,
            &mut iterations,
        )
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

    fn search_relevant(
        &self,
        rel_idx: usize,
        assignment: &mut Vec<bool>,
        cond_names: &[String],
        name_to_idx: &HashMap<&str, usize>,
        assumptions: &HashMap<usize, bool>,
        relevant: &[usize],
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
            );
        }

        let idx = relevant[rel_idx];

        for &val in &[false, true] {
            if let Some(&required) = assumptions.get(&idx) {
                if val != required {
                    continue;
                }
            }

            assignment[idx] = val;

            // Check mutex constraints
            if val {
                let mut violated = false;
                for group in &self.mutex_groups {
                    let true_count = group
                        .conditions
                        .iter()
                        .filter(|c| {
                            name_to_idx
                                .get(c.as_str())
                                .map(|&i| {
                                    // Only count conditions we've already assigned in relevant set
                                    relevant[..=rel_idx].contains(&i) && assignment[i]
                                })
                                .unwrap_or(false)
                        })
                        .count();
                    if true_count > 1 {
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
                iterations,
            ) {
                return true;
            }
        }

        false
    }

    fn assignment_consistent_with_parameters(
        &self,
        assignment: &[bool],
        cond_names: &[String],
        name_to_idx: &HashMap<&str, usize>,
        relevant: &[usize],
    ) -> bool {
        // Collect all parameters referenced in conditions and their possible values
        let mut param_values: HashMap<String, Vec<String>> = HashMap::new();
        // First pass: harvest all (param, literal) pairs across all condition expressions
        let mut compared_literals: HashMap<String, Vec<String>> = HashMap::new();
        for expr in self.conditions.values() {
            collect_equals_pairs(expr, &mut compared_literals);
        }
        // Second pass: for each param, use AllowedValues if present, otherwise
        // use the harvested literals + "__unknown__" (represents "any other value")
        for (param_name, literals) in &compared_literals {
            if let Some(av) = self
                .parameters
                .get(param_name)
                .and_then(|p| p.allowed_values.clone())
            {
                param_values.insert(param_name.clone(), av);
            } else {
                let mut values = literals.clone();
                values.push("__unknown__".to_string());
                values.sort();
                values.dedup();
                param_values.insert(param_name.clone(), values);
            }
        }

        if param_values.is_empty() {
            // No parameters — just evaluate directly
            for (i, name) in cond_names.iter().enumerate() {
                // Non-relevant conditions are unconstrained for this satisfiability
                // query — their assignment[i] is a placeholder, not a real value.
                if !relevant.contains(&i) {
                    continue;
                }
                let expr = &self.conditions[name];
                let evaluated = self.eval_expr_concrete(
                    expr,
                    &HashMap::new(),
                    assignment,
                    cond_names,
                    name_to_idx,
                );
                // None means can't evaluate (e.g., depends on pseudo-parameter) — treat as compatible
                if let Some(eval_val) = evaluated {
                    if eval_val != assignment[i] {
                        return false;
                    }
                }
            }
            return true;
        }

        // Try all combinations of parameter values
        let param_names: Vec<String> = param_values.keys().cloned().collect();
        let param_vals: Vec<Vec<String>> = param_names
            .iter()
            .map(|n| param_values[n].clone())
            .collect();

        let mut indices = vec![0usize; param_names.len()];
        loop {
            // Build parameter assignment
            let mut param_assignment: HashMap<String, String> = HashMap::new();
            for (i, name) in param_names.iter().enumerate() {
                if indices[i] < param_vals[i].len() {
                    param_assignment.insert(name.clone(), param_vals[i][indices[i]].clone());
                }
            }

            // Check if all conditions evaluate consistently
            let mut consistent = true;
            for (i, name) in cond_names.iter().enumerate() {
                // Only verify relevant conditions — non-relevant conditions are
                // unconstrained in this satisfiability query, and their default
                // assignment is a placeholder, not a real value.
                if !relevant.contains(&i) {
                    continue;
                }
                let expr = &self.conditions[name];
                let evaluated = self.eval_expr_concrete(
                    expr,
                    &param_assignment,
                    assignment,
                    cond_names,
                    name_to_idx,
                );
                // None means can't evaluate (e.g., depends on pseudo-parameter) — treat as compatible
                if let Some(eval_val) = evaluated {
                    if eval_val != assignment[i] {
                        consistent = false;
                        break;
                    }
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
        cond_names: &[String],
        name_to_idx: &HashMap<&str, usize>,
    ) -> Option<bool> {
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
                            cond_names,
                            name_to_idx,
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
                            cond_names,
                            name_to_idx,
                        )?;
                }
                Some(result)
            }
            ConditionExpr::Not(e) => Some(!self.eval_expr_concrete(
                e,
                param_assignment,
                cond_assignment,
                cond_names,
                name_to_idx,
            )?),
            ConditionExpr::ConditionRef(name) => {
                name_to_idx.get(name.as_str()).map(|&i| cond_assignment[i])
            }
        }
    }

    fn eval_value_concrete(
        &self,
        expr: &ValueExpr,
        param_assignment: &HashMap<String, String>,
    ) -> Option<String> {
        match expr {
            ValueExpr::Literal(s) => Some(s.clone()),
            ValueExpr::ParamRef(name) => param_assignment.get(name).cloned(),
            ValueExpr::PseudoParam(name) => self.pseudo_overrides.get(name),
            ValueExpr::MappingLookup {
                map_name,
                key1,
                key2,
            } => {
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
            let exprs = children
                .iter()
                .map(|c| parse_condition_expr(arena, *c, parameters))
                .collect();
            ConditionExpr::And(exprs)
        }
        Node::Intrinsic(IntrinsicFn::Or(children)) => {
            let exprs = children
                .iter()
                .map(|c| parse_condition_expr(arena, *c, parameters))
                .collect();
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
            if let Some(entries) = arena.as_map(node_ref) {
                if entries.len() == 1 {
                    let (key, val) = &entries[0];
                    match key.as_str() {
                        "Fn::Equals" => {
                            if let Some(arr) = arena.as_list(*val) {
                                if arr.len() == 2 {
                                    let va = parse_value_expr(arena, arr[0], parameters);
                                    let vb = parse_value_expr(arena, arr[1], parameters);
                                    return ConditionExpr::Equals(va, vb);
                                }
                            }
                        }
                        "Fn::And" => {
                            if let Some(arr) = arena.as_list(*val) {
                                let exprs = arr
                                    .iter()
                                    .map(|c| parse_condition_expr(arena, *c, parameters))
                                    .collect();
                                return ConditionExpr::And(exprs);
                            }
                        }
                        "Fn::Or" => {
                            if let Some(arr) = arena.as_list(*val) {
                                let exprs = arr
                                    .iter()
                                    .map(|c| parse_condition_expr(arena, *c, parameters))
                                    .collect();
                                return ConditionExpr::Or(exprs);
                            }
                        }
                        "Fn::Not" => {
                            if let Some(arr) = arena.as_list(*val) {
                                if !arr.is_empty() {
                                    let expr = parse_condition_expr(arena, arr[0], parameters);
                                    return ConditionExpr::Not(Box::new(expr));
                                }
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
            }
            // Fallback
            ConditionExpr::Equals(ValueExpr::Other, ValueExpr::Other)
        }
    }
}

fn parse_value_expr(
    arena: &Arena,
    node_ref: NodeRef,
    parameters: &HashMap<String, ParameterInfo>,
) -> ValueExpr {
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
        Node::Intrinsic(intrinsic) => {
            // Describe the intrinsic so conditions display something meaningful
            let desc = match intrinsic {
                IntrinsicFn::Select(_, _) => "Select(...)".to_string(),
                IntrinsicFn::FindInMap(m, k1, k2, _) => {
                    let map_name = arena.as_str(*m).unwrap_or("?").to_string();
                    let key1 = parse_value_expr(arena, *k1, parameters);
                    let key2 = parse_value_expr(arena, *k2, parameters);
                    return ValueExpr::MappingLookup {
                        map_name,
                        key1: Box::new(key1),
                        key2: Box::new(key2),
                    };
                }
                IntrinsicFn::Join(_, _) => "Join(...)".to_string(),
                IntrinsicFn::Sub(t, _) => format!("Sub({})", t),
                IntrinsicFn::GetAtt(r, a) => format!("GetAtt({}, {})", r, a),
                IntrinsicFn::If(c, _, _) => format!("If({})", c),
                IntrinsicFn::Split(_, _) => "Split(...)".to_string(),
                IntrinsicFn::Base64(_) => "Base64(...)".to_string(),
                _ => "Intrinsic(...)".to_string(),
            };
            ValueExpr::Literal(desc)
        }
        _ => ValueExpr::Other,
    }
}

fn collect_equals_pairs(expr: &ConditionExpr, out: &mut HashMap<String, Vec<String>>) {
    match expr {
        ConditionExpr::Equals(a, b) => {
            if let (ValueExpr::ParamRef(p), ValueExpr::Literal(v))
            | (ValueExpr::Literal(v), ValueExpr::ParamRef(p)) = (a, b)
            {
                out.entry(p.clone()).or_default().push(v.clone());
            } else {
                // ParamRef compared to non-literal — still register the param
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

fn collect_param_refs_from_value_into_pairs(
    expr: &ValueExpr,
    out: &mut HashMap<String, Vec<String>>,
) {
    match expr {
        ValueExpr::ParamRef(p) => {
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
                param_tests
                    .entry(param)
                    .or_default()
                    .push((name.clone(), _lit));
            }
        }
    }

    param_tests
        .into_iter()
        .filter(|(_, tests)| tests.len() > 1)
        .map(|(param, tests)| {
            let conditions = tests.iter().map(|(n, _)| n.clone()).collect();
            let values = tests.iter().map(|(_, v)| v.clone()).collect();
            MutexGroup {
                conditions,
                parameter: param,
                values,
            }
        })
        .collect()
}

fn extract_equals_test(expr: &ConditionExpr) -> Option<(String, String, bool)> {
    match expr {
        ConditionExpr::Equals(a, b) => {
            if let (ValueExpr::ParamRef(p), ValueExpr::Literal(v))
            | (ValueExpr::Literal(v), ValueExpr::ParamRef(p)) = (a, b)
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
                    implications.push(Implication {
                        antecedent: name.clone(),
                        consequent: ref_name,
                    });
                }
            }
            ConditionExpr::Or(children) => {
                // If any child is true, the Or is true — each child implies the Or
                let mut refs = Vec::new();
                collect_nested_condition_refs_from_list(children, &mut refs);
                for ref_name in refs {
                    implications.push(Implication {
                        antecedent: ref_name,
                        consequent: name.clone(),
                    });
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
        assert!(!model.is_satisfiable(&[
            ("isProduction".into(), true),
            ("isProduction".into(), false),
        ]));
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
        assert!(
            model
                .implications
                .iter()
                .any(|i| i.antecedent == "ProdAndDB" && i.consequent == "IsProd")
        );
        assert!(
            model
                .implications
                .iter()
                .any(|i| i.antecedent == "ProdAndDB" && i.consequent == "CreateDB")
        );
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
        assert!(
            model
                .implications
                .iter()
                .any(|i| i.antecedent == "IsProd" && i.consequent == "ProdOrDev")
        );
        assert!(
            model
                .implications
                .iter()
                .any(|i| i.antecedent == "IsDev" && i.consequent == "ProdOrDev")
        );
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
        assert!(
            model.get("NonExistent").is_none(),
            "unknown condition should return None"
        );
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
    fn pseudo_param_resolves_in_sat_solver() {
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
        // Default region is us-east-1, so IsUsEast1 should always be true
        assert!(model.is_satisfiable(&[("IsUsEast1".into(), true)]));
        // IsUsEast1=false should be unsatisfiable with default region
        assert!(!model.is_satisfiable(&[("IsUsEast1".into(), false)]));
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
        let pseudo = PseudoParameterOverrides {
            region: Some("eu-west-1".to_string()),
            ..Default::default()
        };
        let model = ConditionModel::from_ir(&ir, &params, &pseudo, &mappings);
        // With eu-west-1, IsUsEast1=true should be unsatisfiable
        assert!(!model.is_satisfiable(&[("IsUsEast1".into(), true)]));
        assert!(model.is_satisfiable(&[("IsUsEast1".into(), false)]));
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
        let (param, lit, positive) =
            result.expect("extract_equals_test should return Some for Not(Equals)");
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
        assert!(
            model
                .implications
                .iter()
                .any(|i| i.antecedent == "NestedAnd" && i.consequent == "CondA")
        );
        assert!(
            model
                .implications
                .iter()
                .any(|i| i.antecedent == "NestedAnd" && i.consequent == "CondB")
        );
        assert!(
            model
                .implications
                .iter()
                .any(|i| i.antecedent == "NestedAnd" && i.consequent == "CondC")
        );
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
        assert!(
            model
                .implications
                .iter()
                .any(|i| i.antecedent == "CondA" && i.consequent == "NestedOr")
        );
        assert!(
            model
                .implications
                .iter()
                .any(|i| i.antecedent == "CondB" && i.consequent == "NestedOr")
        );
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
            ConditionExpr::Equals(
                ValueExpr::ParamRef("Env".to_string()),
                ValueExpr::Literal("Dev".to_string()),
            ),
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
            other => panic!(
                "Expected Concrete(\"yes\") from eager eval, got {:?}",
                other
            ),
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
        let inline_count = model
            .conditions
            .conditions
            .keys()
            .filter(|k| k.starts_with("__inline_cond_"))
            .count();
        assert!(
            inline_count > 0,
            "Expected at least one inline condition registered"
        );
    }
}
