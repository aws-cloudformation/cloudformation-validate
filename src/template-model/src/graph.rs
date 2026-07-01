use crate::ir::*;
use crate::resolver::{RefKind, ResolverEdge};
use diagnostics::{Diagnostic, Phase, RegisteredDiagnostic};
use log::{info, warn};
use std::collections::{BTreeSet, HashMap, VecDeque};

#[derive(Debug, Clone)]
pub struct Edge {
    pub source_resource: String,
    pub source_path: String,
    pub target: String,
    pub kind: RefKind,
    pub source_span: SourceSpan,
    pub condition_context: Option<String>,
}

#[derive(Debug)]
pub struct ReferenceGraph {
    pub edges: Vec<Edge>,
    edges_by_source: HashMap<String, Vec<usize>>,
    edges_by_target: HashMap<String, Vec<usize>>,
    cycles: Vec<Vec<String>>,
}

impl ReferenceGraph {
    pub fn build(resolver_edges: Vec<ResolverEdge>, resource_ids: &[String]) -> Self {
        let edges: Vec<Edge> = resolver_edges
            .into_iter()
            .map(|e| Edge {
                source_resource: e.source_resource,
                source_path: e.source_path,
                target: e.target,
                kind: e.kind,
                source_span: e.span,
                condition_context: e.condition_context,
            })
            .collect();

        let mut edges_by_source: HashMap<String, Vec<usize>> = HashMap::new();
        let mut edges_by_target: HashMap<String, Vec<usize>> = HashMap::new();

        for (i, edge) in edges.iter().enumerate() {
            edges_by_source.entry(edge.source_resource.clone()).or_default().push(i);
            edges_by_target.entry(edge.target.clone()).or_default().push(i);
        }

        let resource_set: BTreeSet<&str> = resource_ids.iter().map(|s| s.as_str()).collect();
        let cycles = detect_cycles(&edges, &resource_set);

        if !cycles.is_empty() {
            warn!(
                "{} circular dependencies: {}",
                cycles.len(),
                cycles.iter().map(|c| c.join(" -> ")).collect::<Vec<_>>().join("; ")
            );
        }
        info!(
            "Reference graph: {} resources, {} edges ({} unique sources, {} unique targets), {} cycles",
            resource_ids.len(),
            edges.len(),
            edges_by_source.len(),
            edges_by_target.len(),
            cycles.len()
        );
        ReferenceGraph { edges, edges_by_source, edges_by_target, cycles }
    }

    pub fn outgoing(&self, resource_id: &str) -> Vec<&Edge> {
        self.edges_by_source
            .get(resource_id)
            .map(|indices| indices.iter().map(|&i| &self.edges[i]).collect())
            .unwrap_or_default()
    }

    pub fn incoming(&self, target_id: &str) -> Vec<&Edge> {
        self.edges_by_target
            .get(target_id)
            .map(|indices| indices.iter().map(|&i| &self.edges[i]).collect())
            .unwrap_or_default()
    }

    pub fn depends_on(&self, a: &str, b: &str) -> bool {
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::new();
        // Seed with direct targets of `a`, not `a` itself.
        // This ensures depends_on(A, A) is false unless A→…→A actually exists.
        visited.insert(a);
        if let Some(indices) = self.edges_by_source.get(a) {
            for &i in indices {
                queue.push_back(self.edges[i].target.as_str());
            }
        }
        while let Some(current) = queue.pop_front() {
            if current == b {
                return true;
            }
            if !visited.insert(current) {
                continue;
            }
            if let Some(indices) = self.edges_by_source.get(current) {
                for &i in indices {
                    queue.push_back(self.edges[i].target.as_str());
                }
            }
        }
        false
    }

    pub fn cycles(&self) -> &[Vec<String>] {
        &self.cycles
    }

    pub fn ref_targets(&self, resource_id: &str) -> Vec<&str> {
        self.outgoing(resource_id).iter().map(|e| e.target.as_str()).collect()
    }

    pub fn ref_sources(&self, resource_id: &str) -> Vec<&str> {
        self.incoming(resource_id).iter().map(|e| e.source_resource.as_str()).collect()
    }

    pub fn cycle_diagnostics(&self, span_index: &HashMap<String, SourceSpan>) -> Vec<Diagnostic> {
        let mut out = Vec::new();
        for cycle in &self.cycles {
            for i in 0..cycle.len() {
                let source = &cycle[i];
                let target = &cycle[(i + 1) % cycle.len()];
                let span = span_index.get(&format!("Resources/{}", source)).copied().unwrap_or(UNKNOWN_SPAN);
                out.push(
                    RegisteredDiagnostic::new(
                        "F3004",
                        format!("Circular Dependencies for resource {}. Circular dependency with [{}]", source, target),
                    )
                    .resource(source.clone(), None)
                    .property_path(format!("Resources/{}", source))
                    .location(span)
                    .phase(Phase::Lint)
                    .build(),
                );
            }
        }
        out
    }
}

fn detect_cycles(edges: &[Edge], resource_ids: &BTreeSet<&str>) -> Vec<Vec<String>> {
    let mut adj: HashMap<&str, BTreeSet<&str>> = HashMap::new();
    for edge in edges {
        if resource_ids.contains(edge.source_resource.as_str()) && resource_ids.contains(edge.target.as_str()) {
            adj.entry(edge.source_resource.as_str()).or_default().insert(edge.target.as_str());
        }
    }

    // Kahn's algorithm
    let mut in_degree: HashMap<&str, usize> = HashMap::new();
    for &id in resource_ids {
        in_degree.insert(id, 0);
    }
    for targets in adj.values() {
        for &t in targets {
            *in_degree.entry(t).or_insert(0) += 1;
        }
    }

    let mut queue: VecDeque<&str> = in_degree.iter().filter(|(_, deg)| **deg == 0).map(|(&id, _)| id).collect();

    let mut processed = BTreeSet::new();
    while let Some(node) = queue.pop_front() {
        processed.insert(node);
        if let Some(targets) = adj.get(node) {
            for &t in targets {
                if let Some(deg) = in_degree.get_mut(t) {
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push_back(t);
                    }
                }
            }
        }
    }

    let cycle_nodes: BTreeSet<&str> = resource_ids.iter().filter(|id| !processed.contains(**id)).copied().collect();

    if cycle_nodes.is_empty() {
        return vec![];
    }

    let mut cycles = Vec::new();
    let mut visited_global = BTreeSet::new();

    for &start in &cycle_nodes {
        if visited_global.contains(start) {
            continue;
        }
        let mut path = Vec::new();
        let mut on_stack = BTreeSet::new();
        extract_cycles(start, &adj, &cycle_nodes, &mut path, &mut on_stack, &mut visited_global, &mut cycles);
    }

    // Self-cycles (A→A) may not be caught by DFS if adj deduplicates them
    for edge in edges {
        if edge.source_resource == edge.target && resource_ids.contains(edge.source_resource.as_str()) {
            let self_cycle = vec![edge.source_resource.clone()];
            if !cycles.contains(&self_cycle) {
                cycles.push(self_cycle);
            }
        }
    }

    cycles
}

fn extract_cycles(
    node: &str,
    adj: &HashMap<&str, BTreeSet<&str>>,
    cycle_nodes: &BTreeSet<&str>,
    path: &mut Vec<String>,
    on_stack: &mut BTreeSet<String>,
    visited_global: &mut BTreeSet<String>,
    cycles: &mut Vec<Vec<String>>,
) {
    path.push(node.to_string());
    on_stack.insert(node.to_string());
    visited_global.insert(node.to_string());

    if let Some(targets) = adj.get(node) {
        for &t in targets {
            if !cycle_nodes.contains(t) {
                continue;
            }
            if on_stack.contains(t) {
                if let Some(cycle_start) = path.iter().position(|n| n == t) {
                    let cycle: Vec<String> = path[cycle_start..].to_vec();
                    if !cycles.contains(&cycle) {
                        cycles.push(cycle);
                    }
                }
            } else if !visited_global.contains(t) {
                extract_cycles(t, adj, cycle_nodes, path, on_stack, visited_global, cycles);
            }
        }
    }

    on_stack.remove(node);
    path.pop();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn make_edge(src: &str, tgt: &str) -> ResolverEdge {
        ResolverEdge {
            source_resource: src.into(),
            source_path: String::new(),
            target: tgt.into(),
            kind: RefKind::Ref,
            span: UNKNOWN_SPAN,
            condition_context: None,
        }
    }

    #[test]
    fn graph_ref_edges() {
        let edges = vec![make_edge("A", "B"), make_edge("B", "C")];
        let ids = vec!["A".into(), "B".into(), "C".into()];
        let graph = ReferenceGraph::build(edges, &ids);
        assert_eq!(graph.outgoing("A").len(), 1);
        assert_eq!(graph.outgoing("A")[0].target, "B");
        assert_eq!(graph.incoming("C").len(), 1);
        assert_eq!(graph.incoming("C")[0].source_resource, "B");
    }

    #[test]
    fn graph_no_cycles() {
        let edges = vec![make_edge("A", "B"), make_edge("B", "C")];
        let ids = vec!["A".into(), "B".into(), "C".into()];
        let graph = ReferenceGraph::build(edges, &ids);
        assert!(graph.cycles().is_empty());
    }

    #[test]
    fn graph_cycle_detection_mutual() {
        let edges = vec![make_edge("A", "B"), make_edge("B", "A")];
        let ids = vec!["A".into(), "B".into()];
        let graph = ReferenceGraph::build(edges, &ids);
        assert!(!graph.cycles().is_empty());
    }

    #[test]
    fn graph_transitive_depends_on() {
        let edges = vec![make_edge("A", "B"), make_edge("B", "C")];
        let ids = vec!["A".into(), "B".into(), "C".into()];
        let graph = ReferenceGraph::build(edges, &ids);
        assert!(graph.depends_on("A", "C"));
        assert!(!graph.depends_on("C", "A"));
    }

    #[test]
    fn graph_three_node_cycle() {
        let edges = vec![make_edge("A", "B"), make_edge("B", "C"), make_edge("C", "A")];
        let ids = vec!["A".into(), "B".into(), "C".into()];
        let graph = ReferenceGraph::build(edges, &ids);
        assert_eq!(graph.cycles().len(), 1);
        let cycle = &graph.cycles()[0];
        assert_eq!(cycle.len(), 3);
    }

    #[test]
    fn graph_self_cycle() {
        let edges = vec![make_edge("A", "A")];
        let ids = vec!["A".into()];
        let graph = ReferenceGraph::build(edges, &ids);
        assert_eq!(graph.cycles().len(), 1);
        assert_eq!(graph.cycles()[0], vec!["A".to_string()]);
    }

    #[test]
    fn graph_diamond_no_cycle() {
        let edges = vec![make_edge("A", "B"), make_edge("A", "C"), make_edge("B", "D"), make_edge("C", "D")];
        let ids = vec!["A".into(), "B".into(), "C".into(), "D".into()];
        let graph = ReferenceGraph::build(edges, &ids);
        assert!(graph.cycles().is_empty());
    }

    #[test]
    fn graph_ref_targets_and_sources() {
        let edges = vec![make_edge("A", "B"), make_edge("A", "C"), make_edge("D", "A")];
        let ids = vec!["A".into(), "B".into(), "C".into(), "D".into()];
        let graph = ReferenceGraph::build(edges, &ids);
        let mut targets: Vec<&str> = graph.ref_targets("A");
        targets.sort();
        assert_eq!(targets, vec!["B", "C"]);
        assert_eq!(graph.ref_sources("A"), vec!["D"]);
        assert!(graph.ref_targets("C").is_empty());
        assert!(graph.ref_sources("D").is_empty());
    }

    #[test]
    fn graph_cycle_diagnostics_produce_f3004() {
        let edges = vec![make_edge("A", "B"), make_edge("B", "A")];
        let ids = vec!["A".into(), "B".into()];
        let graph = ReferenceGraph::build(edges, &ids);
        let span_index = HashMap::new();
        let diags = graph.cycle_diagnostics(&span_index);
        assert_eq!(diags.len(), 2, "one diagnostic per resource in cycle");
        assert!(diags.iter().all(|d| d.rule_id == "F3004"));
        assert!(diags[0].message.contains("Circular Dependencies for resource A"));
        assert!(diags[1].message.contains("Circular Dependencies for resource B"));
    }

    #[test]
    fn graph_empty_has_no_cycles() {
        let graph = ReferenceGraph::build(vec![], &["A".into()]);
        assert!(graph.cycles().is_empty());
        assert!(graph.outgoing("A").is_empty());
        assert!(graph.incoming("A").is_empty());
        assert!(graph.ref_targets("A").is_empty());
    }

    #[test]
    fn graph_depends_on_self_without_cycle_is_false() {
        let edges = vec![make_edge("A", "B"), make_edge("B", "C")];
        let ids = vec!["A".into(), "B".into(), "C".into()];
        let graph = ReferenceGraph::build(edges, &ids);
        assert!(!graph.depends_on("A", "A"));
        assert!(!graph.depends_on("B", "B"));
        assert!(!graph.depends_on("C", "C"));
    }

    #[test]
    fn graph_depends_on_self_with_cycle_is_true() {
        let edges = vec![make_edge("A", "B"), make_edge("B", "A")];
        let ids = vec!["A".into(), "B".into()];
        let graph = ReferenceGraph::build(edges, &ids);
        assert!(graph.depends_on("A", "A"));
        assert!(graph.depends_on("B", "B"));
    }

    #[test]
    fn graph_depends_on_self_with_self_edge() {
        let edges = vec![make_edge("A", "A")];
        let ids = vec!["A".into()];
        let graph = ReferenceGraph::build(edges, &ids);
        assert!(graph.depends_on("A", "A"));
    }

    #[test]
    fn graph_overlapping_cycles_no_duplicates() {
        let edges = vec![make_edge("A", "B"), make_edge("B", "A"), make_edge("B", "C"), make_edge("C", "A")];
        let ids = vec!["A".into(), "B".into(), "C".into()];
        let graph = ReferenceGraph::build(edges, &ids);
        assert!(graph.cycles().len() >= 2);
        let mut seen = HashSet::new();
        for cycle in graph.cycles() {
            assert!(seen.insert(cycle.clone()), "duplicate cycle: {:?}", cycle);
        }
    }
}
