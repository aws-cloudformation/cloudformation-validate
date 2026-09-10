use crate::defect::{DefectPhase, ParseDefect};
use crate::ir::*;
use crate::resolver::{RefKind, ResolverEdge};
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
    resource_order: Vec<String>,
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
        ReferenceGraph { edges, edges_by_source, edges_by_target, cycles, resource_order: resource_ids.to_vec() }
    }

    pub fn outgoing(&self, resource_id: &str) -> Vec<&Edge> {
        self.edges_by_source
            .get(resource_id)
            .map(|indices| indices.iter().map(|&i| &self.edges[i]).collect())
            .unwrap_or_default()
    }

    /// Borrowing iterator over the same edges as `outgoing`, in the same order,
    /// without collecting them into a `Vec`. Hot callers that only scan the
    /// outgoing edges use this to avoid the per-call allocation.
    pub fn outgoing_edges(&self, resource_id: &str) -> impl Iterator<Item = &Edge> {
        self.edges_by_source.get(resource_id).into_iter().flatten().map(move |&index| &self.edges[index])
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
        self.outgoing_edges(resource_id).map(|e| e.target.as_str()).collect()
    }

    pub fn ref_sources(&self, resource_id: &str) -> Vec<&str> {
        self.incoming(resource_id).iter().map(|e| e.source_resource.as_str()).collect()
    }

    /// Produces one circular-dependency diagnostic per distinct edge that closes a
    /// cycle: explores from every resource in declaration order, takes the
    /// first back-edge that closes a loop, and reports each such edge once.
    /// This anchors a finding on the resource whose dependency introduces the loop (the edge tail) rather
    /// than flagging every member of the strongly connected component, which would
    /// over-report a large tangled component as dozens of findings for a single
    /// underlying problem.
    pub fn cycle_diagnostics(&self, span_index: &HashMap<String, SourceSpan>) -> Vec<ParseDefect> {
        let adjacency = self.cycle_adjacency();
        let mut reported_edges: Vec<(&str, &str)> = Vec::new();
        for start in &self.resource_order {
            let Some(cycle) = first_cycle_from(start.as_str(), &adjacency) else {
                continue;
            };
            for window in cycle.windows(2) {
                let edge = (window[0], window[1]);
                if !reported_edges.contains(&edge) {
                    reported_edges.push(edge);
                }
            }
        }

        reported_edges
            .into_iter()
            .map(|(source, target)| {
                let path = render_cycle(source, target, &adjacency);
                let span = span_index.get(&format!("Resources/{}", source)).copied().unwrap_or(UNKNOWN_SPAN);
                ParseDefect::new(
                    "F3004",
                    format!("Circular Dependencies for resource {source}. Circular dependency with [{path}]"),
                )
                .resource(source.to_string())
                .property_path(format!("Resources/{}", source))
                .location(span)
                .phase(DefectPhase::Lint)
            })
            .collect()
    }

    /// Builds the resource-to-resource adjacency used for cycle reporting. Each
    /// source's neighbours are ordered by reference kind - DependsOn, then Ref,
    /// then GetAtt, then Sub - and within a kind by the order the edges were
    /// discovered, with duplicates removed.
    fn cycle_adjacency(&self) -> HashMap<&str, Vec<&str>> {
        let resource_set: BTreeSet<&str> = self.resource_order.iter().map(|s| s.as_str()).collect();
        let mut adjacency: HashMap<&str, Vec<&str>> = HashMap::new();
        for kind_rank in 0..=3 {
            for edge in &self.edges {
                if kind_of(&edge.kind) != kind_rank {
                    continue;
                }
                let (source, target) = (edge.source_resource.as_str(), edge.target.as_str());
                if !resource_set.contains(source) || !resource_set.contains(target) {
                    continue;
                }
                let neighbours = adjacency.entry(source).or_default();
                if !neighbours.contains(&target) {
                    neighbours.push(target);
                }
            }
        }
        adjacency
    }
}

/// Ranks a reference kind so cycle reporting visits neighbours in a fixed order.
fn kind_of(kind: &RefKind) -> u8 {
    match kind {
        RefKind::DependsOn => 0,
        RefKind::Ref => 1,
        RefKind::GetAtt { .. } => 2,
        RefKind::Sub { .. } => 3,
    }
}

/// Depth-first search from `start` that returns the first loop it closes as a
/// node path ending where it began (e.g. `[A, B, C, A]`), or `None` if no cycle
/// is reachable. Neighbours are visited in `adjacency` order. A node is marked
/// explored once fully expanded so later starts skip work already proven acyclic
fn first_cycle_from<'a>(start: &'a str, adjacency: &HashMap<&'a str, Vec<&'a str>>) -> Option<Vec<&'a str>> {
    let mut explored: BTreeSet<&str> = BTreeSet::new();
    let mut path: Vec<&str> = Vec::new();
    let mut on_path: BTreeSet<&str> = BTreeSet::new();
    if dfs_first_cycle(start, adjacency, &mut explored, &mut path, &mut on_path) { Some(path) } else { None }
}

fn dfs_first_cycle<'a>(
    node: &'a str,
    adjacency: &HashMap<&'a str, Vec<&'a str>>,
    explored: &mut BTreeSet<&'a str>,
    path: &mut Vec<&'a str>,
    on_path: &mut BTreeSet<&'a str>,
) -> bool {
    path.push(node);
    on_path.insert(node);
    if let Some(neighbours) = adjacency.get(node) {
        for &next in neighbours {
            if explored.contains(next) {
                continue;
            }
            if on_path.contains(next) {
                if let Some(start_index) = path.iter().position(|&n| n == next) {
                    let mut cycle: Vec<&str> = path[start_index..].to_vec();
                    cycle.push(next);
                    *path = cycle;
                }
                return true;
            }
            if dfs_first_cycle(next, adjacency, explored, path, on_path) {
                return true;
            }
        }
    }
    on_path.remove(node);
    explored.insert(node);
    path.pop();
    false
}

/// Traces the loop closed by the edge `source -> target` back to `source`, so the
/// message spells out `source -> target -> … -> source` rather than a single
/// hop. Every reported edge closes a cycle, so a route from `target` back to
/// `source` exists; if it somehow cannot be reconstructed the message falls back
/// to naming just the closing edge.
fn render_cycle(source: &str, target: &str, adjacency: &HashMap<&str, Vec<&str>>) -> String {
    let mut nodes = vec![source];
    match path_between(target, source, adjacency) {
        Some(return_path) => nodes.extend(return_path),
        None => {
            nodes.push(target);
            nodes.push(source);
        }
    }
    nodes.join(" -> ")
}

/// Finds a path from `from` to `to` following `adjacency`, returned as the node
/// sequence including both endpoints, or `None` if `to` is unreachable.
fn path_between<'a>(from: &'a str, to: &'a str, adjacency: &HashMap<&'a str, Vec<&'a str>>) -> Option<Vec<&'a str>> {
    let mut visited: BTreeSet<&str> = BTreeSet::new();
    let mut path: Vec<&str> = Vec::new();
    fn walk<'a>(
        node: &'a str,
        to: &'a str,
        adjacency: &HashMap<&'a str, Vec<&'a str>>,
        visited: &mut BTreeSet<&'a str>,
        path: &mut Vec<&'a str>,
    ) -> bool {
        path.push(node);
        visited.insert(node);
        if node == to {
            return true;
        }
        if let Some(neighbours) = adjacency.get(node) {
            for &next in neighbours {
                if !visited.contains(next) && walk(next, to, adjacency, visited, path) {
                    return true;
                }
            }
        }
        path.pop();
        false
    }
    if walk(from, to, adjacency, &mut visited, &mut path) { Some(path) } else { None }
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

    fn make_kind_edge(src: &str, tgt: &str, kind: RefKind) -> ResolverEdge {
        ResolverEdge {
            source_resource: src.into(),
            source_path: String::new(),
            target: tgt.into(),
            kind,
            span: UNKNOWN_SPAN,
            condition_context: None,
        }
    }

    /// Collects each diagnostic's resource id together with the loop rendered in
    /// its message, so a test can assert both which resource a finding is anchored
    /// on and the path it traces.
    fn diagnostic_resources_and_paths(diags: &[ParseDefect]) -> Vec<(String, String)> {
        diags
            .iter()
            .map(|d| {
                let resource = d.resource_logical_id().map(String::from).unwrap_or_default();
                let path = d
                    .message
                    .split_once('[')
                    .and_then(|(_, rest)| rest.split_once(']'))
                    .map(|(inner, _)| inner.to_string())
                    .unwrap_or_default();
                (resource, path)
            })
            .collect()
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
        // Each diagnostic spells out the full loop starting and ending at its own
        // resource, so the reader can trace every edge rather than guessing from a
        // single next-hop.
        let by_resource = |id: &str| {
            diags
                .iter()
                .find(|d| d.resource_logical_id() == Some(id))
                .unwrap_or_else(|| panic!("expected an F3004 for {id}"))
        };
        assert!(by_resource("A").message.contains("Circular Dependencies for resource A"));
        assert!(by_resource("A").message.contains("[A -> B -> A]"), "got: {}", by_resource("A").message);
        assert!(by_resource("B").message.contains("[B -> A -> B]"), "got: {}", by_resource("B").message);
    }

    #[test]
    fn graph_cycle_diagnostics_render_full_three_node_path() {
        // The exact shape from issue #53: a three-node loop where naming only the
        // next hop reads like a two-node cycle. Every member's message must trace
        // the whole loop back to itself.
        let edges = vec![make_edge("A", "B"), make_edge("B", "C"), make_edge("C", "A")];
        let ids = vec!["A".into(), "B".into(), "C".into()];
        let graph = ReferenceGraph::build(edges, &ids);
        let diags = graph.cycle_diagnostics(&HashMap::new());
        assert_eq!(diags.len(), 3);
        for (id, expected) in [("A", "[A -> B -> C -> A]"), ("B", "[B -> C -> A -> B]"), ("C", "[C -> A -> B -> C]")] {
            let d = diags
                .iter()
                .find(|d| d.resource_logical_id() == Some(id))
                .unwrap_or_else(|| panic!("expected an F3004 for {id}"));
            assert!(d.message.contains(expected), "{id}: got {}", d.message);
        }
    }

    #[test]
    fn graph_cycle_diagnostics_render_self_cycle() {
        let edges = vec![make_edge("A", "A")];
        let ids = vec!["A".into()];
        let graph = ReferenceGraph::build(edges, &ids);
        let diags = graph.cycle_diagnostics(&HashMap::new());
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("[A -> A]"), "got: {}", diags[0].message);
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

    /// A resource that only points *into* a cycle but is not itself on one is not
    /// flagged: the diagnostic is anchored on the edges that close the loop, not on
    /// every resource reachable from or into it. Here `X -> A` feeds the `A <-> B`
    /// cycle, so only A and B are reported.
    #[test]
    fn graph_cycle_diagnostics_skip_nodes_feeding_into_a_cycle() {
        let edges = vec![make_edge("X", "A"), make_edge("A", "B"), make_edge("B", "A")];
        let ids = vec!["X".into(), "A".into(), "B".into()];
        let graph = ReferenceGraph::build(edges, &ids);
        let diags = graph.cycle_diagnostics(&HashMap::new());
        let mut resources: Vec<String> =
            diags.iter().filter_map(|d| d.resource_logical_id().map(String::from)).collect();
        resources.sort();
        assert_eq!(resources, vec!["A".to_string(), "B".to_string()], "X only feeds the cycle and must not be flagged");
    }

    /// A cycle reachable only through a chain of one-way references is still found:
    /// the walk explores every resource in declaration order, so `A -> B -> C -> B`
    /// surfaces the `B <-> C` loop even though A is acyclic.
    #[test]
    fn graph_cycle_diagnostics_find_cycle_reachable_through_acyclic_prefix() {
        let edges = vec![make_edge("A", "B"), make_edge("B", "C"), make_edge("C", "B")];
        let ids = vec!["A".into(), "B".into(), "C".into()];
        let graph = ReferenceGraph::build(edges, &ids);
        let found = diagnostic_resources_and_paths(&graph.cycle_diagnostics(&HashMap::new()));
        assert_eq!(
            found,
            vec![("B".to_string(), "B -> C -> B".to_string()), ("C".to_string(), "C -> B -> C".to_string())]
        );
    }

    /// A single large strongly connected component is reported as one finding per
    /// edge that closes a loop, not one per member. The old behaviour enumerated
    /// every node of every simple cycle in the component, exploding a tangled
    /// component into many findings for a single underlying problem. Here A, B and
    /// C are mutually reachable, but the first loop found from A is the two-node
    /// `A <-> B` cycle, so exactly its two edges are reported and C - reachable but
    /// not on that first loop - is not.
    #[test]
    fn graph_cycle_diagnostics_report_edges_not_scc_members() {
        let edges = vec![make_edge("A", "B"), make_edge("B", "A"), make_edge("B", "C"), make_edge("C", "A")];
        let ids = vec!["A".into(), "B".into(), "C".into()];
        let graph = ReferenceGraph::build(edges, &ids);
        let found = diagnostic_resources_and_paths(&graph.cycle_diagnostics(&HashMap::new()));
        assert_eq!(
            found,
            vec![("A".to_string(), "A -> B -> A".to_string()), ("B".to_string(), "B -> A -> B".to_string())],
            "a tangled component must not report every member"
        );
    }

    /// Neighbours are visited by reference kind - DependsOn, then Ref, then GetAtt,
    /// then Sub - before insertion order, because a depth-first walk returns the
    /// first back-edge it closes and that ordering decides which loop through a
    /// resource surfaces. Resource A closes a loop through both a Ref (to B) and a
    /// DependsOn (to C); the DependsOn neighbour is explored first, so the reported
    /// loop runs through C.
    #[test]
    fn graph_cycle_diagnostics_visit_neighbours_by_reference_kind() {
        let edges = vec![
            make_kind_edge("A", "B", RefKind::Ref),
            make_kind_edge("A", "C", RefKind::DependsOn),
            make_kind_edge("B", "A", RefKind::Ref),
            make_kind_edge("C", "A", RefKind::Ref),
        ];
        let ids = vec!["A".into(), "B".into(), "C".into()];
        let graph = ReferenceGraph::build(edges, &ids);
        let found = diagnostic_resources_and_paths(&graph.cycle_diagnostics(&HashMap::new()));
        assert_eq!(
            found,
            vec![("A".to_string(), "A -> C -> A".to_string()), ("C".to_string(), "C -> A -> C".to_string())],
            "the DependsOn edge is followed before the Ref edge"
        );
    }

    /// Parallel edges between the same pair of resources (for example a Ref and a
    /// DependsOn that both point A -> B) collapse to a single neighbour, so the
    /// closing edge is reported once rather than once per underlying reference.
    #[test]
    fn graph_cycle_diagnostics_deduplicate_parallel_edges() {
        let edges = vec![
            make_kind_edge("A", "B", RefKind::Ref),
            make_kind_edge("A", "B", RefKind::DependsOn),
            make_kind_edge("B", "A", RefKind::Ref),
        ];
        let ids = vec!["A".into(), "B".into()];
        let graph = ReferenceGraph::build(edges, &ids);
        let diags = graph.cycle_diagnostics(&HashMap::new());
        assert_eq!(diags.len(), 2, "the A->B edge is reported once despite two parallel references");
    }

    /// The reported set does not depend on the order edges were discovered: two
    /// builds of the same graph with edges supplied in different orders produce the
    /// same findings, because neighbours are ordered by reference kind and the walk
    /// starts from resources in declaration order.
    #[test]
    fn graph_cycle_diagnostics_are_order_independent() {
        let ids = vec!["A".into(), "B".into(), "C".into()];
        let forward =
            ReferenceGraph::build(vec![make_edge("A", "B"), make_edge("B", "C"), make_edge("C", "A")], &ids.clone());
        let shuffled = ReferenceGraph::build(vec![make_edge("C", "A"), make_edge("A", "B"), make_edge("B", "C")], &ids);
        assert_eq!(
            diagnostic_resources_and_paths(&forward.cycle_diagnostics(&HashMap::new())),
            diagnostic_resources_and_paths(&shuffled.cycle_diagnostics(&HashMap::new())),
        );
    }

    /// Two independent cycles each report their own edges, and only their members
    /// are flagged. `A <-> B` and `C <-> D` are disjoint, so all four resources are
    /// reported, each tracing its own two-node loop.
    #[test]
    fn graph_cycle_diagnostics_two_disjoint_cycles() {
        let edges = vec![make_edge("A", "B"), make_edge("B", "A"), make_edge("C", "D"), make_edge("D", "C")];
        let ids = vec!["A".into(), "B".into(), "C".into(), "D".into()];
        let graph = ReferenceGraph::build(edges, &ids);
        let mut found = diagnostic_resources_and_paths(&graph.cycle_diagnostics(&HashMap::new()));
        found.sort();
        assert_eq!(
            found,
            vec![
                ("A".to_string(), "A -> B -> A".to_string()),
                ("B".to_string(), "B -> A -> B".to_string()),
                ("C".to_string(), "C -> D -> C".to_string()),
                ("D".to_string(), "D -> C -> D".to_string()),
            ]
        );
    }

    /// Edges that touch a resource not declared in the template (for example a
    /// dangling `DependsOn`) are ignored, so a dangling reference never fabricates
    /// a cycle.
    #[test]
    fn graph_cycle_diagnostics_ignore_edges_to_unknown_resources() {
        let edges = vec![make_edge("A", "Ghost"), make_edge("Ghost", "A")];
        let ids = vec!["A".into()];
        let graph = ReferenceGraph::build(edges, &ids);
        assert!(graph.cycle_diagnostics(&HashMap::new()).is_empty());
    }

    /// A diagnostic carries the source span of the resource it is anchored on, so
    /// the finding points at the offending resource in the template.
    #[test]
    fn graph_cycle_diagnostics_carry_resource_span() {
        let edges = vec![make_edge("A", "B"), make_edge("B", "A")];
        let ids = vec!["A".into(), "B".into()];
        let graph = ReferenceGraph::build(edges, &ids);
        let span = SourceSpan { start_line: 42, start_column: 3, end_line: 42, end_column: 20 };
        let mut span_index = HashMap::new();
        span_index.insert("Resources/A".to_string(), span);
        let diags = graph.cycle_diagnostics(&span_index);
        let a = diags.iter().find(|d| d.resource_logical_id() == Some("A")).expect("F3004 for A");
        assert_eq!(a.span.start_line, 42);
        assert_eq!(a.property_path.as_deref(), Some("Resources/A"));
    }
}
