"""Two-layer constraint baseline. Reads observations and declared priors, never oracle.

Layer 1 keeps every edge supported by a feasible one-to-one call matching.
Layer 2 builds a union of possible equal-value response propagation paths.
The union represents alternatives, not one simultaneously established causal graph.
"""
import argparse
from collections import defaultdict, deque
import json
import math
from pathlib import Path

from common import append_json, node, read_jsonl

DEFAULT_PROFILE = Path(__file__).with_name("constraint_profile.json")


def perfect_matching(adjacency, parents, forced=None):
    """Return a witness or None; deterministic augmenting paths, no score tie-break."""
    if len(adjacency) != len(parents):
        return None
    match = {} if forced is None else {forced[1]: forced[0]}

    def augment(child, seen):
        for parent in sorted(adjacency[child]):
            if parent in seen or (forced is not None and parent == forced[1]):
                continue
            seen.add(parent)
            if parent not in match or augment(match[parent], seen):
                match[parent] = child
                return True
        return False

    for child in sorted(adjacency, key=lambda c: (len(adjacency[c]), c)):
        if forced is not None and child == forced[0]:
            continue
        if not augment(child, set()):
            return None
    return match


def components(adjacency, parent_ids):
    """Connected components of the temporal bipartite graph, including isolates."""
    reverse = defaultdict(set)
    for child, parents in adjacency.items():
        for parent in parents:
            reverse[parent].add(child)
    seen = set()
    starts = [("c", c) for c in sorted(adjacency)] + [("p", p) for p in sorted(parent_ids)]
    for start in starts:
        if start in seen:
            continue
        queue, children, parents = deque([start]), set(), set()
        seen.add(start)
        while queue:
            kind, key = queue.popleft()
            if kind == "c":
                children.add(key)
                neighbors = [("p", p) for p in adjacency[key]]
            else:
                parents.add(key)
                neighbors = [("c", c) for c in reverse[key]]
            for neighbor in neighbors:
                if neighbor not in seen:
                    seen.add(neighbor)
                    queue.append(neighbor)
        yield children, parents


def supported_edges(temporal, semantic, parent_ids, capacity=True,
                    max_component=128, max_edges=4096):
    """On unsatisfied/oversized components retain temporal edges and diagnose.

    Feasibility cannot detect every violated prior (e.g. balanced missing events).
    It is a guard against forced solutions, not a completeness guarantee.
    """
    output = {c: set() for c in temporal}
    diagnostics = []
    for children, parents in components(temporal, parent_ids):
        reduced = {c: set(semantic[c]) for c in children}
        reason = None
        if capacity:
            if len(children) != len(parents):
                reason = "unbalanced_counts"
            elif len(children) > max_component or sum(map(len, reduced.values())) > max_edges:
                reason = "component_limit"
            elif perfect_matching(reduced, parents) is None:
                reason = "no_perfect_matching"
            else:
                reduced = {c: {p for p in opts if perfect_matching(reduced, parents, (c, p)) is not None}
                           for c, opts in reduced.items()}
        if reason:
            reduced = {c: set(temporal[c]) for c in children}
        for child, candidates in reduced.items():
            output[child] = candidates
        diagnostics.append({
            "children": sorted(children), "parents": sorted(parents),
            "temporal_edges": sum(len(temporal[c]) for c in children),
            "retained_edges": sum(map(len, reduced.values())),
            "status": "fallback" if reason else ("matched" if capacity else "capacity_disabled"),
            "reason": reason,
        })
    return output, diagnostics


def predict(events, queries, profile, tolerance_ms=5, semantics=True, capacity=True,
            max_component=128, max_edges=4096):
    if not math.isfinite(tolerance_ms) or tolerance_ms < 0:
        raise ValueError("tolerance_ms must be finite and nonnegative")
    if not 1 <= max_component <= 256 or max_edges < 1:
        raise ValueError("max_component must be 1..256 and max_edges positive")
    by_id = {e["event_id"]: e for e in events}
    if len(by_id) != len(events):
        raise ValueError("duplicate observation ID")
    if len({q["query_id"] for q in queries}) != len(queries):
        raise ValueError("duplicate query ID")
    field = profile["field"]
    if any(q["sink"]["field"] != field or q["sink"]["location"] != "response" for q in queries):
        raise ValueError("queries must select the profile's response field")
    tolerance = int(tolerance_ms * 1_000_000)
    graph, call_edges, rule_diagnostics = defaultdict(set), [], []
    for rule in profile["rules"]:
        a, b = rule["parent_service"], rule["child_service"]
        parents = [e for e in events if e["callee"] == a and
                   e["operation"].startswith(rule.get("parent_operation_prefix", ""))]
        children = [e for e in events if e["caller"] == a and e["callee"] == b]
        temporal, semantic = {}, {}
        missing_fields = 0
        for child in children:
            cid = child["event_id"]
            temporal[cid], semantic[cid] = set(), set()
            for parent in parents:
                pid = parent["event_id"]
                if pid == cid or child["start_ns"] < parent["start_ns"] - tolerance or child["end_ns"] > parent["end_ns"] + tolerance:
                    continue
                temporal[cid].add(pid)
                fields = rule["preserve_fields"] if semantics else []
                missing_fields += int(any(f not in child["request"] or f not in parent["request"] for f in fields))
                # Missing fields are unknown, not proof of a mismatch.
                if all(f not in child["request"] or f not in parent["request"] or
                       child["request"][f] == parent["request"][f] for f in fields):
                    semantic[cid].add(pid)
        supported, diagnostics = supported_edges(
            temporal, semantic, {e["event_id"] for e in parents}, capacity, max_component, max_edges)
        for child, candidates in supported.items():
            for parent in sorted(candidates):
                graph[parent].add(child)
                call_edges.append({"parent": parent, "child": child, "service_edge": [a, b]})
        rule_diagnostics.append({"service_edge": [a, b], "missing_parameter_pairs": missing_fields,
                                 "components": diagnostics})
    predictions = []
    for query in queries:
        visited, sources, edges = set(), set(), set()
        def walk(pid):
            if pid in visited or pid not in by_id:
                return
            visited.add(pid)
            event = by_id[pid]
            if field not in event["response"] or event["response"][field] != query["value"]:
                return
            if event["callee"] in profile["source_services"]:
                sources.add(pid)
                return
            for cid in sorted(graph[pid]):
                if field in by_id[cid]["response"] and by_id[cid]["response"][field] == query["value"]:
                    edges.add((cid, pid))
                    walk(cid)
        walk(query["sink"]["event_id"])
        predictions.append({
            "query_id": query["query_id"], "sink": query["sink"],
            "status": "unknown" if not sources else ("unique" if len(sources) == 1 else "ambiguous"),
            "candidate_sources": [node(s, field) for s in sorted(sources)],
            "edges": [{"from": node(c, field), "to": node(p, field),
                       "evidence": ["candidate_call", "equal_response_value"]} for c, p in sorted(edges)],
        })
    diagnostics = {
        "profile": profile, "tolerance_ms": tolerance_ms, "semantics": semantics,
        "capacity": capacity, "max_component": max_component, "max_edges": max_edges,
        "fallback_components": sum(c["status"] == "fallback" for r in rule_diagnostics for c in r["components"]),
        "rules": rule_diagnostics, "call_candidates": call_edges,
    }
    return predictions, diagnostics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observations", type=Path, required=True)
    parser.add_argument("--queries", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--diagnostics", type=Path, required=True)
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--tolerance-ms", type=float, default=5)
    parser.add_argument("--disable-semantics", action="store_true")
    parser.add_argument("--disable-capacity", action="store_true")
    parser.add_argument("--max-component", type=int, default=128)
    parser.add_argument("--max-edges", type=int, default=4096)
    args = parser.parse_args()
    if args.output.exists() or args.diagnostics.exists() or args.output.resolve() == args.diagnostics.resolve():
        parser.error("prediction and diagnostics paths must be distinct, new files")
    predictions, diagnostics = predict(
        read_jsonl(args.observations), read_jsonl(args.queries), json.loads(args.profile.read_text()),
        args.tolerance_ms, not args.disable_semantics, not args.disable_capacity,
        args.max_component, args.max_edges)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.touch(exist_ok=False)
    for prediction in predictions:
        append_json(args.output, prediction)
    args.diagnostics.parent.mkdir(parents=True, exist_ok=True)
    args.diagnostics.write_text(json.dumps(diagnostics, indent=2) + "\n")


if __name__ == "__main__":
    main()
