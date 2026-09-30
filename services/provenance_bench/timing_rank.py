"""Observation-only timing prioritization; never removes a provenance candidate.

An edge's regret is the extra minimum matching cost when that edge is forced.
Source priority is the least sum of edge regrets along a candidate path. This is
an uncalibrated heuristic, not probability, causal proof, or a unique assignment.
"""
import argparse
from collections import defaultdict
import copy
import json
import math
from pathlib import Path

from common import append_json, read_jsonl


def minimum_cost(matrix):
    """Square Hungarian assignment, including forbidden (infinite-cost) edges."""
    n = len(matrix)
    if any(len(row) != n for row in matrix):
        raise ValueError("assignment matrix must be square")
    if any(math.isnan(x) or x < 0 for row in matrix for x in row):
        raise ValueError("costs must be nonnegative and not NaN")
    u, v, p, way = [0.0]*(n+1), [0.0]*(n+1), [0]*(n+1), [0]*(n+1)
    for i in range(1, n+1):
        p[0], j0 = i, 0
        mins, used = [math.inf]*(n+1), [False]*(n+1)
        while True:
            used[j0] = True
            i0, delta, j1 = p[j0], math.inf, 0
            for j in range(1, n+1):
                if used[j]:
                    continue
                cur = matrix[i0-1][j-1] - u[i0] - v[j]
                if cur < mins[j]:
                    mins[j], way[j] = cur, j0
                if mins[j] < delta:
                    delta, j1 = mins[j], j
            if not math.isfinite(delta):
                return math.inf
            for j in range(n+1):
                if used[j]:
                    u[p[j]] += delta
                    v[j] -= delta
                else:
                    mins[j] -= delta
            j0 = j1
            if p[j0] == 0:
                break
        while j0:
            previous = way[j0]
            p[j0] = p[previous]
            j0 = previous
    return sum(matrix[p[j]-1][j-1] for j in range(1, n+1))


def edge_regrets(events, diagnostics, mode, scale_ms, max_component):
    if mode not in {"all_return", "single_child_return"}:
        raise ValueError("unknown timing mode")
    if not math.isfinite(scale_ms) or scale_ms <= 0 or not 1 <= max_component <= 32:
        raise ValueError("scale must be positive finite; component limit must be 1..32")
    by = {e["event_id"]: e for e in events}
    if len(by) != len(events):
        raise ValueError("duplicate event ID")
    calls = {(e["parent"], e["child"]) for e in diagnostics["call_candidates"]}
    if any(p not in by or c not in by for p, c in calls):
        raise ValueError("diagnostics and observations do not match")
    rules = diagnostics["profile"]["rules"]
    def outgoing_count(event):
        return sum(event["callee"] == r["parent_service"] and
                   event["operation"].startswith(r.get("parent_operation_prefix", "")) for r in rules)
    regrets = {edge: 0.0 for edge in calls}
    notes = []
    for rule in diagnostics["rules"]:
        for component in rule["components"]:
            parents, children = sorted(component["parents"]), sorted(component["children"])
            pairs = [(p, c) for p in parents for c in children if (p, c) in calls]
            reason = None
            if component["status"] != "matched":
                reason = "constraint_component_not_matched"
            elif len(parents) != len(children):
                reason = "unbalanced_counts"
            elif len(parents) > max_component:
                reason = "ranking_component_limit"
            elif any(p not in by for p in parents) or any(c not in by for c in children):
                raise ValueError("component references missing events")
            matrix = None
            if reason is None:
                matrix = []
                for parent in parents:
                    row = []
                    for child in children:
                        if (parent, child) not in calls:
                            row.append(math.inf)
                        elif mode == "single_child_return" and outgoing_count(by[parent]) != 1:
                            row.append(0.0)
                        else:
                            gap = (by[parent]["end_ns"] - by[child]["end_ns"]) / 1_000_000
                            row.append((gap / scale_ms)**2)
                    matrix.append(row)
                optimum = minimum_cost(matrix)
                if not math.isfinite(optimum):
                    reason = "no_finite_assignment"
            if reason is None:
                updates = {}
                for i, parent in enumerate(parents):
                    for j, child in enumerate(children):
                        if (parent, child) not in calls:
                            continue
                        smaller = [[x for col, x in enumerate(row) if col != j]
                                   for idx, row in enumerate(matrix) if idx != i]
                        forced = matrix[i][j] + minimum_cost(smaller)
                        if not math.isfinite(forced):
                            reason = "edge_has_no_finite_assignment"
                            break
                        gap = max(0.0, forced - optimum)
                        updates[parent, child] = 0.0 if gap <= 1e-8*max(1.0, abs(optimum)) else gap
                    if reason:
                        break
                if reason is None:
                    regrets.update(updates)
            notes.append({"service_edge": rule["service_edge"], "parent_count": len(parents),
                          "child_count": len(children), "edge_count": len(pairs),
                          "status": "unranked" if reason else "ranked", "reason": reason})
    return regrets, notes


def annotate(events, predictions, diagnostics, mode="single_child_return", scale_ms=5, max_component=24):
    regrets, notes = edge_regrets(events, diagnostics, mode, scale_ms, max_component)
    annotated = copy.deepcopy(predictions)
    for prediction in annotated:
        sources = {n["event_id"] for n in prediction["candidate_sources"]}
        adjacency = defaultdict(list)
        for edge in prediction["edges"]:
            parent, child = edge["to"]["event_id"], edge["from"]["event_id"]
            if (parent, child) not in regrets:
                raise ValueError("propagation edge is absent from call candidates")
            adjacency[parent].append(child)
        memo, active = {}, set()
        def paths(parent):
            if parent in active:
                raise ValueError("ranking requires an acyclic candidate graph")
            if parent in memo:
                return memo[parent]
            active.add(parent)
            found = {parent: 0.0} if parent in sources else {}
            for child in adjacency[parent]:
                for source, cost in paths(child).items():
                    score = cost + regrets[parent, child]
                    found[source] = min(found.get(source, math.inf), score)
            active.remove(parent)
            memo[parent] = found
            return found
        scores = paths(prediction["sink"]["event_id"])
        if set(scores) != sources:
            raise ValueError("candidate sources must be reachable from the sink")
        best = min(scores.values(), default=0.0)
        epsilon = 1e-8 * max(1.0, abs(best))
        ordered = sorted(prediction["candidate_sources"], key=lambda n: (scores[n["event_id"]], n["event_id"]))
        prediction["timing_ranking"] = {
            "mode": mode, "is_probability": False,
            "score_definition": "minimum sum of forced-edge matching regrets along a candidate path; lower is preferred",
            "sources": [{"node": n, "score": scores[n["event_id"]],
                         "top_tier": scores[n["event_id"]] <= best + epsilon} for n in ordered],
        }
        # Preserve status, all candidate_sources, and every propagation edge exactly.
    return annotated, {"mode": mode, "scale_ms": scale_ms, "max_component": max_component,
                       "unranked_components": sum(n["status"] == "unranked" for n in notes),
                       "components": notes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observations", type=Path, required=True)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--call-diagnostics", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--diagnostics", type=Path, required=True)
    parser.add_argument("--mode", choices=("all_return", "single_child_return"), default="single_child_return")
    parser.add_argument("--scale-ms", type=float, default=5)
    parser.add_argument("--max-component", type=int, default=24)
    args = parser.parse_args()
    if args.output.exists() or args.diagnostics.exists() or args.output.resolve() == args.diagnostics.resolve():
        parser.error("outputs must be distinct new files")
    predictions, diagnostics = annotate(read_jsonl(args.observations), read_jsonl(args.predictions),
        json.loads(args.call_diagnostics.read_text()), args.mode, args.scale_ms, args.max_component)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.touch(exist_ok=False)
    for row in predictions:
        append_json(args.output, row)
    args.diagnostics.parent.mkdir(parents=True, exist_ok=True)
    args.diagnostics.write_text(json.dumps(diagnostics, indent=2) + "\n")


if __name__ == "__main__":
    main()
