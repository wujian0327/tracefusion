"""Value/time candidate baseline, not the TraceFusion reconstruction algorithm.

This module reads ONLY observations and sink queries. It preserves ambiguity.
"""
import argparse
import json
from pathlib import Path
from common import append_json, node, read_jsonl


def predict(events, queries, tolerance_ms=5):
    by_id = {event["event_id"]: event for event in events}
    by_caller = {}
    for event in events:
        by_caller.setdefault(event["caller"], []).append(event)
    tolerance = int(tolerance_ms * 1_000_000)
    results = []
    for query in queries:
        sink_id = query["sink"]["event_id"]
        value = query["value"]
        edges, sources, visited = {}, {}, set()

        def visit(parent_id):
            if parent_id in visited:
                return
            visited.add(parent_id)
            parent = by_id.get(parent_id)
            if parent is None:
                return
            if parent["response"].get("phone") != value:
                return
            if parent["callee"] == "store":
                sources[parent_id] = node(parent_id)
                return
            for child in by_caller.get(parent["callee"], []):
                if child["response"].get("phone") != value:
                    continue
                if (child["start_ns"] < parent["start_ns"] - tolerance
                        or child["end_ns"] > parent["end_ns"] + tolerance):
                    continue
                child_id = child["event_id"]
                if child_id == parent_id:
                    continue
                edges[(child_id, parent_id)] = {
                    "from": node(child_id), "to": node(parent_id),
                    "evidence": ["equal_response_value", "caller_callee", "temporal_containment"],
                }
                visit(child_id)

        visit(sink_id)
        results.append({
            "query_id": query["query_id"], "sink": query["sink"],
            "status": "unknown" if not sources else ("unique" if len(sources) == 1 else "ambiguous"),
            "candidate_sources": [sources[key] for key in sorted(sources)],
            "edges": [edges[key] for key in sorted(edges)],
        })
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--observations", type=Path, required=True)
    parser.add_argument("--queries", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--tolerance-ms", type=float, default=5)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists")
    for result in predict(read_jsonl(args.observations), read_jsonl(args.queries), args.tolerance_ms):
        append_json(args.output, result)


if __name__ == "__main__":
    main()
