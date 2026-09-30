"""Independent field-level evaluator. This is the only inference-stage oracle reader."""
import argparse
import json
from pathlib import Path
from common import node_key, read_jsonl


def edge_key(edge):
    return (node_key(edge["from"]), node_key(edge["to"]))


def evaluate(queries, predictions, oracle_records, group=True):
    by_query = {}
    for prediction in predictions:
        key = prediction["query_id"]
        if key in by_query:
            raise ValueError(f"duplicate prediction: {key}")
        by_query[key] = prediction
    valid_queries = {q["query_id"] for q in queries}
    if set(by_query) - valid_queries:
        raise ValueError("predictions contain unknown query IDs")
    by_target, source_nodes, oracle_ids = {}, set(), set()
    for record in oracle_records:
        event_id = record["event_id"]
        if event_id in oracle_ids:
            raise ValueError(f"duplicate oracle event: {event_id}")
        oracle_ids.add(event_id)
        if record["source"]:
            source_nodes.add(node_key(record["source"]["node"]))
        for edge in record["flow_edges"]:
            origin, target = edge_key(edge)
            by_target.setdefault(target, set()).add(origin)
    totals = dict(queries=len(queries), source_tp=0, source_predicted=0, source_true=0,
                  edge_tp=0, edge_predicted=0, edge_true=0, exact_graph=0,
                  unique=0, unique_correct=0, ambiguous=0, unknown=0,
                  candidate_source_covered=0)
    details = []
    for query in queries:
        gold_sources, gold_edges, visited = set(), set(), set()

        def walk(target):
            if target in visited:
                return
            visited.add(target)
            if target in source_nodes:
                gold_sources.add(target)
            for origin in by_target.get(target, ()):
                gold_edges.add((origin, target))
                walk(origin)

        sink = node_key(query["sink"])
        if sink[0] not in oracle_ids:
            raise ValueError(f"missing oracle sink: {sink[0]}")
        walk(sink)
        if not gold_sources:
            raise ValueError(f"incomplete oracle path: {query['query_id']}")
        prediction = by_query.get(query["query_id"], {})
        if prediction and node_key(prediction["sink"]) != sink:
            raise ValueError("prediction sink differs from query")
        predicted_sources = {node_key(n) for n in prediction.get("candidate_sources", [])}
        predicted_edges = {edge_key(e) for e in prediction.get("edges", [])}
        count = len(predicted_sources)
        status = "unknown" if count == 0 else ("unique" if count == 1 else "ambiguous")
        totals[status] += 1
        exact = predicted_edges == gold_edges and predicted_sources == gold_sources
        totals["exact_graph"] += int(exact)
        totals["unique_correct"] += int(count == 1 and predicted_sources == gold_sources)
        totals["candidate_source_covered"] += int(gold_sources <= predicted_sources)
        for name, predicted, gold in (("source", predicted_sources, gold_sources),
                                      ("edge", predicted_edges, gold_edges)):
            totals[f"{name}_tp"] += len(predicted & gold)
            totals[f"{name}_predicted"] += len(predicted)
            totals[f"{name}_true"] += len(gold)
        details.append({"query_id": query["query_id"], "status": status,
                        "candidate_count": count, "exact_graph": exact,
                        "source_covered": gold_sources <= predicted_sources})
    def ratio(numerator, denominator):
        return numerator / denominator if denominator else None
    metrics = {}
    for name in ("source", "edge"):
        metrics[f"{name}_precision"] = ratio(totals[f"{name}_tp"], totals[f"{name}_predicted"])
        metrics[f"{name}_recall"] = ratio(totals[f"{name}_tp"], totals[f"{name}_true"])
    metrics.update({
        "exact_graph_rate": ratio(totals["exact_graph"], totals["queries"]),
        "candidate_source_coverage": ratio(totals["candidate_source_covered"], totals["queries"]),
        "unique_answer_rate": ratio(totals["unique"], totals["queries"]),
        "unique_answer_accuracy": ratio(totals["unique_correct"], totals["unique"]),
        "ambiguous_rate": ratio(totals["ambiguous"], totals["queries"]),
        "unknown_rate": ratio(totals["unknown"], totals["queries"]),
    })
    report = {"schema_version": 1, "counts": totals, "metrics": metrics, "per_query": details}
    if group:
        report["by_scenario"] = {}
        for scenario in sorted({q.get("scenario", "unspecified") for q in queries}):
            subset = [q for q in queries if q.get("scenario", "unspecified") == scenario]
            ids = {q["query_id"] for q in subset}
            sub = evaluate(subset, [p for p in predictions if p["query_id"] in ids], oracle_records, False)
            report["by_scenario"][scenario] = {"counts": sub["counts"], "metrics": sub["metrics"]}
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--queries", type=Path, required=True)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--oracle-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    records = []
    for role in ("api", "profile", "decoy", "store"):
        path = args.oracle_dir / f"{role}.jsonl"
        if path.exists():
            records.extend(read_jsonl(path))
    report = evaluate(read_jsonl(args.queries), read_jsonl(args.predictions), records)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report["metrics"], indent=2))


if __name__ == "__main__":
    main()
