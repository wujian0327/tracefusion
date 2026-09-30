"""Evaluate timing priorities independently; never break tied priorities by ID."""
import argparse
import copy
import json
import math
from pathlib import Path

from common import node_key, read_jsonl
from evaluate import evaluate


def summarize(queries, predictions, oracle):
    retained = evaluate(queries, predictions, oracle)
    preferred = copy.deepcopy(predictions)
    for prediction in preferred:
        ranked = prediction["timing_ranking"]["sources"]
        if len({node_key(r["node"]) for r in ranked}) != len(ranked):
            raise ValueError("duplicate source ranking")
        if {node_key(r["node"]) for r in ranked} != {node_key(n) for n in prediction["candidate_sources"]}:
            raise ValueError("ranking changed the candidate source set")
        if any(not math.isfinite(r["score"]) or r["score"] < 0 for r in ranked):
            raise ValueError("ranking scores must be finite and nonnegative")
        best = min((r["score"] for r in ranked), default=0.0)
        epsilon = 1e-8*max(1.0, abs(best))
        # Compute the highest-priority tier from scores; do not trust labels.
        prediction["candidate_sources"] = [r["node"] for r in ranked if r["score"] <= best+epsilon]
    result = evaluate(queries, preferred, oracle)
    def source_summary(report):
        c, m = report["counts"], report["metrics"]
        return {
            "queries": c["queries"], "preferred_candidates": c["source_predicted"],
            "true_sources_in_top_tier": c["source_tp"],
            "top_tier_source_recall": m["source_recall"],
            "top_tier_source_precision": m["source_precision"],
            "unique_top_queries": c["unique"], "correct_unique_top": c["unique_correct"],
            "wrong_unique_top": c["unique"]-c["unique_correct"],
            "unique_top_accuracy": m["unique_answer_accuracy"],
            "tied_top_queries": c["ambiguous"], "unknown_queries": c["unknown"],
        }
    return {
        "status": "complete",
        "note": "Top-tier selection is a diagnostic counterfactual, not a deployed unique answer. All candidates remain in predictions.",
        "retained_candidates": {"counts": retained["counts"], "metrics": retained["metrics"]},
        "top_tier": source_summary(result),
        "by_scenario": {name: source_summary(value) for name, value in result["by_scenario"].items()},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queries", type=Path, required=True)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--oracle-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists")
    records = []
    for role in ("api", "profile", "decoy", "store"):
        path = args.oracle_dir / f"{role}.jsonl"
        if path.exists():
            records.extend(read_jsonl(path))
    result = summarize(read_jsonl(args.queries), read_jsonl(args.predictions), records)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
