#!/usr/bin/env python3
"""Separate observation preparation, prediction and evaluation for the paper.

Preparation sees X-Mark labels; inference sees only an allowlisted CSV. This is
process/input separation, not an OS security sandbox. The original capture
parsers can filter traces upstream; this script cannot restore discarded data.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

FIELDS = ["protocol_type", "client", "server", "stream_id", "msg_type", "timestamp", "data"]
RESERVED = {
    "xmark", "traceid", "spanid", "parentspanid", "traceparent", "tracestate",
    "b3", "xb3traceid", "xb3spanid", "xb3parentspanid", "xobservationid",
    "xtfevalspanid", "xtfevalparentspanid", "xtfevalobservationid",
}


def reserved(key):
    return "".join(c for c in str(key).lower() if c.isalnum()) in RESERVED


def clean_payload(value):
    if isinstance(value, dict):
        return {k: clean_payload(v) for k, v in value.items() if not reserved(k)
                and str(k).lower() not in {"headers", "request_headers", "response_headers"}}
    if isinstance(value, list):
        return [clean_payload(v) for v in value]
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith(("{", "[")):
            try:
                return json.dumps(clean_payload(json.loads(value)), ensure_ascii=False)
            except json.JSONDecodeError:
                pass
        if value.startswith(("/", "http://", "https://")):
            parts = urlsplit(value)
            return urlunsplit(parts._replace(query=urlencode(
                [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if not reserved(k)]
            )))
    return value


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n",
                          encoding="utf-8")


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def event_key(row):
    return tuple(row[k] for k in ("client", "server", "stream_id"))


def prepare(csv_path, output, scope="previously-filtered", expected_traces=None):
    output = Path(output)
    if output.exists():
        raise ValueError("Output directory already exists; use a new run directory")
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if not set(FIELDS + ["trace_id"]).issubset(reader.fieldnames or []):
            raise ValueError("Input must be the RPC-form cleaned CSV, including trace_id")
        rows = list(reader)
    if not rows:
        raise ValueError("Empty CSV")
    grouped = {}
    sanitized = []
    truth_labels = {row["trace_id"] for row in rows if row.get("trace_id")}
    for row in rows:
        if row["protocol_type"].strip().lower() not in {"http", "http1", "http2", "http/1.1", "http/2", "grpc"}:
            raise ValueError("Only HTTP/gRPC RPC records are supported by this paper workflow")
        if row["msg_type"] not in {"Request", "Response"} or not row["trace_id"]:
            raise ValueError("Each row requires Request/Response and a preparation-only truth label")
        key = event_key(row)
        entry = grouped.setdefault(key, {"key": list(key), "trace_id": row["trace_id"], "kinds": []})
        if entry["trace_id"] != row["trace_id"] or row["msg_type"] in entry["kinds"]:
            raise ValueError("Conflicting label or duplicate direction for an RPC key")
        entry["kinds"].append(row["msg_type"])
        observation = {k: row[k] for k in FIELDS}
        try:
            observation["data"] = json.dumps(clean_payload(json.loads(row["data"])), ensure_ascii=False)
        except json.JSONDecodeError:
            # Free-form payloads may hide evaluation identifiers; fail closed.
            if row["data"].strip():
                raise ValueError("Non-JSON payload needs an explicitly audited parser before blind inference")
            observation["data"] = "{}"
        if any(label in observation["data"] for label in truth_labels):
            raise ValueError("An evaluation identifier remains in payload data; audit and remove its source")
        sanitized.append(observation)
    paired = [v for v in grouped.values() if set(v["kinds"]) == {"Request", "Response"}]
    if not paired:
        raise ValueError("No complete request-response pair")
    servers = {e["key"][1].split(":")[0] for e in paired}
    roots = [e for e in paired if e["key"][0].split(":")[0] not in servers]
    root_by_trace = {}
    for root in roots:
        if root["trace_id"] in root_by_trace:
            raise ValueError("Multiple entry RPCs for one truth label; use rpc span form")
        root_by_trace[root["trace_id"]] = root["key"]
    if not root_by_trace:
        raise ValueError("No entry RPC")
    traces = {e["trace_id"] for e in grouped.values()}
    if expected_traces is not None and expected_traces < len(traces):
        raise ValueError("Expected trace count is smaller than the observed trace population")
    output.mkdir(parents=True)
    obs = output / "observations.csv"
    with obs.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(sanitized)
    write_json(output / "oracle.json", {
        "schema_version": 1, "capture_scope": scope,
        "expected_traces": expected_traces, "root_by_trace": root_by_trace,
        "events": list(grouped.values()), "parent_truth": "unavailable",
    })
    write_json(output / "manifest.json", {
        "source_sha256": sha256(csv_path), "observations_sha256": sha256(obs),
        "row_count": len(rows), "observed_rpc_count": len(grouped),
        "paired_rpc_count": len(paired), "unpaired_rpc_count": len(grouped) - len(paired),
        "observed_trace_count": len(traces), "entry_trace_count": len(root_by_trace),
        "capture_scope": scope, "expected_traces": expected_traces,
        "upstream_filtering_cannot_be_reversed": True,
    })
    return output


def infer(observations, predictions, variant="full"):
    predictions = Path(predictions)
    if predictions.exists():
        raise ValueError("Prediction output already exists")
    with open(observations, newline="", encoding="utf-8") as f:
        if csv.DictReader(f).fieldnames != FIELDS:
            raise ValueError("Inference accepts only the allowlisted observations schema")
    env = {k: v for k, v in os.environ.items() if not k.startswith("LINEAGE_")}
    env.update({
        "LINEAGE_GRAPH_CONTEXT_MODE": "iterative",
        "LINEAGE_GRAPH_DATA_WEIGHT": "20" if variant != "time-only" else "0",
        "LINEAGE_GRAPH_TRACE_CONTEXT_WEIGHT": "40" if variant == "full" else "0",
        "LINEAGE_CONTEXT_MIX_WEIGHT": "0.5" if variant == "full" else "0",
    })
    engine = Path(__file__).resolve().parents[1] / "src" / "tracefusion.py"
    subprocess.run([sys.executable, str(engine), "--csv-path", str(observations),
                    "--topology-mode", "service-graph",
                    "--blind-predictions-out", str(predictions)], env=env, check=True)
    if not predictions.is_file():
        raise RuntimeError("Engine produced no predictions; inspect root detection and input")
    report = read_json(predictions)
    report.update({"variant": variant, "observations_sha256": sha256(observations),
                   "engine_sha256": sha256(engine)})
    write_json(predictions, report)


def evaluate(oracle_path, predictions_path, output, observations, parent_oracle=None):
    oracle = read_json(oracle_path)
    predictions = read_json(predictions_path)
    if predictions.get("mode") != "blind-service-graph":
        raise ValueError("Predictions must be produced by the blind inference path")
    if predictions.get("observations_sha256") != sha256(observations):
        raise ValueError("Predictions and evaluation observations do not match")
    truth = {tuple(e["key"]): e for e in oracle["events"]}
    roots = {t: tuple(k) for t, k in oracle["root_by_trace"].items()}
    independent = None
    if parent_oracle:
        independent = read_json(parent_oracle)
        if independent.get("complete_population") is not True:
            raise ValueError("Parent oracle must declare the complete expected RPC population")
        parent_truth = {}
        roots = {}
        for e in independent["events"]:
            k = tuple(e["key"])
            if k in parent_truth or len(k) != 3 or not e.get("trace_id"):
                raise ValueError("Invalid or duplicate independent truth event")
            parent_truth[k] = e
            if e["parent_key"] is None:
                if e["trace_id"] in roots:
                    raise ValueError("Independent truth must have one root per trace")
                roots[e["trace_id"]] = k
        if not set(truth).issubset(parent_truth):
            raise ValueError("Independent truth omits captured RPCs")
        for k, e in truth.items():
            if parent_truth[k]["trace_id"] != e["trace_id"]:
                raise ValueError("Independent and capture truth labels disagree")
        for e in parent_truth.values():
            if e["trace_id"] not in roots:
                raise ValueError("Independent truth has a trace without a root")
            if e["parent_key"] is not None:
                p = tuple(e["parent_key"])
                if p not in parent_truth or parent_truth[p]["trace_id"] != e["trace_id"] or p == tuple(e["key"]):
                    raise ValueError("Invalid independent parent reference")
        truth = parent_truth
        if oracle.get("expected_traces") is not None and oracle["expected_traces"] != len(roots):
            raise ValueError("Independent truth disagrees with the expected request population")
    pred = {}
    for e in predictions["predictions"]:
        k = tuple(e["key"])
        if k in pred or k not in truth:
            raise ValueError("Duplicate prediction or unknown RPC")
        pred[k] = e
    traces = {e["trace_id"] for e in truth.values()}
    def correct(k):
        expected = roots.get(truth[k]["trace_id"])
        value = pred.get(k, {}).get("root_key")
        return expected is not None and value is not None and tuple(value) == expected
    def trace_correct(trace):
        expected_keys = {k for k, e in truth.items() if e["trace_id"] == trace}
        root = roots.get(trace)
        predicted_keys = {k for k, e in pred.items()
                          if e.get("root_key") is not None and tuple(e["root_key"]) == root}
        return root is not None and expected_keys == predicted_keys and all(correct(k) for k in expected_keys)
    assigned = sum(p.get("root_key") is not None for p in pred.values())
    span_ok = sum(correct(k) for k in truth)
    trace_ok = sum(trace_correct(t) for t in traces)
    denominator = oracle.get("expected_traces") or len(traces)
    if independent:
        denominator = len(traces)
    if denominator < len(traces):
        raise ValueError("Trace population denominator is smaller than the truth inventory")
    metrics = {
        "variant": predictions.get("variant"), "truth_rpc_count": len(truth),
        "predicted_rpc_count": len(pred), "observed_trace_count": len(traces),
        "trace_denominator": denominator,
        "span_accuracy_pct": span_ok / len(truth) * 100 if truth else None,
        "coverage_pct": assigned / len(truth) * 100 if truth else None,
        "trace_assignment_accuracy_pct": trace_ok / denominator * 100 if denominator else None,
        "full_trace_accuracy_pct": None, "parent_edge_precision_pct": None,
        "parent_edge_recall_pct": None, "parent_edge_f1_pct": None,
        "scope": "complete-independent-population" if independent else oracle["capture_scope"],
        "parent_truth": "independent" if independent else "unavailable",
        "trace_assignment_semantics": "all inventoried RPCs assigned to correct root with no cross-trace contamination; missing predictions count as failures",
        "observations_sha256": sha256(observations),
        "oracle_sha256": sha256(oracle_path), "predictions_sha256": sha256(predictions_path),
        "parent_oracle_sha256": sha256(parent_oracle) if independent else None,
    }
    if independent:
        true_edges = {(tuple(e["parent_key"]), k) for k, e in truth.items() if e["parent_key"] is not None}
        pred_edges = {(tuple(e["parent_key"]), k) for k, e in pred.items() if e["parent_key"] is not None}
        tp = len(true_edges & pred_edges)
        precision = tp / len(pred_edges) if pred_edges else 0.0
        recall = tp / len(true_edges) if true_edges else 0.0
        full_ok = sum(
            trace_correct(t) and all(correct(k) and
                (tuple(pred[k]["parent_key"]) if pred[k]["parent_key"] is not None else None) ==
                (tuple(e["parent_key"]) if e["parent_key"] is not None else None)
                for k, e in truth.items() if e["trace_id"] == t)
            for t in traces
        )
        metrics.update({
            "full_trace_accuracy_pct": full_ok / denominator * 100 if denominator else None,
            "parent_edge_precision_pct": precision * 100, "parent_edge_recall_pct": recall * 100,
            "parent_edge_f1_pct": 2 * precision * recall / (precision + recall) * 100 if precision + recall else 0.0,
        })
    write_json(output, metrics)
    return metrics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("--csv", required=True)
    prep.add_argument("--output", required=True)
    prep.add_argument("--capture-scope", choices=["unfiltered", "previously-filtered"], default="previously-filtered")
    prep.add_argument("--expected-traces", type=int)
    inf = sub.add_parser("infer")
    inf.add_argument("--observations", required=True)
    inf.add_argument("--predictions", required=True)
    inf.add_argument("--variant", choices=["time-only", "no-context", "full"], default="full")
    ev = sub.add_parser("evaluate")
    for name in ["oracle", "predictions", "output", "observations"]:
        ev.add_argument("--" + name, required=True)
    ev.add_argument("--parent-oracle")
    args = parser.parse_args()
    if args.command == "prepare":
        prepare(args.csv, args.output, args.capture_scope, args.expected_traces)
    elif args.command == "infer":
        infer(args.observations, args.predictions, args.variant)
    else:
        evaluate(args.oracle, args.predictions, args.output, args.observations, args.parent_oracle)


if __name__ == "__main__":
    main()
