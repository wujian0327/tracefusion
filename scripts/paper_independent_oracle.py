#!/usr/bin/env python3
"""Evaluation-only bridge from instrumented RPC truth to blind evaluation keys.

Never pass the manifest or the CSV with evaluation headers to inference. Missing
captured RPCs remain in the complete truth inventory and count as failures.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def header_value(value):
    # tshark exports may encode CR/LF once or twice inside a JSON string.
    value = str(value or "")
    for _ in range(3):
        value = value.replace("\\\\r", "").replace("\\\\n", "")
        value = value.replace("\\r", "").replace("\\n", "")
    return value.strip()


def build_oracle(manifest_path, capture_path):
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if manifest.get("schema_version") != "independent-rpc-parent-ground-truth-v1":
        raise ValueError("Unsupported independent truth schema")
    requested = [r["request_id"] for r in manifest["requests"]]
    if not requested or len(set(requested)) != len(requested):
        raise ValueError("Empty or duplicate requested population")
    truth, observations, roots = {}, set(), {}
    for rpc in manifest["rpcs"]:
        span, trace, observation = rpc["span_id"], rpc["request_id"], rpc["observation_id"]
        if not span or span in truth or not observation or observation in observations:
            raise ValueError("Empty or duplicate independent RPC identity")
        if trace not in requested:
            raise ValueError("RPC outside requested population")
        truth[span] = rpc
        observations.add(observation)
        if not rpc.get("parent_span_id"):
            if trace in roots:
                raise ValueError("Multiple independent roots for a request")
            roots[trace] = span
    if set(roots) != set(requested):
        raise ValueError("Every requested trace requires an independently logged root")
    # Check all references and cycles before using any capture information.
    for rpc in truth.values():
        parent = rpc.get("parent_span_id")
        if parent and (parent not in truth or truth[parent]["request_id"] != rpc["request_id"]):
            raise ValueError("Missing or cross-request independent parent")
    done = set()
    for span in truth:
        chain, current = set(), span
        while current and current not in done:
            if current in chain:
                raise ValueError("Cycle in independent parents")
            if current not in truth or truth[current]["request_id"] != truth[span]["request_id"]:
                raise ValueError("Missing or cross-request independent parent")
            chain.add(current)
            current = truth[current].get("parent_span_id")
        done.update(chain)
    pairs, by_span = {}, {}
    with open(capture_path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = {"client", "server", "stream_id", "trace_id", "msg_type", "headers"}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError("Capture requires RPC keys, directions and evaluation headers")
        for row in reader:
            key = tuple(row[k] for k in ("client", "server", "stream_id"))
            kind = row["msg_type"]
            if kind not in {"Request", "Response"}:
                raise ValueError("Unexpected message direction")
            pair = pairs.setdefault(key, {})
            if kind in pair:
                raise ValueError("Duplicate capture direction for an RPC key")
            pair[kind] = row
    for key, pair in pairs.items():
        if "Request" not in pair:
            raise ValueError("Response without request identity cannot be aligned")
        request = pair["Request"]
        headers = {k.lower(): header_value(v) for k, v in json.loads(request["headers"]).items()}
        span = headers.get("x-tf-eval-span-id")
        if span not in truth or span in by_span:
            raise ValueError("Unknown or repeated captured span identity")
        rpc = truth[span]
        if any(r["trace_id"] != rpc["request_id"] for r in pair.values()):
            raise ValueError("Capture and independent request labels disagree")
        if headers.get("x-tf-eval-parent-span-id", "") != (rpc.get("parent_span_id") or ""):
            raise ValueError("Capture and independently logged parents disagree")
        if headers.get("x-tf-eval-observation-id") != rpc["observation_id"]:
            raise ValueError("Capture and independent observation identities disagree")
        by_span[span] = key
    # Synthetic keys are evaluation-only placeholders for missing observations.
    keys = {s: by_span.get(s, ("unobserved:" + s, "independent-truth", "missing")) for s in truth}
    if len(set(keys.values())) != len(keys):
        raise ValueError("Independent keys collide")
    return {
        "schema_version": 1, "complete_population": True, "evaluation_only": True,
        "population_source": "instrumented request and RPC manifest; completeness is conditional on that logging",
        "manifest_sha256": digest(manifest_path), "capture_sha256": digest(capture_path),
        "requested_trace_count": len(requested), "truth_rpc_count": len(truth),
        "captured_rpc_count": len(by_span), "missing_capture_rpc_count": len(truth) - len(by_span),
        "paired_capture_rpc_count": sum(len(p) == 2 for p in pairs.values()),
        "events": [{"key": list(keys[s]), "trace_id": r["request_id"],
                    "parent_key": list(keys[r["parent_span_id"]]) if r.get("parent_span_id") else None,
                    "span_id": s, "observation_id": r["observation_id"], "observed": s in by_span}
                   for s, r in truth.items()],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--capture-with-eval", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = build_oracle(args.manifest, args.capture_with_eval)
    with open(args.output, "x", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2, allow_nan=False)
        handle.write("\n")
    print(json.dumps({k: v for k, v in result.items() if k != "events"}, ensure_ascii=False))


if __name__ == "__main__":
    main()
