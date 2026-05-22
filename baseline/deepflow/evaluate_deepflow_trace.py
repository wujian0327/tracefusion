#!/usr/bin/env python3
"""Evaluate DeepFlow's original L7FlowTracing result with X-Mark ground truth.

The trace reconstruction step is delegated to DeepFlow app's
`/v1/stats/querier/L7FlowTracing` endpoint. This script only finds one anchor
flow for each generated request, calls DeepFlow for the reconstructed `_ids`,
and scores the returned rows.
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


DEFAULT_EXPECTED_EDGES = "productpage->details,productpage->reviews,reviews->ratings"

SQL_COLUMNS = [
    "toString(_id) AS deepflow_id",
    "time",
    "toUnixTimestamp64Micro(start_time) AS start_time_us",
    "toUnixTimestamp64Micro(end_time) AS end_time_us",
    "signal_source",
    "type",
    "protocol",
    "l7_protocol",
    "l7_protocol_str",
    "req_tcp_seq",
    "resp_tcp_seq",
    "vtap_id",
    "tap_side",
    "syscall_trace_id_request",
    "syscall_trace_id_response",
    "trace_id",
    "span_id",
    "parent_span_id",
    "x_request_id_0",
    "x_request_id_1",
    "request_id",
    "http_proxy_client",
    "version",
    "endpoint",
    "request_type",
    "request_domain",
    "request_resource",
    "response_code",
    "response_exception",
    "response_result",
    "pod_ns_0",
    "pod_ns_1",
    "pod_service_0",
    "pod_service_1",
    "auto_service_0",
    "auto_service_1",
    "auto_instance_0",
    "auto_instance_1",
    "process_kname_0",
    "process_kname_1",
    "attribute",
]


@dataclass(frozen=True)
class Row:
    raw: dict

    def __getattr__(self, key: str):
        return self.raw.get(key)


def no_proxy_opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def sql_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def post_sql(api_url: str, db: str, sql: str, timeout: int) -> list[dict]:
    body = urllib.parse.urlencode({"db": db, "sql": sql}).encode()
    request = urllib.request.Request(api_url, data=body, method="POST")
    with no_proxy_opener().open(request, timeout=timeout) as response:
        data = json.loads(response.read().decode())
    if data.get("OPT_STATUS") != "SUCCESS":
        raise RuntimeError(data.get("DESCRIPTION") or json.dumps(data)[:1000])
    result = data.get("result") or {}
    columns = result.get("columns") or []
    return [dict(zip(columns, row)) for row in (result.get("values") or [])]


def post_deepflow_l7_tracing(
    app_url: str,
    db: str,
    table: str,
    anchor_id: str,
    start_ts: int,
    end_ts: int,
    max_iteration: int,
    network_delay_us: int,
    timeout: int,
) -> set[str]:
    payload = {
        "_id": str(anchor_id),
        "time_start": start_ts,
        "time_end": end_ts,
        "database": db,
        "table": table,
        "has_attributes": 1,
        "max_iteration": max_iteration,
        "network_delay_us": network_delay_us,
    }
    request = urllib.request.Request(
        app_url,
        data=json.dumps(payload).encode(),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with no_proxy_opener().open(request, timeout=timeout) as response:
        data = json.loads(response.read().decode())
    if data.get("OPT_STATUS") != "SUCCESS":
        raise RuntimeError(data.get("DESCRIPTION") or json.dumps(data)[:1000])

    selected_ids: set[str] = set()
    for trace in ((data.get("DATA") or {}).get("tracing") or []):
        for flow_id in trace.get("_ids") or []:
            selected_ids.add(str(flow_id))
    return selected_ids


def run_l7_tracing_request(
    index: int,
    mark: str,
    anchor_id: str,
    app_url: str,
    db: str,
    table: str,
    start_ts: int,
    end_ts: int,
    max_iteration: int,
    network_delay_us: int,
    timeout: int,
) -> dict:
    t0 = time.time()
    try:
        selected_ids = post_deepflow_l7_tracing(
            app_url,
            db,
            table,
            anchor_id,
            start_ts,
            end_ts,
            max_iteration,
            network_delay_us,
            timeout,
        )
    except Exception as exc:  # Keep one bad trace from aborting a whole sweep.
        return {
            "index": index,
            "mark": mark,
            "anchor_id": str(anchor_id),
            "status": "l7_tracing_error",
            "error": str(exc),
            "selected_ids": set(),
            "duration": time.time() - t0,
        }
    return {
        "index": index,
        "mark": mark,
        "anchor_id": str(anchor_id),
        "status": "ok",
        "selected_ids": selected_ids,
        "duration": time.time() - t0,
    }


def collect_l7_tracing_results(
    work_items: list[tuple[int, str, str]],
    concurrency: int,
    app_url: str,
    db: str,
    table: str,
    start_ts: int,
    end_ts: int,
    max_iteration: int,
    network_delay_us: int,
    timeout: int,
) -> dict[int, dict]:
    if not work_items:
        return {}

    def run(item: tuple[int, str, str]) -> dict:
        index, mark, anchor_id = item
        return run_l7_tracing_request(
            index,
            mark,
            anchor_id,
            app_url,
            db,
            table,
            start_ts,
            end_ts,
            max_iteration,
            network_delay_us,
            timeout,
        )

    results: dict[int, dict] = {}
    if concurrency <= 1:
        for item in work_items:
            result = run(item)
            results[int(result["index"])] = result
        return results

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(run, item) for item in work_items]
        for future in as_completed(futures):
            result = future.result()
            results[int(result["index"])] = result
    return results


def load_service_map(path: str | None) -> dict[str, dict[str, str]]:
    if not path:
        return {}
    raw = json.loads(Path(path).read_text())
    service_map: dict[str, dict[str, str]] = {}
    for key, value in raw.items():
        if isinstance(value, str):
            service_map[str(key)] = {"service": value, "namespace": ""}
        elif isinstance(value, dict):
            service_map[str(key)] = {
                "service": str(value.get("service") or value.get("name") or ""),
                "namespace": str(value.get("namespace") or value.get("ns") or ""),
            }
    return service_map


def apply_service_map(rows: list[dict], service_map: dict[str, dict[str, str]]) -> None:
    if not service_map:
        return
    for row in rows:
        for side in ("0", "1"):
            service_key = f"pod_service_{side}"
            ns_key = f"pod_ns_{side}"
            if row.get(service_key):
                continue
            for candidate_key in (f"auto_service_{side}", f"auto_instance_{side}"):
                match = service_map.get(str(row.get(candidate_key) or ""))
                if match and match.get("service"):
                    row[service_key] = match["service"]
                    if match.get("namespace") and not row.get(ns_key):
                        row[ns_key] = match["namespace"]
                    break


def parse_attr(value: object) -> dict:
    if not value or value == "{}":
        return {}
    try:
        parsed = json.loads(str(value))
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def extract_rid(resource: object) -> str | None:
    match = re.search(r"[?&]rid=([^&#]+)", str(resource or ""))
    if not match:
        return None
    return urllib.parse.unquote(match.group(1))


def parse_expected_edges(value: str) -> set[tuple[str, str]]:
    edges = set()
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        if "->" in item:
            lhs, rhs = item.split("->", 1)
        elif ":" in item:
            lhs, rhs = item.split(":", 1)
        else:
            raise ValueError(f"Expected edge must look like service->service: {item}")
        lhs = lhs.strip()
        rhs = rhs.strip()
        if not lhs or not rhs:
            raise ValueError(f"Expected edge must look like service->service: {item}")
        edges.add((lhs, rhs))
    if not edges:
        raise ValueError("At least one expected edge is required")
    return edges


def parse_expected_edge_counts(value: str | None) -> dict[tuple[str, str], int]:
    if not value:
        return {}
    counts: dict[tuple[str, str], int] = {}
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        if "=" not in item:
            raise ValueError(f"Expected edge count must look like service->service=N: {item}")
        edge_text, count_text = item.split("=", 1)
        edge = parse_edge(edge_text.strip())
        count = int(count_text.strip())
        if count < 0:
            raise ValueError(f"Expected edge count must be non-negative: {item}")
        counts[edge] = count
    return counts


def parse_edge(value: str) -> tuple[str, str]:
    edges = parse_expected_edges(value)
    if len(edges) != 1:
        raise ValueError(f"Expected exactly one edge, got: {value}")
    return next(iter(edges))


def service_edge(row: Row, expected_edges: set[tuple[str, str]]) -> tuple[str, str] | None:
    edge = (str(row.pod_service_0 or ""), str(row.pod_service_1 or ""))
    return edge if edge in expected_edges else None


def business_edge_counts(rows: list[Row], expected_edges: set[tuple[str, str]]) -> tuple[list[Row], Counter[tuple[str, str]]]:
    business_rows = [row for row in rows if service_edge(row, expected_edges)]
    return business_rows, Counter(service_edge(row, expected_edges) for row in business_rows)


def edge_counts_dict(edge_counts: Counter[tuple[str, str]], expected_edges: set[tuple[str, str]]) -> dict[str, int]:
    return {f"{a}->{b}": edge_counts[(a, b)] for a, b in sorted(expected_edges)}


def expected_count_for(
    edge: tuple[str, str],
    expected_edge_counts: dict[tuple[str, str], int],
    expected_per_edge: int,
) -> int:
    return expected_edge_counts.get(edge, expected_per_edge)


def span_shortfall(
    edge_counts: Counter[tuple[str, str]],
    expected_edges: set[tuple[str, str]],
    expected_edge_counts: dict[tuple[str, str], int],
    expected_per_edge: int,
) -> int:
    return sum(
        max(0, expected_count_for(edge, expected_edge_counts, expected_per_edge) - edge_counts[edge])
        for edge in expected_edges
    )


def span_excess(
    edge_counts: Counter[tuple[str, str]],
    expected_edges: set[tuple[str, str]],
    expected_edge_counts: dict[tuple[str, str], int],
    expected_per_edge: int,
) -> int:
    return sum(
        max(0, edge_counts[edge] - expected_count_for(edge, expected_edge_counts, expected_per_edge))
        for edge in expected_edges
    )


def correctly_marked_edge_counts(
    rows: list[Row],
    expected_edges: set[tuple[str, str]],
    expected_mark: str,
    mark_consistent: bool,
    rid_consistent: bool,
) -> Counter[tuple[str, str]]:
    if mark_consistent and rid_consistent:
        return Counter(service_edge(row, expected_edges) for row in rows if service_edge(row, expected_edges))

    counts: Counter[tuple[str, str]] = Counter()
    for row in rows:
        edge = service_edge(row, expected_edges)
        if not edge:
            continue
        row_mark = mark_for(row)
        row_rid = extract_rid(row.request_resource)
        if row_mark == expected_mark or row_rid == expected_mark:
            counts[edge] += 1
    return counts


def capped_correct_edge_occurrences(
    edge_counts: Counter[tuple[str, str]],
    expected_edges: set[tuple[str, str]],
    expected_edge_counts: dict[tuple[str, str], int],
    expected_per_edge: int,
) -> int:
    return sum(
        min(edge_counts[edge], expected_count_for(edge, expected_edge_counts, expected_per_edge))
        for edge in expected_edges
    )


def total_expected_edge_occurrences(
    expected_edges: set[tuple[str, str]],
    expected_edge_counts: dict[tuple[str, str], int],
    expected_per_edge: int,
) -> int:
    return sum(
        expected_count_for(edge, expected_edge_counts, expected_per_edge)
        for edge in expected_edges
    )


def pairing_missing_spans(
    selected_edge_counts: Counter[tuple[str, str]],
    captured_edge_counts: Counter[tuple[str, str]],
    expected_edges: set[tuple[str, str]],
    expected_edge_counts: dict[tuple[str, str], int],
    expected_per_edge: int,
) -> int:
    missing = 0
    for edge in expected_edges:
        expected_count = expected_count_for(edge, expected_edge_counts, expected_per_edge)
        selected_available = min(selected_edge_counts[edge], expected_count)
        captured_available = min(captured_edge_counts[edge], expected_count)
        missing += max(0, captured_available - selected_available)
    return missing


def build_sql(
    namespace: str,
    start_ts: int,
    end_ts: int,
    limit: int,
    query_all: bool,
    mark_prefix: str | None,
) -> str:
    columns = ", ".join(SQL_COLUMNS)
    where = [f"time >= {start_ts}", f"time <= {end_ts}"]
    if mark_prefix:
        needle = sql_quote(f"%{mark_prefix}%")
        where.append(f"(attribute LIKE {needle} OR request_resource LIKE {needle})")
    if not query_all:
        ns = sql_quote(namespace)
        where.append(f"(pod_ns_0 = {ns} OR pod_ns_1 = {ns} OR request_resource LIKE '/productpage%')")
    return (
        f"SELECT {columns} FROM l7_flow_log "
        f"WHERE {' AND '.join(where)} "
        "ORDER BY time ASC, start_time ASC "
        f"LIMIT {limit}"
    )


def fetch_rows_by_ids(api_url: str, db: str, ids: set[str], timeout: int) -> list[dict]:
    if not ids:
        return []
    rows: list[dict] = []
    columns = ", ".join(SQL_COLUMNS)
    id_list = sorted(str(item) for item in ids)
    for offset in range(0, len(id_list), 500):
        batch = id_list[offset : offset + 500]
        id_values = ", ".join(sql_quote(item) for item in batch)
        sql = (
            f"SELECT {columns} FROM l7_flow_log "
            f"WHERE toString(_id) IN ({id_values}) "
            f"LIMIT {len(batch)}"
        )
        rows.extend(post_sql(api_url, db, sql, timeout))
    return rows


def mean(values: list[float]) -> float | None:
    return round(statistics.mean(values), 4) if values else None


def mark_for(row: Row) -> str | None:
    return parse_attr(row.attribute).get("x_mark") or extract_rid(row.request_resource)


def wrong_mark_span_count(rows: list[Row], expected_mark: str) -> int:
    count = 0
    for row in rows:
        row_mark = mark_for(row)
        if row_mark and row_mark != expected_mark:
            count += 1
    return count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--load-report", default="result/deepflow_xmark_200_load_report.json")
    parser.add_argument("--output", default="result/deepflow_trace_report.json")
    parser.add_argument("--api-url", default="http://127.0.0.1:20416/v1/query/")
    parser.add_argument("--deepflow-app-url", default="http://127.0.0.1:20418/v1/stats/querier/L7FlowTracing")
    parser.add_argument("--db", default="flow_log")
    parser.add_argument("--table", default="l7_flow_log")
    parser.add_argument("--service-map", default=None, help="Optional IP/endpoint to service-name JSON map for non-Kubernetes local runs")
    parser.add_argument("--query-all", action="store_true", help="Query all l7_flow_log rows in the time window before scoring")
    parser.add_argument("--namespace", default="bookinfo")
    parser.add_argument(
        "--mark-prefix",
        default=None,
        help=(
            "Optional X-Mark prefix used to narrow the initial anchor query. "
            "Rows returned by DeepFlow L7FlowTracing are still fetched by _id before scoring."
        ),
    )
    parser.add_argument("--expected-edges", default=DEFAULT_EXPECTED_EDGES)
    parser.add_argument(
        "--expected-edge-counts",
        default=None,
        help=(
            "Optional comma-separated service->service=N counts. When set, "
            "these per-edge counts override --expected-spans-per-edge for exact scoring."
        ),
    )
    parser.add_argument("--anchor-edge", default="productpage->details")
    parser.add_argument("--count", type=int, default=200)
    parser.add_argument("--query-timeout", type=int, default=60)
    parser.add_argument("--window-padding-seconds", type=int, default=90)
    parser.add_argument("--limit", type=int, default=500000)
    parser.add_argument("--max-iteration", type=int, default=6)
    parser.add_argument("--network-delay-us", type=int, default=50000)
    parser.add_argument(
        "--trace-concurrency",
        type=int,
        default=1,
        help="Number of concurrent DeepFlow L7FlowTracing requests. 1 preserves the old serial behavior.",
    )
    parser.add_argument("--expected-spans-per-edge", type=int, default=4)
    args = parser.parse_args()

    started_at = time.time()
    load_report = json.loads(Path(args.load_report).read_text())
    requests = (load_report.get("requests") or [])[: args.count]
    if not requests:
        raise RuntimeError(f"No requests found in {args.load_report}")

    expected_edges = parse_expected_edges(args.expected_edges)
    expected_edge_counts = parse_expected_edge_counts(args.expected_edge_counts)
    if expected_edge_counts:
        expected_edges |= set(expected_edge_counts)
    anchor_edge = parse_edge(args.anchor_edge)
    service_map = load_service_map(args.service_map)

    expected_marks = [item.get("mark") or item.get("rid") for item in requests]
    start_ts = int(min(float(item["start_time"]) for item in requests)) - args.window_padding_seconds
    end_ts = int(max(float(item["end_time"]) for item in requests)) + args.window_padding_seconds

    sql = build_sql(
        args.namespace,
        start_ts,
        end_ts,
        args.limit,
        args.query_all or bool(service_map),
        args.mark_prefix,
    )
    raw_rows = post_sql(args.api_url, args.db, sql, args.query_timeout)
    apply_service_map(raw_rows, service_map)
    rows_by_id = {str(row["deepflow_id"]): Row(row) for row in raw_rows}
    rows_by_mark: dict[str, list[Row]] = {}
    for row in rows_by_id.values():
        row_mark = mark_for(row)
        if row_mark:
            rows_by_mark.setdefault(row_mark, []).append(row)

    anchors: dict[str, Row] = {}
    for row in rows_by_id.values():
        mark = mark_for(row)
        if not mark or mark in anchors:
            continue
        if (row.pod_service_0, row.pod_service_1) == anchor_edge:
            anchors[mark] = row

    expected_occurrences_total = total_expected_edge_occurrences(
        expected_edges,
        expected_edge_counts,
        args.expected_spans_per_edge,
    )
    trace_work_items = [
        (index, mark, str(anchors[mark].deepflow_id))
        for index, mark in enumerate(expected_marks)
        if mark and mark in anchors
    ]
    trace_results = collect_l7_tracing_results(
        trace_work_items,
        max(1, args.trace_concurrency),
        args.deepflow_app_url,
        args.db,
        args.table,
        start_ts,
        end_ts,
        args.max_iteration,
        args.network_delay_us,
        args.query_timeout,
    )
    reconstruction_durations = [
        float(result["duration"])
        for result in trace_results.values()
        if result.get("status") == "ok"
    ]
    all_selected_ids: set[str] = set()
    for result in trace_results.values():
        if result.get("status") == "ok":
            all_selected_ids.update(str(row_id) for row_id in (result.get("selected_ids") or set()))
    missing_ids = all_selected_ids - set(rows_by_id)
    if missing_ids:
        fetched_rows = fetch_rows_by_ids(args.api_url, args.db, missing_ids, args.query_timeout)
        apply_service_map(fetched_rows, service_map)
        for raw_row in fetched_rows:
            row_id = str(raw_row["deepflow_id"])
            if row_id in rows_by_id:
                continue
            row = Row(raw_row)
            rows_by_id[row_id] = row
            row_mark = mark_for(row)
            if row_mark:
                rows_by_mark.setdefault(row_mark, []).append(row)

    per_trace = []
    full_trace_correct = 0
    trace_assignment_correct = 0
    span_correct_total = 0
    span_coverage_total = 0
    span_ground_truth_total = 0
    parent_child_correct_predicted_total = 0
    parent_child_recall_correct_total = 0
    parent_child_predicted_total = 0
    parent_child_ground_truth_total = 0
    for mark_index, mark in enumerate(expected_marks):
        if not mark:
            per_trace.append({"mark": mark, "status": "missing_expected_mark"})
            span_ground_truth_total += expected_occurrences_total
            parent_child_ground_truth_total += expected_occurrences_total
            continue
        anchor = anchors.get(mark)
        if not anchor:
            per_trace.append({"mark": mark, "status": "missing_anchor"})
            span_ground_truth_total += expected_occurrences_total
            parent_child_ground_truth_total += expected_occurrences_total
            continue
        trace_result = trace_results.get(mark_index)
        if not trace_result or trace_result.get("status") != "ok":
            per_trace.append(
                {
                    "mark": mark,
                    "status": (trace_result or {}).get("status", "missing_l7_tracing_result"),
                    "anchor_deepflow_id": "id-" + str(anchor.deepflow_id),
                    "error": (trace_result or {}).get("error"),
                }
            )
            span_ground_truth_total += expected_occurrences_total
            parent_child_ground_truth_total += expected_occurrences_total
            continue

        selected_ids = {str(row_id) for row_id in (trace_result.get("selected_ids") or set())}
        missing_selected_ids = sorted(row_id for row_id in selected_ids if row_id not in rows_by_id)

        selected_rows = [rows_by_id[row_id] for row_id in selected_ids if row_id in rows_by_id]
        business_rows, edge_counts = business_edge_counts(selected_rows, expected_edges)
        captured_rows = rows_by_mark.get(mark, [])
        captured_business_rows, captured_edge_counts = business_edge_counts(captured_rows, expected_edges)
        mark_values = sorted({mark_for(row) for row in selected_rows if mark_for(row)})
        rid_values = sorted({rid for row in selected_rows for rid in [extract_rid(row.request_resource)] if rid})
        observed_edges = {edge for edge, count in edge_counts.items() if edge and count > 0}
        missing_edges = expected_edges - observed_edges
        false_positive_edges = observed_edges - expected_edges
        covered_expected_business_spans = all(
            edge_counts[edge] >= expected_count_for(edge, expected_edge_counts, args.expected_spans_per_edge)
            for edge in expected_edges
        )
        mark_consistent = not mark_values or mark_values == [mark]
        rid_consistent = not rid_values or rid_values == [mark]
        expected_occurrences = expected_occurrences_total
        correct_edge_counts = correctly_marked_edge_counts(
            business_rows,
            expected_edges,
            mark,
            mark_consistent,
            rid_consistent,
        )
        correct_edge_occurrences = capped_correct_edge_occurrences(
            correct_edge_counts,
            expected_edges,
            expected_edge_counts,
            args.expected_spans_per_edge,
        )
        correct_predicted_edge_occurrences = sum(correct_edge_counts[edge] for edge in expected_edges)
        covered_edge_occurrences = capped_correct_edge_occurrences(
            edge_counts,
            expected_edges,
            expected_edge_counts,
            args.expected_spans_per_edge,
        )
        predicted_edge_occurrences = sum(edge_counts[edge] for edge in expected_edges)
        deepflow_missing_span_count = span_shortfall(
            edge_counts,
            expected_edges,
            expected_edge_counts,
            args.expected_spans_per_edge,
        )
        deepflow_extra_span_count = span_excess(
            edge_counts,
            expected_edges,
            expected_edge_counts,
            args.expected_spans_per_edge,
        )
        capture_missing_span_count = span_shortfall(
            captured_edge_counts,
            expected_edges,
            expected_edge_counts,
            args.expected_spans_per_edge,
        )
        capture_extra_span_count = span_excess(
            captured_edge_counts,
            expected_edges,
            expected_edge_counts,
            args.expected_spans_per_edge,
        )
        pairing_missing_span_count = pairing_missing_spans(
            edge_counts,
            captured_edge_counts,
            expected_edges,
            expected_edge_counts,
            args.expected_spans_per_edge,
        )
        pairing_extra_span_count = deepflow_extra_span_count
        selected_wrong_mark_span_count = wrong_mark_span_count(selected_rows, mark)
        span_capture_missing = capture_missing_span_count > 0
        span_pairing_error = (
            pairing_missing_span_count > 0
            or selected_wrong_mark_span_count > 0
            or bool(false_positive_edges)
        )
        trace_assignment_ok = (
            correct_edge_occurrences == expected_occurrences
            and selected_wrong_mark_span_count == 0
            and not false_positive_edges
        )
        trace_exact = (
            mark_consistent
            and rid_consistent
            and covered_expected_business_spans
            and not missing_edges
            and not false_positive_edges
        )
        full_trace_correct += int(trace_exact)
        trace_assignment_correct += int(trace_assignment_ok)
        span_correct_total += correct_edge_occurrences
        span_coverage_total += covered_edge_occurrences
        span_ground_truth_total += expected_occurrences
        parent_child_correct_predicted_total += correct_predicted_edge_occurrences
        parent_child_recall_correct_total += correct_edge_occurrences
        parent_child_predicted_total += predicted_edge_occurrences
        parent_child_ground_truth_total += expected_occurrences

        per_trace.append(
            {
                "mark": mark,
                "status": "ok",
                "anchor_deepflow_id": "id-" + anchor.deepflow_id,
                "missing_selected_ids": missing_selected_ids[:20],
                "missing_selected_id_count": len(missing_selected_ids),
                "deepflow_flow_count": len(selected_rows),
                "business_span_count": len(business_rows),
                "edge_span_counts": edge_counts_dict(edge_counts, expected_edges),
                "correct_edge_span_counts": edge_counts_dict(correct_edge_counts, expected_edges),
                "captured_business_span_count": len(captured_business_rows),
                "captured_edge_span_counts": edge_counts_dict(captured_edge_counts, expected_edges),
                "expected_edge_occurrences": expected_occurrences,
                "correct_edge_occurrences": correct_edge_occurrences,
                "correct_predicted_edge_occurrences": correct_predicted_edge_occurrences,
                "covered_edge_occurrences": covered_edge_occurrences,
                "predicted_edge_occurrences": predicted_edge_occurrences,
                "deepflow_missing_span_count": deepflow_missing_span_count,
                "deepflow_extra_span_count": deepflow_extra_span_count,
                "capture_missing_span_count": capture_missing_span_count,
                "capture_extra_span_count": capture_extra_span_count,
                "pairing_missing_span_count": pairing_missing_span_count,
                "pairing_extra_span_count": pairing_extra_span_count,
                "wrong_mark_span_count": selected_wrong_mark_span_count,
                "span_capture_missing": span_capture_missing,
                "span_pairing_error": span_pairing_error,
                "observed_edges": sorted(f"{a}->{b}" for a, b in observed_edges),
                "missing_edges": sorted(f"{a}->{b}" for a, b in missing_edges),
                "false_positive_edges": sorted(f"{a}->{b}" for a, b in false_positive_edges),
                "mark_values": mark_values,
                "rid_values": rid_values,
                "mark_consistent": mark_consistent,
                "rid_consistent": rid_consistent,
                "covered_expected_business_spans": covered_expected_business_spans,
                "exact_business_spans": covered_expected_business_spans,
                "trace_assignment_ok": trace_assignment_ok,
                "trace_exact": trace_exact,
            }
        )

    successful = [item for item in per_trace if item.get("status") == "ok"]
    exact_count = full_trace_correct
    span_capture_missing_traces = [item for item in successful if item.get("span_capture_missing")]
    span_pairing_error_traces = [item for item in successful if item.get("span_pairing_error")]
    parent_child_precision = (
        parent_child_correct_predicted_total / parent_child_predicted_total
        if parent_child_predicted_total else 0.0
    )
    parent_child_recall = (
        parent_child_recall_correct_total / parent_child_ground_truth_total
        if parent_child_ground_truth_total else 0.0
    )
    parent_child_f1 = (
        2.0 * parent_child_precision * parent_child_recall / (parent_child_precision + parent_child_recall)
        if parent_child_precision + parent_child_recall > 0.0 else 0.0
    )
    report = {
        "load_report": args.load_report,
        "rows": None,
        "use_deepflow_app_tracing": True,
        "deepflow_app_url": args.deepflow_app_url,
        "namespace": args.namespace,
        "expected_edges": sorted(f"{a}->{b}" for a, b in expected_edges),
        "expected_edge_span_counts": {
            f"{a}->{b}": expected_count_for((a, b), expected_edge_counts, args.expected_spans_per_edge)
            for a, b in sorted(expected_edges)
        },
        "anchor_edge": f"{anchor_edge[0]}->{anchor_edge[1]}",
        "requested_count": len(expected_marks),
        "load_completed": load_report.get("completed"),
        "load_errors": load_report.get("errors"),
        "query_rows": len(rows_by_id),
        "anchor_marks_found": len(set(expected_marks) & set(anchors)),
        "max_iteration": args.max_iteration,
        "network_delay_us": args.network_delay_us,
        "trace_concurrency": max(1, args.trace_concurrency),
        "expected_spans_per_edge": args.expected_spans_per_edge,
        "deepflow_trace_success_count": len(successful),
        "l7_tracing_error_count": sum(1 for item in per_trace if item.get("status") == "l7_tracing_error"),
        "trace_exact_count": exact_count,
        "trace_exact_pct_of_requested": round(100.0 * exact_count / len(expected_marks), 4),
        "accuracy_pct": round(100.0 * full_trace_correct / len(expected_marks), 4),
        "accuracy_ok": full_trace_correct,
        "root_trace_count": len(expected_marks),
        "full_trace_accuracy_pct": round(100.0 * full_trace_correct / len(expected_marks), 4),
        "full_trace_accuracy_ok": full_trace_correct,
        "full_trace_accuracy_total": len(expected_marks),
        "trace_assignment_accuracy_pct": round(100.0 * trace_assignment_correct / len(expected_marks), 4),
        "trace_assignment_accuracy_ok": trace_assignment_correct,
        "trace_assignment_accuracy_total": len(expected_marks),
        "span_accuracy_pct": round(100.0 * span_correct_total / span_ground_truth_total, 4) if span_ground_truth_total else 0.0,
        "span_accuracy_ok": span_correct_total,
        "span_accuracy_total": span_ground_truth_total,
        "coverage_pct": round(100.0 * span_coverage_total / span_ground_truth_total, 4) if span_ground_truth_total else 0.0,
        "coverage_ok": span_coverage_total,
        "coverage_total": span_ground_truth_total,
        "unpredicted_event_count": max(0, span_ground_truth_total - span_coverage_total),
        "parent_child_edge_precision_pct": round(parent_child_precision * 100.0, 4),
        "parent_child_edge_recall_pct": round(parent_child_recall * 100.0, 4),
        "parent_child_edge_f1_pct": round(parent_child_f1 * 100.0, 4),
        "parent_child_edge_correct": parent_child_recall_correct_total,
        "parent_child_edge_correct_predicted": parent_child_correct_predicted_total,
        "parent_child_edge_predicted": parent_child_predicted_total,
        "parent_child_edge_ground_truth": parent_child_ground_truth_total,
        "parent_child_edge_false_positive": max(0, parent_child_predicted_total - parent_child_correct_predicted_total),
        "parent_child_edge_false_negative": max(0, parent_child_ground_truth_total - parent_child_recall_correct_total),
        "parent_child_edge_unpredicted": max(0, parent_child_ground_truth_total - span_coverage_total),
        "mark_consistent_count": sum(1 for item in successful if item.get("mark_consistent")),
        "rid_consistent_count": sum(1 for item in successful if item.get("rid_consistent")),
        "covered_expected_business_spans_count": sum(1 for item in successful if item.get("covered_expected_business_spans")),
        "exact_business_spans_count": sum(1 for item in successful if item.get("exact_business_spans")),
        "business_span_count_distribution": dict(sorted(Counter(item.get("business_span_count") for item in successful).items())),
        "captured_business_span_count_distribution": dict(sorted(Counter(item.get("captured_business_span_count") for item in successful).items())),
        "span_capture_missing_trace_count": len(span_capture_missing_traces),
        "span_capture_missing_total_spans": sum(item.get("capture_missing_span_count", 0) for item in successful),
        "span_pairing_error_trace_count": len(span_pairing_error_traces),
        "span_pairing_missing_total_spans": sum(item.get("pairing_missing_span_count", 0) for item in successful),
        "span_pairing_extra_total_spans": sum(item.get("pairing_extra_span_count", 0) for item in successful),
        "wrong_mark_span_count": sum(item.get("wrong_mark_span_count", 0) for item in successful),
        "deepflow_flow_count_avg": mean([item["deepflow_flow_count"] for item in successful]),
        "reconstruction_time_seconds_avg": mean(reconstruction_durations),
        "reconstruction_time_seconds_max": round(max(reconstruction_durations), 4) if reconstruction_durations else None,
        "elapsed_seconds": round(time.time() - started_at, 4),
        "sql": sql,
        "per_trace": per_trace,
    }

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False))

    print(f"rows: {report['query_rows']}")
    print(f"anchors: {report['anchor_marks_found']}/{report['requested_count']}")
    print(f"deepflow_trace_success: {report['deepflow_trace_success_count']}/{report['requested_count']}")
    print(f"FullTraceAcc: {report['full_trace_accuracy_ok']}/{report['full_trace_accuracy_total']} ({report['full_trace_accuracy_pct']:.2f}%)")
    print(
        "TraceAssignment / Span / Coverage / ParentEdgeF1: "
        f"{report['trace_assignment_accuracy_pct']:.2f}% / "
        f"{report['span_accuracy_pct']:.2f}% / "
        f"{report['coverage_pct']:.2f}% / "
        f"{report['parent_child_edge_f1_pct']:.2f}%"
    )
    print(f"trace_exact: {report['trace_exact_count']}/{report['requested_count']} ({report['trace_exact_pct_of_requested']:.2f}%)")
    print(f"business_span_distribution: {report['business_span_count_distribution']}")
    print(
        "span_capture_missing: "
        f"{report['span_capture_missing_trace_count']} traces, "
        f"{report['span_capture_missing_total_spans']} spans"
    )
    print(
        "span_pairing_error: "
        f"{report['span_pairing_error_trace_count']} traces, "
        f"missing={report['span_pairing_missing_total_spans']} "
        f"extra={report['span_pairing_extra_total_spans']} "
        f"wrong_mark={report['wrong_mark_span_count']}"
    )
    print(
        f"deepflow_l7tracing_avg={report['reconstruction_time_seconds_avg']}s "
        f"max={report['reconstruction_time_seconds_max']}s"
    )
    print(
        f"trace_concurrency={report['trace_concurrency']} "
        f"l7_tracing_errors={report['l7_tracing_error_count']}"
    )
    print(f"report: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
