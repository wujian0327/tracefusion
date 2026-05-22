#!/usr/bin/env python3
"""Evaluate DeepFlow L7FlowTracing with the original app algorithm in batch.

This script keeps DeepFlow's upstream Python tracing algorithm from
``deepflow-app-source/application/l7_flow_tracing.py`` and replaces only
the data access layer: instead of calling ``/L7FlowTracing`` once per request,
it loads the whole experiment window once and serves DeepFlow's iterative
queries from an in-memory DataFrame.
"""

from __future__ import annotations

import argparse
import asyncio
import concurrent.futures
import importlib
import json
import math
import multiprocessing as mp
import re
import sys
import time
import types
import urllib.parse
import traceback
from collections import Counter
from pathlib import Path

import pandas as pd

import evaluate_deepflow_trace as ev


_WORKER_DEEPFLOW_MODULE = None
_WORKER_STORE = None
_WORKER_ARGS = None


APP_FIELDS = [
    "toString(_id) AS deepflow_id",
    "_id",
    "toUnixTimestamp(time) AS time",
    "toUnixTimestamp64Micro(start_time) AS start_time_us",
    "toUnixTimestamp64Micro(end_time) AS end_time_us",
    "signal_source",
    "type",
    "protocol",
    "l7_protocol",
    "Enum(l7_protocol)",
    "l7_protocol_str",
    "req_tcp_seq",
    "resp_tcp_seq",
    "vtap_id",
    "tap_side",
    "Enum(tap_side)",
    "flow_id",
    "syscall_trace_id_request",
    "syscall_trace_id_response",
    "syscall_cap_seq_0",
    "syscall_cap_seq_1",
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
    "response_status",
    "response_code",
    "response_exception",
    "response_result",
    "response_duration",
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
    "process_id_0",
    "process_id_1",
    "app_service",
    "app_instance",
    "is_tls",
    "is_async",
    "server_port",
    "ip_0",
    "ip_1",
    "subnet_id_0",
    "subnet_id_1",
    "subnet_0",
    "subnet_1",
    "resource_from_vtap",
    "tap",
    "attribute",
]

STRING_DEFAULTS = {
    "trace_id",
    "span_id",
    "parent_span_id",
    "x_request_id_0",
    "x_request_id_1",
    "http_proxy_client",
    "version",
    "endpoint",
    "request_type",
    "request_domain",
    "request_resource",
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
    "app_service",
    "app_instance",
    "ip_0",
    "ip_1",
    "subnet_0",
    "subnet_1",
    "resource_from_vtap",
    "tap",
    "tap_port_name",
    "tap_port_type",
    "Enum(tap_side)",
    "Enum(l7_protocol)",
    "l7_protocol_str",
    "attribute",
}


class AttrDict(dict):
    def __getattr__(self, key: str):
        return self.get(key)

    def __setattr__(self, key: str, value):
        self[key] = value


def install_deepflow_app_import_stubs(app_source: Path, cfg_values: dict):
    config_module = types.ModuleType("config")
    config = types.SimpleNamespace(**cfg_values)
    config_module.config = config
    sys.modules["config"] = config_module

    id_gen_module = types.ModuleType("opentelemetry.sdk.trace.id_generator")

    class RandomIdGenerator:
        def generate_span_id(self):
            return 1

    id_gen_module.RandomIdGenerator = RandomIdGenerator
    sys.modules.setdefault("opentelemetry", types.ModuleType("opentelemetry"))
    sys.modules.setdefault("opentelemetry.sdk", types.ModuleType("opentelemetry.sdk"))
    sys.modules.setdefault("opentelemetry.sdk.trace", types.ModuleType("opentelemetry.sdk.trace"))
    sys.modules["opentelemetry.sdk.trace.id_generator"] = id_gen_module

    log_module = types.ModuleType("log")

    class LoggerFactory:
        @staticmethod
        def getLogger(name):
            import logging

            return logging.getLogger(name)

    log_module.logger = LoggerFactory
    sys.modules["log"] = log_module

    utils_module = types.ModuleType("common.utils")

    async def curl_perform(*_args, **_kwargs):
        return {}, 500

    def inner_defaultdict_int():
        from collections import defaultdict

        return defaultdict(int)

    utils_module.curl_perform = curl_perform
    utils_module.inner_defaultdict_int = inner_defaultdict_int
    sys.modules["common.utils"] = utils_module

    querier_module = types.ModuleType("data.querier_client")

    class Querier:
        pass

    querier_module.Querier = Querier
    sys.modules["data.querier_client"] = querier_module

    source_path = str(app_source.resolve())
    if source_path not in sys.path:
        sys.path.insert(0, source_path)

    return importlib.import_module("application.l7_flow_tracing")


def sql_quote_like(value: str) -> str:
    return "'%" + value.replace("'", "''") + "%'"


def build_window_sql(start_ts: int, end_ts: int, limit: int, mark_prefix: str | None) -> str:
    where = [f"time >= {start_ts}", f"time <= {end_ts}"]
    if mark_prefix:
        needle = sql_quote_like(mark_prefix)
        where.append(f"(attribute LIKE {needle} OR request_resource LIKE {needle})")
    return (
        "SELECT "
        + ", ".join(APP_FIELDS)
        + " FROM l7_flow_log WHERE "
        + " AND ".join(where)
        + " ORDER BY time ASC, start_time ASC "
        + f"LIMIT {limit}"
    )


def split_sql_values(value: str) -> list[str]:
    values = []
    for item in value.split(","):
        item = item.strip().strip("'").strip('"')
        if item:
            values.append(item)
    return values


def trace_id_intersects(series: pd.Series, trace_ids: set[str]) -> pd.Series:
    def has_match(value) -> bool:
        return bool({item.strip() for item in str(value or "").split(",") if item.strip()} & trace_ids)

    return series.map(has_match)


def coerce_values_for_series(series: pd.Series, values: list[str]) -> list:
    if pd.api.types.is_numeric_dtype(series):
        out = []
        for value in values:
            try:
                out.append(int(value))
            except ValueError:
                try:
                    out.append(float(value))
                except ValueError:
                    pass
        return out
    return values


def union_indexes(indexes: list[pd.Index], empty: pd.Index) -> pd.Index:
    if not indexes:
        return empty
    values: set[int] = set()
    for index in indexes:
        values.update(int(item) for item in index)
    return pd.Index(sorted(values), dtype="int64")


def ensure_deepflow_columns(df: pd.DataFrame, return_fields: list[str] | None = None) -> pd.DataFrame:
    df = df.copy()
    fields = set(return_fields or [])
    fields.update(
        {
            "_id",
            "_querier_region",
            "time",
            "start_time_us",
            "end_time_us",
            "signal_source",
            "type",
            "protocol",
            "l7_protocol",
            "req_tcp_seq",
            "resp_tcp_seq",
            "vtap_id",
            "tap_side",
            "flow_id",
            "syscall_trace_id_request",
            "syscall_trace_id_response",
            "syscall_cap_seq_0",
            "syscall_cap_seq_1",
            "trace_id",
            "span_id",
            "parent_span_id",
            "x_request_id_0",
            "x_request_id_1",
            "request_id",
            "response_duration",
            "is_async",
        }
    )
    for field in fields:
        if field not in df.columns:
            df[field] = "" if field in STRING_DEFAULTS else 0
    if "_querier_region" not in df.columns:
        df["_querier_region"] = "local"
    for field in STRING_DEFAULTS & set(df.columns):
        df[field] = df[field].fillna("").astype(str)
    for field in set(df.columns) - STRING_DEFAULTS:
        if field in {"_querier_region"}:
            continue
        df[field] = df[field].where(df[field].notna(), 0)
    if "time" in df.columns:
        numeric_time = pd.to_numeric(df["time"], errors="coerce")
        if "start_time_us" in df.columns:
            start_seconds = pd.to_numeric(df["start_time_us"], errors="coerce") // 1_000_000
            numeric_time = numeric_time.fillna(start_seconds)
        df["time"] = numeric_time.fillna(0).astype(int)
    if "response_duration" in df.columns:
        missing = df["response_duration"].isna() | (df["response_duration"] == 0)
        df.loc[missing, "response_duration"] = df.loc[missing, "end_time_us"] - df.loc[missing, "start_time_us"]
    return df


class LocalFlowStore:
    INDEXED_FIELDS = {
        "_id",
        "trace_id",
        "req_tcp_seq",
        "resp_tcp_seq",
        "syscall_trace_id_request",
        "syscall_trace_id_response",
        "x_request_id_0",
        "x_request_id_1",
        "request_id",
    }

    def __init__(self, rows: pd.DataFrame):
        self.all_rows = ensure_deepflow_columns(rows).reset_index(drop=True)
        self.all_index = pd.Index(self.all_rows.index, dtype="int64")
        self.empty_index = pd.Index([], dtype="int64")
        self.field_indexes: dict[str, dict[object, pd.Index]] = {}
        self.id_to_pos = {
            str(value): int(pos)
            for pos, value in enumerate(self.all_rows["_id"].astype(str))
        }

    def positions_for_ids(self, ids: set[str]) -> pd.Index:
        positions = [self.id_to_pos[item] for item in ids if item in self.id_to_pos]
        return pd.Index(sorted(positions), dtype="int64") if positions else self.empty_index

    def field_index(self, field: str) -> dict[object, pd.Index]:
        if field in self.field_indexes:
            return self.field_indexes[field]
        buckets: dict[object, list[int]] = {}
        if field not in self.all_rows.columns:
            self.field_indexes[field] = {}
            return self.field_indexes[field]

        series = self.all_rows[field]
        if field == "trace_id":
            for pos, value in series.items():
                for token in str(value or "").split(","):
                    token = token.strip()
                    if token:
                        buckets.setdefault(token, []).append(int(pos))
        else:
            for pos, value in series.items():
                if pd.isna(value):
                    continue
                if isinstance(value, str):
                    if not value:
                        continue
                    key: object = value
                else:
                    try:
                        if float(value) == 0.0:
                            continue
                    except (TypeError, ValueError):
                        pass
                    key = value
                buckets.setdefault(key, []).append(int(pos))

        self.field_indexes[field] = {
            key: pd.Index(values, dtype="int64")
            for key, values in buckets.items()
        }
        return self.field_indexes[field]

    def positions_for_field_values(self, field: str, values: list[str]) -> pd.Index:
        if field not in self.INDEXED_FIELDS or field not in self.all_rows.columns:
            return self.empty_index
        coerced_values = coerce_values_for_series(self.all_rows[field], values)
        index = self.field_index(field)
        return union_indexes([index[value] for value in coerced_values if value in index], self.empty_index)

    def time_positions(self, positions: pd.Index, time_filter: str) -> pd.Index:
        if len(positions) == 0:
            return self.empty_index
        lower = re.search(r"time\s*>=\s*(\d+)", time_filter or "")
        upper = re.search(r"time\s*<=\s*(\d+)", time_filter or "")
        if not lower and not upper:
            return positions
        times = self.all_rows.loc[positions, "time"].astype(int)
        mask = pd.Series(True, index=positions)
        if lower:
            mask &= times >= int(lower.group(1))
        if upper:
            mask &= times <= int(upper.group(1))
        return pd.Index(mask.index[mask.to_numpy()], dtype="int64")

    def eq_positions(self, positions: pd.Index, field: str, value: int) -> pd.Index:
        if len(positions) == 0 or field not in self.all_rows.columns:
            return self.empty_index
        series = self.all_rows.loc[positions, field].astype(int)
        return pd.Index(series.index[series.to_numpy() == value], dtype="int64")


class LocalL7FlowTracing:
    def __init__(self, deepflow_module, args: AttrDict, store: LocalFlowStore):
        self.impl = deepflow_module.L7FlowTracing(args, headers={})
        self.impl.query_flowmetas = self.query_flowmetas
        self.impl.query_all_flows = self.query_all_flows
        self.store = store
        self.all_rows = store.all_rows
        self.config = deepflow_module.config

    async def query(self):
        return await self.impl.query()

    def _base_positions(self, base_filter: str) -> pd.Index:
        base_filter = base_filter or "1=1"
        if "1=0" in base_filter:
            return self.store.empty_index
        if base_filter.strip() == "1=1":
            return self.store.all_index

        id_match = re.search(r"(?<![\w])_id\s*=\s*'?(\d+)'?", base_filter)
        if id_match:
            positions = self.store.positions_for_ids({id_match.group(1)})
        else:
            indexes: list[pd.Index] = []
            fast_trace_in = re.search(r"FastFilter\(trace_id\)\s+IN\s*\(([^)]*)\)", base_filter, flags=re.I)
            if fast_trace_in:
                indexes.append(self.store.positions_for_field_values("trace_id", split_sql_values(fast_trace_in.group(1))))
            fast_trace_eq = re.search(r"FastFilter\(trace_id\)\s*=\s*'([^']*)'", base_filter, flags=re.I)
            if fast_trace_eq:
                indexes.append(self.store.positions_for_field_values("trace_id", [fast_trace_eq.group(1)]))

            for field, values_text in re.findall(r"\b([A-Za-z_][\w]*)\s+[Ii][Nn]\s*\(([^)]*)\)", base_filter):
                indexes.append(self.store.positions_for_field_values(field, split_sql_values(values_text)))

            positions = union_indexes(indexes, self.store.empty_index) if indexes else self.store.all_index

        for field in ("signal_source", "l7_protocol"):
            eq = re.search(rf"\b{field}\s*=\s*(\d+)", base_filter, flags=re.I)
            if eq:
                positions = self.store.eq_positions(positions, field, int(eq.group(1)))
        return positions

    async def query_flowmetas(self, time_filter: str, base_filter: str):
        positions = self.store.time_positions(self._base_positions(base_filter), time_filter)
        df = self.all_rows.loc[positions].head(int(self.config.l7_tracing_limit)).copy().reset_index(drop=True)
        fields = [
            "type",
            "signal_source",
            "req_tcp_seq",
            "resp_tcp_seq",
            "start_time_us",
            "end_time_us",
            "vtap_id",
            "protocol",
            "syscall_trace_id_request",
            "syscall_trace_id_response",
            "span_id",
            "parent_span_id",
            "request_id",
            "l7_protocol",
            "trace_id",
            "x_request_id_0",
            "x_request_id_1",
            "_id",
            "tap_side",
        ]
        return ensure_deepflow_columns(df, fields)[fields]

    async def query_all_flows(self, _time_filter: str, l7_flow_ids: list, return_fields: list):
        ids = {str(item) for item in l7_flow_ids}
        positions = self.store.positions_for_ids(ids)
        df = self.all_rows.loc[positions].copy()
        return_fields = list(dict.fromkeys([*return_fields, "_querier_region"]))
        df = ensure_deepflow_columns(df, return_fields)
        return df[return_fields].sort_values("start_time_us").reset_index(drop=True)


async def run_one_trace_local(deepflow_module, store: LocalFlowStore, args, index: int, mark: str, anchor_id: str):
    t0 = time.time()
    trace_args = AttrDict(
        {
            "_id": str(anchor_id),
            "time_start": args.start_ts,
            "time_end": args.end_ts,
            "has_attributes": 1,
            "max_iteration": args.max_iteration,
            "network_delay_us": args.network_delay_us,
            "host_clock_offset_us": args.host_clock_offset_us,
            "debug": False,
            "signal_sources": [],
        }
    )
    try:
        tracer = LocalL7FlowTracing(deepflow_module, trace_args, store)
        _status, response, _failed_regions = await tracer.query()
        selected_ids = {
            str(row_id)
            for trace in (response or {}).get("tracing", [])
            for row_id in (trace.get("_ids") or [])
        }
        return {
            "index": index,
            "mark": mark,
            "anchor_id": str(anchor_id),
            "status": "ok",
            "selected_ids": selected_ids,
            "duration": time.time() - t0,
        }
    except Exception as exc:  # keep one bad trace from aborting a sweep
        return {
            "index": index,
            "mark": mark,
            "anchor_id": str(anchor_id),
            "status": "local_tracing_error",
            "error": repr(exc),
            "traceback": traceback.format_exc(limit=8),
            "selected_ids": set(),
            "duration": time.time() - t0,
        }


def run_one_trace_process(item: tuple[int, str, str]):
    if _WORKER_DEEPFLOW_MODULE is None or _WORKER_STORE is None or _WORKER_ARGS is None:
        raise RuntimeError("local DeepFlow worker context was not initialized")
    return asyncio.run(run_one_trace_local(_WORKER_DEEPFLOW_MODULE, _WORKER_STORE, _WORKER_ARGS, *item))


def warm_flow_store_indexes(store: LocalFlowStore):
    for field in sorted(store.INDEXED_FIELDS):
        store.field_index(field)


async def run_local_trace(deepflow_module, store: LocalFlowStore, work_items: list[tuple[int, str, str]], args):
    results = {}
    if args.process_workers > 1 and work_items:
        global _WORKER_DEEPFLOW_MODULE, _WORKER_STORE, _WORKER_ARGS
        warm_flow_store_indexes(store)
        _WORKER_DEEPFLOW_MODULE = deepflow_module
        _WORKER_STORE = store
        _WORKER_ARGS = args
        context = mp.get_context("fork")
        with concurrent.futures.ProcessPoolExecutor(
            max_workers=args.process_workers,
            mp_context=context,
        ) as pool:
            for result in pool.map(run_one_trace_process, work_items, chunksize=max(1, len(work_items) // (args.process_workers * 8))):
                results[result["index"]] = result
        return results

    semaphore = asyncio.Semaphore(max(1, args.trace_concurrency))

    async def run_one(index: int, mark: str, anchor_id: str):
        async with semaphore:
            results[index] = await run_one_trace_local(deepflow_module, store, args, index, mark, anchor_id)

    await asyncio.gather(*(run_one(*item) for item in work_items))
    return results


def score_report(args, rows_by_id, rows_by_mark, anchors, trace_results, expected_marks, expected_edges, expected_edge_counts, anchor_edge, started_at):
    expected_occurrences_total = ev.total_expected_edge_occurrences(
        expected_edges, expected_edge_counts, args.expected_spans_per_edge
    )
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
                    "status": (trace_result or {}).get("status", "missing_local_tracing_result"),
                    "anchor_deepflow_id": "id-" + str(anchor.deepflow_id),
                    "error": (trace_result or {}).get("error"),
                    "traceback": (trace_result or {}).get("traceback"),
                }
            )
            span_ground_truth_total += expected_occurrences_total
            parent_child_ground_truth_total += expected_occurrences_total
            continue

        selected_ids = {str(row_id) for row_id in (trace_result.get("selected_ids") or set())}
        selected_rows = [rows_by_id[row_id] for row_id in selected_ids if row_id in rows_by_id]
        business_rows, edge_counts = ev.business_edge_counts(selected_rows, expected_edges)
        captured_rows = rows_by_mark.get(mark, [])
        captured_business_rows, captured_edge_counts = ev.business_edge_counts(captured_rows, expected_edges)
        mark_values = sorted({ev.mark_for(row) for row in selected_rows if ev.mark_for(row)})
        rid_values = sorted({rid for row in selected_rows for rid in [ev.extract_rid(row.request_resource)] if rid})
        observed_edges = {edge for edge, count in edge_counts.items() if edge and count > 0}
        missing_edges = expected_edges - observed_edges
        false_positive_edges = observed_edges - expected_edges
        covered_expected_business_spans = all(
            edge_counts[edge] >= ev.expected_count_for(edge, expected_edge_counts, args.expected_spans_per_edge)
            for edge in expected_edges
        )
        mark_consistent = not mark_values or mark_values == [mark]
        rid_consistent = not rid_values or rid_values == [mark]
        expected_occurrences = expected_occurrences_total
        correct_edge_counts = ev.correctly_marked_edge_counts(
            business_rows, expected_edges, mark, mark_consistent, rid_consistent
        )
        correct_edge_occurrences = ev.capped_correct_edge_occurrences(
            correct_edge_counts, expected_edges, expected_edge_counts, args.expected_spans_per_edge
        )
        correct_predicted_edge_occurrences = sum(correct_edge_counts[edge] for edge in expected_edges)
        covered_edge_occurrences = ev.capped_correct_edge_occurrences(
            edge_counts, expected_edges, expected_edge_counts, args.expected_spans_per_edge
        )
        predicted_edge_occurrences = sum(edge_counts[edge] for edge in expected_edges)
        deepflow_missing_span_count = ev.span_shortfall(
            edge_counts, expected_edges, expected_edge_counts, args.expected_spans_per_edge
        )
        deepflow_extra_span_count = ev.span_excess(
            edge_counts, expected_edges, expected_edge_counts, args.expected_spans_per_edge
        )
        capture_missing_span_count = ev.span_shortfall(
            captured_edge_counts, expected_edges, expected_edge_counts, args.expected_spans_per_edge
        )
        pairing_missing_span_count = ev.pairing_missing_spans(
            edge_counts, captured_edge_counts, expected_edges, expected_edge_counts, args.expected_spans_per_edge
        )
        selected_wrong_mark_span_count = ev.wrong_mark_span_count(selected_rows, mark)
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
                "anchor_deepflow_id": "id-" + str(anchor.deepflow_id),
                "deepflow_flow_count": len(selected_rows),
                "business_span_count": len(business_rows),
                "edge_span_counts": ev.edge_counts_dict(edge_counts, expected_edges),
                "correct_edge_span_counts": ev.edge_counts_dict(correct_edge_counts, expected_edges),
                "captured_business_span_count": len(captured_business_rows),
                "captured_edge_span_counts": ev.edge_counts_dict(captured_edge_counts, expected_edges),
                "expected_edge_occurrences": expected_occurrences,
                "correct_edge_occurrences": correct_edge_occurrences,
                "correct_predicted_edge_occurrences": correct_predicted_edge_occurrences,
                "covered_edge_occurrences": covered_edge_occurrences,
                "predicted_edge_occurrences": predicted_edge_occurrences,
                "deepflow_missing_span_count": deepflow_missing_span_count,
                "deepflow_extra_span_count": deepflow_extra_span_count,
                "capture_missing_span_count": capture_missing_span_count,
                "pairing_missing_span_count": pairing_missing_span_count,
                "pairing_extra_span_count": deepflow_extra_span_count,
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
    span_capture_missing_traces = [item for item in successful if item.get("span_capture_missing")]
    span_pairing_error_traces = [item for item in successful if item.get("span_pairing_error")]
    parent_child_precision = (
        parent_child_correct_predicted_total / parent_child_predicted_total if parent_child_predicted_total else 0.0
    )
    parent_child_recall = (
        parent_child_recall_correct_total / parent_child_ground_truth_total if parent_child_ground_truth_total else 0.0
    )
    parent_child_f1 = (
        2.0 * parent_child_precision * parent_child_recall / (parent_child_precision + parent_child_recall)
        if parent_child_precision + parent_child_recall > 0.0
        else 0.0
    )
    reconstruction_durations = [
        float(result["duration"]) for result in trace_results.values() if result.get("status") == "ok"
    ]
    return {
        "load_report": args.load_report,
        "use_deepflow_app_tracing": False,
        "use_deepflow_local_batch_tracing": True,
        "deepflow_app_source": args.deepflow_app_source,
        "namespace": args.namespace,
        "expected_edges": sorted(f"{a}->{b}" for a, b in expected_edges),
        "expected_edge_span_counts": {
            f"{a}->{b}": ev.expected_count_for((a, b), expected_edge_counts, args.expected_spans_per_edge)
            for a, b in sorted(expected_edges)
        },
        "anchor_edge": f"{anchor_edge[0]}->{anchor_edge[1]}",
        "requested_count": len(expected_marks),
        "query_rows": len(rows_by_id),
        "anchor_marks_found": len(set(expected_marks) & set(anchors)),
        "max_iteration": args.max_iteration,
        "network_delay_us": args.network_delay_us,
        "host_clock_offset_us": args.host_clock_offset_us,
        "trace_concurrency": max(1, args.trace_concurrency),
        "process_workers": max(1, args.process_workers),
        "expected_spans_per_edge": args.expected_spans_per_edge,
        "deepflow_trace_success_count": len(successful),
        "l7_tracing_error_count": sum(1 for item in per_trace if item.get("status") == "local_tracing_error"),
        "trace_exact_count": full_trace_correct,
        "trace_exact_pct_of_requested": round(100.0 * full_trace_correct / len(expected_marks), 4),
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
        "parent_child_edge_precision_pct": round(parent_child_precision * 100.0, 4),
        "parent_child_edge_recall_pct": round(parent_child_recall * 100.0, 4),
        "parent_child_edge_f1_pct": round(parent_child_f1 * 100.0, 4),
        "parent_child_edge_correct": parent_child_recall_correct_total,
        "parent_child_edge_correct_predicted": parent_child_correct_predicted_total,
        "parent_child_edge_predicted": parent_child_predicted_total,
        "parent_child_edge_ground_truth": parent_child_ground_truth_total,
        "business_span_count_distribution": dict(sorted(Counter(item.get("business_span_count") for item in successful).items())),
        "captured_business_span_count_distribution": dict(sorted(Counter(item.get("captured_business_span_count") for item in successful).items())),
        "span_capture_missing_trace_count": len(span_capture_missing_traces),
        "span_capture_missing_total_spans": sum(item.get("capture_missing_span_count", 0) for item in successful),
        "span_pairing_error_trace_count": len(span_pairing_error_traces),
        "span_pairing_missing_total_spans": sum(item.get("pairing_missing_span_count", 0) for item in successful),
        "span_pairing_extra_total_spans": sum(item.get("pairing_extra_span_count", 0) for item in successful),
        "wrong_mark_span_count": sum(item.get("wrong_mark_span_count", 0) for item in successful),
        "deepflow_flow_count_avg": ev.mean([item["deepflow_flow_count"] for item in successful]),
        "reconstruction_time_seconds_avg": ev.mean(reconstruction_durations),
        "reconstruction_time_seconds_max": round(max(reconstruction_durations), 4) if reconstruction_durations else None,
        "elapsed_seconds": round(time.time() - started_at, 4),
        "per_trace": per_trace,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--load-report", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--api-url", default="http://127.0.0.1:20416/v1/query/")
    parser.add_argument("--db", default="flow_log")
    parser.add_argument("--service-map", default=None)
    parser.add_argument("--namespace", default="hotel-http1")
    parser.add_argument("--mark-prefix", default=None)
    parser.add_argument("--expected-edges", default=ev.DEFAULT_EXPECTED_EDGES)
    parser.add_argument("--expected-edge-counts", default=None)
    parser.add_argument("--anchor-edge", default="productpage->details")
    parser.add_argument("--count", type=int, default=0)
    parser.add_argument("--query-timeout", type=int, default=60)
    parser.add_argument("--window-padding-seconds", type=int, default=30)
    parser.add_argument("--limit", type=int, default=500000)
    parser.add_argument("--max-iteration", type=int, default=6)
    parser.add_argument("--network-delay-us", type=int, default=50000)
    parser.add_argument("--host-clock-offset-us", type=int, default=10000)
    parser.add_argument("--trace-concurrency", type=int, default=8)
    parser.add_argument("--process-workers", type=int, default=1)
    parser.add_argument("--expected-spans-per-edge", type=int, default=4)
    parser.add_argument("--l7-tracing-limit", type=int, default=100)
    parser.add_argument(
        "--deepflow-app-source",
        default=str(Path(__file__).resolve().parent / "deepflow-app-source"),
    )
    args = parser.parse_args()

    started_at = time.time()
    load_report = json.loads(Path(args.load_report).read_text())
    requests = (load_report.get("requests") or [])[: args.count or None]
    if not requests:
        raise RuntimeError(f"No requests found in {args.load_report}")

    args.start_ts = int(min(float(item["start_time"]) for item in requests)) - args.window_padding_seconds
    args.end_ts = int(max(float(item["end_time"]) for item in requests)) + args.window_padding_seconds
    expected_marks = [item.get("mark") or item.get("rid") for item in requests]
    expected_edges = ev.parse_expected_edges(args.expected_edges)
    expected_edge_counts = ev.parse_expected_edge_counts(args.expected_edge_counts)
    if expected_edge_counts:
        expected_edges |= set(expected_edge_counts)
    anchor_edge = ev.parse_edge(args.anchor_edge)
    service_map = ev.load_service_map(args.service_map)

    # Keep the local algorithm close to DeepFlow's native L7FlowTracing path:
    # the anchor can be mark-filtered by the caller, but iterative expansion is
    # allowed to see every L7 row in the experiment window just like the app API.
    sql = build_window_sql(args.start_ts, args.end_ts, args.limit, None)
    raw_rows = ev.post_sql(args.api_url, args.db, sql, args.query_timeout)
    ev.apply_service_map(raw_rows, service_map)
    rows_by_id = {str(row["deepflow_id"]): ev.Row(row) for row in raw_rows}
    rows_by_mark: dict[str, list[ev.Row]] = {}
    for row in rows_by_id.values():
        row_mark = ev.mark_for(row)
        if row_mark:
            rows_by_mark.setdefault(row_mark, []).append(row)

    anchors: dict[str, ev.Row] = {}
    for row in rows_by_id.values():
        mark = ev.mark_for(row)
        if not mark or mark in anchors:
            continue
        if (row.pod_service_0, row.pod_service_1) == anchor_edge:
            anchors[mark] = row

    flow_store = LocalFlowStore(pd.DataFrame(raw_rows))
    cfg = {
        "max_iteration": args.max_iteration,
        "network_delay_us": args.network_delay_us,
        "host_clock_offset_us": args.host_clock_offset_us,
        "l7_tracing_limit": args.l7_tracing_limit,
        "allow_multiple_trace_ids_in_tracing_result": False,
        "call_apm_api_to_supplement_trace": False,
        "tracing_source": ["trace_id", "syscall", "tcp_seq", "x_request_id"],
        "span_set_connection_strategies": [],
        "iteration_expand_time_range": 0,
    }
    deepflow_module = install_deepflow_app_import_stubs(Path(args.deepflow_app_source), cfg)
    work_items = [
        (index, mark, str(anchors[mark].deepflow_id))
        for index, mark in enumerate(expected_marks)
        if mark and mark in anchors
    ]
    trace_results = asyncio.run(run_local_trace(deepflow_module, flow_store, work_items, args))
    report = score_report(
        args,
        rows_by_id,
        rows_by_mark,
        anchors,
        trace_results,
        expected_marks,
        expected_edges,
        expected_edge_counts,
        anchor_edge,
        started_at,
    )
    report["sql"] = sql
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

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
    print(f"business_span_distribution: {report['business_span_count_distribution']}")
    print(
        f"local_l7tracing_avg={report['reconstruction_time_seconds_avg']}s "
        f"max={report['reconstruction_time_seconds_max']}s "
        f"elapsed={report['elapsed_seconds']}s"
    )
    print(f"trace_concurrency={args.trace_concurrency} process_workers={args.process_workers}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
