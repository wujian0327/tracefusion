#!/usr/bin/env python3
"""Uniformly paced /productpage?id=N workload for the Bookinfo service."""

from __future__ import annotations

import argparse
import http.client
import json
import math
import queue
import random
import ssl
import statistics
import threading
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Job:
    index: int
    scheduled_at: float
    scheduled_time: float
    book_id: int
    mark: str
    path: str


def duration_to_seconds(value: str) -> float:
    value = value.strip().lower()
    if value.endswith("ms"):
        return float(value[:-2]) / 1000.0
    if value.endswith("s"):
        return float(value[:-1])
    if value.endswith("m"):
        return float(value[:-1]) * 60.0
    return float(value)


def percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[int((len(ordered) - 1) * q)]


def choose_book_id(index: int, book_count: int, mode: str, rng: random.Random) -> int:
    if book_count <= 0:
        return 0
    if mode == "random":
        return rng.randrange(book_count)
    return index % book_count


def make_productpage_path(base_path: str, base_query: str, book_id: int) -> str:
    params = urllib.parse.parse_qs(base_query, keep_blank_values=True)
    params["id"] = [str(book_id)]
    query = urllib.parse.urlencode(params, doseq=True)
    return base_path + ("?" + query if query else "")


def make_mark(prefix: str, index: int) -> str:
    return f"{prefix}-{index + 1:06d}"


def worker(
    worker_id: int,
    scheme: str,
    host: str,
    port: int,
    host_header: str,
    timeout: float,
    jobs: queue.Queue[Job | None],
    results: list[dict[str, float | int | str | None]],
    results_lock: threading.Lock,
) -> None:
    conn: http.client.HTTPConnection | None = None
    while True:
        job = jobs.get()
        if job is None:
            jobs.task_done()
            break

        status: int | None = None
        body_bytes = 0
        error = ""
        started_at = time.perf_counter()
        start_time = time.time()
        try:
            if conn is None:
                if scheme == "https":
                    context = ssl._create_unverified_context()
                    conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
                else:
                    conn = http.client.HTTPConnection(host, port, timeout=timeout)
            headers = {
                "Host": host_header,
                "User-Agent": "trace-fusion-bookinfo-load/1.0",
                "X-Mark": job.mark,
            }
            conn.request("GET", job.path, headers=headers)
            response = conn.getresponse()
            status = response.status
            body = response.read()
            body_bytes = len(body)
            if response.getheader("Connection", "").lower() == "close":
                conn.close()
                conn = None
        except Exception as exc:  # noqa: BLE001 - keep the load test running.
            error = type(exc).__name__
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
            conn = None
        ended_at = time.perf_counter()
        end_time = time.time()

        with results_lock:
            results.append(
                {
                    "index": job.index,
                    "worker": worker_id,
                    "book_id": job.book_id,
                    "mark": job.mark,
                    "trace_id": job.mark,
                    "span_id": job.mark,
                    "scheduled_at": job.scheduled_at,
                    "scheduled_time": job.scheduled_time,
                    "started_at": started_at,
                    "ended_at": ended_at,
                    "start_time": start_time,
                    "end_time": end_time,
                    "start_lag_ms": (started_at - job.scheduled_at) * 1000.0,
                    "latency_ms": (ended_at - started_at) * 1000.0,
                    "status": status,
                    "bytes": body_bytes,
                    "error": error,
                }
            )
        jobs.task_done()

    if conn is not None:
        conn.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "url",
        help="Base URL, for example http://127.0.0.1:9080 or https://127.0.0.1:9440/productpage",
    )
    parser.add_argument("-c", "--connections", type=int, default=20)
    parser.add_argument("-d", "--duration", default="30s")
    parser.add_argument("-R", "--rate", type=float, default=100.0)
    parser.add_argument("--count", type=int, default=None)
    parser.add_argument("--book-count", type=int, default=100)
    parser.add_argument("--id-mode", choices=["random", "round-robin"], default="random")
    parser.add_argument("--mark-prefix", default="bookinfo-xmark")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--json-out", default=None)
    parser.add_argument(
        "--queue-factor",
        type=int,
        default=1,
        help="Pending queue capacity as a multiple of connections.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    parsed = urllib.parse.urlparse(args.url)
    if parsed.scheme not in {"http", "https"}:
        raise SystemExit("only http:// and https:// URLs are supported")
    if args.connections <= 0:
        raise SystemExit("--connections must be positive")
    if args.rate < 0:
        raise SystemExit("--rate must be non-negative")

    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    host_header = f"{host}:{port}" if parsed.port else host
    base_path = parsed.path or "/productpage"
    duration_s = duration_to_seconds(args.duration)
    total_requests = max(0, args.count if args.count is not None else int(math.floor(args.rate * duration_s)))
    if args.count is not None and args.rate > 0:
        duration_s = total_requests / args.rate
    interval_s = 1.0 / args.rate if args.rate > 0 else duration_s
    rng = random.Random(args.seed)

    max_queue = max(1, args.connections * max(1, args.queue_factor))
    jobs: queue.Queue[Job | None] = queue.Queue(maxsize=max_queue)
    results: list[dict[str, float | int | str | None]] = []
    results_lock = threading.Lock()

    threads = [
        threading.Thread(
            target=worker,
            args=(idx, parsed.scheme, host, port, host_header, args.timeout, jobs, results, results_lock),
            daemon=True,
        )
        for idx in range(args.connections)
    ]

    started_at = time.perf_counter()
    started_time = time.time()
    for thread in threads:
        thread.start()

    late_events = 0
    for index in range(total_requests):
        scheduled_at = started_at + index * interval_s
        sleep_s = scheduled_at - time.perf_counter()
        if sleep_s > 0:
            time.sleep(sleep_s)
        else:
            late_events += 1

        book_id = choose_book_id(index, args.book_count, args.id_mode, rng)
        jobs.put(
            Job(
                index=index,
                scheduled_at=scheduled_at,
                scheduled_time=started_time + index * interval_s,
                book_id=book_id,
                mark=make_mark(args.mark_prefix, index),
                path=make_productpage_path(base_path, parsed.query, book_id),
            )
        )

    jobs.join()
    ended_at = time.perf_counter()
    ended_time = time.time()
    for _ in threads:
        jobs.put(None)
    for thread in threads:
        thread.join(timeout=1.0)

    ok = [row for row in results if row["status"] and 200 <= int(row["status"]) < 400]
    errors = [row for row in results if row["error"] or not row["status"] or int(row["status"]) >= 400]
    latencies = [float(row["latency_ms"]) for row in results]
    lags = [float(row["start_lag_ms"]) for row in results]
    starts = sorted(float(row["started_at"]) for row in results)
    gaps_ms = [(b - a) * 1000.0 for a, b in zip(starts, starts[1:])]
    elapsed_s = ended_at - started_at
    status_counts: dict[str, int] = {}
    for row in results:
        key = str(row["status"]) if row["status"] is not None else "none"
        status_counts[key] = status_counts.get(key, 0) + 1

    report = {
        "url": args.url,
        "base_path": base_path,
        "connections": args.connections,
        "target_rate": args.rate,
        "duration_s": duration_s,
        "book_count": args.book_count,
        "id_mode": args.id_mode,
        "marker_header": "X-Mark",
        "mark_prefix": args.mark_prefix,
        "target_requests": total_requests,
        "count": total_requests,
        "completed_requests": len(results),
        "completed": len(results),
        "ok_requests": len(ok),
        "errors": len(errors),
        "status_counts": status_counts,
        "unique_book_ids": len({int(row["book_id"]) for row in results}),
        "late_schedule_events": late_events,
        "started_at": started_time,
        "ended_at": ended_time,
        "elapsed_s": elapsed_s,
        "actual_requests_sec": len(results) / elapsed_s if elapsed_s else 0.0,
        "latency_ms": {
            "p50": percentile(latencies, 0.50),
            "p90": percentile(latencies, 0.90),
            "p99": percentile(latencies, 0.99),
        },
        "start_lag_ms": {
            "p50": percentile(lags, 0.50),
            "p90": percentile(lags, 0.90),
            "p99": percentile(lags, 0.99),
            "max": max(lags) if lags else 0.0,
        },
        "start_gap_ms": {
            "p50": percentile(gaps_ms, 0.50),
            "p90": percentile(gaps_ms, 0.90),
            "p99": percentile(gaps_ms, 0.99),
            "stdev": statistics.pstdev(gaps_ms) if len(gaps_ms) > 1 else 0.0,
        },
        "requests": sorted(results, key=lambda row: int(row["index"])),
    }

    print(f"Uniform Bookinfo load @ {args.url}")
    print(
        f"  {args.connections} connections, target {args.rate:.2f} requests/sec "
        f"for {duration_s:.2f}s"
    )
    print(f"  book ids: {args.id_mode} over 0..{max(args.book_count - 1, 0)}")
    print(f"  marker: X-Mark prefix={args.mark_prefix}")
    print(f"  {len(results)} requests in {elapsed_s:.2f}s")
    print(f"Requests/sec: {report['actual_requests_sec']:.2f}")
    print(
        "Latency ms: "
        f"p50={report['latency_ms']['p50']:.3f} "
        f"p90={report['latency_ms']['p90']:.3f} "
        f"p99={report['latency_ms']['p99']:.3f}"
    )
    print(
        "Start gap ms: "
        f"p50={report['start_gap_ms']['p50']:.3f} "
        f"p90={report['start_gap_ms']['p90']:.3f} "
        f"p99={report['start_gap_ms']['p99']:.3f} "
        f"stdev={report['start_gap_ms']['stdev']:.3f}"
    )
    print(
        "Start lag ms: "
        f"p50={report['start_lag_ms']['p50']:.3f} "
        f"p90={report['start_lag_ms']['p90']:.3f} "
        f"p99={report['start_lag_ms']['p99']:.3f} "
        f"max={report['start_lag_ms']['max']:.3f}"
    )
    print(f"Status counts: {status_counts}")
    print(f"Errors: {len(errors)}")

    if args.json_out:
        out_path = Path(args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
            f.write("\n")

    return 0 if len(errors) == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
