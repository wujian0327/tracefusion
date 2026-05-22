#!/usr/bin/env python3
"""Uniformly paced preserve workload for the TrainTicket service."""

from __future__ import annotations

import argparse
import datetime as dt
import http.client
import json
import math
import queue
import random
import re
import statistics
import threading
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path


DEFAULT_CONTACT_ID = "auto"
TRAIN_TICKET_20_STATIONS: tuple[tuple[str, str], ...] = (
    ("shanghai", "Shang Hai"),
    ("shanghaihongqiao", "Shang Hai Hong Qiao"),
    ("suzhou", "Su Zhou"),
    ("wuxi", "Wu Xi"),
    ("changzhou", "Chang Zhou"),
    ("zhenjiang", "Zhen Jiang"),
    ("nanjing", "Nan Jing"),
    ("xuzhou", "Xu Zhou"),
    ("jinan", "Ji Nan"),
    ("beijing", "Bei Jing"),
    ("tianjin", "Tian Jin"),
    ("shijiazhuang", "Shi Jia Zhuang"),
    ("taiyuan", "Tai Yuan"),
    ("hangzhou", "Hang Zhou"),
    ("jiaxingnan", "Jia Xing Nan"),
    ("ningbo", "Ning Bo"),
    ("hefei", "He Fei"),
    ("wuhan", "Wu Han"),
    ("changsha", "Chang Sha"),
    ("guangzhou", "Guang Zhou"),
)


@dataclass(frozen=True)
class Job:
    index: int
    scheduled_at: float
    scheduled_time: float
    mark: str
    payload: dict[str, object]


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


def make_mark(prefix: str, index: int) -> str:
    return f"{prefix}-{index + 1:06d}"


def default_departure_date() -> str:
    return (dt.date.today() + dt.timedelta(days=1)).isoformat()


def choose_departure_date(index: int, base_date: dt.date, date_count: int, mode: str, rng: random.Random) -> str:
    if date_count <= 1 or mode == "fixed":
        offset = 0
    elif mode == "random":
        offset = rng.randrange(date_count)
    else:
        offset = index % date_count
    return (base_date + dt.timedelta(days=offset)).isoformat()


def parse_csv_values(value: str | None) -> list[str]:
    if not value:
        return []
    values = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        match = re.fullmatch(r"([A-Za-z]+)(\d+)-([A-Za-z]+)?(\d+)", item)
        if match:
            start_prefix, start_num, end_prefix, end_num = match.groups()
            end_prefix = end_prefix or start_prefix
            if start_prefix != end_prefix:
                raise SystemExit(f"trip id range prefixes differ: {item}")
            width = max(len(start_num), len(end_num))
            start = int(start_num)
            end = int(end_num)
            step = 1 if end >= start else -1
            values.extend(f"{start_prefix}{num:0{width}d}" for num in range(start, end + step, step))
        else:
            values.append(item)
    return values


def choose_trip_id(index: int, trip_ids: list[str], mode: str, rng: random.Random) -> str:
    if not trip_ids:
        raise SystemExit("at least one trip id is required")
    if len(trip_ids) == 1 or mode == "fixed":
        return trip_ids[0]
    if mode == "random":
        return rng.choice(trip_ids)
    return trip_ids[index % len(trip_ids)]


def train_ticket_20_station_pair(trip_id: str) -> tuple[str, str] | None:
    match = re.fullmatch(r"D(\d+)", trip_id)
    if not match:
        return None
    number = int(match.group(1))
    if number < 1345 or number > 1444:
        return None
    index = number - 1345
    start = TRAIN_TICKET_20_STATIONS[index % len(TRAIN_TICKET_20_STATIONS)]
    terminal = TRAIN_TICKET_20_STATIONS[(index + 2) % len(TRAIN_TICKET_20_STATIONS)]
    return start[1], terminal[1]


def parse_http_url(url: str, default_path: str) -> tuple[str, int, str, str]:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "http":
        raise SystemExit("only http:// URLs are supported")
    host = parsed.hostname or "localhost"
    port = parsed.port or 80
    host_header = f"{host}:{port}" if parsed.port else host
    path = parsed.path or default_path
    if parsed.query:
        path += "?" + parsed.query
    return host, port, host_header, path


def post_json(
    url: str,
    body: dict[str, object],
    headers: dict[str, str] | None = None,
    timeout: float = 10.0,
) -> tuple[int, bytes]:
    host, port, host_header, path = parse_http_url(url, "/")
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        req_headers = {
            "Host": host_header,
            "Content-Type": "application/json",
            "User-Agent": "trace-fusion-trainticket-load/1.0",
        }
        if headers:
            req_headers.update(headers)
        conn.request("POST", path, body=json.dumps(body), headers=req_headers)
        response = conn.getresponse()
        data = response.read()
        return response.status, data
    finally:
        conn.close()


def get_json(url: str, headers: dict[str, str] | None = None, timeout: float = 10.0) -> tuple[int, bytes]:
    host, port, host_header, path = parse_http_url(url, "/")
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        req_headers = {
            "Host": host_header,
            "User-Agent": "trace-fusion-trainticket-load/1.0",
        }
        if headers:
            req_headers.update(headers)
        conn.request("GET", path, headers=req_headers)
        response = conn.getresponse()
        data = response.read()
        return response.status, data
    finally:
        conn.close()


def login(auth_url: str, username: str, password: str, verification_code: str, timeout: float) -> tuple[str, str]:
    status, raw = post_json(
        auth_url,
        {
            "username": username,
            "password": password,
            "verificationCode": verification_code,
        },
        timeout=timeout,
    )
    if status < 200 or status >= 300:
        raise SystemExit(f"login failed with HTTP {status}: {raw[:200]!r}")
    try:
        payload = json.loads(raw.decode())
    except json.JSONDecodeError as exc:
        raise SystemExit(f"login returned non-JSON body: {raw[:200]!r}") from exc
    if payload.get("status") != 1:
        raise SystemExit(f"login failed: {payload}")
    data = payload.get("data") or {}
    token = data.get("token")
    user_id = data.get("userId")
    if not token or not user_id:
        raise SystemExit(f"login response missing token/userId: {payload}")
    return str(token), str(user_id)


def resolve_contact_id(contact_url: str, token: str, account_id: str, timeout: float) -> str:
    status, raw = get_json(
        contact_url.rstrip("/") + "/" + account_id,
        headers={"Authorization": "Bearer " + token},
        timeout=timeout,
    )
    if status < 200 or status >= 300:
        raise SystemExit(f"contact lookup failed with HTTP {status}: {raw[:200]!r}")
    try:
        payload = json.loads(raw.decode())
    except json.JSONDecodeError as exc:
        raise SystemExit(f"contact lookup returned non-JSON body: {raw[:200]!r}") from exc
    contacts = payload.get("data") or []
    if payload.get("status") != 1 or not contacts:
        raise SystemExit(f"contact lookup found no contacts: {payload}")
    contact_id = contacts[0].get("id")
    if not contact_id:
        raise SystemExit(f"first contact has no id: {payload}")
    return str(contact_id)


def make_payload(args: argparse.Namespace, account_id: str, index: int, rng: random.Random) -> dict[str, object]:
    base_date = dt.date.fromisoformat(args.date)
    trip_id = choose_trip_id(index, args.trip_ids, args.trip_mode, rng)
    station_pair = train_ticket_20_station_pair(trip_id) if args.station_mode == "trip" else None
    from_station, to_station = station_pair or (args.from_station, args.to_station)
    return {
        "accountId": account_id,
        "contactsId": args.contact_id,
        "tripId": trip_id,
        "seatType": args.seat_type,
        "date": choose_departure_date(index, base_date, args.date_count, args.date_mode, rng),
        "from": from_station,
        "to": to_station,
        "assurance": args.assurance,
        "foodType": args.food_type,
    }


def worker(
    worker_id: int,
    host: str,
    port: int,
    host_header: str,
    path: str,
    token: str,
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
        app_status: int | None = None
        app_msg = ""
        body_bytes = 0
        error = ""
        started_at = time.perf_counter()
        start_time = time.time()
        try:
            if conn is None:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)
            headers = {
                "Host": host_header,
                "User-Agent": "trace-fusion-trainticket-load/1.0",
                "Authorization": "Bearer " + token,
                "Content-Type": "application/json",
                "X-Mark": job.mark,
            }
            conn.request("POST", path, body=json.dumps(job.payload), headers=headers)
            response = conn.getresponse()
            status = response.status
            body = response.read()
            body_bytes = len(body)
            try:
                parsed = json.loads(body.decode())
                app_status = parsed.get("status")
                app_msg = str(parsed.get("msg", ""))
                if status and 200 <= status < 400 and app_status != 1:
                    error = f"app_status_{app_status}"
            except Exception:
                if status and 200 <= status < 400:
                    error = "invalid_json"
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
                    "app_status": app_status,
                    "app_msg": app_msg,
                    "bytes": body_bytes,
                    "error": error,
                    "date": str(job.payload.get("date", "")),
                    "trip_id": str(job.payload.get("tripId", "")),
                    "from_station": str(job.payload.get("from", "")),
                    "to_station": str(job.payload.get("to", "")),
                    "contact_id": str(job.payload.get("contactsId", "")),
                }
            )
        jobs.task_done()

    if conn is not None:
        conn.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "url",
        help=(
            "Preserve URL, for example http://127.0.0.1:14568 or "
            "http://127.0.0.1:14568/api/v1/preserveservice/preserve"
        ),
    )
    parser.add_argument("-c", "--connections", type=int, default=20)
    parser.add_argument("-d", "--duration", default="30s")
    parser.add_argument("-R", "--rate", type=float, default=100.0)
    parser.add_argument("--count", type=int, default=None)
    parser.add_argument("--mark-prefix", default="trainticket-preserve-xmark")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--json-out", default=None)
    parser.add_argument(
        "--queue-factor",
        type=int,
        default=1,
        help="Pending queue capacity as a multiple of connections.",
    )

    parser.add_argument("--auth-url", default="http://127.0.0.1:12340/api/v1/users/login")
    parser.add_argument("--contact-url", default="http://127.0.0.1:12347/api/v1/contactservice/contacts/account")
    parser.add_argument("--username", default="fdse_microservice")
    parser.add_argument("--password", default="111111")
    parser.add_argument("--verification-code", default="1234")
    parser.add_argument("--token", default=None, help="Reuse an existing JWT instead of logging in.")
    parser.add_argument("--account-id", default=None, help="Required when --token is used.")

    parser.add_argument("--contact-id", default=DEFAULT_CONTACT_ID, help="Contact UUID, or 'auto' to use the first contact for the logged-in account.")
    parser.add_argument("--trip-id", default="D1345")
    parser.add_argument(
        "--trip-ids",
        default=None,
        help="Comma-separated trip IDs to use per request. Defaults to --trip-id.",
    )
    parser.add_argument("--trip-mode", choices=["fixed", "round-robin", "random"], default="fixed")
    parser.add_argument("--seat-type", type=int, default=2)
    parser.add_argument("--date", default=default_departure_date())
    parser.add_argument("--date-count", type=int, default=1)
    parser.add_argument("--date-mode", choices=["fixed", "round-robin", "random"], default="fixed")
    parser.add_argument(
        "--station-mode",
        choices=["trip", "fixed"],
        default="trip",
        help="Use the D1345-D1444 20-station mapping, or always use --from-station/--to-station.",
    )
    parser.add_argument("--from-station", default="Shang Hai", help="Used when --station-mode=fixed or trip ID is outside D1345-D1444.")
    parser.add_argument("--to-station", default="Su Zhou", help="Used when --station-mode=fixed or trip ID is outside D1345-D1444.")
    parser.add_argument("--assurance", type=int, default=0)
    parser.add_argument("--food-type", type=int, default=0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.connections <= 0:
        raise SystemExit("--connections must be positive")
    if args.rate < 0:
        raise SystemExit("--rate must be non-negative")
    if args.date_count <= 0:
        raise SystemExit("--date-count must be positive")
    args.trip_ids = parse_csv_values(args.trip_ids) or [args.trip_id]
    if not args.trip_ids:
        raise SystemExit("at least one trip id is required")

    dt.date.fromisoformat(args.date)
    rng = random.Random(args.seed)
    host, port, host_header, path = parse_http_url(args.url, "/api/v1/preserveservice/preserve")
    duration_s = duration_to_seconds(args.duration)
    total_requests = max(0, args.count if args.count is not None else int(math.floor(args.rate * duration_s)))
    if args.count is not None and args.rate > 0:
        duration_s = total_requests / args.rate
    interval_s = 1.0 / args.rate if args.rate > 0 else duration_s

    if args.token:
        if not args.account_id:
            raise SystemExit("--account-id is required when --token is used")
        token = args.token
        account_id = args.account_id
    else:
        token, account_id = login(args.auth_url, args.username, args.password, args.verification_code, args.timeout)
    if args.contact_id == "auto":
        args.contact_id = resolve_contact_id(args.contact_url, token, account_id, args.timeout)

    max_queue = max(1, args.connections * max(1, args.queue_factor))
    jobs: queue.Queue[Job | None] = queue.Queue(maxsize=max_queue)
    results: list[dict[str, float | int | str | None]] = []
    results_lock = threading.Lock()

    threads = [
        threading.Thread(
            target=worker,
            args=(idx, host, port, host_header, path, token, args.timeout, jobs, results, results_lock),
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

        jobs.put(
            Job(
                index=index,
                scheduled_at=scheduled_at,
                scheduled_time=started_time + index * interval_s,
                mark=make_mark(args.mark_prefix, index),
                payload=make_payload(args, account_id, index, rng),
            )
        )

    jobs.join()
    ended_at = time.perf_counter()
    ended_time = time.time()
    for _ in threads:
        jobs.put(None)
    for thread in threads:
        thread.join(timeout=1.0)

    ok = [
        row
        for row in results
        if row["status"] and 200 <= int(row["status"]) < 400 and row["app_status"] == 1 and not row["error"]
    ]
    errors = [row for row in results if row not in ok]
    latencies = [float(row["latency_ms"]) for row in results]
    lags = [float(row["start_lag_ms"]) for row in results]
    starts = sorted(float(row["started_at"]) for row in results)
    gaps_ms = [(b - a) * 1000.0 for a, b in zip(starts, starts[1:])]
    elapsed_s = ended_at - started_at
    status_counts: dict[str, int] = {}
    app_status_counts: dict[str, int] = {}
    for row in results:
        status_key = str(row["status"]) if row["status"] is not None else "none"
        app_key = str(row["app_status"]) if row["app_status"] is not None else "none"
        status_counts[status_key] = status_counts.get(status_key, 0) + 1
        app_status_counts[app_key] = app_status_counts.get(app_key, 0) + 1

    report = {
        "url": args.url,
        "path": path,
        "auth_url": args.auth_url if not args.token else None,
        "connections": args.connections,
        "target_rate": args.rate,
        "duration_s": duration_s,
        "marker_header": "X-Mark",
        "mark_prefix": args.mark_prefix,
        "target_requests": total_requests,
        "count": total_requests,
        "completed_requests": len(results),
        "completed": len(results),
        "ok_requests": len(ok),
        "errors": len(errors),
        "status_counts": status_counts,
        "app_status_counts": app_status_counts,
        "unique_dates": len({str(row["date"]) for row in results}),
        "unique_trip_ids": len({str(row["trip_id"]) for row in results}),
        "unique_station_pairs": len({(str(row["from_station"]), str(row["to_station"])) for row in results}),
        "late_schedule_events": late_events,
        "started_at": started_time,
        "ended_at": ended_time,
        "elapsed_s": elapsed_s,
        "actual_requests_sec": len(results) / elapsed_s if elapsed_s else 0.0,
        "preserve": {
            "account_id": account_id,
            "contact_id": args.contact_id,
            "trip_id": args.trip_id,
            "trip_ids": args.trip_ids,
            "trip_mode": args.trip_mode,
            "station_mode": args.station_mode,
            "seat_type": args.seat_type,
            "date": args.date,
            "date_count": args.date_count,
            "date_mode": args.date_mode,
            "from_station": args.from_station,
            "to_station": args.to_station,
            "assurance": args.assurance,
            "food_type": args.food_type,
        },
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

    print(f"Uniform TrainTicket preserve load @ {args.url}")
    print(
        f"  {args.connections} connections, target {args.rate:.2f} requests/sec "
        f"for {duration_s:.2f}s"
    )
    route_label = (
        "D1345-D1444 20-station map"
        if args.station_mode == "trip"
        else f"{args.from_station}->{args.to_station}"
    )
    print(
        f"  trip_mode={args.trip_mode}, trips={','.join(args.trip_ids)}, "
        f"station_mode={args.station_mode}, "
        f"route={route_label}, "
        f"date_mode={args.date_mode}, date_count={args.date_count}"
    )
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
    print(f"App status counts: {app_status_counts}")
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
