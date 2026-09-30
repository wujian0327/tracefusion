"""Controlled workload: HTTP boundaries, SQLite query gateway, independent oracle.

Boundary logs are instrumented smoke-test inputs, NOT non-intrusive capture.
The response observation ID identifies one exchange only; it is never propagated.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import random
import signal
import sqlite3
import threading
import time
import uuid

from common import ADDRESSES, ROLES, SCENARIOS, append_json, call, node


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=ROLES, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-delay-ms", type=float, default=25)
    parser.add_argument("--postprocess-ms", type=float, default=80)
    parser.add_argument("--branch-delay-ms", type=float, default=100)
    args = parser.parse_args()
    rng = random.Random(args.seed + ROLES.index(args.role))
    random_lock = threading.Lock()
    # Thread-local connections below all access this on-disk database.
    db_path = args.run_dir / "oracle" / "fixture.sqlite"
    if args.role == "store":
        with sqlite3.connect(db_path) as db:
            db.execute("CREATE TABLE users (user_id TEXT PRIMARY KEY, phone TEXT)")
            db.executemany("INSERT INTO users VALUES (?, ?)", [
                ("u17", "SYNTH-PHONE-0017"),
                ("u29", "SYNTH-PHONE-0017"),
                ("u88", "SYNTH-PHONE-0088"),
            ])

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *unused):
            pass

        def send_json(self, status, body, event_id=None):
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Connection", "close")
            if event_id:
                self.send_header("X-Observation-ID", event_id)
            self.end_headers()
            self.wfile.write(raw)
            self.wfile.flush()
            self.close_connection = True

        def do_GET(self):
            self.send_json(200 if self.path == "/health" else 404, {"ok": self.path == "/health"})

        def do_POST(self):
            started = time.time_ns()
            event_id = uuid.uuid4().hex
            children, flows, source = [], [], None
            postprocess_delay = branch_delay = 0.0
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 8192:
                    raise ValueError("invalid request size")
                request = json.loads(self.rfile.read(length))
                uid = request["user_id"]
                if uid not in {"u17", "u29", "u88"}:
                    raise ValueError("unknown fixture user")
                with random_lock:
                    delay = rng.uniform(0, args.max_delay_ms) / 1000
                    choose_decoy = bool(rng.getrandbits(1))
                time.sleep(delay)
                if args.role == "api":
                    scenario = self.path.removeprefix("/case/")
                    if scenario not in SCENARIOS or not self.path.startswith("/case/"):
                        raise ValueError("unknown scenario")
                    if scenario.startswith("decoy_"):
                        other_uid = "u29" if scenario.endswith("_same") else "u88"
                        decoy_path = "/lookup_slow" if scenario.startswith("decoy_unbalanced_") else "/lookup"
                        with ThreadPoolExecutor(max_workers=2) as pool:
                            first = pool.submit(call, "api", "profile", args.port, "/lookup", {"user_id": uid})
                            other = pool.submit(call, "api", "decoy", args.port, decoy_path, {"user_id": other_uid})
                            a, b = first.result(), other.result()
                        children = [a[1], b[1]]
                        # Deliberately hidden selection: this is oracle-only state.
                        # For same-valued results the selected source cannot be
                        # uniquely determined from the exported observations.
                        result, selected = b if choose_decoy else a
                    else:
                        path = "/lookup_postprocess" if scenario == "postprocess" else "/lookup"
                        result, selected = call("api", "profile", args.port, path, {"user_id": uid})
                        children = [selected]
                    body = {"phone": result["phone"]}
                    flows = [{"from": node(selected), "to": node(event_id)}]
                elif args.role in {"profile", "decoy"}:
                    if self.path not in {"/lookup", "/lookup_postprocess", "/lookup_slow"}:
                        raise ValueError("unknown operation")
                    with random_lock:
                        if self.path == "/lookup_postprocess":
                            postprocess_delay = rng.uniform(0, args.postprocess_ms) / 1000
                        elif self.path == "/lookup_slow":
                            branch_delay = rng.uniform(args.branch_delay_ms / 2, args.branch_delay_ms) / 1000
                    if branch_delay:
                        time.sleep(branch_delay)
                    result, selected = call(args.role, "store", args.port, "/query", {"user_id": uid})
                    # Simulate work/wait after the read; not a CPU-overhead benchmark.
                    if postprocess_delay:
                        time.sleep(postprocess_delay)
                    children = [selected]
                    body = {"phone": result["phone"]}
                    flows = [{"from": node(selected), "to": node(event_id)}]
                else:
                    if self.path != "/query":
                        raise ValueError("unknown operation")
                    with sqlite3.connect(db_path) as db:
                        row = db.execute("SELECT phone FROM users WHERE user_id = ?", (uid,)).fetchone()
                    body = {"phone": row[0]}
                    source = {"node": node(event_id), "table": "users", "row": uid, "column": "phone"}
                # Record actual dependency decisions, never infer them from time.
                append_json(args.run_dir / "oracle" / f"{args.role}.jsonl", {
                    "event_id": event_id, "call_children": children,
                    "flow_edges": flows, "source": source,
                    "injected_postprocess_ms": postprocess_delay * 1000,
                    "injected_branch_delay_ms": branch_delay * 1000,
                })
                self.send_json(200, body, event_id)
                append_json(args.run_dir / "oracle" / "boundary" / f"{args.role}.jsonl", {
                    "event_id": event_id,
                    "caller": next((r for r, ip in ADDRESSES.items() if ip == self.client_address[0]), "unknown"),
                    "callee": args.role, "operation": self.path,
                    "start_ns": started, "end_ns": time.time_ns(),
                    "request": request, "response": body,
                })
            except Exception as exc:
                append_json(args.run_dir / "oracle" / "errors.jsonl", {
                    "role": args.role, "error": str(exc), "event_id": event_id,
                })
                self.send_json(500, {"error": "benchmark operation failed"})

    server = ThreadingHTTPServer((ADDRESSES[args.role], args.port), Handler)
    server.daemon_threads = False
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=server.shutdown).start())
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
