#!/usr/bin/env python3
"""Run the isolated synthetic provenance benchmark (Python 3.10+, Linux for pcap)."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "services" / "provenance_bench"
sys.path.insert(0, str(BENCH))
from common import ADDRESSES, ROLES, SCENARIOS, append_json, call, node, read_jsonl


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--requests", type=int, default=20, help="requests PER scenario")
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--scenario", choices=("all",) + SCENARIOS, default="all")
    parser.add_argument("--port", type=int, default=18780)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-delay-ms", type=float, default=25)
    parser.add_argument("--capture", choices=("boundary", "pcap"), default="boundary")
    args = parser.parse_args()
    if args.requests < 1 or not 1 <= args.concurrency <= 128 or args.max_delay_ms < 0:
        parser.error("requests >= 1, concurrency in [1,128], max-delay-ms >= 0 required")
    if not 1024 <= args.port <= 65535:
        parser.error("port must be in [1024,65535]")
    if args.capture == "pcap" and (not shutil.which("tcpdump") or not shutil.which("tshark")):
        parser.error("pcap mode needs tcpdump and tshark, plus permission to capture loopback")
    # Check all listeners before starting; never kill an existing service.
    checks = []
    try:
        for role in ROLES:
            sock = socket.socket()
            checks.append(sock)
            sock.bind((ADDRESSES[role], args.port))
    finally:
        for sock in checks:
            sock.close()
    run_dir = (args.output or ROOT / "result" / "provenance_bench" /
               datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")).resolve()
    run_dir.mkdir(parents=True, exist_ok=False)
    for name in ("observations", "oracle", "logs"):
        (run_dir / name).mkdir()
    scenarios = SCENARIOS if args.scenario == "all" else (args.scenario,)
    metadata = {"schema_version": 1, "status": "running", "capture_mode": args.capture,
                "seed": args.seed, "requests_per_scenario": args.requests,
                "concurrency": args.concurrency, "scenarios": list(scenarios),
                "max_delay_ms": args.max_delay_ms, "port": args.port,
                "python": sys.version, "benchmark": "synthetic-http-sqlite-gateway-v1"}
    processes, logs, capture = [], [], None
    try:
        for role in reversed(ROLES):
            log = (run_dir / "logs" / f"{role}.log").open("w")
            logs.append(log)
            process = subprocess.Popen([
                sys.executable, str(BENCH / "server.py"), "--role", role,
                "--port", str(args.port), "--run-dir", str(run_dir),
                "--seed", str(args.seed), "--max-delay-ms", str(args.max_delay_ms),
            ], stdout=log, stderr=subprocess.STDOUT)
            processes.append(process)
            deadline = time.monotonic() + 10
            while True:
                if process.poll() is not None:
                    raise RuntimeError(f"{role} failed to start; see logs/{role}.log")
                try:
                    call("loadgen", role, args.port, "/health")
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        raise RuntimeError(f"{role} health check timed out")
                    time.sleep(0.05)
        if args.capture == "pcap":
            capture_log_path = run_dir / "logs" / "tcpdump.log"
            log = capture_log_path.open("w")
            logs.append(log)
            capture = subprocess.Popen([
                "tcpdump", "-i", "lo", "-nn", "-s", "0", "-U",
                "-w", str(run_dir / "traffic.pcap"), "tcp", "port", str(args.port),
            ], stdout=log, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 10
            while "listening on" not in capture_log_path.read_text():
                if capture.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("tcpdump did not become ready; see logs/tcpdump.log")
                time.sleep(0.05)
        queries = []
        for scenario in scenarios:
            # Basic reference is serial; stress cases use the requested concurrency.
            workers = 1 if scenario == "basic" else args.concurrency

            def request(index):
                uid = "u29" if scenario == "same_value_concurrent" and index % 2 else "u17"
                body, event_id = call("loadgen", "api", args.port, f"/case/{scenario}", {"user_id": uid})
                if not event_id:
                    raise RuntimeError("sink response lacks observation ID")
                return {"query_id": f"{scenario}:{index}", "scenario": scenario,
                        "sink": node(event_id), "value": body["phone"]}

            with ThreadPoolExecutor(max_workers=workers) as pool:
                queries.extend(pool.map(request, range(args.requests)))
            print(f"completed {scenario}: {args.requests} requests", flush=True)
            time.sleep(0.05)
        # Services flush oracle and boundary records before normalizer/evaluator run.
        for process in processes:
            stop(process)
        if capture:
            time.sleep(0.1)
            capture.send_signal(signal.SIGINT)
            capture.wait(timeout=10)
            if capture.returncode != 0:
                raise RuntimeError("tcpdump failed; inspect capture log")
        errors = run_dir / "oracle" / "errors.jsonl"
        if errors.exists():
            raise RuntimeError("workload errors recorded in oracle/errors.jsonl")
        if args.capture == "pcap":
            from capture import from_pcap
            observations, metadata["capture_stats"] = from_pcap(run_dir / "traffic.pcap", args.port)
        else:
            observations = []
            for path in sorted((run_dir / "oracle" / "boundary").glob("*.jsonl")):
                observations.extend(read_jsonl(path))
            observations.sort(key=lambda r: (r["start_ns"], r["event_id"]))
        for record in observations:
            append_json(run_dir / "observations" / "events.jsonl", record)
        for query in queries:
            append_json(run_dir / "observations" / "queries.jsonl", query)
        expected = sum(args.requests * (5 if s.startswith("decoy_") else 3) for s in scenarios)
        event_ids = {e["event_id"] for e in observations}
        if len(event_ids) != len(observations):
            raise RuntimeError("duplicate observation IDs")
        metadata["observed_exchanges"] = len(observations)
        metadata["expected_exchanges"] = expected
        metadata["capture_complete"] = len(observations) == expected
        # All queries remain in the denominator even if pcap loses their events.
        subprocess.run([
            sys.executable, str(BENCH / "baseline.py"),
            "--observations", str(run_dir / "observations" / "events.jsonl"),
            "--queries", str(run_dir / "observations" / "queries.jsonl"),
            "--output", str(run_dir / "predictions.jsonl"),
        ], check=True)
        subprocess.run([
            sys.executable, str(BENCH / "evaluate.py"),
            "--queries", str(run_dir / "observations" / "queries.jsonl"),
            "--predictions", str(run_dir / "predictions.jsonl"),
            "--oracle-dir", str(run_dir / "oracle"), "--output", str(run_dir / "report.json"),
        ], check=True)
        subprocess.run([
            sys.executable, str(BENCH / "compare_baselines.py"), "--run-dir", str(run_dir),
        ], check=True)
        metadata["status"] = "complete"
        print(f"Results: {run_dir}")
        if not metadata["capture_complete"]:
            print("Capture is incomplete; missing exchanges were NOT filtered out.")
    except (Exception, KeyboardInterrupt) as exc:
        metadata.update(status="failed", error=str(exc) or "interrupted")
        raise
    finally:
        if capture:
            stop(capture)
        for process in processes:
            stop(process)
        for log in logs:
            log.close()
        (run_dir / "run.json").write_text(json.dumps(metadata, indent=2) + "\n")


if __name__ == "__main__":
    main()
