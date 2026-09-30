"""Replay four fixed variants on one run; evaluate only after predictions exist."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--profile", type=Path, default=HERE / "constraint_profile.json")
    parser.add_argument("--tolerance-ms", type=float, default=5)
    args = parser.parse_args()
    output = args.output_dir or args.run_dir / "comparison"
    output.mkdir(parents=True, exist_ok=False)
    observations = args.run_dir / "observations" / "events.jsonl"
    queries = args.run_dir / "observations" / "queries.jsonl"
    variants = {
        "value_time": None,
        "semantics": ["--disable-capacity"],
        "capacity": ["--disable-semantics"],
        "combined": [],
    }
    summary = {"status": "running", "tolerance_ms": args.tolerance_ms, "input_sha256": {}, "variants": {}, "timing_rankings": {}}
    try:
        for path in (observations, queries, args.profile):
            summary["input_sha256"][path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        # Every predictor is a separate process with only observations/queries/profile paths.
        # No evaluation result is consulted to choose parameters or candidates.
        for name, flags in variants.items():
            cmd = [sys.executable, str(HERE / ("baseline.py" if flags is None else "constrained.py")),
                   "--observations", str(observations), "--queries", str(queries),
                   "--output", str(output / f"{name}_predictions.jsonl"),
                   "--tolerance-ms", str(args.tolerance_ms)]
            if flags is not None:
                cmd += ["--profile", str(args.profile), "--diagnostics", str(output / f"{name}_diagnostics.json")] + flags
            subprocess.run(cmd, check=True)
        timing_modes = ("all_return", "single_child_return")
        for mode in timing_modes:
            subprocess.run([
                sys.executable, str(HERE / "timing_rank.py"), "--observations", str(observations),
                "--predictions", str(output / "combined_predictions.jsonl"),
                "--call-diagnostics", str(output / "combined_diagnostics.json"),
                "--output", str(output / f"timing_{mode}_predictions.jsonl"),
                "--diagnostics", str(output / f"timing_{mode}_diagnostics.json"), "--mode", mode,
            ], check=True)
        for name in variants:
            report_path = output / f"{name}_report.json"
            subprocess.run([
                sys.executable, str(HERE / "evaluate.py"), "--queries", str(queries),
                "--predictions", str(output / f"{name}_predictions.jsonl"),
                "--oracle-dir", str(args.run_dir / "oracle"), "--output", str(report_path),
            ], check=True, stdout=subprocess.DEVNULL)
            report = json.loads(report_path.read_text())
            compact = {k: report[k] for k in ("counts", "metrics", "by_scenario")}
            diagnostics = output / f"{name}_diagnostics.json"
            if diagnostics.exists():
                compact["fallback_components"] = json.loads(diagnostics.read_text())["fallback_components"]
            summary["variants"][name] = compact
            metrics = report["metrics"]
            print(f"{name}: exact_graph={metrics['exact_graph_rate']}, "
                  f"source_recall={metrics['source_recall']}, "
                  f"source_precision={metrics['source_precision']}", flush=True)
        for mode in timing_modes:
            report_path = output / f"timing_{mode}_report.json"
            subprocess.run([
                sys.executable, str(HERE / "evaluate_ranking.py"), "--queries", str(queries),
                "--predictions", str(output / f"timing_{mode}_predictions.jsonl"),
                "--oracle-dir", str(args.run_dir / "oracle"), "--output", str(report_path),
            ], check=True)
            report = json.loads(report_path.read_text())
            diagnostics = json.loads((output / f"timing_{mode}_diagnostics.json").read_text())
            report["unranked_components"] = diagnostics["unranked_components"]
            summary["timing_rankings"][mode] = report
            print(f"timing_{mode}: {report['top_tier']}", flush=True)
        summary["status"] = "complete"
        print(f"Comparison: {output.resolve() / 'summary.json'}")
    except (Exception, KeyboardInterrupt) as exc:
        summary.update(status="failed", error=str(exc) or "interrupted")
        raise
    finally:
        (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")


if __name__ == "__main__":
    main()
