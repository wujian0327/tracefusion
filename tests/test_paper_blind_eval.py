import csv
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("paper_blind_eval", ROOT / "scripts/paper_blind_eval.py")
workflow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(workflow)


class BlindWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)

    def source(self, labels=("truth-a", "truth-b"), orphan=False):
        rows = []
        for idx, label in enumerate(labels):
            business = f"book-{idx}"
            for edge, (client, server, start, end) in enumerate([
                ("outside:10", "api:80", idx * .1, idx * .1 + .08),
                ("api:81", "dbgw:80", idx * .1 + .01, idx * .1 + .05),
            ]):
                for kind, ts in [("Request", start), ("Response", end)]:
                    if orphan and idx == 1 and edge == 1 and kind == "Response":
                        continue
                    rows.append({
                        "protocol_type": "http1", "client": client, "server": server,
                        "stream_id": f"rpc-{idx}-{edge}", "msg_type": kind,
                        "timestamp": f"2026-10-13 08:00:00.{int(ts * 1e6):06d}",
                        "data": json.dumps({"book": business, "trace_id": label,
                                            "headers": {"X-Mark": label},
                                            "url": f"/books?id={business}&X-Mark={label}"}),
                        "trace_id": label, "headers": json.dumps({"X-Mark": label}),
                    })
        source = self.path / f"source-{len(list(self.path.glob('source-*')))}.csv"
        with source.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        return source

    def prepared(self, source, name):
        return workflow.prepare(source, self.path / name)

    def test_identifiers_and_headers_are_removed(self):
        run = self.prepared(self.source(), "run")
        text = (run / "observations.csv").read_text()
        for token in ["truth-a", "truth-b", "trace_id", "X-Mark", "headers"]:
            self.assertNotIn(token, text)
        self.assertIn("book-0", text)

    def test_renaming_all_truth_labels_leaves_inference_input_and_predictions_unchanged(self):
        a = self.prepared(self.source(), "a")
        b = self.prepared(self.source(labels=("random-z", "random-q")), "b")
        self.assertEqual((a / "observations.csv").read_bytes(), (b / "observations.csv").read_bytes())
        with patch.dict(os.environ, {"LINEAGE_CHILD_ORDER_MODE": "trace",
                                     "LINEAGE_GRAPH_SLOT_FALLBACK": "1",
                                     "LINEAGE_GRAPH_UNSUPERVISED_GATE": "1"}):
            workflow.infer(a / "observations.csv", a / "predictions.json")
            workflow.infer(b / "observations.csv", b / "predictions.json")
        pa = workflow.read_json(a / "predictions.json")
        pb = workflow.read_json(b / "predictions.json")
        self.assertEqual(pa["predictions"], pb["predictions"])
        self.assertEqual(pa["root_child_order_source"], "temporal-gap")
        self.assertEqual(pa["environment"]["LINEAGE_GRAPH_SLOT_FALLBACK"], "0")

    def test_unpaired_rpc_remains_in_evaluation_denominator(self):
        run = self.prepared(self.source(orphan=True), "orphan")
        workflow.infer(run / "observations.csv", run / "predictions.json")
        report = workflow.evaluate(run / "oracle.json", run / "predictions.json", run / "metrics.json",
                                   run / "observations.csv")
        self.assertEqual(report["truth_rpc_count"], 4)
        self.assertEqual(report["coverage_pct"], 75)
        self.assertIsNone(report["full_trace_accuracy_pct"])
        self.assertIsNone(report["parent_edge_f1_pct"])

    def test_expected_missing_roots_count_as_failures(self):
        run = workflow.prepare(self.source(), self.path / "population", expected_traces=4)
        workflow.infer(run / "observations.csv", run / "predictions.json")
        report = workflow.evaluate(run / "oracle.json", run / "predictions.json", run / "metrics.json",
                                   run / "observations.csv")
        self.assertEqual(report["trace_assignment_accuracy_pct"], 50)

    def parent_inventory(self, oracle):
        entries = []
        for e in oracle["events"]:
            root = oracle["root_by_trace"][e["trace_id"]]
            entries.append({"key": e["key"], "trace_id": e["trace_id"],
                            "parent_key": None if e["key"] == root else root})
        return {"complete_population": True, "events": entries}

    def test_independent_parent_inventory_enables_structural_metrics(self):
        run = self.prepared(self.source(), "independent")
        workflow.infer(run / "observations.csv", run / "predictions.json")
        inventory = self.parent_inventory(workflow.read_json(run / "oracle.json"))
        workflow.write_json(run / "parents.json", inventory)
        report = workflow.evaluate(run / "oracle.json", run / "predictions.json", run / "metrics.json",
                                   run / "observations.csv", run / "parents.json")
        self.assertEqual(report["full_trace_accuracy_pct"], 100)
        self.assertEqual(report["parent_edge_f1_pct"], 100)

    def test_incomplete_parent_inventory_is_rejected(self):
        run = self.prepared(self.source(), "bad-parent")
        workflow.infer(run / "observations.csv", run / "predictions.json")
        inventory = self.parent_inventory(workflow.read_json(run / "oracle.json"))
        inventory["events"].pop()
        workflow.write_json(run / "parents.json", inventory)
        with self.assertRaisesRegex(ValueError, "omits"):
            workflow.evaluate(run / "oracle.json", run / "predictions.json", run / "metrics.json",
                              run / "observations.csv", run / "parents.json")

    def test_observation_hash_mismatch_is_rejected(self):
        run = self.prepared(self.source(), "mismatch")
        workflow.infer(run / "observations.csv", run / "predictions.json")
        with (run / "observations.csv").open("a") as f:
            f.write("\n")
        with self.assertRaisesRegex(ValueError, "do not match"):
            workflow.evaluate(run / "oracle.json", run / "predictions.json", run / "metrics.json",
                              run / "observations.csv")

    def test_no_overwrite_and_too_small_population(self):
        source = self.source()
        run = self.prepared(source, "existing")
        with self.assertRaises(ValueError):
            workflow.prepare(source, run)
        with self.assertRaises(ValueError):
            workflow.prepare(source, self.path / "small", expected_traces=1)

    def test_cross_trace_contamination_invalidates_both_traces(self):
        run = self.prepared(self.source(), "contamination")
        workflow.infer(run / "observations.csv", run / "predictions.json")
        p = workflow.read_json(run / "predictions.json")
        roots = workflow.read_json(run / "oracle.json")["root_by_trace"]
        p["predictions"][-1]["root_key"] = roots["truth-a"]
        workflow.write_json(run / "predictions.json", p)
        report = workflow.evaluate(run / "oracle.json", run / "predictions.json", run / "metrics.json",
                                   run / "observations.csv")
        self.assertEqual(report["trace_assignment_accuracy_pct"], 0)
        self.assertEqual(report["span_accuracy_pct"], 75)

    def test_missing_rpc_in_complete_inventory_counts_against_structural_accuracy(self):
        run = self.prepared(self.source(), "missing-rpc")
        workflow.infer(run / "observations.csv", run / "predictions.json")
        inventory = self.parent_inventory(workflow.read_json(run / "oracle.json"))
        inventory["events"].append({"key": ["api:82", "dbgw:80", "missing-rpc"],
                                    "trace_id": "truth-a",
                                    "parent_key": inventory["events"][0]["key"]})
        workflow.write_json(run / "parents.json", inventory)
        report = workflow.evaluate(run / "oracle.json", run / "predictions.json", run / "metrics.json",
                                   run / "observations.csv", run / "parents.json")
        self.assertEqual(report["coverage_pct"], 80)
        self.assertEqual(report["full_trace_accuracy_pct"], 50)


if __name__ == "__main__":
    unittest.main()
