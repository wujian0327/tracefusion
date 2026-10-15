import csv
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("independent", ROOT / "scripts/paper_independent_oracle.py")
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


class IndependentOracleTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.truth = {"schema_version": "independent-rpc-parent-ground-truth-v1",
                      "requests": [{"request_id": "r"}], "rpcs": [
                          {"request_id": "r", "span_id": "root", "parent_span_id": None,
                           "observation_id": "obs-root"},
                          {"request_id": "r", "span_id": "child", "parent_span_id": "root",
                           "observation_id": "obs-child"}]}

    def run_bridge(self, omit_child=False, parent_override=None, duplicate=False):
        manifest = self.path / "manifest.json"
        manifest.write_text(json.dumps(self.truth))
        rows = []
        for i, rpc in enumerate(self.truth["rpcs"][:1] if omit_child else self.truth["rpcs"]):
            headers = {"X-TF-Eval-Span-Id": rpc["span_id"] + "\\\\r\\\\n",
                       "X-TF-Eval-Observation-Id": rpc["observation_id"] + "\r\n",
                       "X-TF-Eval-Parent-Span-Id": parent_override if parent_override is not None else
                       (rpc["parent_span_id"] or "")}
            for direction in ["Request", "Response"]:
                rows.append({"client": "a:1", "server": "b:2", "stream_id": str(i),
                             "trace_id": "r", "msg_type": direction, "headers": json.dumps(headers)})
        if duplicate:
            rows.append(rows[0])
        capture = self.path / "capture.csv"
        with capture.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        return bridge.build_oracle(manifest, capture)

    def test_exact_header_alignment_and_escaped_newlines(self):
        result = self.run_bridge()
        self.assertEqual(result["paired_capture_rpc_count"], 2)
        self.assertEqual(result["events"][1]["parent_key"], result["events"][0]["key"])

    def test_missing_capture_stays_in_complete_population(self):
        result = self.run_bridge(omit_child=True)
        self.assertEqual(result["truth_rpc_count"], 2)
        self.assertEqual(result["missing_capture_rpc_count"], 1)
        self.assertFalse(result["events"][1]["observed"])

    def test_mismatched_capture_parent_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "parents disagree"):
            self.run_bridge(parent_override="wrong")

    def test_duplicate_capture_direction_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Duplicate capture"):
            self.run_bridge(duplicate=True)

    def test_cycle_is_rejected(self):
        self.truth["rpcs"].append({"request_id": "r", "span_id": "cycle", "parent_span_id": "child",
                                   "observation_id": "obs-cycle"})
        self.truth["rpcs"][1]["parent_span_id"] = "cycle"
        with self.assertRaisesRegex(ValueError, "Cycle"):
            self.run_bridge()

    def test_missing_request_root_is_rejected(self):
        self.truth["requests"].append({"request_id": "not-logged"})
        with self.assertRaisesRegex(ValueError, "Every requested"):
            self.run_bridge()

    def test_duplicate_observation_identity_is_rejected(self):
        self.truth["rpcs"][1]["observation_id"] = "obs-root"
        with self.assertRaisesRegex(ValueError, "duplicate independent"):
            self.run_bridge()

    def test_cross_request_parent_is_rejected_even_if_parent_was_already_visited(self):
        self.truth["requests"].append({"request_id": "other"})
        self.truth["rpcs"].extend([
            {"request_id": "other", "span_id": "other-root", "parent_span_id": None,
             "observation_id": "obs-other-root"},
            {"request_id": "other", "span_id": "wrong-child", "parent_span_id": "root",
             "observation_id": "obs-wrong-child"},
        ])
        with self.assertRaisesRegex(ValueError, "cross-request"):
            self.run_bridge()


if __name__ == "__main__":
    unittest.main()
