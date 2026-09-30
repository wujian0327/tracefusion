"""Contract checks for ground-truth independence, ambiguity, and capture parsing."""
import unittest
from baseline import predict
from capture import normalize
from common import node
from evaluate import evaluate


def event(key, caller, callee, start, end, value="SYNTH-PHONE-0017"):
    return {"event_id": key, "caller": caller, "callee": callee,
            "start_ns": start, "end_ns": end, "operation": "/lookup",
            "request": {"user_id": "u17"}, "response": {"phone": value}}


class BenchmarkContracts(unittest.TestCase):
    def setUp(self):
        self.events = [event("api", "loadgen", "api", 0, 100),
                       event("profile", "api", "profile", 10, 90),
                       event("db", "profile", "store", 20, 80)]
        self.queries = [{"query_id": "q", "scenario": "basic", "sink": node("api"),
                         "value": "SYNTH-PHONE-0017"}]
        self.oracle = [
            {"event_id": "api", "call_children": ["profile"], "source": None,
             "flow_edges": [{"from": node("profile"), "to": node("api")}]},
            {"event_id": "profile", "call_children": ["db"], "source": None,
             "flow_edges": [{"from": node("db"), "to": node("profile")}]},
            {"event_id": "db", "call_children": [], "source": {"node": node("db")}, "flow_edges": []},
        ]

    def test_exact_path(self):
        result = predict(self.events, self.queries, 0)
        report = evaluate(self.queries, result, self.oracle)
        self.assertEqual(report["metrics"]["exact_graph_rate"], 1)
        self.assertEqual(report["metrics"]["source_precision"], 1)

    def test_equal_value_decoy_remains_ambiguous(self):
        events = self.events + [event("decoy", "api", "decoy", 10, 90),
                                event("db2", "decoy", "store", 20, 80)]
        result = predict(events, self.queries, 0)
        self.assertEqual(result[0]["status"], "ambiguous")
        report = evaluate(self.queries, result, self.oracle)
        self.assertEqual(report["metrics"]["source_precision"], 0.5)
        self.assertEqual(report["metrics"]["source_recall"], 1)
        self.assertEqual(report["metrics"]["exact_graph_rate"], 0)
        self.assertIsNone(report["metrics"]["unique_answer_accuracy"])

    def test_missing_capture_keeps_query_in_denominator(self):
        result = predict([], self.queries, 0)
        report = evaluate(self.queries, result, self.oracle)
        self.assertEqual(report["counts"]["queries"], 1)
        self.assertEqual(report["metrics"]["source_recall"], 0)
        self.assertEqual(report["metrics"]["unknown_rate"], 1)

    def test_wrong_unique_source_is_penalized(self):
        result = [{"query_id": "q", "sink": node("api"), "candidate_sources": [node("wrong")], "edges": []}]
        report = evaluate(self.queries, result, self.oracle)
        self.assertEqual(report["metrics"]["unique_answer_accuracy"], 0)
        self.assertEqual(report["metrics"]["source_precision"], 0)

    def test_truth_is_not_reconstructed_from_time(self):
        # An oracle with a different source changes the score without changing
        # the predictor's observations or its result.
        result = predict(self.events, self.queries, 0)
        self.oracle[1]["flow_edges"] = [{"from": node("other"), "to": node("profile")}]
        self.oracle.append({"event_id": "other", "call_children": [],
                            "source": {"node": node("other")}, "flow_edges": []})
        report = evaluate(self.queries, result, self.oracle)
        self.assertEqual(report["metrics"]["source_recall"], 0)

    def test_duplicate_predictions_rejected(self):
        result = predict(self.events, self.queries, 0)
        with self.assertRaises(ValueError):
            evaluate(self.queries, result + result, self.oracle)

    def test_tshark_json_pairing_and_header_isolation(self):
        def packet(stamp, http, reverse=False):
            return {"_source": {"layers": {
                "frame": {"frame.time_epoch": stamp}, "tcp": {"tcp.stream": "2"},
                "ip": {"ip.src": "127.0.0.2" if reverse else "127.0.0.1",
                       "ip.dst": "127.0.0.1" if reverse else "127.0.0.2"}, "http": http,
            }}}
        records, stats = normalize([
            packet("1.000000001", {"line": {"http.request.method": "POST", "http.request.uri": "/case/basic"},
                                   "http.file_data": '{"user_id":"u17"}'}),
            packet("1.000000009", {"line": {"http.response.code": "200"},
                                   "http.response.line": ["Content-Type: application/json", "X-Observation-ID: " + "a" * 32],
                                   "http.file_data": '{"phone":"SYNTH-PHONE-0017"}'}, True),
        ])
        self.assertEqual(stats["paired"], 1)
        self.assertEqual(records[0]["start_ns"], 1000000001)
        self.assertEqual(records[0]["event_id"], "a" * 32)
        self.assertEqual(set(records[0]), {"event_id", "caller", "callee", "operation", "start_ns", "end_ns", "request", "response"})


if __name__ == "__main__":
    unittest.main()
