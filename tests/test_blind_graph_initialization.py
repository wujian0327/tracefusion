import csv
from datetime import datetime, timedelta
import importlib.util
import json
from pathlib import Path
import random
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


workflow = module('blind_workflow', ROOT / 'scripts/paper_blind_eval.py')
engine = module('graph_engine', ROOT / 'src/tracefusion.py')


class BlindGraphInitializationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)

    def run_capture(self, events, variant='full', shuffle=False):
        """Fixture truth is used only by prepare/evaluate, never by infer."""
        directory = self.path / f'case-{len(list(self.path.iterdir()))}'
        directory.mkdir()
        rows, truth, keys = [], [], {}
        for name, client, server, trace, parent, start, end, req, res in events:
            keys[name] = [client, server, name]
        for name, client, server, trace, parent, start, end, req, res in events:
            for direction, seconds, data in [('Request', start, req), ('Response', end, res)]:
                rows.append({'protocol_type': 'http1', 'client': client, 'server': server,
                             'stream_id': name, 'trace_id': trace, 'msg_type': direction,
                             'timestamp': (datetime(2026, 1, 1) + timedelta(seconds=seconds)).strftime('%Y-%m-%d %H:%M:%S.%f'),
                             'data': json.dumps(data)})
            truth.append({'key': keys[name], 'trace_id': trace,
                          'parent_key': keys[parent] if parent else None})
        if shuffle:
            random.Random(16).shuffle(rows)
        source = directory / 'source.csv'
        with source.open('w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        run = workflow.prepare(source, directory / 'run')
        workflow.infer(run / 'observations.csv', run / 'predictions.json', variant)
        workflow.write_json(run / 'parents.json', {'complete_population': True, 'events': truth})
        metrics = workflow.evaluate(run / 'oracle.json', run / 'predictions.json', run / 'metrics.json',
                                    run / 'observations.csv', run / 'parents.json')
        report = workflow.read_json(run / 'predictions.json')
        predictions = {tuple(p['key']): p for p in report['predictions']}
        return metrics, report, predictions

    def test_optional_and_repeated_root_calls_are_not_forced_one_per_parent(self):
        a, b = {'record': 'record-alpha'}, {'record': 'record-bravo'}
        events = [
            ('a', 'outside:1', 'router:80', 'truth-a', None, 0, 1, a, a),
            ('b', 'outside:2', 'router:80', 'truth-b', None, .01, 1.01, b, b),
            ('a-first', 'router:1', 'worker:80', 'truth-a', 'a', .1, .2, a, a),
            ('a-repeat', 'router:2', 'worker:80', 'truth-a', 'a', .3, .4, a, a),
        ]
        metrics, report, _ = self.run_capture(events)
        self.assertEqual(metrics['full_trace_accuracy_pct'], 100)
        self.assertEqual(report['initialization']['fixed_internal_rpc_count'], 0)

    def test_parallel_siblings_and_input_row_order_do_not_define_call_order(self):
        a, b = {'record': 'record-alpha'}, {'record': 'record-bravo'}
        events = [
            ('a', 'outside:1', 'router:80', 'truth-a', None, 0, 1, a, a),
            ('b', 'outside:2', 'router:80', 'truth-b', None, .01, 1.01, b, b),
            ('a-x', 'router:1', 'z-worker:80', 'truth-a', 'a', .1, .6, a, a),
            ('a-y', 'router:2', 'a-worker:80', 'truth-a', 'a', .2, .5, a, a),
            ('b-y', 'router:3', 'a-worker:80', 'truth-b', 'b', .11, .61, b, b),
            ('b-x', 'router:4', 'z-worker:80', 'truth-b', 'b', .21, .51, b, b),
        ]
        ma, report, pa = self.run_capture(events)
        mb, _, pb = self.run_capture(events, shuffle=True)
        self.assertEqual(ma['full_trace_accuracy_pct'], 100)
        self.assertEqual(mb['full_trace_accuracy_pct'], 100)
        self.assertEqual(pa, pb)
        self.assertEqual(report['root_child_order_source'], 'independent-service-edges')

    def test_strict_causal_candidate_precedes_relaxed_future_parent(self):
        value = {'record': 'reused-business-value'}
        events = [
            ('early', 'outside:1', 'router:80', 'truth-a', None, 0, .05, value, value),
            ('future', 'outside:2', 'router:80', 'truth-b', None, .02, .03, value, value),
            ('child', 'router:1', 'worker:80', 'truth-a', 'early', .019, .025, value, value),
        ]
        metrics, _, _ = self.run_capture(events, variant='time-only')
        self.assertEqual(metrics['full_trace_accuracy_pct'], 100)

    def test_bounded_clock_tolerance_still_works_when_no_strict_parent_exists(self):
        value = {'record': 'record-alpha'}
        events = [
            ('a', 'outside:1', 'router:80', 'truth-a', None, .1, .3, value, value),
            ('child', 'router:1', 'worker:80', 'truth-a', 'a', .09, .31, value, value),
        ]
        metrics, _, _ = self.run_capture(events)
        self.assertEqual(metrics['full_trace_accuracy_pct'], 100)

    def test_ancestor_business_evidence_can_resolve_an_ambiguous_deeper_hop(self):
        root_a = {'route': 'route-red', 'token': 'secret-copper'}
        root_b = {'route': 'route-blue', 'token': 'secret-silver'}
        # Route and deeper-hop identifiers deliberately share no business token.
        self.assertFalse(engine.extract_lineage_tokens(json.dumps({'route': 'route-red'})) &
                         engine.extract_lineage_tokens(json.dumps({'token': 'secret-copper'})))
        events = [
            ('a', 'outside:1', 'router:80', 'truth-a', None, 0, 1, root_a, root_a),
            ('b', 'outside:2', 'router:80', 'truth-b', None, .01, 1.01, root_b, root_b),
            ('middle-a', 'router:1', 'middle:80', 'truth-a', 'a', .1, .7, {'route': 'route-red'}, {}),
            ('middle-b', 'router:2', 'middle:80', 'truth-b', 'b', .2, .6, {'route': 'route-blue'}, {}),
            ('leaf-a', 'middle:1', 'leaf:80', 'truth-a', 'middle-a', .3, .4, {'token': 'secret-copper'}, {}),
            ('leaf-b', 'middle:2', 'leaf:80', 'truth-b', 'middle-b', .35, .45, {'token': 'secret-silver'}, {}),
        ]
        metrics, _, _ = self.run_capture(events)
        local, _, _ = self.run_capture(events, variant='no-context')
        self.assertEqual(metrics['full_trace_accuracy_pct'], 100)
        self.assertLess(local['full_trace_accuracy_pct'], 100)

    def test_context_contains_ancestors_but_not_parent_siblings_or_descendants(self):
        records = {k: {'lineage_req_tokens': {k}, 'lineage_res_tokens': set()}
                   for k in ['entry', 'parent', 'sibling', 'child']}
        parents = {'parent': 'entry', 'sibling': 'entry', 'child': 'parent'}
        labels = dict.fromkeys(records, 'predicted-root')
        context = engine.predicted_ancestor_lineage_context('parent', records, parents, labels)
        self.assertEqual(set(context), {'entry'})

    def test_cyclic_or_inconsistent_ancestry_contributes_no_context(self):
        records = {k: {'lineage_req_tokens': {k}} for k in ['entry', 'parent']}
        self.assertEqual(engine.predicted_ancestor_lineage_context('parent', records,
            {'parent': 'entry', 'entry': 'parent'}, dict.fromkeys(records, 'root')), {})
        self.assertEqual(engine.predicted_ancestor_lineage_context('parent', records,
            {'parent': 'entry'}, {'parent': 'one', 'entry': 'another'}), {})


if __name__ == '__main__':
    unittest.main()
