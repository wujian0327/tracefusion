"""Sound candidate pruning under declared priors, plus safe failure behavior."""
import itertools
import json
import unittest

from common import node
from constrained import DEFAULT_PROFILE, predict, supported_edges


class MatchingContracts(unittest.TestCase):
    def test_all_small_graphs_against_exhaustive_permutations(self):
        # Verify support of ALL perfect matchings, not one arbitrary witness.
        n = 3
        for mask in range(1 << (n*n)):
            adj = {c: {p for p in range(n) if mask & (1 << (c*n+p))} for c in range(n)}
            matchings = [p for p in itertools.permutations(range(n)) if all(p[c] in adj[c] for c in range(n))]
            result, diagnostics = supported_edges(adj, adj, set(range(n)))
            if matchings:
                self.assertEqual(result, {c: {m[c] for m in matchings} for c in range(n)})
                self.assertFalse(any(d['status']=='fallback' for d in diagnostics))
            else:
                # Every original edge inside an infeasible component is retained.
                for d in diagnostics:
                    if d['status']=='fallback':
                        for c in d['children']:
                            self.assertEqual(result[c], adj[c])

    def test_complete_symmetry_keeps_both_options(self):
        adj = {0: {0, 1}, 1: {0, 1}}
        self.assertEqual(supported_edges(adj, adj, {0, 1})[0], adj)

    def test_missing_child_does_not_force_a_parent(self):
        adj = {0: {0, 1}}
        out, diag = supported_edges(adj, adj, {0, 1})
        self.assertEqual(out, adj)
        self.assertEqual(diag[0]['reason'], 'unbalanced_counts')

    def test_infeasible_parameter_prior_restores_temporal_options(self):
        temporal = {0: {0, 1}, 1: {0, 1}}
        reduced = {0: {0}, 1: {0}}
        out, diag = supported_edges(temporal, reduced, {0, 1})
        self.assertEqual(out, temporal)
        self.assertEqual(diag[0]['reason'], 'no_perfect_matching')

    def test_work_limit_is_diagnosed(self):
        adj = {0: {0, 1}, 1: {0, 1}}
        out, diag = supported_edges(adj, adj, {0, 1}, max_component=1)
        self.assertEqual(out, adj)
        self.assertEqual(diag[0]['reason'], 'component_limit')


class PredictionContracts(unittest.TestCase):
    def setUp(self):
        self.profile = json.loads(DEFAULT_PROFILE.read_text())
        def event(key, caller, callee, start, end, uid):
            return {'event_id':key, 'caller':caller, 'callee':callee,
                    'operation':'/case/decoy_same' if key=='a' else '/lookup',
                    'start_ns':start, 'end_ns':end,
                    'request':{'user_id':uid}, 'response':{'phone':'synthetic'}}
        self.events = [event('a','loadgen','api',0,100,'u17'),
                       event('p','api','profile',10,90,'u17'),
                       event('d','api','decoy',10,90,'u29'),
                       event('s1','profile','store',20,80,'u17'),
                       event('s2','decoy','store',20,80,'u29')]
        self.queries = [{'query_id':'q','sink':node('a'),'value':'synthetic'}]

    def test_different_user_decoy_is_legitimate_and_stays_ambiguous(self):
        predictions, diagnostics = predict(self.events, self.queries, self.profile, 0)
        self.assertEqual(predictions[0]['status'], 'ambiguous')
        self.assertEqual({n['event_id'] for n in predictions[0]['candidate_sources']}, {'s1','s2'})
        self.assertEqual(diagnostics['fallback_components'], 0)

    def test_missing_sink_keeps_unknown_query(self):
        pred, _ = predict(self.events[1:], self.queries, self.profile, 0)
        self.assertEqual(pred[0]['status'], 'unknown')

    def test_input_order_does_not_choose_a_winner(self):
        a, _ = predict(self.events, self.queries, self.profile, 0)
        b, _ = predict(list(reversed(self.events)), self.queries, self.profile, 0)
        self.assertEqual(a,b)

    def test_missing_parameter_is_unknown(self):
        self.events[1]['request'] = {}
        pred, diag = predict(self.events, self.queries, self.profile, 0)
        self.assertEqual(len(pred[0]['candidate_sources']),2)
        self.assertGreater(sum(r['missing_parameter_pairs'] for r in diag['rules']),0)

    def test_invalid_tolerance_rejected(self):
        with self.assertRaises(ValueError):
            predict(self.events, self.queries, self.profile, float('nan'))


if __name__ == '__main__':
    unittest.main()
