"""Ranking is supplementary evidence; it must not overwrite feasible candidates."""
import copy
import itertools
import json
import math
import unittest

from common import node
from constrained import DEFAULT_PROFILE, predict
from evaluate_ranking import summarize
from timing_rank import annotate, minimum_cost


class AssignmentTests(unittest.TestCase):
    def test_minimum_cost_against_exhaustive_matchings(self):
        for mask in range(512):
            matrix = [[float((i*7+j*3)%11) if mask & (1 << (i*3+j)) else math.inf
                       for j in range(3)] for i in range(3)]
            expected = min(sum(matrix[i][p[i]] for i in range(3)) for p in itertools.permutations(range(3)))
            self.assertEqual(minimum_cost(matrix), expected)
        self.assertEqual(minimum_cost([]), 0)

    def test_fractional_and_tied_costs(self):
        self.assertAlmostEqual(minimum_cost([[0.8, 0.1], [0.2, 0.7]]), 0.3)
        self.assertEqual(minimum_cost([[0,0],[0,0]]), 0)


class RankingTests(unittest.TestCase):
    def fixture(self, symmetric=False):
        def event(key, caller, callee, start, end):
            return {'event_id':key, 'caller':caller, 'callee':callee, 'operation':'/lookup',
                    'start_ns':int(start*1e6), 'end_ns':int(end*1e6),
                    'request':{'user_id':'u17'}, 'response':{'phone':'synthetic'}}
        events = [event('p1','api','profile',0,100),event('p2','api','profile',0,100 if symmetric else 110),
                  event('s1','profile','store',10,90),event('s2','profile','store',10,90 if symmetric else 95)]
        queries = [{'query_id':i,'sink':node(i),'value':'synthetic'} for i in ('p1','p2')]
        profile=json.loads(DEFAULT_PROFILE.read_text())
        predictions,diag=predict(events,queries,profile)
        return events,queries,predictions,diag

    def test_original_candidates_and_status_are_unchanged(self):
        events,queries,predictions,diag=self.fixture()
        original=copy.deepcopy(predictions)
        ranked,notes=annotate(events,predictions,diag)
        self.assertEqual(predictions,original)
        for base,row in zip(original,ranked):
            self.assertEqual({k:v for k,v in row.items() if k!='timing_ranking'},base)
            self.assertEqual(row['status'],'ambiguous')
            self.assertEqual(sum(s['top_tier'] for s in row['timing_ranking']['sources']),1)

    def test_equal_scores_preserve_ties(self):
        e,q,p,d=self.fixture(True)
        ranked,_=annotate(e,p,d)
        for row in ranked:
            self.assertEqual(sum(s['top_tier'] for s in row['timing_ranking']['sources']),2)

    def test_component_limit_keeps_all_candidates_unranked(self):
        e,q,p,d=self.fixture()
        ranked,notes=annotate(e,p,d,max_component=1)
        self.assertGreater(notes['unranked_components'],0)
        self.assertTrue(all(s['top_tier'] for r in ranked for s in r['timing_ranking']['sources']))

    def test_oracle_can_reveal_wrong_priority_without_candidate_loss(self):
        e,q,p,d=self.fixture()
        ranked,_=annotate(e,p,d)
        # Actual assignments deliberately oppose the timing preference.
        oracle=[{'event_id':'p1','source':None,'flow_edges':[{'from':node('s2'),'to':node('p1')}]},
                {'event_id':'p2','source':None,'flow_edges':[{'from':node('s1'),'to':node('p2')}]},
                {'event_id':'s1','source':{'node':node('s1')},'flow_edges':[]},
                {'event_id':'s2','source':{'node':node('s2')},'flow_edges':[]}]
        report=summarize(q,ranked,oracle)
        self.assertEqual(report['retained_candidates']['metrics']['source_recall'],1)
        self.assertEqual(report['top_tier']['wrong_unique_top'],2)

    def test_parallel_mode_does_not_use_return_time(self):
        e,q,p,d=self.fixture()
        # Two declared downstream edges disable this parent timing factor.
        d['profile']['rules'].append({'parent_service':'profile','child_service':'another','preserve_fields':[]})
        ranked,_=annotate(e,p,d)
        self.assertTrue(all(s['top_tier'] for r in ranked for s in r['timing_ranking']['sources']))


if __name__=='__main__':
    unittest.main()
