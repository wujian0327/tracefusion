#!/usr/bin/env python3
"""Run a self-contained TraceWeaver V2 matcher on this repo's trace formats."""

import argparse
import bisect
import copy
import csv
import heapq
import json
import math
import os
from collections import Counter, defaultdict, deque
from datetime import datetime

import networkx as nx
import scipy.stats

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_INPUT = os.path.join(REPO_ROOT, "data", "pcap_cleaned_data.csv")
EXCLUDED_HOSTS = {"172.17.0.11"}
VERBOSE = False


class Span:
    """Small local copy of the fields/methods TraceWeaver needs."""

    def __init__(
        self,
        trace_id,
        sid,
        start_mus,
        duration_mus,
        op_name,
        references,
        process_id,
        span_kind,
        span_tags,
    ):
        self.sid = sid
        self.trace_id = trace_id
        self.start_mus = start_mus
        self.duration_mus = duration_mus
        self.op_name = op_name
        self.references = references
        self.process_id = process_id
        self.span_kind = span_kind
        self.tags = span_tags
        self.children_spans = []
        self.taken = False
        self.ep = None

    def AddChild(self, child_span_id):
        self.children_spans.append(child_span_id)

    def GetChildProcess(self, all_processes, all_spans):
        assert self.span_kind == "client"
        assert len(self.children_spans) == 1
        return all_processes[self.trace_id][
            all_spans[self.children_spans[0]].process_id
        ]

    def GetParentProcess(self, all_processes, all_spans):
        if self.IsRoot():
            return "client_" + self.op_name
        assert len(self.references) == 1
        parent_span_id = self.references[0]
        return all_processes[self.trace_id][all_spans[parent_span_id].process_id]

    def GetId(self):
        return (self.trace_id, self.sid)

    def IsRoot(self):
        return len(self.references) == 0

    def __lt__(self, other):
        return self.start_mus < other.start_mus

    def __repr__(self):
        return "Span:(%s, %s, %s, %s, %s, %s)" % (
            self.trace_id,
            self.sid,
            self.op_name,
            self.start_mus,
            self.duration_mus,
            self.span_kind,
        )


class TraceWeaverV2:
    """TraceWeaver V2 MaxScoreBatch implementation, kept local to this runner."""

    def __init__(self, all_spans, all_processes):
        self.all_spans = all_spans
        self.all_processes = all_processes
        self.process = ""
        self.services_times = {}
        self.parallel = False
        self.instrumented_hops = []
        self.true_assignments = None
        self.per_span_candidates = {}
        self.normal = True

    def GetOutEpsInOrder(self, out_span_partitions):
        eps = []
        for ep, spans in out_span_partitions.items():
            assert len(spans) > 0
            eps.append((ep, spans[0].start_mus))
        eps.sort(key=lambda x: x[1])
        return [x[0] for x in eps]

    def ComputeEpPairDistParams(
        self,
        in_span_partitions,
        out_span_partitions,
        out_eps,
        in_span_start,
        in_span_end,
    ):
        def compute_dist_params(ep1, ep2, t1, t2):
            t1 = t1[in_span_start:in_span_end]
            t2 = t2[in_span_start:in_span_end]
            assert len(t1) == len(t2)
            if not t1:
                self.services_times[(ep1, ep2)] = (0.0, 0.001)
                return

            mean = (sum(t2) - sum(t1)) / len(t1)
            batch_means = []
            nbatches = 10
            batch_size = math.ceil(float(len(t1)) / nbatches)
            for i in range(nbatches):
                start = i * batch_size
                end = min(len(t1), (i + 1) * batch_size)
                if end - start > 0:
                    batch_means.append(
                        (sum(t2[start:end]) - sum(t1[start:end])) / (end - start)
                    )
            std = math.sqrt(batch_size) * scipy.stats.tstd(batch_means)
            if math.isnan(std) or std < 1.0e-12:
                std = 0.001
            self.services_times[(ep1, ep2)] = mean, std

        if self.parallel:
            for ep2 in out_eps:
                ep1 = list(in_span_partitions.keys())[0]
                t1 = sorted(s.start_mus for s in in_span_partitions[ep1])
                t2 = sorted(s.start_mus for s in out_span_partitions[ep2])
                compute_dist_params(ep1, ep2, t1, t2)
        else:
            ep1 = list(in_span_partitions.keys())[0]
            ep2 = out_eps[0]
            t1 = sorted(s.start_mus for s in in_span_partitions[ep1])
            t2 = sorted(s.start_mus for s in out_span_partitions[ep2])
            compute_dist_params(ep1, ep2, t1, t2)

            for i in range(len(out_eps) - 1):
                ep1 = out_eps[i]
                ep2 = out_eps[i + 1]
                t1 = sorted(
                    s.start_mus + s.duration_mus for s in out_span_partitions[ep1]
                )
                t2 = sorted(s.start_mus for s in out_span_partitions[ep2])
                compute_dist_params(ep1, ep2, t1, t2)

            ep1 = out_eps[-1]
            ep2 = list(in_span_partitions.keys())[0]
            t1 = sorted(s.start_mus + s.duration_mus for s in out_span_partitions[ep1])
            t2 = sorted(
                s.start_mus + s.duration_mus for s in in_span_partitions[ep2]
            )
            compute_dist_params(ep1, ep2, t1, t2)

    def GetEpPairCost(self, ep1, ep2, t1, t2):
        mean, std = self.services_times[(ep1, ep2)]
        if std < 1.0e-12:
            std = 0.001
        z = ((t2 - t1) - mean) / std
        return -0.5 * z * z - math.log(std) - 0.5 * math.log(2.0 * math.pi)

    def ScoreAssignmentSequential(self, assignment):
        cost = 0
        for i in range(len(assignment)):
            curr_ep = (
                assignment[i].GetParentProcess(self.all_processes, self.all_spans)
                if i == 0
                else assignment[i].GetChildProcess(self.all_processes, self.all_spans)
            )
            curr_time = (
                assignment[i].start_mus
                if i == 0
                else assignment[i].start_mus + assignment[i].duration_mus
            )

            next_i = (i + 1) % len(assignment)
            next_ep = (
                assignment[next_i].GetParentProcess(self.all_processes, self.all_spans)
                if next_i == 0
                else assignment[next_i].GetChildProcess(self.all_processes, self.all_spans)
            )
            next_time = (
                assignment[next_i].start_mus + assignment[next_i].duration_mus
                if next_i == 0
                else assignment[next_i].start_mus
            )
            cost += self.GetEpPairCost(curr_ep, next_ep, curr_time, next_time)
        return cost

    def ScoreAssignmentParallel(self, assignment):
        cost = 0
        for i in range(1, len(assignment)):
            curr_ep = assignment[0].GetParentProcess(self.all_processes, self.all_spans)
            curr_time = float(assignment[0].start_mus)
            next_ep = assignment[i].GetChildProcess(self.all_processes, self.all_spans)
            next_time = float(assignment[i].start_mus)
            cost += self.GetEpPairCost(curr_ep, next_ep, curr_time, next_time)
        return cost

    def AddToCandidatesList(self, stack):
        key = stack[0].GetId()
        if key not in self.per_span_candidates:
            self.per_span_candidates[key] = 0
        self.per_span_candidates[key] += 1

    def FindTopKAssignments(self, in_span, out_eps, out_span_partitions, k):
        top_assignments = []
        max_candidates = int(os.getenv("TRACEWEAVER_MAX_CANDIDATES_PER_EP", "20"))

        def candidate_spans(ep, spans, lower_start, upper_end, anchor_ep, anchor_time):
            starts = [span.start_mus for span in spans]
            left = bisect.bisect_left(starts, lower_start)
            right = bisect.bisect_right(starts, upper_end)
            candidates = [
                span for span in spans[left:right]
                if lower_start <= span.start_mus
                and span.start_mus + span.duration_mus <= upper_end
            ]
            if max_candidates <= 0 or len(candidates) <= max_candidates:
                return candidates

            mean, _ = self.services_times.get((anchor_ep, ep), (0.0, 1.0))
            expected_start = anchor_time + mean
            return sorted(
                candidates,
                key=lambda span: (abs(span.start_mus - expected_start), span.start_mus, span.sid),
            )[:max_candidates]

        def dfs_traverse(stack):
            i = len(stack)
            last_span = stack[-1]
            if i == len(out_span_partitions) + 1:
                self.AddToCandidatesList(stack)
                score = (
                    self.ScoreAssignmentParallel(stack)
                    if self.parallel
                    else self.ScoreAssignmentSequential(stack)
                )
                heapq.heappush(top_assignments, (score, stack))
                if len(top_assignments) > k:
                    heapq.heappop(top_assignments)
            elif i in self.instrumented_hops:
                ep = out_eps[i - 1]
                span_id = self.true_assignments[ep][in_span.GetId()]
                for span in out_span_partitions[ep]:
                    if span.GetId() == span_id:
                        dfs_traverse(stack + [span])
                        break
            else:
                ep = out_eps[i - 1]
                parent_end = in_span.start_mus + in_span.duration_mus
                if self.parallel:
                    lower_start = in_span.start_mus if i == 1 else last_span.start_mus
                    anchor_ep = in_span.GetParentProcess(self.all_processes, self.all_spans)
                    anchor_time = in_span.start_mus
                else:
                    lower_start = (
                        in_span.start_mus
                        if i == 1
                        else last_span.start_mus + last_span.duration_mus
                    )
                    anchor_ep = (
                        in_span.GetParentProcess(self.all_processes, self.all_spans)
                        if i == 1
                        else last_span.GetChildProcess(self.all_processes, self.all_spans)
                    )
                    anchor_time = lower_start

                for span in candidate_spans(
                    ep,
                    out_span_partitions[ep],
                    lower_start,
                    parent_end,
                    anchor_ep,
                    anchor_time,
                ):
                    dfs_traverse(stack + [span])

        dfs_traverse([in_span])
        top_assignments.sort(reverse=True)
        return top_assignments

    def GetSpanIDNotation(self, out_eps, assignment, type1):
        if type1:
            return [assignment[i].GetId() for i in range(1, len(assignment))]
        return [assignment[out_ep].GetId() for out_ep in out_eps]

    def AddAssignment(
        self,
        in_span,
        assignment,
        all_assignments,
        out_span_partitions,
        out_eps,
        delete_out_spans=False,
    ):
        for ep in out_eps:
            if ep not in all_assignments:
                all_assignments[ep] = {}
            out_span = assignment.get(ep, None)
            all_assignments[ep][in_span.GetId()] = (
                out_span.GetId() if out_span is not None else ("NA", "NA")
            )

        if delete_out_spans:
            for ep, span in assignment.items():
                out_span_partitions[ep].remove(span)

    def FindAssignments(
        self,
        method,
        process,
        in_span_partitions,
        out_span_partitions,
        parallel,
        instrumented_hops,
        true_assignments,
    ):
        assert method == "MaxScoreBatch"
        assert len(in_span_partitions) == 1
        self.process = process
        self.parallel = parallel
        self.instrumented_hops = instrumented_hops
        self.true_assignments = true_assignments
        self.per_span_candidates = {}
        for ep in out_span_partitions.keys():
            for key in true_assignments[ep].keys():
                self.per_span_candidates[key] = 0

        span_to_top_assignments = {}
        _, in_spans = list(in_span_partitions.items())[0]
        out_eps = self.GetOutEpsInOrder(out_span_partitions)
        out_span_partitions_copy = copy.deepcopy(out_span_partitions)
        batch_size = int(os.getenv("TRACEWEAVER_DIST_BATCH_SIZE", "100"))
        batch_size_mis = int(os.getenv("TRACEWEAVER_MIS_BATCH_SIZE", "30"))
        top_k = int(os.getenv("TRACEWEAVER_TOP_K", "5"))
        cnt = 0
        cnt_unassigned = 0
        not_best_count = 0
        all_assignments = {}
        top_assignments = []
        batch_in_spans = []

        for in_span in in_spans:
            if cnt % batch_size == 0:
                self.ComputeEpPairDistParams(
                    in_span_partitions,
                    out_span_partitions,
                    out_eps,
                    cnt,
                    min(len(in_spans), cnt + batch_size),
                )
                print("Finished %d spans, unassigned spans: %d" % (cnt, cnt_unassigned))

            top_k_assignments = self.FindTopKAssignments(
                in_span, out_eps, out_span_partitions_copy, top_k
            )
            span_to_top_assignments[in_span] = top_k_assignments
            top_assignments.append(top_k_assignments)
            batch_in_spans.append(in_span)
            cnt += 1

            if cnt % batch_size_mis == 0:
                assignments = self.GetAssignmentsMIS(top_assignments)
                assert len(assignments) == len(top_assignments) == len(batch_in_spans)
                for ind, selected in enumerate(assignments):
                    assignment = {}
                    if len(selected) > 0:
                        assert len(out_eps) == len(selected) - 1
                        for ii, ep in enumerate(out_eps):
                            assignment[ep] = selected[ii + 1]
                    if len(span_to_top_assignments[batch_in_spans[ind]]) < 1 or not assignment:
                        not_best_count += 1
                    else:
                        best = self.GetSpanIDNotation(
                            out_eps,
                            span_to_top_assignments[batch_in_spans[ind]][0][1],
                            type1=True,
                        )
                        chosen = self.GetSpanIDNotation(out_eps, assignment, type1=False)
                        if best != chosen:
                            not_best_count += 1
                    self.AddAssignment(
                        batch_in_spans[ind],
                        assignment,
                        all_assignments,
                        out_span_partitions_copy,
                        out_eps,
                        delete_out_spans=True,
                    )
                    cnt_unassigned += int(len(assignment) == 0)
                top_assignments = []
                batch_in_spans = []

        if batch_in_spans:
            assignments = self.GetAssignmentsMIS(top_assignments)
            assert len(assignments) == len(top_assignments) == len(batch_in_spans)
            for ind, selected in enumerate(assignments):
                assignment = {}
                if len(selected) > 0:
                    assert len(out_eps) == len(selected) - 1
                    for ii, ep in enumerate(out_eps):
                        assignment[ep] = selected[ii + 1]
                if len(span_to_top_assignments[batch_in_spans[ind]]) < 1 or not assignment:
                    not_best_count += 1
                else:
                    best = self.GetSpanIDNotation(
                        out_eps,
                        span_to_top_assignments[batch_in_spans[ind]][0][1],
                        type1=True,
                    )
                    chosen = self.GetSpanIDNotation(out_eps, assignment, type1=False)
                    if best != chosen:
                        not_best_count += 1
                self.AddAssignment(
                    batch_in_spans[ind],
                    assignment,
                    all_assignments,
                    out_span_partitions_copy,
                    out_eps,
                    delete_out_spans=True,
                )
                cnt_unassigned += int(len(assignment) == 0)

        return all_assignments, not_best_count, len(in_spans), self.per_span_candidates

    def GetAssignmentsMIS(self, top_assignments):
        mis_assignments = [[]] * len(top_assignments)
        graph = self.BuildMISInstance(top_assignments)
        if len(graph.nodes) <= 0:
            return mis_assignments
        mis = self.GetMIS(graph)
        for in_span_ind, assignment_ind in mis:
            _, assignment = top_assignments[in_span_ind][assignment_ind]
            mis_assignments[in_span_ind] = assignment
        return mis_assignments

    def BuildMISInstance(self, top_assignments):
        graph = nx.Graph()
        for ind1 in range(len(top_assignments)):
            for i1 in range(len(top_assignments[ind1])):
                aid1 = (ind1, i1)
                score = top_assignments[ind1][i1][0]
                graph.add_node(aid1, weight=10000.0 + score)
                for i0 in range(i1):
                    graph.add_edge((ind1, i0), aid1)
                for ind0 in range(ind1):
                    for i0 in range(len(top_assignments[ind0])):
                        if self.AssignmentIntersect(
                            top_assignments[ind0][i0][1],
                            top_assignments[ind1][i1][1],
                        ):
                            graph.add_edge((ind0, i0), aid1)
        return graph

    def AssignmentIntersect(self, a1, a2):
        assert len(a1) == len(a2)
        return any(s1.GetId() == s2.GetId() for s1, s2 in zip(a1, a2))

    def GetMIS(self, graph):
        solver = os.getenv("TRACEWEAVER_MIS_SOLVER", "random").strip().lower()
        if solver == "greedy":
            return self.GetGreedyMIS(graph)

        best_mis = None
        best_score = -math.inf
        max_iters = int(os.getenv("TRACEWEAVER_MIS_ITERS", "5000"))
        for _ in range(max_iters):
            mis = nx.maximal_independent_set(graph)
            score = sum(graph.nodes[n]["weight"] for n in mis)
            if best_mis is None or score > best_score:
                best_mis = mis
                best_score = score
        return best_mis

    def GetGreedyMIS(self, graph):
        selected = []
        blocked = set()
        for node in sorted(graph.nodes, key=lambda n: graph.nodes[n]["weight"], reverse=True):
            if node in blocked:
                continue
            selected.append(node)
            blocked.add(node)
            blocked.update(graph.neighbors(node))
        return selected


def ts_to_micros(ts_str):
    if not ts_str:
        return 0
    dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S.%f")
    return int(round(dt.timestamp() * 1_000_000))


def endpoint_host(endpoint):
    return endpoint.rsplit(":", 1)[0] if endpoint else ""


def tag_value(tags, key):
    for tag in tags or []:
        if tag.get("key") == key:
            return tag.get("value")
    return None


def load_rpc_events(csv_path):
    pairs = defaultdict(dict)
    request_order = 0
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            client = row.get("client", "")
            server = row.get("server", "")
            if endpoint_host(client) in EXCLUDED_HOSTS or endpoint_host(server) in EXCLUDED_HOSTS:
                continue

            msg_type = row.get("msg_type", "")
            if msg_type not in {"Request", "Response"}:
                continue

            key = (client, server, row.get("stream_id", ""))
            pairs[key][msg_type] = ts_to_micros(row.get("timestamp", ""))
            pairs[key]["trace_id"] = row.get("trace_id", "")
            pairs[key]["span_id"] = row.get("span_id", "")
            pairs[key]["parent_span_id"] = row.get("parent_span_id", "")
            pairs[key]["protocol"] = row.get("protocol_type", "")
            if msg_type == "Request":
                request_order += 1
                pairs[key]["request_order"] = request_order

    events = []
    for (client, server, stream_id), data in pairs.items():
        if "Request" not in data or "Response" not in data or not data.get("trace_id"):
            continue
        start_mus = data["Request"]
        end_mus = data["Response"]
        if end_mus < start_mus:
            continue
        events.append(
            {
                "event_id": f"{len(events):08d}",
                "trace_id": data["trace_id"],
                "source_span_id": data.get("span_id", ""),
                "parent_span_id": data.get("parent_span_id", ""),
                "client_endpoint": client,
                "server_endpoint": server,
                "client": endpoint_host(client),
                "server": endpoint_host(server),
                "stream_id": stream_id,
                "protocol": data.get("protocol", ""),
                "start_mus": start_mus,
                "duration_mus": max(1, end_mus - start_mus),
                "request_order": data.get("request_order", 10**9),
            }
        )
    events.sort(key=lambda e: (e["start_mus"], e["start_mus"] + e["duration_mus"], e["request_order"]))
    return events


def infer_topology(events):
    server_ips = {e["server"] for e in events}
    client_ips = {e["client"] for e in events}
    external_clients = client_ips - server_ips

    root_counter = Counter()
    for event in events:
        if event["client"] in external_clients:
            root_counter[event["server"]] += 1
    if not root_counter:
        return None, {}

    root_ip = root_counter.most_common(1)[0][0]
    call_edges = {
        (event["client"], event["server"])
        for event in events
        if event["client"] in server_ips and event["client"] != event["server"]
    }

    tree = {}
    parent_of = {}
    visited = {root_ip}
    queue = deque([root_ip])
    while queue:
        service_ip = queue.popleft()
        children = sorted(dst for src, dst in call_edges if src == service_ip and dst not in visited)
        if service_ip == root_ip:
            service_events = [
                e for e in events if e["server"] == service_ip and e["client"] in external_clients
            ]
        else:
            parent = parent_of[service_ip]
            service_events = [
                e for e in events if e["server"] == service_ip and e["client"] == parent
            ]

        tree[service_ip] = {
            "events": sorted(
                service_events,
                key=lambda e: (e["start_mus"], e["start_mus"] + e["duration_mus"], e["request_order"]),
            ),
            "children": children,
        }
        for child in children:
            parent_of[child] = service_ip
            visited.add(child)
            queue.append(child)

    return root_ip, tree


def process_id_for(host):
    return f"process:{host}"


def build_traceweaver_inputs(events, tree):
    all_spans = {}
    all_processes = defaultdict(dict)
    server_spans_by_event = {}
    client_spans_by_event = {}
    server_span_by_id = {}
    client_to_server = {}

    for event in events:
        trace_id = event["trace_id"]
        client_process_id = process_id_for(event["client"])
        server_process_id = process_id_for(event["server"])
        all_processes[trace_id][client_process_id] = event["client"]
        all_processes[trace_id][server_process_id] = event["server"]

        sid_base = f"rpc-{event['event_id']}"
        client_sid = f"{sid_base}.client"
        server_sid = f"{sid_base}.server"
        client_span_id = (trace_id, client_sid)
        server_span_id = (trace_id, server_sid)

        op_name = f"{event['client']}->{event['server']}"
        client_span = Span(
            trace_id=trace_id,
            sid=client_sid,
            start_mus=event["start_mus"],
            duration_mus=event["duration_mus"],
            op_name=op_name,
            references=[],
            process_id=client_process_id,
            span_kind="client",
            span_tags=[],
        )
        server_span = Span(
            trace_id=trace_id,
            sid=server_sid,
            start_mus=event["start_mus"],
            duration_mus=event["duration_mus"],
            op_name=op_name,
            references=[client_span_id],
            process_id=server_process_id,
            span_kind="server",
            span_tags=[],
        )
        client_span.AddChild(server_span_id)

        all_spans[client_span_id] = client_span
        all_spans[server_span_id] = server_span
        client_spans_by_event[event["event_id"]] = client_span
        server_spans_by_event[event["event_id"]] = server_span
        server_span_by_id[server_span_id] = server_span
        client_to_server[client_span_id] = server_span_id

    in_spans_by_process = {service: [] for service in tree}
    out_spans_by_process = {service: [] for service in tree}
    for service, node in tree.items():
        in_spans_by_process[service] = [
            server_spans_by_event[event["event_id"]] for event in node["events"]
        ]
        child_set = set(node["children"])
        out_spans_by_process[service] = [
            client_spans_by_event[event["event_id"]]
            for event in events
            if event["client"] == service and event["server"] in child_set
        ]

    return (
        dict(all_spans),
        {trace_id: dict(processes) for trace_id, processes in all_processes.items()},
        in_spans_by_process,
        out_spans_by_process,
        client_to_server,
        server_span_by_id,
    )


def partition_spans(spans, endpoint_fn):
    partitions = defaultdict(list)
    for span in spans:
        partitions[endpoint_fn(span)].append(span)
    return {
        endpoint: sorted(part, key=lambda s: (s.start_mus, s.start_mus + s.duration_mus, s.sid))
        for endpoint, part in partitions.items()
    }


def get_ground_truth(in_span_partitions, out_span_partitions):
    _, in_spans = list(in_span_partitions.items())[0]
    true_assignments = {endpoint: {} for endpoint in out_span_partitions}
    for in_span in in_spans:
        for endpoint, out_spans in out_span_partitions.items():
            true_assignments[endpoint][in_span.GetId()] = ("NA", "NA")
            for out_span in out_spans:
                if out_span.trace_id == in_span.trace_id:
                    true_assignments[endpoint][in_span.GetId()] = out_span.GetId()
                    break
    return true_assignments


def accuracy_for_service(pred_assignments, true_assignments, in_span_partitions):
    _, in_spans = list(in_span_partitions.items())[0]
    if not in_spans:
        return 0, 0, 0.0

    correct = 0
    for in_span in in_spans:
        in_span_id = in_span.GetId()
        span_ok = True
        for endpoint in true_assignments:
            span_ok = span_ok and (
                pred_assignments.get(endpoint, {}).get(in_span_id) == true_assignments[endpoint][in_span_id]
            )
        correct += int(span_ok)
    return correct, len(in_spans), correct / len(in_spans) * 100.0


def make_predictor(version, all_spans, all_processes):
    if version == "v2":
        return TraceWeaverV2(all_spans, all_processes), "TraceWeaverV2", "MaxScoreBatch"
    raise ValueError(f"unsupported TraceWeaver version: {version}; this runner is self-contained for v2 only")


def find_assignments_with_predictor(
    predictor,
    method,
    process,
    in_span_partitions,
    out_span_partitions,
    parallel,
    true_assignments,
):
    result = predictor.FindAssignments(
        method,
        process,
        in_span_partitions,
        out_span_partitions,
        parallel,
        [],
        true_assignments,
    )

    return result[0] if isinstance(result, tuple) else result


def run_traceweaver(
    all_spans,
    all_processes,
    tree,
    in_spans_by_process,
    out_spans_by_process,
    tw_version="v2",
    parallel=False,
    verbose=True,
):
    predictor, predictor_name, method = make_predictor(tw_version, all_spans, all_processes)
    pred_by_process = {}
    true_by_process = {}
    partitions_by_process = {}
    service_accuracy = {}

    for service, node in tree.items():
        if not node["children"]:
            continue

        in_span_partitions = partition_spans(
            in_spans_by_process[service],
            lambda s: s.GetParentProcess(all_processes, all_spans),
        )
        out_span_partitions = partition_spans(
            out_spans_by_process[service],
            lambda s: s.GetChildProcess(all_processes, all_spans),
        )
        if not in_span_partitions or not out_span_partitions:
            continue
        if len(in_span_partitions) != 1:
            raise ValueError(f"{service} has multiple incoming endpoints: {list(in_span_partitions)}")

        true_assignments = get_ground_truth(in_span_partitions, out_span_partitions)
        pred_assignments = find_assignments_with_predictor(
            predictor,
            method,
            service,
            in_span_partitions,
            out_span_partitions,
            parallel,
            true_assignments,
        )
        correct, total, pct = accuracy_for_service(
            pred_assignments, true_assignments, in_span_partitions
        )

        pred_by_process[service] = pred_assignments
        true_by_process[service] = true_assignments
        partitions_by_process[service] = in_span_partitions
        service_accuracy[service] = {
            "correct": correct,
            "total": total,
            "accuracy_pct": pct,
            "incoming_endpoint": next(iter(in_span_partitions)),
            "outgoing_endpoints": list(out_span_partitions),
        }

        if verbose:
            mode = "parallel" if parallel else "sequential"
            print(
                f"[{service}] local {predictor_name} {method} ({mode}): "
                f"{pct:.2f}% ({correct}/{total})"
            )

    return pred_by_process, true_by_process, partitions_by_process, service_accuracy


def evaluate_end_to_end(root_ip, tree, pred_by_process, in_spans_by_process, client_to_server, server_span_by_id):
    root_spans = in_spans_by_process[root_ip]
    root_to_service_span = {root_ip: {span.GetId(): span.GetId() for span in root_spans}}

    queue = deque([root_ip])
    while queue:
        service = queue.popleft()
        for child in tree[service]["children"]:
            root_to_service_span[child] = {}
            assignments_for_service = pred_by_process.get(service, {})
            assignments_for_child = assignments_for_service.get(child, {})
            for root_span in root_spans:
                root_span_id = root_span.GetId()
                service_span_id = root_to_service_span.get(service, {}).get(root_span_id)
                if service_span_id is None:
                    continue
                predicted_client_span_id = assignments_for_child.get(service_span_id)
                predicted_server_span_id = client_to_server.get(predicted_client_span_id)
                if predicted_server_span_id is not None:
                    root_to_service_span[child][root_span_id] = predicted_server_span_id
            queue.append(child)

    service_ips = [service for service in tree if service != root_ip]
    per_service_correct = Counter()
    per_service_total = Counter()
    full_correct = 0

    for root_span in root_spans:
        root_span_id = root_span.GetId()
        trace_id = root_span.trace_id
        span_ok = True
        for service in service_ips:
            per_service_total[service] += 1
            predicted_server_span_id = root_to_service_span.get(service, {}).get(root_span_id)
            predicted_span = server_span_by_id.get(predicted_server_span_id)
            if predicted_span is not None and predicted_span.trace_id == trace_id:
                per_service_correct[service] += 1
            else:
                span_ok = False
        full_correct += int(span_ok)

    total = len(root_spans)
    per_service = {
        service: {
            "correct": per_service_correct[service],
            "total": per_service_total[service],
            "accuracy_pct": (
                per_service_correct[service] / per_service_total[service] * 100.0
                if per_service_total[service]
                else 0.0
            ),
        }
        for service in service_ips
    }
    return {
        "correct": full_correct,
        "total": total,
        "accuracy_pct": full_correct / total * 100.0 if total else 0.0,
        "per_service": per_service,
    }


def event_id_from_span_id(span_id):
    if not span_id or len(span_id) != 2:
        return None
    sid = str(span_id[1])
    if not sid.startswith("rpc-"):
        return None
    parts = sid.split(".")
    if not parts:
        return None
    return parts[0].replace("rpc-", "", 1)


def evaluate_reconstruction_metrics(
    events,
    root_ip,
    tree,
    pred_by_process,
    in_spans_by_process,
    client_to_server,
):
    server_ips = {event["server"] for event in events}
    client_ips = {event["client"] for event in events}
    external_clients = client_ips - server_ips
    root_events = sorted(
        [
            event
            for event in events
            if event["server"] == root_ip and event["client"] in external_clients
        ],
        key=lambda event: (event["start_mus"], event["start_mus"] + event["duration_mus"], event["event_id"]),
    )
    root_trace_ids = [event["trace_id"] for event in root_events]
    root_trace_set = set(root_trace_ids)
    eval_events = [event for event in events if event["trace_id"] in root_trace_set]
    eval_event_by_id = {event["event_id"]: event for event in eval_events}
    root_event_ids = {event["event_id"] for event in root_events}

    predicted_parent_by_event = {}
    for service, node in tree.items():
        assignments_for_service = pred_by_process.get(service, {})
        parent_spans = in_spans_by_process.get(service, [])
        for child in node["children"]:
            assignments_for_child = assignments_for_service.get(child, {})
            for parent_span in parent_spans:
                parent_event_id = event_id_from_span_id(parent_span.GetId())
                predicted_client_span_id = assignments_for_child.get(parent_span.GetId())
                predicted_server_span_id = client_to_server.get(predicted_client_span_id)
                child_event_id = event_id_from_span_id(predicted_server_span_id)
                if (
                    parent_event_id in eval_event_by_id
                    and child_event_id in eval_event_by_id
                    and child_event_id not in root_event_ids
                ):
                    predicted_parent_by_event[child_event_id] = parent_event_id

    children_by_parent = defaultdict(list)
    for child_event_id, parent_event_id in predicted_parent_by_event.items():
        children_by_parent[parent_event_id].append(child_event_id)
    for child_ids in children_by_parent.values():
        child_ids.sort(
            key=lambda event_id: (
                eval_event_by_id[event_id]["start_mus"],
                eval_event_by_id[event_id]["start_mus"] + eval_event_by_id[event_id]["duration_mus"],
                event_id,
            )
        )

    predicted_trace_by_event = {}
    for root_event in root_events:
        predicted_trace_by_event[root_event["event_id"]] = root_event["trace_id"]
        queue = deque([root_event["event_id"]])
        visited = {root_event["event_id"]}
        while queue:
            parent_event_id = queue.popleft()
            for child_event_id in children_by_parent.get(parent_event_id, []):
                if child_event_id in visited:
                    continue
                visited.add(child_event_id)
                predicted_trace_by_event[child_event_id] = root_event["trace_id"]
                queue.append(child_event_id)

    req_tolerance_mus = int(os.getenv("TRACEWEAVER_GT_REQ_TOLERANCE_US", "50000"))
    res_tolerance_mus = int(os.getenv("TRACEWEAVER_GT_RES_TOLERANCE_US", "80000"))
    events_by_trace = defaultdict(list)
    for event in eval_events:
        events_by_trace[event["trace_id"]].append(event)
    for trace_events in events_by_trace.values():
        trace_events.sort(key=lambda event: (event["start_mus"], event["start_mus"] + event["duration_mus"], event["event_id"]))

    def select_ground_truth_parent(child_event, trace_events):
        if child_event["event_id"] in root_event_ids or child_event["client"] in external_clients:
            return None
        candidates = [
            event
            for event in trace_events
            if event["event_id"] != child_event["event_id"] and event["server"] == child_event["client"]
        ]
        if not candidates:
            return None

        child_start = child_event["start_mus"]
        child_end = child_event["start_mus"] + child_event["duration_mus"]
        containing = [
            event
            for event in candidates
            if event["start_mus"] - req_tolerance_mus <= child_start
            and event["start_mus"] + event["duration_mus"] + res_tolerance_mus >= child_end
        ]
        if containing:
            return min(
                containing,
                key=lambda event: (
                    event["duration_mus"],
                    abs(child_start - event["start_mus"]),
                    event["event_id"],
                ),
            )

        causal = [
            event
            for event in candidates
            if event["start_mus"] <= child_start + req_tolerance_mus
        ]
        if causal:
            return min(
                causal,
                key=lambda event: (
                    max(child_end - (event["start_mus"] + event["duration_mus"]), 0),
                    abs(child_start - event["start_mus"]),
                    event["duration_mus"],
                    event["event_id"],
                ),
            )
        return min(
            candidates,
            key=lambda event: (
                abs(child_start - event["start_mus"]),
                event["duration_mus"],
                event["event_id"],
            ),
        )

    ground_truth_parent_by_event = {}
    for trace_events in events_by_trace.values():
        for child_event in trace_events:
            parent_event = select_ground_truth_parent(child_event, trace_events)
            if parent_event is not None:
                ground_truth_parent_by_event[child_event["event_id"]] = parent_event["event_id"]

    total_events = len(eval_events)
    correct_events = 0
    unpredicted_events = 0
    per_trace_total = Counter()
    per_trace_correct = Counter()
    trace_assignment_ok_by_trace = {trace_id: True for trace_id in root_trace_ids}
    for event in eval_events:
        predicted_trace_id = predicted_trace_by_event.get(event["event_id"])
        is_ok = predicted_trace_id == event["trace_id"]
        correct_events += int(is_ok)
        per_trace_total[event["trace_id"]] += 1
        per_trace_correct[event["trace_id"]] += int(is_ok)
        if predicted_trace_id is None:
            unpredicted_events += 1
        if not is_ok:
            trace_assignment_ok_by_trace[event["trace_id"]] = False

    ground_truth_edges = {
        (parent_event_id, child_event_id)
        for child_event_id, parent_event_id in ground_truth_parent_by_event.items()
    }
    predicted_edges = {
        (parent_event_id, child_event_id)
        for child_event_id, parent_event_id in predicted_parent_by_event.items()
        if child_event_id in eval_event_by_id and child_event_id not in root_event_ids
    }
    correct_edges = predicted_edges & ground_truth_edges
    precision = len(correct_edges) / len(predicted_edges) if predicted_edges else 0.0
    recall = len(correct_edges) / len(ground_truth_edges) if ground_truth_edges else 0.0
    f1 = 2.0 * precision * recall / (precision + recall) if precision + recall > 0.0 else 0.0

    ground_truth_edges_by_trace = defaultdict(set)
    for parent_event_id, child_event_id in ground_truth_edges:
        ground_truth_edges_by_trace[eval_event_by_id[child_event_id]["trace_id"]].add((parent_event_id, child_event_id))
    predicted_edges_by_trace = defaultdict(set)
    for parent_event_id, child_event_id in predicted_edges:
        predicted_edges_by_trace[eval_event_by_id[child_event_id]["trace_id"]].add((parent_event_id, child_event_id))

    structural_trace_errors = {}
    full_correct = 0
    for trace_id in root_trace_ids:
        missing_edges = ground_truth_edges_by_trace.get(trace_id, set()) - predicted_edges_by_trace.get(trace_id, set())
        extra_edges = predicted_edges_by_trace.get(trace_id, set()) - ground_truth_edges_by_trace.get(trace_id, set())
        trace_assignment_ok = trace_assignment_ok_by_trace.get(trace_id, False)
        if trace_assignment_ok and not missing_edges and not extra_edges:
            full_correct += 1
        else:
            structural_trace_errors[trace_id] = {
                "span_trace_ok": trace_assignment_ok,
                "span_errors": per_trace_total[trace_id] - per_trace_correct[trace_id],
                "missing_parent_child_edges": len(missing_edges),
                "extra_parent_child_edges": len(extra_edges),
            }

    trace_assignment_correct = sum(1 for trace_id in root_trace_ids if trace_assignment_ok_by_trace.get(trace_id))
    predicted_span_count = total_events - unpredicted_events
    return {
        "correct": full_correct,
        "total": len(root_trace_ids),
        "accuracy_pct": full_correct / len(root_trace_ids) * 100.0 if root_trace_ids else 0.0,
        "full_trace_accuracy_pct": full_correct / len(root_trace_ids) * 100.0 if root_trace_ids else 0.0,
        "full_trace_accuracy_ok": full_correct,
        "full_trace_accuracy_total": len(root_trace_ids),
        "trace_assignment_accuracy_pct": (
            trace_assignment_correct / len(root_trace_ids) * 100.0 if root_trace_ids else 0.0
        ),
        "trace_assignment_accuracy_ok": trace_assignment_correct,
        "trace_assignment_accuracy_total": len(root_trace_ids),
        "span_accuracy_pct": correct_events / total_events * 100.0 if total_events else 0.0,
        "span_accuracy_ok": correct_events,
        "span_accuracy_total": total_events,
        "coverage_pct": predicted_span_count / total_events * 100.0 if total_events else 0.0,
        "coverage_ok": predicted_span_count,
        "coverage_total": total_events,
        "unpredicted_event_count": unpredicted_events,
        "parent_child_edge_precision_pct": precision * 100.0,
        "parent_child_edge_recall_pct": recall * 100.0,
        "parent_child_edge_f1_pct": f1 * 100.0,
        "parent_child_edge_correct": len(correct_edges),
        "parent_child_edge_predicted": len(predicted_edges),
        "parent_child_edge_ground_truth": len(ground_truth_edges),
        "parent_child_edge_false_positive": len(predicted_edges - ground_truth_edges),
        "parent_child_edge_false_negative": len(ground_truth_edges - predicted_edges),
        "parent_child_edge_unpredicted": sum(
            1 for child_event_id in ground_truth_parent_by_event if child_event_id not in predicted_parent_by_event
        ),
        "structural_trace_error_count": len(structural_trace_errors),
        "structural_trace_errors": structural_trace_errors,
    }


def print_tree(tree, root_ip):
    def walk(service, indent=0):
        print(f"{'  ' * indent}{service} ({len(tree[service]['events'])} incoming)")
        for child in tree[service]["children"]:
            walk(child, indent + 1)

    walk(root_ip)


def write_report(path, csv_path, root_ip, tree, service_accuracy, e2e_accuracy, parallel):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    report = {
        "algorithm": "local_traceweaver_v2",
        "parallel": parallel,
        "input_csv": os.path.abspath(csv_path),
        "root_ip": root_ip,
        "call_graph": {
            service: {
                "children": node["children"],
                "incoming_count": len(node["events"]),
            }
            for service, node in tree.items()
        },
        "service_accuracy": service_accuracy,
        "end_to_end_accuracy": e2e_accuracy,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)


def parse_jaeger_trace(path, synthesize_http_clients=True):
    with open(path, "r", encoding="utf-8") as f:
        json_data = json.load(f)
    traces = json_data.get("data", [])
    if len(traces) != 1:
        return None

    trace = traces[0]
    trace_id = trace["traceID"]
    processes = {
        process_id: process["serviceName"]
        for process_id, process in trace.get("processes", {}).items()
    }
    spans = {}
    for span_json in trace.get("spans", []):
        span_id = (trace_id, span_json["spanID"])
        references = [
            (ref["traceID"], ref["spanID"])
            for ref in span_json.get("references", [])
        ]
        spans[span_id] = Span(
            trace_id=trace_id,
            sid=span_json["spanID"],
            start_mus=span_json["startTime"],
            duration_mus=span_json["duration"],
            op_name=span_json.get("operationName"),
            references=references,
            process_id=span_json["processID"],
            span_kind=tag_value(span_json.get("tags", []), "span.kind"),
            span_tags=span_json.get("tags", []),
        )

    if synthesize_http_clients:
        additions = {}
        rewrites = {}
        for span_id, span in list(spans.items()):
            if span.span_kind != "server" or not span.references:
                continue
            parent = spans.get(span.references[0])
            if parent is None or parent.span_kind != "server":
                continue
            if processes[parent.process_id] == processes[span.process_id]:
                continue

            synthetic_sid = f"{span.sid}.synthetic_client"
            synthetic_id = (trace_id, synthetic_sid)
            additions[synthetic_id] = Span(
                trace_id=trace_id,
                sid=synthetic_sid,
                start_mus=span.start_mus,
                duration_mus=span.duration_mus,
                op_name=span.op_name,
                references=[span.references[0]],
                process_id=parent.process_id,
                span_kind="client",
                span_tags=[{"key": "span.kind", "value": "client"}],
            )
            rewrites[span_id] = synthetic_id

        spans.update(additions)
        for span_id, synthetic_id in rewrites.items():
            spans[span_id].references = [synthetic_id]

    for span in spans.values():
        span.children_spans = []
    for span_id, span in spans.items():
        for reference in span.references:
            if reference in spans:
                spans[reference].AddChild(span_id)
    for span in spans.values():
        span.children_spans.sort(key=lambda child_id: spans[child_id].start_mus)

    return trace_id, spans, processes


def load_jaeger_inputs(jaeger_dir, root_operation, synthesize_http_clients=True):
    all_spans = {}
    all_processes = {}
    in_spans_by_process = defaultdict(list)
    out_spans_by_process = defaultdict(list)
    skipped = 0

    for filename in sorted(os.listdir(jaeger_dir)):
        if not filename.endswith(".json"):
            continue
        parsed = parse_jaeger_trace(
            os.path.join(jaeger_dir, filename),
            synthesize_http_clients=synthesize_http_clients,
        )
        if parsed is None:
            skipped += 1
            continue

        trace_id, spans, processes = parsed
        roots = [span for span in spans.values() if span.IsRoot()]
        if root_operation and (not roots or roots[0].op_name != root_operation):
            skipped += 1
            continue

        all_processes[trace_id] = processes
        all_spans.update(spans)
        for span in spans.values():
            process = processes[span.process_id]
            if span.span_kind == "server":
                in_spans_by_process[process].append(span)
            elif span.span_kind == "client":
                out_spans_by_process[process].append(span)

    for span_map in (in_spans_by_process, out_spans_by_process):
        for process, spans in span_map.items():
            span_map[process] = sorted(
                spans,
                key=lambda span: (span.start_mus, span.start_mus + span.duration_mus, span.sid),
            )

    return (
        all_spans,
        all_processes,
        dict(in_spans_by_process),
        dict(out_spans_by_process),
        skipped,
    )


def build_jaeger_call_tree(all_spans, all_processes, root_operation=None):
    root_counter = Counter()
    client_to_server = {}
    server_span_by_id = {}
    edge_first_start = {}

    for span_id, span in all_spans.items():
        process_name = all_processes[span.trace_id][span.process_id]
        if span.span_kind == "server":
            server_span_by_id[span_id] = span
            if span.IsRoot() and (root_operation is None or span.op_name == root_operation):
                root_counter[process_name] += 1
        elif span.span_kind == "client" and len(span.children_spans) == 1:
            child_span_id = span.children_spans[0]
            child_span = all_spans.get(child_span_id)
            if child_span is None or child_span.span_kind != "server":
                continue
            parent_process = process_name
            child_process = all_processes[span.trace_id][child_span.process_id]
            if parent_process == child_process:
                continue
            client_to_server[span_id] = child_span_id
            edge = (parent_process, child_process)
            edge_first_start[edge] = min(edge_first_start.get(edge, span.start_mus), span.start_mus)

    if not root_counter:
        return None, {}, client_to_server, server_span_by_id

    root_process = root_counter.most_common(1)[0][0]
    children_by_process = defaultdict(set)
    for parent_process, child_process in edge_first_start:
        children_by_process[parent_process].add(child_process)

    tree = {}
    visited = {root_process}
    queue = deque([root_process])
    while queue:
        process = queue.popleft()
        children = sorted(
            children_by_process.get(process, set()) - visited,
            key=lambda child: (edge_first_start.get((process, child), float("inf")), child),
        )
        tree[process] = {"children": children}
        for child in children:
            visited.add(child)
            queue.append(child)

    return root_process, tree, client_to_server, server_span_by_id


def restrict_to_complete_traces(in_span_partitions, out_span_partitions):
    incoming_endpoint, incoming_spans = list(in_span_partitions.items())[0]
    trace_sets = [{span.trace_id for span in incoming_spans}]
    trace_sets.extend({span.trace_id for span in spans} for spans in out_span_partitions.values())
    complete_trace_ids = set.intersection(*trace_sets) if trace_sets else set()

    return (
        {
            incoming_endpoint: [
                span for span in incoming_spans if span.trace_id in complete_trace_ids
            ]
        },
        {
            endpoint: [span for span in spans if span.trace_id in complete_trace_ids]
            for endpoint, spans in out_span_partitions.items()
        },
        complete_trace_ids,
    )


def run_jaeger_traceweaver(
    all_spans,
    all_processes,
    in_spans_by_process,
    out_spans_by_process,
    tw_version="v2",
    parallel=False,
    complete_only=True,
    verbose=True,
):
    predictor, predictor_name, method = make_predictor(tw_version, all_spans, all_processes)
    pred_by_process = {}
    true_by_process = {}
    in_partitions_by_process = {}
    service_accuracy = {}
    complete_traces_by_process = {}

    for process in sorted(out_spans_by_process):
        if process not in in_spans_by_process:
            continue

        in_span_partitions = partition_spans(
            in_spans_by_process[process],
            lambda span: span.GetParentProcess(all_processes, all_spans),
        )
        out_span_partitions = partition_spans(
            out_spans_by_process[process],
            lambda span: (
                span.GetChildProcess(all_processes, all_spans)
                if len(span.children_spans) == 1
                else None
            ),
        )
        out_span_partitions.pop(None, None)

        if len(in_span_partitions) != 1 or not out_span_partitions:
            continue

        if complete_only:
            in_span_partitions, out_span_partitions, complete_trace_ids = restrict_to_complete_traces(
                in_span_partitions,
                out_span_partitions,
            )
        else:
            complete_trace_ids = {
                span.trace_id for spans in in_span_partitions.values() for span in spans
            }

        true_assignments = get_ground_truth(in_span_partitions, out_span_partitions)
        pred_assignments = find_assignments_with_predictor(
            predictor,
            method,
            process,
            in_span_partitions,
            out_span_partitions,
            parallel,
            true_assignments,
        )
        correct, total, pct = accuracy_for_service(
            pred_assignments,
            true_assignments,
            in_span_partitions,
        )

        pred_by_process[process] = pred_assignments
        true_by_process[process] = true_assignments
        in_partitions_by_process[process] = in_span_partitions
        complete_traces_by_process[process] = complete_trace_ids
        service_accuracy[process] = {
            "correct": correct,
            "total": total,
            "accuracy_pct": pct,
            "incoming_endpoint": next(iter(in_span_partitions)),
            "outgoing_endpoints": list(out_span_partitions),
            "complete_traces": len(complete_trace_ids),
        }

        if verbose:
            print(
                f"[{process}] local {predictor_name} {method}: "
                f"{pct:.2f}% ({correct}/{total}), "
                f"out={list(out_span_partitions)}"
            )

    return (
        pred_by_process,
        true_by_process,
        in_partitions_by_process,
        complete_traces_by_process,
        service_accuracy,
    )


def trace_correctness_by_process(pred_assignments, true_assignments, in_span_partitions):
    trace_correct = {}
    _, incoming_spans = list(in_span_partitions.items())[0]
    for incoming_span in incoming_spans:
        incoming_id = incoming_span.GetId()
        trace_correct[incoming_span.trace_id] = all(
            pred_assignments.get(endpoint, {}).get(incoming_id)
            == true_assignments[endpoint][incoming_id]
            for endpoint in true_assignments
        )
    return trace_correct


def jaeger_full_topology_accuracy(
    root_process,
    tree,
    pred_by_process,
    in_spans_by_process,
    client_to_server,
    server_span_by_id,
):
    if not root_process or root_process not in tree or root_process not in in_spans_by_process:
        return None
    return evaluate_end_to_end(
        root_process,
        tree,
        pred_by_process,
        in_spans_by_process,
        client_to_server,
        server_span_by_id,
    )


def write_jaeger_report(
    path,
    jaeger_dir,
    service_accuracy,
    full_topology_accuracy,
    call_tree,
    root_process,
    parallel,
    skipped,
    synthesize_http_clients,
    tw_version,
):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    weighted_correct = sum(item["correct"] for item in service_accuracy.values())
    weighted_total = sum(item["total"] for item in service_accuracy.values())
    report = {
        "algorithm": f"local_traceweaver_{tw_version}",
        "input_jaeger_dir": os.path.abspath(jaeger_dir),
        "parallel": parallel,
        "skipped_trace_files": skipped,
        "root_process": root_process,
        "call_graph": {
            process: {
                "children": node["children"],
            }
            for process, node in call_tree.items()
        },
        "service_accuracy": service_accuracy,
        "weighted_service_accuracy": {
            "correct": weighted_correct,
            "total": weighted_total,
            "accuracy_pct": (
                weighted_correct / weighted_total * 100.0 if weighted_total else 0.0
            ),
        },
        "full_topology_accuracy": full_topology_accuracy,
        "notes": [
            (
                "Jaeger HTTP server-to-server edges are adapted by synthesizing client spans."
                if synthesize_http_clients
                else "Jaeger traces are evaluated using real client spans only; synthetic HTTP client spans are disabled."
            ),
            "TraceWeaver assumes each outgoing endpoint appears once per incoming span; incomplete traces are filtered per service.",
        ],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Adapt cleaned CSV or Jaeger traces to a self-contained TraceWeaver V2 MaxScoreBatch runner"
    )
    parser.add_argument("--csv", default=DEFAULT_INPUT, help="Input cleaned CSV")
    parser.add_argument(
        "--jaeger-dir",
        default=None,
        help="Directory of Jaeger API trace JSON files; when set, CSV input is ignored",
    )
    parser.add_argument(
        "--root-operation",
        default="HTTP GET /hotels",
        help="Root operation to keep when reading Jaeger traces",
    )
    parser.add_argument(
        "--report-out",
        default="result/traceweaver_baseline_report.json",
        help="JSON report path",
    )
    parser.add_argument(
        "--tw-version",
        choices=["v2"],
        default="v2",
        help="TraceWeaver implementation to run; this runner is self-contained for V2",
    )
    parser.add_argument(
        "--parallel",
        action="store_true",
        help="Use TraceWeaver's parallel sibling-scoring mode instead of sequential scoring",
    )
    parser.add_argument(
        "--no-synthesize-http-clients",
        action="store_true",
        help="Do not add synthetic client spans for Jaeger server-to-server HTTP edges",
    )
    parser.add_argument("--quiet", action="store_true", help="Suppress topology and per-service details")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.jaeger_dir:
        (
            all_spans,
            all_processes,
            in_spans_by_process,
            out_spans_by_process,
            skipped,
        ) = load_jaeger_inputs(
            args.jaeger_dir,
            args.root_operation,
            synthesize_http_clients=not args.no_synthesize_http_clients,
        )
        (
            pred_by_process,
            true_by_process,
            in_partitions_by_process,
            complete_traces_by_process,
            service_accuracy,
        ) = run_jaeger_traceweaver(
            all_spans,
            all_processes,
            in_spans_by_process,
            out_spans_by_process,
            tw_version=args.tw_version,
            parallel=args.parallel,
            complete_only=True,
            verbose=not args.quiet,
        )
        (
            root_process,
            call_tree,
            client_to_server,
            server_span_by_id,
        ) = build_jaeger_call_tree(
            all_spans,
            all_processes,
            root_operation=args.root_operation,
        )
        full_topology_accuracy = jaeger_full_topology_accuracy(
            root_process,
            call_tree,
            pred_by_process,
            in_spans_by_process,
            client_to_server,
            server_span_by_id,
        )
        weighted_correct = sum(item["correct"] for item in service_accuracy.values())
        weighted_total = sum(item["total"] for item in service_accuracy.values())

        print("\n==================================================")
        print(
            f"Jaeger local TraceWeaver {args.tw_version} weighted service accuracy: "
            f"{(weighted_correct / weighted_total * 100.0 if weighted_total else 0.0):.2f}% "
            f"({weighted_correct}/{weighted_total})"
        )
        for process, stats in service_accuracy.items():
            print(
                f"  {process}: {stats['accuracy_pct']:.2f}% "
                f"({stats['correct']}/{stats['total']})"
            )
        if full_topology_accuracy:
            print(
                "Full-topology accuracy: "
                f"{full_topology_accuracy['accuracy_pct']:.2f}% "
                f"({full_topology_accuracy['correct']}/{full_topology_accuracy['total']})"
            )
        print("==================================================")

        write_jaeger_report(
            args.report_out,
            args.jaeger_dir,
            service_accuracy,
            full_topology_accuracy,
            call_tree,
            root_process,
            args.parallel,
            skipped,
            not args.no_synthesize_http_clients,
            args.tw_version,
        )
        print(f"Report saved to {os.path.abspath(args.report_out)}")
        return

    events = load_rpc_events(args.csv)
    root_ip, tree = infer_topology(events)
    if not root_ip:
        raise SystemExit("Failed to infer call graph from cleaned CSV")

    if not args.quiet:
        print("Inferred call graph:")
        print_tree(tree, root_ip)
        print()

    (
        all_spans,
        all_processes,
        in_spans_by_process,
        out_spans_by_process,
        client_to_server,
        server_span_by_id,
    ) = build_traceweaver_inputs(events, tree)

    pred_by_process, _, _, service_accuracy = run_traceweaver(
        all_spans,
        all_processes,
        tree,
        in_spans_by_process,
        out_spans_by_process,
        tw_version=args.tw_version,
        parallel=args.parallel,
        verbose=not args.quiet,
    )
    legacy_e2e_accuracy = evaluate_end_to_end(
        root_ip,
        tree,
        pred_by_process,
        in_spans_by_process,
        client_to_server,
        server_span_by_id,
    )
    e2e_accuracy = evaluate_reconstruction_metrics(
        events,
        root_ip,
        tree,
        pred_by_process,
        in_spans_by_process,
        client_to_server,
    )
    e2e_accuracy["per_service"] = legacy_e2e_accuracy["per_service"]
    e2e_accuracy["legacy_trace_assignment_accuracy"] = {
        "correct": legacy_e2e_accuracy["correct"],
        "total": legacy_e2e_accuracy["total"],
        "accuracy_pct": legacy_e2e_accuracy["accuracy_pct"],
    }

    print("\n==================================================")
    print(
        f"Upstream TraceWeaver {args.tw_version} FullTraceAcc(structural): "
        f"{e2e_accuracy['accuracy_pct']:.2f}% "
        f"({e2e_accuracy['correct']}/{e2e_accuracy['total']})"
    )
    print(
        "TraceAssignment / Span / Coverage / ParentEdgeF1: "
        f"{e2e_accuracy['trace_assignment_accuracy_pct']:.2f}% / "
        f"{e2e_accuracy['span_accuracy_pct']:.2f}% / "
        f"{e2e_accuracy['coverage_pct']:.2f}% / "
        f"{e2e_accuracy['parent_child_edge_f1_pct']:.2f}%"
    )
    print("Per-service end-to-end chain accuracy:")
    for service, stats in e2e_accuracy["per_service"].items():
        print(
            f"  {service}: {stats['accuracy_pct']:.2f}% "
            f"({stats['correct']}/{stats['total']})"
        )
    print("==================================================")

    write_report(
        args.report_out,
        args.csv,
        root_ip,
        tree,
        service_accuracy,
        e2e_accuracy,
        args.parallel,
    )
    print(f"Report saved to {os.path.abspath(args.report_out)}")


if __name__ == "__main__":
    main()
