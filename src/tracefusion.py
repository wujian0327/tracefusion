import argparse
import bisect
import csv
import json
import math
import os
import re
import time
from collections import defaultdict
from datetime import datetime
from urllib.parse import parse_qsl, urlparse
import numpy as np
from scipy.optimize import linear_sum_assignment

def ts_to_float(ts_str):
    if not ts_str: return 0.0
    dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S.%f")
    return dt.timestamp()

def normalize_token_value(v):
    s = str(v).strip().lower()
    if not s or s in {'nil', 'none', 'null'}:
        return ''
    if re.fullmatch(r"-?\d+\.\d+", s):
        try:
            return f"{float(s):.3f}"
        except ValueError:
            return s
    return s

def is_html_lineage_noise(value):
    if not isinstance(value, str):
        return False
    s = value.strip().lower()
    if not s:
        return False
    if s.startswith(('<!doctype html', '<html', '<head', '<body', '<meta ', '<div ', '<script', '<style')):
        return True
    html_markers = (
        '<!doctype html',
        '<html',
        '<head',
        '<body',
        '<meta ',
        '<script',
        '<style',
        '</div>',
        '</html>',
    )
    marker_hits = sum(1 for marker in html_markers if marker in s)
    if marker_hits >= 2:
        return True
    return len(s) > 1000 and '<' in s and '>' in s and re.search(r"</(div|html|body|script|style|span|table)>", s)

def extract_lineage_tokens(data_str):
    """
    从 Request payload 中提取结构化血缘 token。
    """
    tokens = set()
    if not data_str:
        return tokens

    def add_derived_value_tokens(nv):
        for part in re.split(r"[^a-z0-9]+", nv):
            if len(part) < 2 or part in {'http', 'https', 'json', 'true', 'false'}:
                continue
            tokens.add(f"p:{part}")
            m = re.fullmatch(r"[a-z]+(\d{3,8})", part)
            if m:
                tokens.add(f"n:{m.group(1)}")
            elif re.fullmatch(r"\d{3,8}", part):
                tokens.add(f"n:{part}")

    def add_value_token(v):
        if is_html_lineage_noise(v):
            return
        nv = normalize_token_value(v)
        if not nv or nv in {'0', '1', '0000000000'}:
            return
        tokens.add(f"v:{nv}")
        add_derived_value_tokens(nv)
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", nv):
            tokens.add(f"d:{nv}")
        if re.fullmatch(r"-?\d+\.\d+", nv):
            try:
                f = float(nv)
                tokens.add(f"f2:{f:.2f}")
                tokens.add(f"f3:{f:.3f}")
            except ValueError:
                pass

    def add_kv_tokens(key, value):
        if is_html_lineage_noise(value):
            return
        nk = str(key).strip().lower()
        nv = normalize_token_value(value)
        if not nk or not nv:
            return
        if nv in {'0', '1', '0000000000'}:
            return
        tokens.add(f"kv:{nk}={nv}")
        add_derived_value_tokens(nv)

    def try_walk_json_string(value):
        if not isinstance(value, str):
            return False
        stripped = value.strip()
        if not stripped or stripped[0] not in "[{":
            return False
        try:
            walk(json.loads(stripped))
            return True
        except Exception:
            return False

    def walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if is_html_lineage_noise(v):
                    continue
                if k == 'paras' and isinstance(v, str):
                    for pk, pv in parse_qsl(v, keep_blank_values=True):
                        add_kv_tokens(pk, pv)
                        add_value_token(pv)
                elif k == 'url' and isinstance(v, str):
                    try:
                        parsed = urlparse(v)
                        for segment in parsed.path.split('/'):
                            if segment:
                                add_kv_tokens('path', segment)
                                add_value_token(segment)
                        for pk, pv in parse_qsl(parsed.query, keep_blank_values=True):
                            add_kv_tokens(pk, pv)
                            add_value_token(pv)
                    except ValueError:
                        pass
                    continue
                elif isinstance(v, str) and try_walk_json_string(v):
                    continue
                elif isinstance(v, list):
                    for item in v:
                        if isinstance(item, (int, float, str)):
                            add_kv_tokens(k, item)
                elif isinstance(v, (int, float, str)):
                    add_kv_tokens(k, v)
                    add_value_token(v)
                elif k in {'text', 'value', 'value_f32', 'value_f64', 'value_u32', 'value_u64'}:
                    add_value_token(v)
                walk(v)
        elif isinstance(obj, list):
            for item in obj:
                if is_html_lineage_noise(item):
                    continue
                walk(item)
        elif isinstance(obj, (int, float, str)):
            if is_html_lineage_noise(obj):
                return
            if isinstance(obj, str) and try_walk_json_string(obj):
                return
            add_value_token(obj)

    try:
        parsed = json.loads(data_str)
        walk(parsed)
    except Exception:
        # 兜底: 非 JSON 时抓取简单数值/日期模式
        if is_html_lineage_noise(data_str):
            return tokens
        for d in re.findall(r"\b\d{4}-\d{2}-\d{2}\b", data_str):
            tokens.add(f"d:{d}")
            tokens.add(f"v:{d}")
        for f in re.findall(r"-?\d+\.\d+", data_str):
            try:
                fv = float(f)
                tokens.add(f"f2:{fv:.2f}")
                tokens.add(f"f3:{fv:.3f}")
                tokens.add(f"v:{fv:.3f}")
            except ValueError:
                continue
    return tokens

def extract_db_lineage_tokens(data_str):
    """
    Extract business-oriented DB lineage tokens from query/result payloads.
    MongoDB rows contain protocol wrappers and nested JSON strings; this keeps
    business fields and values while dropping command/collection/cursor metadata.
    """
    tokens = set()
    if not data_str or is_html_lineage_noise(data_str):
        return tokens

    meta_keys = {
        '$db', '$clustertime', '$readpreference',
        '_id', 'id', 'lsid', 'operationtime', 'signature',
        '_class', 'password', 'roles',
        'ismaster', 'hello', 'connectionid', 'localtime',
        'logicalsessiontimeoutminutes', 'topologyversion', 'processid',
        'maxbsonobjectsize', 'maxmessagesizebytes', 'maxwireversion',
        'maxwritebatchsize', 'minwireversion', 'readonly',
        'cursor', 'firstbatch', 'nextbatch', 'ns', 'ok',
        'collection', 'command', 'query', 'result',
        'find', 'aggregate', 'insert', 'update', 'delete', 'count',
        'documents', 'updates', 'deletes', 'writeconcern',
        'roomtype',
    }
    structural_keys = {
        'filter', 'projection', 'sort', 'limit', 'skip', 'batchsize', 'singlebatch',
        '$in', '$lte', '$gte', '$lt', '$gt', '$eq', '$ne', '$and', '$or',
        '$set', '$unset', '$inc', '$push', '$pull',
    }
    wrapper_keys = {
        'query', 'result', 'cursor', 'firstbatch', 'nextbatch', 'documents',
    }
    low_value_tokens = {
        '0', '1', '0000000000', 'true', 'false',
        'rack',
    }

    def key_name(key):
        return str(key).strip()

    def normalized_key(key):
        return key_name(key).lower()

    def is_index_key(key):
        return re.fullmatch(r"\d+", key_name(key)) is not None

    def add_derived_value_tokens(nv):
        for part in re.split(r"[^a-z0-9]+", nv):
            if len(part) < 2 or part in {'http', 'https', 'json', 'true', 'false'}:
                continue
            tokens.add(f"p:{part}")
            m = re.fullmatch(r"[a-z]+(\d{3,8})", part)
            if m:
                tokens.add(f"n:{m.group(1)}")
            elif re.fullmatch(r"\d{3,8}", part):
                tokens.add(f"n:{part}")

    def add_db_value(value):
        if is_html_lineage_noise(value):
            return
        nv = normalize_token_value(value)
        if not nv or nv in low_value_tokens:
            return
        # Drop opaque Mongo/session/object ids. Business IDs such as hotelId are
        # still kept through their field-specific kv token below.
        if re.fullmatch(r"[0-9a-f]{24,32}", nv):
            return
        tokens.add(f"v:{nv}")
        add_derived_value_tokens(nv)
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", nv):
            tokens.add(f"d:{nv}")
        if re.fullmatch(r"-?\d+\.\d+", nv):
            try:
                f = float(nv)
                tokens.add(f"f2:{f:.2f}")
                tokens.add(f"f3:{f:.3f}")
            except ValueError:
                pass

    def add_db_kv(field, value):
        nk = normalized_key(field)
        nv = normalize_token_value(value)
        if not nk or not nv or nv in {'true', 'false', 'rack'}:
            return
        if re.fullmatch(r"[0-9a-f]{24,32}", nv):
            return
        tokens.add(f"kv:{nk}={nv}")
        add_db_value(value)

    def parse_json_maybe(value):
        if not isinstance(value, str):
            return None
        stripped = value.strip()
        if not stripped or stripped[0] not in '[{':
            return None
        try:
            return json.loads(stripped)
        except Exception:
            return None

    def walk(obj, active_field=None):
        parsed = parse_json_maybe(obj)
        if parsed is not None:
            walk(parsed, active_field)
            return

        if isinstance(obj, dict):
            for raw_key, value in obj.items():
                nk = normalized_key(raw_key)
                if is_html_lineage_noise(value):
                    continue
                if is_index_key(raw_key):
                    walk(value, active_field)
                elif nk in meta_keys:
                    # query/result wrappers are parsed, but their key names and
                    # command values are not useful lineage signals.
                    if nk in wrapper_keys:
                        walk(value, active_field)
                    continue
                elif nk in structural_keys or nk.startswith('$'):
                    walk(value, active_field)
                elif isinstance(value, (str, int, float)):
                    add_db_kv(raw_key, value)
                else:
                    walk(value, raw_key)
        elif isinstance(obj, list):
            for item in obj:
                walk(item, active_field)
        elif isinstance(obj, (str, int, float)):
            if active_field:
                add_db_kv(active_field, obj)
            else:
                add_db_value(obj)

    try:
        walk(json.loads(data_str))
    except Exception:
        for d in re.findall(r"\b\d{4}-\d{2}-\d{2}\b", data_str):
            tokens.add(f"d:{d}")
            tokens.add(f"v:{d}")
        for number in re.findall(r"\b\d{2,8}\b", data_str):
            tokens.add(f"v:{number}")

    return tokens

def filter_db_result_tokens(req_tokens, res_tokens):
    if not req_tokens or not res_tokens:
        return set()

    req_values = set()
    for token in req_tokens:
        if token.startswith('kv:') and '=' in token:
            req_values.add(token.split('=', 1)[1])
        elif token.startswith(('v:', 'd:')):
            req_values.add(token.split(':', 1)[1])

    filtered = set()
    for token in res_tokens:
        if token in req_tokens:
            filtered.add(token)
            continue
        if not token.startswith('kv:') or '=' not in token:
            continue
        key_value = token[3:]
        key, value = key_value.split('=', 1)
        if value in req_values:
            filtered.add(token)
            continue
        is_business_identifier = (
            key.endswith('id')
            or key in {'id', 'name', 'username', 'userid', 'hotelid', 'reservationid'}
        )
        if is_business_identifier and not re.fullmatch(r"[0-9a-f]{24,32}", value):
            filtered.add(token)
    return filtered

def compute_idf_weights(events):
    """
    基于目标集合估计 IDF，抑制高频无区分 token。
    """
    n = len(events)
    if n == 0:
        return {}
    df = defaultdict(int)
    for e in events:
        all_tokens = e.get('lineage_all_tokens')
        if all_tokens is None:
            all_tokens = set()
            all_tokens.update(e.get('lineage_req_tokens', set()))
            all_tokens.update(e.get('lineage_res_tokens', set()))
        for t in all_tokens:
            df[t] += 1
    return {t: math.log((n + 1.0) / (c + 1.0)) + 1.0 for t, c in df.items()}

def token_set_to_weight_map(tokens, weight=1.0):
    return {t: float(weight) for t in tokens}

def merge_token_weight_maps(*maps):
    merged = {}
    for token_map in maps:
        if not token_map:
            continue
        for token, weight in token_map.items():
            if weight <= 0:
                continue
            merged[token] = max(merged.get(token, 0.0), float(weight))
    return merged

def decay_token_weight_map(token_map, decay):
    if not token_map:
        return {}
    out = {}
    for token, weight in token_map.items():
        decayed = float(weight) * decay
        if decayed > 1e-9:
            out[token] = decayed
    return out

def lineage_overlap_score(parent_tokens, child_tokens, idf_weights):
    if not parent_tokens or not child_tokens:
        return 0.0
    num = 0.0
    den = 0.0
    idf_get = idf_weights.get
    for token in parent_tokens:
        weight = idf_get(token, 1.0)
        den += weight
        if token in child_tokens:
            num += weight
    if den <= 0:
        return 0.0
    return num / den

def weighted_lineage_overlap_score(parent_token_weights, child_tokens, idf_weights):
    if not parent_token_weights or not child_tokens:
        return 0.0
    num = 0.0
    den = 0.0
    idf_get = idf_weights.get
    for token, token_weight in parent_token_weights.items():
        weighted = token_weight * idf_get(token, 1.0)
        den += weighted
        if token in child_tokens:
            num += weighted
    if den <= 0:
        return 0.0
    return num / den

def parent_child_lineage_score(parent_event, child_event, idf_weights):
    parent_req = parent_event.get('lineage_req_tokens', set())
    parent_res = parent_event.get('lineage_res_tokens', set())
    child_req = child_event.get('lineage_req_tokens', set())
    child_res = child_event.get('lineage_res_tokens', set())
    parent_weights = parent_event.get('lineage_parent_weights')
    if parent_weights is None:
        parent_weights = merge_token_weight_maps(
            token_set_to_weight_map(parent_req, 1.0),
            token_set_to_weight_map(parent_res, 0.8),
        )
    child_tokens = child_event.get('lineage_all_tokens')
    if child_tokens is None:
        child_tokens = set(child_req) | set(child_res)
    context_score = weighted_lineage_overlap_score(parent_weights, child_tokens, idf_weights)
    req_req = lineage_overlap_score(parent_req, child_req, idf_weights)
    req_res = lineage_overlap_score(parent_req, child_res, idf_weights)
    res_req = lineage_overlap_score(parent_res, child_req, idf_weights)
    res_res = lineage_overlap_score(parent_res, child_res, idf_weights)
    return max(context_score, 0.35 * req_req + 0.20 * req_res + 0.30 * res_req + 0.15 * res_res)

def attach_db_lineage_to_service_spans(all_events, db_events):
    """
    Optional DB lineage augmentation. DB events do not carry trace_id, so we
    attach filtered query/result business tokens to the shortest service span
    whose server IP is the DB client IP and whose time window contains the DB
    call. Result tokens are weighted lower because result sets are often broad
    under high concurrency.
    """
    if not all_events or not db_events:
        return 0

    events_by_service = defaultdict(list)
    for event in all_events:
        events_by_service[event['server']].append(event)
    for events in events_by_service.values():
        events.sort(key=lambda e: (e['req_ts'], e['res_ts'], e['key']))

    attached = 0
    min_match_score = float(os.getenv("LINEAGE_DB_MIN_MATCH_SCORE", "0.08"))
    ambiguity_margin = float(os.getenv("LINEAGE_DB_AMBIGUITY_MARGIN", "0.03"))

    def strong_lineage_tokens(tokens):
        return {
            token
            for token in tokens
            if token.startswith(('kv:', 'd:'))
        }

    def db_owner_score(event, db_tokens):
        event_tokens = strong_lineage_tokens(
            event.get('lineage_req_tokens', set()) | event.get('lineage_res_tokens', set())
        )
        if not event_tokens or not db_tokens:
            return 0.0
        shared = event_tokens & db_tokens
        if not shared:
            return 0.0
        return len(shared) / max(1, min(len(event_tokens), len(db_tokens)))

    for db_event in db_events:
        db_req_tokens = db_event.get('lineage_req_tokens', set())
        db_res_tokens = db_event.get('lineage_res_tokens', set())
        if not db_req_tokens and not db_res_tokens:
            continue
        db_match_tokens = strong_lineage_tokens(db_req_tokens | db_res_tokens)
        candidates = [
            event
            for event in events_by_service.get(db_event['client'], [])
            if event['req_ts'] - 0.02 <= db_event['req_ts']
            and event['res_ts'] + 0.08 >= db_event['res_ts']
        ]
        if not candidates:
            candidates = [
                event
                for event in events_by_service.get(db_event['client'], [])
                if event['req_ts'] - 0.02 <= db_event['req_ts'] <= event['res_ts'] + 0.08
            ]
        if not candidates:
            continue

        ranked = sorted(
            (
                (
                    db_owner_score(event, db_match_tokens),
                    -(event['res_ts'] - event['req_ts']),
                    -abs(db_event['req_ts'] - event['req_ts']),
                    event,
                )
                for event in candidates
            ),
            reverse=True,
        )
        best_score = ranked[0][0]
        second_score = ranked[1][0] if len(ranked) > 1 else 0.0
        if best_score < min_match_score or best_score - second_score < ambiguity_margin:
            continue
        owner = ranked[0][3]
        owner['lineage_req_tokens'].update(db_req_tokens)
        owner['lineage_all_tokens'].update(db_req_tokens)
        owner['lineage_parent_weights'] = merge_token_weight_maps(
            owner.get('lineage_parent_weights', {}),
            token_set_to_weight_map(db_req_tokens, 0.9),
            token_set_to_weight_map(db_res_tokens, 0.2),
        )
        attached += 1

    return attached

def detect_child_call_order(parent_events, children_events_map):
    est_gap = {}
    for child_ip, child_events in children_events_map.items():
        gaps = []
        for p in parent_events:
            for c in child_events:
                if p['req_ts'] <= c['req_ts'] and p['res_ts'] >= c['res_ts']:
                    gaps.append(c['req_ts'] - p['req_ts'])
        if not gaps:
            for p in parent_events:
                for c in child_events:
                    if p['req_ts'] <= c['req_ts'] <= p['res_ts'] + 0.05:
                        gaps.append(c['req_ts'] - p['req_ts'])
        est_gap[child_ip] = (
            (
                float(np.percentile(gaps, 10)),
                float(np.percentile(gaps, 50)),
                -len(gaps),
            )
            if gaps
            else (float('inf'), float('inf'), 0)
        )
    order = sorted(children_events_map.keys(), key=lambda ip: (*est_gap[ip], ip))
    return order, est_gap

def build_cost_matrix(
    parent_events,
    child_events,
    prev_sibling_matched=None,
    propagated_contexts=None,
    time_weight=1.0,
    lineage_weight=120.0,
    causal_penalty=2.0,
    cascade_gap_weight=0.3,
    cascade_negative_penalty=2.5,
    context_req_weight=0.65,
    context_res_weight=0.35,
    context_mix_weight=0.45,
):
    n_p = len(parent_events)
    n_c = len(child_events)
    cost_matrix = np.full((n_p, n_c), 1e9)
    idf_weights = compute_idf_weights(child_events)
    for i, p in enumerate(parent_events):
        p_req_tokens = p.get('lineage_req_tokens', set())
        p_res_tokens = p.get('lineage_res_tokens', set())
        context_token_weights = {}
        if propagated_contexts is not None and i < len(propagated_contexts):
            context_token_weights = propagated_contexts[i] or {}
        prev = None
        if prev_sibling_matched is not None and i < len(prev_sibling_matched):
            prev = prev_sibling_matched[i]
        prev_res_tokens = prev.get('lineage_res_tokens', set()) if prev else set()
        for j, c in enumerate(child_events):
            c_req_tokens = c.get('lineage_req_tokens', set())
            c_res_tokens = c.get('lineage_res_tokens', set())

            # 血缘分项:
            # 1) 请求参数/body 对 请求参数/body
            # 2) 请求参数/body 对 响应body（很多场景在响应里回显/扩展关键ID）
            # 3) 响应body 对 响应body（上下游返回结构相似时可增强区分）
            score_req_req = lineage_overlap_score(p_req_tokens, c_req_tokens, idf_weights)
            score_req_res = lineage_overlap_score(p_req_tokens, c_res_tokens, idf_weights)
            score_res_res = lineage_overlap_score(p_res_tokens, c_res_tokens, idf_weights)
            parent_lineage_score = 0.50 * score_req_req + 0.30 * score_req_res + 0.20 * score_res_res

            # 跨链路传递：利用前序兄弟调用的响应 token 继续约束当前子调用。
            score_prev_req = lineage_overlap_score(prev_res_tokens, c_req_tokens, idf_weights)
            score_prev_res = lineage_overlap_score(prev_res_tokens, c_res_tokens, idf_weights)
            propagated_score = 0.65 * score_prev_req + 0.35 * score_prev_res

            context_req_score = weighted_lineage_overlap_score(context_token_weights, c_req_tokens, idf_weights)
            context_res_score = weighted_lineage_overlap_score(context_token_weights, c_res_tokens, idf_weights)
            context_score = context_req_weight * context_req_score + context_res_weight * context_res_score

            if prev is None and not context_token_weights:
                lineage_score = parent_lineage_score
            elif prev is None:
                lineage_score = (1.0 - context_mix_weight) * parent_lineage_score + context_mix_weight * context_score
            else:
                direct_mix = 0.35 * parent_lineage_score + 0.65 * propagated_score
                lineage_score = (1.0 - context_mix_weight) * direct_mix + context_mix_weight * context_score

            sg = c['req_ts'] - p['req_ts']
            if sg > -0.05 and p['res_ts'] >= c['res_ts']:
                # 时间项与血缘项加权融合
                cost_matrix[i, j] = (sg * time_weight) - (lineage_score * lineage_weight)
            elif sg > -0.05:
                # request 时间因果成立，但 response 越界，做强罚分
                cost_matrix[i, j] = (sg * time_weight) + causal_penalty - (lineage_score * lineage_weight)
            else:
                cost_matrix[i, j] = 1e8  # 完全逆转因果，不参与匹配

            # 级联时间约束：若有前序兄弟，应当发生在其响应之后
            if prev is not None:
                gap_prev = c['req_ts'] - prev['res_ts']
                if gap_prev < -0.02:
                    cost_matrix[i, j] += cascade_negative_penalty
                else:
                    cost_matrix[i, j] += max(gap_prev, 0.0) * cascade_gap_weight
    return cost_matrix

def select_candidate_indices(
    child_events,
    child_req_ts,
    unmatched_child_indices,
    parent_batch,
    window_seconds,
    max_candidates,
):
    batch_req_min = min(p['req_ts'] for p in parent_batch)
    batch_req_max = max(p['req_ts'] for p in parent_batch)
    min_req = batch_req_min - window_seconds
    max_res = max(p['res_ts'] for p in parent_batch) + window_seconds
    left = bisect.bisect_left(child_req_ts, min_req)
    right = bisect.bisect_right(child_req_ts, max_res)
    candidate_set = set(range(left, right))
    candidates = [idx for idx in unmatched_child_indices if idx in candidate_set]

    def cap_candidates(indices):
        if max_candidates <= 0 or len(indices) <= max_candidates:
            return sorted(indices, key=lambda idx: child_events[idx]['req_ts'])

        req_window_min = batch_req_min - window_seconds
        req_window_max = batch_req_max + window_seconds

        def distance_to_batch(idx):
            req_ts = child_events[idx]['req_ts']
            if req_ts < req_window_min:
                distance = req_window_min - req_ts
            elif req_ts > req_window_max:
                distance = req_ts - req_window_max
            else:
                distance = 0.0
            return (distance, abs(req_ts - batch_req_min), req_ts)

        capped = sorted(indices, key=distance_to_batch)[:max_candidates]
        return sorted(capped, key=lambda idx: child_events[idx]['req_ts'])

    if len(candidates) >= len(parent_batch):
        return cap_candidates(candidates)

    # Fall back by expanding around the nearest unmatched children. This keeps
    # matching total under short bursts where timestamps are slightly skewed.
    midpoint = (min_req + max_res) / 2.0
    expanded = sorted(
        unmatched_child_indices,
        key=lambda idx: abs(child_events[idx]['req_ts'] - midpoint),
    )
    needed = min(len(parent_batch) * 2, len(expanded))
    return cap_candidates(set(candidates).union(expanded[:needed]))

def match_child_events_windowed(
    parent_events,
    child_events,
    prev_sibling_matched,
    propagated_contexts,
    time_weight,
    lineage_weight,
    causal_penalty,
    cascade_gap_weight,
    cascade_negative_penalty,
    context_mix_weight,
    context_decay,
    batch_size,
    window_seconds,
):
    child_matches = [None] * len(parent_events)
    if not parent_events or not child_events:
        return child_matches

    parent_order = sorted(range(len(parent_events)), key=lambda idx: parent_events[idx]['req_ts'])
    child_order = sorted(range(len(child_events)), key=lambda idx: child_events[idx]['req_ts'])
    child_req_ts = [child_events[idx]['req_ts'] for idx in child_order]
    sorted_child_events = [child_events[idx] for idx in child_order]
    sorted_to_original = {sorted_idx: original_idx for sorted_idx, original_idx in enumerate(child_order)}
    unmatched_sorted_child_indices = list(range(len(sorted_child_events)))
    max_candidates = int(os.getenv(
        "LINEAGE_MATCH_MAX_CANDIDATES",
        str(max(batch_size * 8, batch_size + 32)),
    ))

    for start in range(0, len(parent_order), batch_size):
        batch_parent_indices = parent_order[start:start + batch_size]
        parent_batch = [parent_events[idx] for idx in batch_parent_indices]
        candidate_sorted_indices = select_candidate_indices(
            sorted_child_events,
            child_req_ts,
            unmatched_sorted_child_indices,
            parent_batch,
            window_seconds,
            max_candidates,
        )
        if not candidate_sorted_indices:
            continue

        child_batch = [sorted_child_events[idx] for idx in candidate_sorted_indices]
        prev_batch = (
            [prev_sibling_matched[idx] for idx in batch_parent_indices]
            if prev_sibling_matched is not None
            else None
        )
        context_batch = [propagated_contexts[idx] for idx in batch_parent_indices]
        cost_matrix = build_cost_matrix(
            parent_batch,
            child_batch,
            prev_sibling_matched=prev_batch,
            propagated_contexts=context_batch,
            time_weight=time_weight,
            lineage_weight=lineage_weight,
            causal_penalty=causal_penalty,
            cascade_gap_weight=cascade_gap_weight,
            cascade_negative_penalty=cascade_negative_penalty,
            context_mix_weight=context_mix_weight,
        )
        p_ind, c_ind = linear_sum_assignment(cost_matrix)
        used_sorted_child_indices = set()
        for local_p_i, local_c_i in zip(p_ind, c_ind):
            if cost_matrix[local_p_i, local_c_i] >= 1e7:
                continue
            parent_idx = batch_parent_indices[local_p_i]
            sorted_child_idx = candidate_sorted_indices[local_c_i]
            original_child_idx = sorted_to_original[sorted_child_idx]
            matched_child = child_events[original_child_idx]
            child_matches[parent_idx] = matched_child
            propagated_contexts[parent_idx] = merge_token_weight_maps(
                decay_token_weight_map(propagated_contexts[parent_idx], context_decay),
                token_set_to_weight_map(matched_child.get('lineage_req_tokens', set()), 1.0),
                token_set_to_weight_map(matched_child.get('lineage_res_tokens', set()), 0.9),
            )
            used_sorted_child_indices.add(sorted_child_idx)

        if used_sorted_child_indices:
            unmatched_sorted_child_indices = [
                idx for idx in unmatched_sorted_child_indices if idx not in used_sorted_child_indices
            ]

    return child_matches

def infer_topology(all_events):
    """
    从事件中自动推断服务拓扑（IP 级）。
    返回:
        root_ip: 根服务 IP
        tree: {ip: {'events': [...], 'children': [child_ip, ...]}}
    """
    server_ips = set(e['server'] for e in all_events)
    client_ips = set(e['client'] for e in all_events)
    external_clients = client_ips - server_ips

    root_counter = defaultdict(int)
    for e in all_events:
        if e['client'] in external_clients:
            root_counter[e['server']] += 1
    if not root_counter:
        return None, {}
    root_ip = max(root_counter, key=root_counter.get)

    call_edges = set()
    for e in all_events:
        if e['client'] in server_ips:
            call_edges.add((e['client'], e['server']))

    tree = {}
    parent_of = {}
    visited = {root_ip}
    queue = [root_ip]

    while queue:
        ip = queue.pop(0)
        children = [dst for (src, dst) in call_edges if src == ip and dst not in visited]
        if ip == root_ip:
            events = [e for e in all_events if e['server'] == ip and e['client'] in external_clients]
        else:
            par = parent_of[ip]
            events = [e for e in all_events if e['server'] == ip and e['client'] == par]
        tree[ip] = {'events': events, 'children': children}
        for child in children:
            visited.add(child)
            parent_of[child] = ip
            queue.append(child)

    return root_ip, tree

def reorder_tree_by_trace(tree, root_ip):
    """
    用根节点最早一条 trace 的真实时序，对每个父节点的 children 顺序做重排。
    """
    root_events = sorted(tree[root_ip]['events'], key=lambda e: e['req_ts'])
    if not root_events:
        return None
    first_trace_id = root_events[0]['trace_id']

    for parent_ip, node in tree.items():
        children = node['children']
        if len(children) <= 1:
            continue

        order_key = {}
        for child_ip in children:
            child_events = tree[child_ip]['events']
            # 在该父->子边里，找 first_trace_id 对应事件的 req_ts 作为排序依据
            t = None
            for e in child_events:
                if e['trace_id'] == first_trace_id:
                    t = e['req_ts']
                    break
            order_key[child_ip] = t if t is not None else float('inf')

        # 对于没有 first_trace 样本的边，保持原有相对顺序
        node['children'] = sorted(children, key=lambda c: (order_key[c], children.index(c)))

    return first_trace_id

def tree_to_serializable(tree):
    return {
        ip: {
            'children': node['children'],
            'event_count': len(node['events']),
        }
        for ip, node in tree.items()
    }

def run_edge_slot_algorithm(all_events, csv_path, json_out, topology_mode):
    server_ips = set(e['server'] for e in all_events)
    client_ips = set(e['client'] for e in all_events)
    external_clients = client_ips - server_ips

    root_counter = defaultdict(int)
    for e in all_events:
        if e['client'] in external_clients:
            root_counter[e['server']] += 1
    if not root_counter:
        print("未能从数据中自动推断出根节点！")
        return
    root_ip = max(root_counter, key=root_counter.get)
    root_events = sorted(
        [e for e in all_events if e['server'] == root_ip and e['client'] in external_clients],
        key=lambda e: (e['req_ts'], e['res_ts'], e['key']),
    )
    if not root_events:
        print("根节点缺少事件，无法进行 edge-slot 匹配！")
        return

    first_trace_id = root_events[0]['trace_id']
    first_root = root_events[0]
    root_trace_ids = [e['trace_id'] for e in root_events]
    root_trace_set = set(root_trace_ids)
    edge_events = defaultdict(list)
    for e in all_events:
        if e['trace_id'] not in root_trace_set:
            continue
        edge_events[(e['client'], e['server'])].append(e)
    for events in edge_events.values():
        events.sort(key=lambda e: (e['req_ts'], e['res_ts'], e['key']))

    slot_profiles = {}
    occurrence_vector = {}
    for edge, events in edge_events.items():
        first_events = [e for e in events if e['trace_id'] == first_trace_id]
        first_events.sort(key=lambda e: (e['req_ts'], e['res_ts'], e['key']))
        if not first_events:
            continue
        offsets = [e['req_ts'] - first_root['req_ts'] for e in first_events]
        slot_profiles[edge] = offsets
        occurrence_vector[edge] = len(offsets)

    trace_edge_vectors = defaultdict(lambda: defaultdict(int))
    for edge, events in edge_events.items():
        for e in events:
            trace_edge_vectors[e['trace_id']][edge] += 1
    same_occurrence_vector = all(
        dict(trace_edge_vectors[tid]) == occurrence_vector
        for tid in root_trace_ids
    )

    predicted_trace_by_key = {}
    root_edge = (root_events[0]['client'], root_events[0]['server'])
    for root_event in root_events:
        predicted_trace_by_key[root_event['key']] = root_event['trace_id']

    slot_accuracy = {}
    for edge, events in edge_events.items():
        if edge == root_edge:
            continue
        offsets = slot_profiles.get(edge, [])
        if not offsets:
            continue
        expected = []
        for root_idx, root_event in enumerate(root_events):
            for slot_idx, offset in enumerate(offsets):
                expected.append((root_idx, slot_idx, root_event['req_ts'] + offset))

        if not expected or not events:
            continue
        cost = np.zeros((len(events), len(expected)))
        for i, event in enumerate(events):
            for j, (root_idx, _slot_idx, expected_ts) in enumerate(expected):
                root_event = root_events[root_idx]
                time_cost = abs(event['req_ts'] - expected_ts)
                containment_penalty = 0.0
                if event['req_ts'] < root_event['req_ts'] - 0.05:
                    containment_penalty += 1.0
                if event['res_ts'] > root_event['res_ts'] + 0.05:
                    containment_penalty += 1.0
                cost[i, j] = time_cost + containment_penalty

        row_ind, col_ind = linear_sum_assignment(cost)
        ok = 0
        for row, col in zip(row_ind, col_ind):
            event = events[row]
            root_idx, slot_idx, _expected_ts = expected[col]
            predicted_tid = root_events[root_idx]['trace_id']
            predicted_trace_by_key[event['key']] = predicted_tid
            if predicted_tid == event['trace_id']:
                ok += 1
        slot_accuracy[f"{edge[0]}->{edge[1]}"] = {
            'accuracy_pct': ok / len(events) * 100.0 if events else 0.0,
            'accuracy_ok': ok,
            'total': len(events),
            'occurrences_per_trace': len(offsets),
        }

    total = 0
    correct = 0
    trace_ok = {tid: True for tid in root_trace_ids}
    root_direct_total = defaultdict(int)
    root_direct_ok = defaultdict(int)
    root_direct_all_ok = {tid: True for tid in root_trace_ids}
    for e in all_events:
        if e['trace_id'] not in root_trace_set:
            continue
        total += 1
        predicted_tid = predicted_trace_by_key.get(e['key'])
        is_ok = predicted_tid == e['trace_id']
        correct += int(is_ok)
        if not is_ok:
            trace_ok[e['trace_id']] = False
        if e['client'] == root_ip:
            root_direct_total[e['trace_id']] += 1
            root_direct_ok[e['trace_id']] += int(is_ok)
            if not is_ok:
                root_direct_all_ok[e['trace_id']] = False

    full_ok = sum(1 for tid in root_trace_ids if trace_ok.get(tid))
    root_direct_eval = sum(1 for tid in root_trace_ids if root_direct_total[tid] > 0)
    root_direct_full_ok = sum(
        1
        for tid in root_trace_ids
        if root_direct_total[tid] > 0 and root_direct_all_ok[tid]
    )
    root_direct_occ_total = sum(root_direct_total.values())
    root_direct_occ_ok = sum(root_direct_ok.values())

    report = {
        'csv_path': csv_path,
        'root_ip': root_ip,
        'first_trace_id': first_trace_id,
        'topology_mode': topology_mode,
        'accuracy_pct': full_ok / len(root_trace_ids) * 100.0 if root_trace_ids else 0.0,
        'accuracy_ok': full_ok,
        'root_trace_count': len(root_trace_ids),
        'root_direct_accuracy_pct': root_direct_full_ok / root_direct_eval * 100.0 if root_direct_eval else 0.0,
        'root_direct_accuracy_ok': root_direct_full_ok,
        'root_direct_evaluated_event_count': root_direct_eval,
        'root_direct_edge_occurrence_accuracy_pct': root_direct_occ_ok / root_direct_occ_total * 100.0 if root_direct_occ_total else 0.0,
        'root_direct_edge_occurrence_accuracy_ok': root_direct_occ_ok,
        'root_direct_edge_occurrence_accuracy_total': root_direct_occ_total,
        'edge_accuracy_pct': correct / total * 100.0 if total else 0.0,
        'edge_accuracy_ok': correct,
        'edge_accuracy_total': total,
        'same_occurrence_vector': same_occurrence_vector,
        'slot_profiles': {
            f"{edge[0]}->{edge[1]}": {
                'occurrences_per_trace': len(offsets),
                'offset_ms': [round(offset * 1000.0, 3) for offset in offsets],
            }
            for edge, offsets in slot_profiles.items()
        },
        'slot_accuracy': slot_accuracy,
    }

    os.makedirs(os.path.dirname(json_out), exist_ok=True)
    with open(json_out, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    span_distribution = defaultdict(int)
    for tid, vector in trace_edge_vectors.items():
        span_distribution[sum(vector.values())] += 1
    print("edge-slot 固定结构检查:")
    print(f"  trace 数: {len(root_trace_ids)}")
    print(f"  每 trace span 数分布: {dict(sorted(span_distribution.items()))}")
    print(f"  每 trace 边 occurrence 向量一致: {same_occurrence_vector}")
    print("==================================================")
    print(f"根节点直接子调用一致率: {report['root_direct_accuracy_pct']:.2f}%   ({root_direct_full_ok}/{root_direct_eval})")
    print(f"拓扑调用 occurrence 一致率: {report['edge_accuracy_pct']:.2f}%   ({correct}/{total})")
    print(f"完整拓扑调用链还原一致率: {report['accuracy_pct']:.2f}%   ({full_ok}/{len(root_trace_ids)})")
    print("==================================================")
    print(f"结构化结果已写入: {json_out}")
    return report

def run_service_tree_edge_parent_slot_algorithm(all_events, csv_path, json_out, topology_mode):
    server_ips = set(e['server'] for e in all_events)
    client_ips = set(e['client'] for e in all_events)
    external_clients = client_ips - server_ips

    root_counter = defaultdict(int)
    for e in all_events:
        if e['client'] in external_clients:
            root_counter[e['server']] += 1
    if not root_counter:
        print("未能从数据中自动推断出根节点！")
        return
    root_ip = max(root_counter, key=root_counter.get)
    root_events = sorted(
        [e for e in all_events if e['server'] == root_ip and e['client'] in external_clients],
        key=lambda e: (e['req_ts'], e['res_ts'], e['key']),
    )
    if not root_events:
        print("根节点缺少事件，无法进行 service-tree-edge 匹配！")
        return

    first_trace_id = root_events[0]['trace_id']
    root_trace_ids = [e['trace_id'] for e in root_events]
    root_trace_set = set(root_trace_ids)

    incoming_by_service = defaultdict(list)
    outgoing_by_edge = defaultdict(list)
    all_edge_events = defaultdict(list)
    for e in all_events:
        if e['trace_id'] not in root_trace_set:
            continue
        all_edge_events[(e['client'], e['server'])].append(e)
        if e['server'] == root_ip and e['client'] in external_clients:
            incoming_by_service[root_ip].append(e)
        elif e['client'] in server_ips:
            incoming_by_service[e['server']].append(e)
            outgoing_by_edge[(e['client'], e['server'])].append(e)
    for events in incoming_by_service.values():
        events.sort(key=lambda e: (e['req_ts'], e['res_ts'], e['key']))
    for events in outgoing_by_edge.values():
        events.sort(key=lambda e: (e['req_ts'], e['res_ts'], e['key']))
    for events in all_edge_events.values():
        events.sort(key=lambda e: (e['req_ts'], e['res_ts'], e['key']))

    first_service_slot = {}
    for service_ip, events in incoming_by_service.items():
        first_events = [e for e in events if e['trace_id'] == first_trace_id]
        first_events.sort(key=lambda e: (e['req_ts'], e['res_ts'], e['key']))
        first_service_slot[service_ip] = {e['key']: idx for idx, e in enumerate(first_events)}

    def build_edge_profile(edge, parent_ip, child_ip):
        parent_first = [e for e in incoming_by_service[parent_ip] if e['trace_id'] == first_trace_id]
        child_first = [e for e in outgoing_by_edge[edge] if e['trace_id'] == first_trace_id]
        parent_first.sort(key=lambda e: (e['req_ts'], e['res_ts'], e['key']))
        child_first.sort(key=lambda e: (e['req_ts'], e['res_ts'], e['key']))
        parent_slot_by_key = first_service_slot.get(parent_ip, {})
        child_slot_by_key = first_service_slot.get(child_ip, {})
        profile = defaultdict(list)
        for child_event in child_first:
            contained = [
                parent_event
                for parent_event in parent_first
                if parent_event['req_ts'] - 0.02 <= child_event['req_ts']
                and parent_event['res_ts'] + 0.02 >= child_event['res_ts']
            ]
            if contained:
                parent_event = min(
                    contained,
                    key=lambda e: (e['res_ts'] - e['req_ts'], abs(child_event['req_ts'] - e['req_ts'])),
                )
            elif parent_first:
                parent_event = min(parent_first, key=lambda e: abs(child_event['req_ts'] - e['req_ts']))
            else:
                continue
            parent_slot = parent_slot_by_key.get(parent_event['key'])
            child_slot = child_slot_by_key.get(child_event['key'])
            if parent_slot is None or child_slot is None:
                continue
            profile[parent_slot].append({
                'offset': child_event['req_ts'] - parent_event['req_ts'],
                'child_slot': child_slot,
                'first_child_key': str(child_event['key']),
            })
        for slots in profile.values():
            slots.sort(key=lambda item: (item['offset'], item['child_slot']))
        return profile

    edge_profiles = {
        edge: build_edge_profile(edge, edge[0], edge[1])
        for edge in outgoing_by_edge
    }

    predicted_trace_by_key = {}
    predicted_slot_by_key = {}
    for root_event in root_events:
        predicted_trace_by_key[root_event['key']] = root_event['trace_id']
        predicted_slot_by_key[root_event['key']] = 0

    time_weight = float(os.getenv("LINEAGE_EDGE_SLOT_TIME_WEIGHT", os.getenv("LINEAGE_TIME_WEIGHT", "1.0")))
    lineage_weight = float(os.getenv("LINEAGE_EDGE_SLOT_DATA_WEIGHT", os.getenv("LINEAGE_DATA_WEIGHT", "20.0")))
    containment_penalty_weight = float(os.getenv("LINEAGE_EDGE_SLOT_CONTAINMENT_PENALTY", "2.0"))

    def parent_to_child_lineage_score(parent_event, child_event, idf_weights):
        parent_req = parent_event.get('lineage_req_tokens', set())
        parent_res = parent_event.get('lineage_res_tokens', set())
        child_req = child_event.get('lineage_req_tokens', set())
        child_res = child_event.get('lineage_res_tokens', set())
        parent_weights = merge_token_weight_maps(
            token_set_to_weight_map(parent_req, 1.0),
            token_set_to_weight_map(parent_res, 0.8),
        )
        child_tokens = set(child_req) | set(child_res)
        context_score = weighted_lineage_overlap_score(parent_weights, child_tokens, idf_weights)
        req_req = lineage_overlap_score(parent_req, child_req, idf_weights)
        req_res = lineage_overlap_score(parent_req, child_res, idf_weights)
        res_req = lineage_overlap_score(parent_res, child_req, idf_weights)
        res_res = lineage_overlap_score(parent_res, child_res, idf_weights)
        return max(context_score, 0.35 * req_req + 0.20 * req_res + 0.30 * res_req + 0.15 * res_res)

    outgoing_children = defaultdict(list)
    for parent_ip, child_ip in outgoing_by_edge:
        outgoing_children[parent_ip].append(child_ip)
    for parent_ip in outgoing_children:
        outgoing_children[parent_ip].sort()

    attempted_edges = set()
    slot_accuracy = {}
    all_edges = sorted(outgoing_by_edge.keys())
    max_iterations = int(os.getenv("LINEAGE_EDGE_SLOT_MAX_ITER", "20"))
    for _iteration in range(max_iterations):
        changed = False
        for edge in all_edges:
            parent_ip, child_ip = edge
            profile = edge_profiles.get(edge, {})
            if not profile:
                continue

            parent_events = [
                e for e in incoming_by_service[parent_ip]
                if e['key'] in predicted_trace_by_key and e['key'] in predicted_slot_by_key
            ]
            expected = []
            for parent_event in parent_events:
                parent_slot = predicted_slot_by_key[parent_event['key']]
                for slot_item in profile.get(parent_slot, []):
                    expected.append({
                        'parent_event': parent_event,
                        'trace_id': predicted_trace_by_key[parent_event['key']],
                        'expected_ts': parent_event['req_ts'] + slot_item['offset'],
                        'child_slot': slot_item['child_slot'],
                    })

            child_events = outgoing_by_edge[edge]
            if not expected or not child_events:
                continue
            if len(expected) > len(child_events):
                expected = sorted(
                    expected,
                    key=lambda exp: (exp['expected_ts'], exp['trace_id'], exp['child_slot']),
                )[:len(child_events)]

            idf_weights = compute_idf_weights(child_events)
            cost = np.zeros((len(child_events), len(expected)))
            for i, child_event in enumerate(child_events):
                for j, exp in enumerate(expected):
                    parent_event = exp['parent_event']
                    time_cost = abs(child_event['req_ts'] - exp['expected_ts']) * time_weight
                    containment_penalty = 0.0
                    if child_event['req_ts'] < parent_event['req_ts'] - 0.05:
                        containment_penalty += containment_penalty_weight
                    if child_event['res_ts'] > parent_event['res_ts'] + 0.05:
                        containment_penalty += containment_penalty_weight
                    lineage_score = parent_to_child_lineage_score(parent_event, child_event, idf_weights)
                    cost[i, j] = time_cost + containment_penalty - (lineage_score * lineage_weight)

            row_ind, col_ind = linear_sum_assignment(cost)
            ok = 0
            matched_rows = set()
            for row, col in zip(row_ind, col_ind):
                child_event = child_events[row]
                exp = expected[col]
                old_prediction = (
                    predicted_trace_by_key.get(child_event['key']),
                    predicted_slot_by_key.get(child_event['key']),
                )
                predicted_trace_by_key[child_event['key']] = exp['trace_id']
                predicted_slot_by_key[child_event['key']] = exp['child_slot']
                if old_prediction != (exp['trace_id'], exp['child_slot']):
                    changed = True
                matched_rows.add(row)
                if exp['trace_id'] == child_event['trace_id']:
                    ok += 1
            total_events = len(child_events)
            slot_accuracy[f"{parent_ip}->{child_ip}"] = {
                'accuracy_pct': ok / total_events * 100.0 if total_events else 0.0,
                'accuracy_ok': ok,
                'total': total_events,
                'unmatched': total_events - len(matched_rows),
                'profile_parent_slots': len(profile),
                'occurrences_per_trace': sum(len(v) for v in profile.values()),
            }
            attempted_edges.add(edge)
        if not changed:
            break

    total = 0
    correct = 0
    trace_ok = {tid: True for tid in root_trace_ids}
    root_direct_total = defaultdict(int)
    root_direct_ok = defaultdict(int)
    root_direct_all_ok = {tid: True for tid in root_trace_ids}
    for e in all_events:
        if e['trace_id'] not in root_trace_set:
            continue
        total += 1
        predicted_tid = predicted_trace_by_key.get(e['key'])
        is_ok = predicted_tid == e['trace_id']
        correct += int(is_ok)
        if not is_ok:
            trace_ok[e['trace_id']] = False
        if e['client'] == root_ip:
            root_direct_total[e['trace_id']] += 1
            root_direct_ok[e['trace_id']] += int(is_ok)
            if not is_ok:
                root_direct_all_ok[e['trace_id']] = False

    full_ok = sum(1 for tid in root_trace_ids if trace_ok.get(tid))
    root_direct_eval = sum(1 for tid in root_trace_ids if root_direct_total[tid] > 0)
    root_direct_full_ok = sum(
        1
        for tid in root_trace_ids
        if root_direct_total[tid] > 0 and root_direct_all_ok[tid]
    )
    root_direct_occ_total = sum(root_direct_total.values())
    root_direct_occ_ok = sum(root_direct_ok.values())

    occurrence_vector = {}
    trace_edge_vectors = defaultdict(lambda: defaultdict(int))
    for edge, events in all_edge_events.items():
        first_events = [e for e in events if e['trace_id'] == first_trace_id]
        occurrence_vector[edge] = len(first_events)
        for e in events:
            trace_edge_vectors[e['trace_id']][edge] += 1
    same_occurrence_vector = all(
        dict(trace_edge_vectors[tid]) == occurrence_vector
        for tid in root_trace_ids
    )

    root_ip_tree, tree = infer_topology(all_events)
    if root_ip_tree:
        reorder_tree_by_trace(tree, root_ip_tree)

    report = {
        'csv_path': csv_path,
        'root_ip': root_ip,
        'first_trace_id': first_trace_id,
        'topology_mode': topology_mode,
        'accuracy_pct': full_ok / len(root_trace_ids) * 100.0 if root_trace_ids else 0.0,
        'accuracy_ok': full_ok,
        'root_trace_count': len(root_trace_ids),
        'root_direct_accuracy_pct': root_direct_full_ok / root_direct_eval * 100.0 if root_direct_eval else 0.0,
        'root_direct_accuracy_ok': root_direct_full_ok,
        'root_direct_evaluated_event_count': root_direct_eval,
        'root_direct_edge_occurrence_accuracy_pct': root_direct_occ_ok / root_direct_occ_total * 100.0 if root_direct_occ_total else 0.0,
        'root_direct_edge_occurrence_accuracy_ok': root_direct_occ_ok,
        'root_direct_edge_occurrence_accuracy_total': root_direct_occ_total,
        'edge_accuracy_pct': correct / total * 100.0 if total else 0.0,
        'edge_accuracy_ok': correct,
        'edge_accuracy_total': total,
        'same_occurrence_vector': same_occurrence_vector,
        'processed_edge_count': len(attempted_edges),
        'total_service_edge_count': len(all_edges),
        'unprocessed_edges': [f"{src}->{dst}" for src, dst in all_edges if (src, dst) not in attempted_edges],
        'weights': {
            'time_weight': time_weight,
            'lineage_weight': lineage_weight,
            'containment_penalty_weight': containment_penalty_weight,
        },
        'topology': tree_to_serializable(tree) if root_ip_tree else {},
        'slot_accuracy': slot_accuracy,
    }

    os.makedirs(os.path.dirname(json_out), exist_ok=True)
    with open(json_out, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    span_distribution = defaultdict(int)
    for tid, vector in trace_edge_vectors.items():
        span_distribution[sum(vector.values())] += 1
    print("service-tree + path-token + independent-edge(parent-slot) 检查:")
    print(f"  trace 数: {len(root_trace_ids)}")
    print(f"  每 trace span 数分布: {dict(sorted(span_distribution.items()))}")
    print(f"  每 trace 边 occurrence 向量一致: {same_occurrence_vector}")
    print(f"  已处理 service edge: {len(attempted_edges)}/{len(all_edges)}")
    print(
        "融合权重: "
        f"time={time_weight}, lineage={lineage_weight}, "
        f"containment_penalty={containment_penalty_weight}"
    )
    print("==================================================")
    print(f"根节点直接子调用一致率: {report['root_direct_accuracy_pct']:.2f}%   ({root_direct_full_ok}/{root_direct_eval})")
    print(f"拓扑调用 occurrence 一致率: {report['edge_accuracy_pct']:.2f}%   ({correct}/{total})")
    print(f"完整拓扑调用链还原一致率: {report['accuracy_pct']:.2f}%   ({full_ok}/{len(root_trace_ids)})")
    print("==================================================")
    print(f"结构化结果已写入: {json_out}")
    return report


def run_service_graph_algorithm(
    all_events,
    csv_path,
    json_out,
    topology_mode,
    calibration_profile_in=None,
    calibration_profile_out=None,
):
    """
    Service-graph lineage:
    - 使用真实 observed service edge，不把微服务图压成一棵树；
    - 每条 edge 上 child span 选择最佳 parent span，parent span 可承载多个 child；
    - 通过已预测 parent span 迭代传播 trace 归属，适配重复调用边和多父节点服务。
    """
    profile_enabled = os.getenv("LINEAGE_PROFILE", "0") != "0"
    profile_started_at = time.perf_counter()
    profile_last_at = profile_started_at

    def profile_mark(name):
        nonlocal profile_last_at
        if not profile_enabled:
            return
        now = time.perf_counter()
        print(
            f"[lineage-profile] {name}: +{now - profile_last_at:.3f}s total={now - profile_started_at:.3f}s",
            flush=True,
        )
        profile_last_at = now

    server_ips = set(e['server'] for e in all_events)
    client_ips = set(e['client'] for e in all_events)
    external_clients = client_ips - server_ips

    root_counter = defaultdict(int)
    for e in all_events:
        if e['client'] in external_clients:
            root_counter[e['server']] += 1
    if not root_counter:
        print("未能从数据中自动推断出根节点！")
        return

    root_ip = max(root_counter, key=root_counter.get)
    root_events = sorted(
        [e for e in all_events if e['server'] == root_ip and e['client'] in external_clients],
        key=lambda e: (e['req_ts'], e['res_ts'], e['key']),
    )
    if not root_events:
        print("根节点缺少事件，无法进行 service-graph 匹配！")
        return
    profile_mark("root-detected")

    root_trace_ids = [e['trace_id'] for e in root_events]
    root_labels = [f"root:{idx}" for idx in range(len(root_events))]
    root_label_by_key = {
        event['key']: root_labels[idx]
        for idx, event in enumerate(root_events)
    }
    root_trace_id_by_label = {
        root_labels[idx]: event['trace_id']
        for idx, event in enumerate(root_events)
    }
    root_eval_trace_set = set(root_trace_ids)

    def predicted_label_to_trace_id(label):
        return root_trace_id_by_label.get(label)

    loaded_calibration_profile = None
    profile_edge_policies = {}
    profile_policy_mode = None
    if calibration_profile_in:
        with open(calibration_profile_in, 'r', encoding='utf-8') as f:
            loaded_calibration_profile = json.load(f)
        profile_edge_policies = loaded_calibration_profile.get('edge_policies', {})
        profile_policy_mode = loaded_calibration_profile.get('policy_mode', 'edge-policies')

    incoming_by_service = defaultdict(list)
    outgoing_by_edge = defaultdict(list)
    all_relevant_events = []
    for e in all_events:
        all_relevant_events.append(e)
        if e['server'] == root_ip and e['client'] in external_clients:
            incoming_by_service[root_ip].append(e)
        elif e['client'] in server_ips:
            incoming_by_service[e['server']].append(e)
            outgoing_by_edge[(e['client'], e['server'])].append(e)

    for events in incoming_by_service.values():
        events.sort(key=lambda e: (e['req_ts'], e['res_ts'], e['key']))
    for events in outgoing_by_edge.values():
        events.sort(key=lambda e: (e['req_ts'], e['res_ts'], e['key']))

    time_weight = float(os.getenv("LINEAGE_GRAPH_TIME_WEIGHT", os.getenv("LINEAGE_TIME_WEIGHT", "1.0")))
    lineage_weight = float(os.getenv("LINEAGE_GRAPH_DATA_WEIGHT", os.getenv("LINEAGE_DATA_WEIGHT", "20.0")))
    containment_penalty = float(os.getenv("LINEAGE_GRAPH_CONTAINMENT_PENALTY", "2.0"))
    trace_context_weight = float(os.getenv("LINEAGE_GRAPH_TRACE_CONTEXT_WEIGHT", "40.0"))
    req_tolerance = float(os.getenv("LINEAGE_GRAPH_REQ_TOLERANCE_MS", "50")) / 1000.0
    res_tolerance = float(os.getenv("LINEAGE_GRAPH_RES_TOLERANCE_MS", "80")) / 1000.0
    fallback_window = float(os.getenv("LINEAGE_GRAPH_FALLBACK_WINDOW_MS", "250")) / 1000.0
    max_iterations = int(os.getenv("LINEAGE_GRAPH_MAX_ITER", "20"))
    max_temporal_candidates = int(os.getenv("LINEAGE_GRAPH_MAX_TEMPORAL_CANDIDATES", "64"))
    max_fallback_candidates = int(os.getenv("LINEAGE_GRAPH_MAX_FALLBACK_CANDIDATES", "64"))
    propagation_mode = os.getenv("LINEAGE_GRAPH_PROPAGATION_MODE", "frontier").strip().lower()

    predicted_trace_by_key = dict(root_label_by_key)
    predicted_parent_by_key = {}
    prediction_score_by_key = {e['key']: float('inf') for e in root_events}
    prediction_meta_by_key = {}
    fixed_prediction_keys = {e['key'] for e in root_events}

    edge_idf = {
        edge: compute_idf_weights(events)
        for edge, events in outgoing_by_edge.items()
    }

    def initial_contexts(parent_events):
        return [
            merge_token_weight_maps(
                token_set_to_weight_map(parent_events[i].get('lineage_req_tokens', set()), 1.0),
                token_set_to_weight_map(parent_events[i].get('lineage_res_tokens', set()), 0.8),
            )
            for i in range(len(parent_events))
        ]

    direct_children_events = {
        child_ip: events
        for (parent_ip, child_ip), events in outgoing_by_edge.items()
        if parent_ip == root_ip
    }
    child_order_mode = os.getenv(
        "LINEAGE_CHILD_ORDER_MODE",
        os.getenv("LINEAGE_TOPOLOGY_CHILD_ORDER", "trace"),
    ).strip().lower()
    root_child_order = []
    root_child_order_source = "none"
    root_seed_count = 0
    if direct_children_events:
        topology_root_ip, topology_tree = infer_topology(all_events)
        if (
            child_order_mode in ("trace", "first-trace", "first_trace")
            and topology_root_ip == root_ip
            and root_ip in topology_tree
        ):
            reorder_tree_by_trace(topology_tree, root_ip)
            root_child_order = [
                child_ip
                for child_ip in topology_tree[root_ip]['children']
                if child_ip in direct_children_events
            ]
            root_child_order_source = "first-trace"
        else:
            root_child_order, _root_gap = detect_child_call_order(root_events, direct_children_events)
            root_child_order_source = "temporal-gap"
        root_match_batch_size = int(os.getenv("LINEAGE_MATCH_BATCH_SIZE", "8"))
        root_match_window_seconds = float(os.getenv("LINEAGE_MATCH_WINDOW_MS", "150")) / 1000.0
        cascade_gap_weight = float(os.getenv("LINEAGE_CASCADE_GAP_WEIGHT", "0.3"))
        cascade_negative_penalty = float(os.getenv("LINEAGE_CASCADE_NEG_PENALTY", "2.5"))
        context_mix_weight = float(os.getenv("LINEAGE_CONTEXT_MIX_WEIGHT", "0.5"))
        context_decay = float(os.getenv("LINEAGE_CONTEXT_DECAY", "0.8"))
        root_contexts = initial_contexts(root_events)
        prev_matched = None
        for child_ip in root_child_order:
            child_events = direct_children_events[child_ip]
            matched_list = match_child_events_windowed(
                root_events,
                child_events,
                prev_sibling_matched=prev_matched,
                propagated_contexts=root_contexts,
                time_weight=time_weight,
                lineage_weight=lineage_weight,
                causal_penalty=containment_penalty,
                cascade_gap_weight=cascade_gap_weight,
                cascade_negative_penalty=cascade_negative_penalty,
                context_mix_weight=context_mix_weight,
                context_decay=context_decay,
                batch_size=root_match_batch_size,
                window_seconds=root_match_window_seconds,
            )
            for root_idx, matched_child in enumerate(matched_list):
                if matched_child is None:
                    continue
                predicted_trace_by_key[matched_child['key']] = root_label_by_key[root_events[root_idx]['key']]
                predicted_parent_by_key[matched_child['key']] = root_events[root_idx]['key']
                prediction_score_by_key[matched_child['key']] = float('inf')
                prediction_meta_by_key[matched_child['key']] = {
                    'source': 'root-seed',
                    'lineage_score': 1.0,
                    'trace_context_score': 1.0,
                    'score': float('inf'),
                }
                fixed_prediction_keys.add(matched_child['key'])
                root_seed_count += 1
            prev_matched = matched_list
        profile_mark("root-seed")

    event_by_key = {e['key']: e for e in all_relevant_events}
    trace_context_mode = os.getenv("LINEAGE_GRAPH_CONTEXT_MODE", "static").strip().lower()
    if trace_context_mode in ("dynamic", "rebuild"):
        trace_context_mode = "iterative"
    if trace_context_mode not in ("static", "iterative"):
        trace_context_mode = "static"

    def rebuild_trace_contexts(trace_predictions, keys=None):
        ctx = defaultdict(dict)
        iterable = (
            ((key, trace_predictions.get(key)) for key in keys)
            if keys is not None
            else trace_predictions.items()
        )
        event_count = 0
        for key, trace_id in iterable:
            event = event_by_key.get(key)
            if event is None or trace_id is None:
                continue
            ctx[trace_id] = merge_token_weight_maps(
                ctx[trace_id],
                token_set_to_weight_map(event.get('lineage_req_tokens', set()), 1.0),
                token_set_to_weight_map(event.get('lineage_res_tokens', set()), 0.9),
            )
            event_count += 1
        return ctx, event_count

    trace_contexts, trace_context_event_count = rebuild_trace_contexts(
        predicted_trace_by_key,
        fixed_prediction_keys,
    )
    trace_context_rebuild_count = 0

    def temporal_score(parent_event, child_event):
        starts_before = parent_event['req_ts'] <= child_event['req_ts'] + req_tolerance
        ends_after = parent_event['res_ts'] + res_tolerance >= child_event['res_ts']
        req_inside = parent_event['req_ts'] - req_tolerance <= child_event['req_ts'] <= parent_event['res_ts'] + res_tolerance
        if not starts_before or not req_inside:
            return None

        outside = 0.0
        if child_event['req_ts'] < parent_event['req_ts']:
            outside += parent_event['req_ts'] - child_event['req_ts']
        if child_event['res_ts'] > parent_event['res_ts']:
            outside += child_event['res_ts'] - parent_event['res_ts']
        if not ends_after and outside > fallback_window:
            return None

        start_gap = max(child_event['req_ts'] - parent_event['req_ts'], 0.0)
        outside_penalty = containment_penalty if outside > res_tolerance else 0.0
        return -(start_gap * time_weight) - outside_penalty - (outside * time_weight * 4.0)

    graph_candidate_parent_cache = {}
    candidate_mode = os.getenv("LINEAGE_GRAPH_CANDIDATE_MODE", "windowed").strip().lower()

    def maybe_cap_temporal_candidates(candidates):
        if max_temporal_candidates <= 0 or len(candidates) <= max_temporal_candidates:
            return candidates
        return sorted(candidates, key=lambda item: item[1], reverse=True)[:max_temporal_candidates]

    def maybe_cap_fallback_candidates(candidates):
        if max_fallback_candidates <= 0 or len(candidates) <= max_fallback_candidates:
            return candidates
        return sorted(candidates, key=lambda item: item[1])[:max_fallback_candidates]

    def build_candidate_parent_cache_bruteforce(edge, parent_events, child_events):
        for child_event in child_events:
            temporal_candidates = []
            fallback_candidates = []
            for parent_event in parent_events:
                t_score = temporal_score(parent_event, child_event)
                if t_score is not None:
                    temporal_candidates.append((parent_event, t_score))
                distance = abs(child_event['req_ts'] - parent_event['req_ts'])
                if distance <= fallback_window:
                    fallback_candidates.append((parent_event, distance))
            graph_candidate_parent_cache[(edge, child_event['key'])] = (
                maybe_cap_temporal_candidates(temporal_candidates),
                maybe_cap_fallback_candidates(fallback_candidates),
            )

    def build_candidate_parent_cache_windowed(edge, parent_events, child_events):
        if not child_events:
            return
        if not parent_events:
            for child_event in child_events:
                graph_candidate_parent_cache[(edge, child_event['key'])] = ([], [])
            return

        parents_by_req = sorted(parent_events, key=lambda e: (e['req_ts'], e['res_ts'], e['key']))
        parent_req_ts = [event['req_ts'] for event in parents_by_req]
        active_parents = []
        add_idx = 0

        for child_event in child_events:
            child_req = child_event['req_ts']
            while add_idx < len(parents_by_req) and parents_by_req[add_idx]['req_ts'] <= child_req + req_tolerance:
                active_parents.append(parents_by_req[add_idx])
                add_idx += 1

            if active_parents:
                active_parents = [
                    parent_event
                    for parent_event in active_parents
                    if parent_event['res_ts'] + res_tolerance >= child_req
                ]

            temporal_candidates = []
            for parent_event in active_parents:
                t_score = temporal_score(parent_event, child_event)
                if t_score is not None:
                    temporal_candidates.append((parent_event, t_score))

            left = bisect.bisect_left(parent_req_ts, child_req - fallback_window)
            right = bisect.bisect_right(parent_req_ts, child_req + fallback_window)
            fallback_candidates = [
                (parent_event, abs(child_req - parent_event['req_ts']))
                for parent_event in parents_by_req[left:right]
            ]

            graph_candidate_parent_cache[(edge, child_event['key'])] = (
                maybe_cap_temporal_candidates(temporal_candidates),
                maybe_cap_fallback_candidates(fallback_candidates),
            )

    edges_by_parent_service = defaultdict(list)
    for edge in outgoing_by_edge:
        edges_by_parent_service[edge[0]].append(edge)

    for edge, child_events in outgoing_by_edge.items():
        parent_events = incoming_by_service.get(edge[0], [])
        if candidate_mode in ("bruteforce", "full", "legacy"):
            build_candidate_parent_cache_bruteforce(edge, parent_events, child_events)
        else:
            build_candidate_parent_cache_windowed(edge, parent_events, child_events)
    profile_mark("candidate-cache")

    parent_child_score_cache = {}
    trace_context_score_cache = {}

    def cached_parent_child_score(edge, parent_event, child_event):
        cache_key = (edge, parent_event['key'], child_event['key'])
        cached = parent_child_score_cache.get(cache_key)
        if cached is not None:
            return cached
        score = parent_child_lineage_score(parent_event, child_event, edge_idf.get(edge, {}))
        parent_child_score_cache[cache_key] = score
        return score

    def cached_trace_context_score(edge, parent_tid, child_event):
        cache_key = (edge, parent_tid, child_event['key'])
        cached = trace_context_score_cache.get(cache_key)
        if cached is not None:
            return cached
        score = weighted_lineage_overlap_score(
            trace_contexts.get(parent_tid, {}),
            child_event.get('lineage_all_tokens', set()),
            edge_idf.get(edge, {}),
        )
        trace_context_score_cache[cache_key] = score
        return score

    def best_parent_for_child(edge, child_event, current_predictions):
        temporal_candidates, fallback_candidates = graph_candidate_parent_cache.get(
            (edge, child_event['key']),
            ((), ()),
        )
        best = None

        for parent_event, t_score in temporal_candidates:
            parent_tid = current_predictions.get(parent_event['key'])
            if parent_tid is None:
                continue
            lineage_score = cached_parent_child_score(edge, parent_event, child_event)
            trace_context_score = cached_trace_context_score(edge, parent_tid, child_event)
            score = (
                (lineage_score * lineage_weight)
                + (trace_context_score * trace_context_weight)
                + t_score
            )
            if best is None or score > best['score']:
                best = {
                    'score': score,
                    'trace_id': parent_tid,
                    'parent_key': parent_event['key'],
                    'lineage_score': lineage_score,
                    'trace_context_score': trace_context_score,
                }

        if best is not None:
            return best

        # 兜底: 短时间窗口内找最近的已预测 parent，避免轻微时间戳越界导致整条链断开。
        nearest = None
        for parent_event, distance in fallback_candidates:
            parent_tid = current_predictions.get(parent_event['key'])
            if parent_tid is None:
                continue
            lineage_score = cached_parent_child_score(edge, parent_event, child_event)
            trace_context_score = cached_trace_context_score(edge, parent_tid, child_event)
            score = (
                (lineage_score * lineage_weight)
                + (trace_context_score * trace_context_weight)
                - (distance * time_weight)
                - containment_penalty
            )
            if nearest is None or score > nearest['score']:
                nearest = {
                    'score': score,
                    'trace_id': parent_tid,
                    'parent_key': parent_event['key'],
                    'lineage_score': lineage_score,
                    'trace_context_score': trace_context_score,
                }
        return nearest

    def services_for_prediction_keys(keys):
        services = set()
        for key in keys:
            event = event_by_key.get(key)
            if event is not None:
                services.add(event['server'])
        return services

    def propagate_graph_predictions(iteration_limit):
        nonlocal trace_contexts, trace_context_event_count, trace_context_rebuild_count
        iterations = 0
        use_frontier = propagation_mode not in ("full", "legacy", "all")
        active_parent_services = (
            services_for_prediction_keys(predicted_trace_by_key.keys())
            if use_frontier
            else set(edges_by_parent_service.keys())
        )
        for iteration in range(iteration_limit):
            if use_frontier and not active_parent_services:
                break
            iterations = iteration + 1
            updates = {}
            if use_frontier:
                edges_to_process = [
                    edge
                    for service in active_parent_services
                    for edge in edges_by_parent_service.get(service, [])
                ]
            else:
                edges_to_process = list(outgoing_by_edge.keys())

            for edge in edges_to_process:
                child_events = outgoing_by_edge.get(edge, ())
                for child_event in child_events:
                    if child_event['key'] in fixed_prediction_keys:
                        continue
                    best = best_parent_for_child(edge, child_event, predicted_trace_by_key)
                    if best is None:
                        continue
                    prev = updates.get(child_event['key'])
                    if prev is None or best['score'] > prev['score']:
                        updates[child_event['key']] = {
                            **best,
                            'edge': edge,
                        }

            changed = False
            changed_keys = set()
            for key, pred in updates.items():
                if key in fixed_prediction_keys:
                    continue
                old = (
                    predicted_trace_by_key.get(key),
                    predicted_parent_by_key.get(key),
                )
                new = (pred['trace_id'], pred['parent_key'])
                if old != new:
                    changed = True
                    changed_keys.add(key)
                predicted_trace_by_key[key] = pred['trace_id']
                predicted_parent_by_key[key] = pred['parent_key']
                prediction_score_by_key[key] = pred['score']
                prediction_meta_by_key[key] = {
                    'source': 'graph',
                    'edge': f"{pred['edge'][0]}->{pred['edge'][1]}",
                    'score': pred['score'],
                    'lineage_score': pred.get('lineage_score', 0.0),
                    'trace_context_score': pred.get('trace_context_score', 0.0),
                }

            if not changed:
                break
            if trace_context_mode == "iterative":
                trace_contexts, trace_context_event_count = rebuild_trace_contexts(predicted_trace_by_key)
                trace_context_score_cache.clear()
                trace_context_rebuild_count += 1
            if use_frontier:
                active_parent_services = services_for_prediction_keys(changed_keys)
        return iterations

    iterations_run = propagate_graph_predictions(max_iterations)
    graph_predicted_trace_by_key = dict(predicted_trace_by_key)
    profile_mark("graph-propagation")

    def edge_token_diversity(events):
        if not events:
            return 0.0
        signatures = {
            tuple(sorted(
                e.get('lineage_all_tokens')
                if e.get('lineage_all_tokens') is not None
                else e.get('lineage_req_tokens', set()) | e.get('lineage_res_tokens', set())
            ))
            for e in events
        }
        return len(signatures) / len(events)

    def edge_graph_signal(events):
        values = []
        for event in events:
            meta = prediction_meta_by_key.get(event['key'], {})
            values.append(max(
                float(meta.get('lineage_score', 0.0)),
                float(meta.get('trace_context_score', 0.0)),
            ))
        return sum(values) / len(values) if values else 0.0

    def prediction_accuracy_for_events(events, trace_predictions):
        total = len(events)
        ok = sum(
            1
            for event in events
            if predicted_label_to_trace_id(trace_predictions.get(event['key'])) == event['trace_id']
        )
        return {
            'accuracy_pct': ok / total * 100.0 if total else 0.0,
            'accuracy_ok': ok,
            'total': total,
        }

    def slot_predictions_for_edge(edge, events):
        first_trace_id = root_events[0]['trace_id']
        first_root_event = root_events[0]
        first_events = [e for e in events if e['trace_id'] == first_trace_id]
        first_events.sort(key=lambda e: (e['req_ts'], e['res_ts'], e['key']))
        if not first_events:
            return {}, None

        offsets = [e['req_ts'] - first_root_event['req_ts'] for e in first_events]
        expected = []
        for root_idx, root_event in enumerate(root_events):
            for slot_idx, offset in enumerate(offsets):
                expected.append((root_idx, slot_idx, root_event['req_ts'] + offset))
        if not expected or not events:
            return {}, None

        cost = np.zeros((len(events), len(expected)))
        for i, event in enumerate(events):
            for j, (root_idx, _slot_idx, expected_ts) in enumerate(expected):
                root_event = root_events[root_idx]
                time_cost = abs(event['req_ts'] - expected_ts)
                containment = 0.0
                if event['req_ts'] < root_event['req_ts'] - req_tolerance:
                    containment += containment_penalty
                if event['res_ts'] > root_event['res_ts'] + res_tolerance:
                    containment += containment_penalty
                cost[i, j] = time_cost + containment

        row_ind, col_ind = linear_sum_assignment(cost)
        predictions = {}
        errors = []
        for row, col in zip(row_ind, col_ind):
            event = events[row]
            root_idx, slot_idx, expected_ts = expected[col]
            root_event = root_events[root_idx]
            predictions[event['key']] = {
                'trace_id': root_label_by_key[root_event['key']],
                'parent_key': root_event['key'],
                'slot_idx': slot_idx,
                'abs_error_ms': abs(event['req_ts'] - expected_ts) * 1000.0,
            }
            errors.append(abs(event['req_ts'] - expected_ts) * 1000.0)

        if not errors:
            return {}, None
        return predictions, {
            'occurrences_per_trace': len(offsets),
            'profile_span_ms': (max(offsets) - min(offsets)) * 1000.0 if len(offsets) > 1 else 0.0,
            'coverage_pct': len(predictions) / len(events) * 100.0 if events else 0.0,
            'median_abs_error_ms': float(np.percentile(errors, 50)),
            'p95_abs_error_ms': float(np.percentile(errors, 95)),
        }

    def service_slot_by_event_key(service_ip, trace_predictions):
        slot_by_key = {}
        by_trace = defaultdict(list)
        for event in incoming_by_service.get(service_ip, []):
            trace_id = trace_predictions.get(event['key'])
            if trace_id is None:
                continue
            by_trace[trace_id].append(event)
        for events in by_trace.values():
            events.sort(key=lambda e: (e['req_ts'], e['res_ts'], e['key']))
            for slot_idx, event in enumerate(events):
                slot_by_key[event['key']] = slot_idx
        return slot_by_key

    def parent_slot_profile_for_edge(edge):
        first_trace_id = root_events[0]['trace_id']
        parent_ip, _child_ip = edge
        parent_first = [
            e for e in incoming_by_service.get(parent_ip, [])
            if e['trace_id'] == first_trace_id
        ]
        child_first = [
            e for e in outgoing_by_edge.get(edge, [])
            if e['trace_id'] == first_trace_id
        ]
        parent_first.sort(key=lambda e: (e['req_ts'], e['res_ts'], e['key']))
        child_first.sort(key=lambda e: (e['req_ts'], e['res_ts'], e['key']))
        if not parent_first or not child_first:
            return {}

        parent_slot_by_key = {
            event['key']: idx
            for idx, event in enumerate(parent_first)
        }
        profile = defaultdict(list)
        for child_slot, child_event in enumerate(child_first):
            contained = [
                parent_event
                for parent_event in parent_first
                if parent_event['req_ts'] - req_tolerance <= child_event['req_ts']
                and parent_event['res_ts'] + res_tolerance >= child_event['res_ts']
            ]
            if contained:
                parent_event = min(
                    contained,
                    key=lambda e: (
                        e['res_ts'] - e['req_ts'],
                        abs(child_event['req_ts'] - e['req_ts']),
                    ),
                )
            else:
                parent_event = min(
                    parent_first,
                    key=lambda e: abs(child_event['req_ts'] - e['req_ts']),
                )
            parent_slot = parent_slot_by_key[parent_event['key']]
            profile[parent_slot].append({
                'offset': child_event['req_ts'] - parent_event['req_ts'],
                'child_slot': child_slot,
            })
        for slots in profile.values():
            slots.sort(key=lambda item: (item['offset'], item['child_slot']))
        return dict(profile)

    def parent_slot_predictions_for_edge(edge, events, trace_predictions):
        parent_ip, _child_ip = edge
        profile = parent_slot_profile_for_edge(edge)
        if not profile:
            return {}, None

        parent_slots = service_slot_by_event_key(parent_ip, trace_predictions)
        expected = []
        for parent_event in incoming_by_service.get(parent_ip, []):
            parent_trace_id = trace_predictions.get(parent_event['key'])
            parent_slot = parent_slots.get(parent_event['key'])
            if parent_trace_id is None or parent_slot is None:
                continue
            for slot_item in profile.get(parent_slot, []):
                expected.append({
                    'trace_id': parent_trace_id,
                    'parent_key': parent_event['key'],
                    'parent_event': parent_event,
                    'child_slot': slot_item['child_slot'],
                    'expected_ts': parent_event['req_ts'] + slot_item['offset'],
                })
        if not expected or not events:
            return {}, None

        cost = np.zeros((len(events), len(expected)))
        for i, event in enumerate(events):
            for j, exp in enumerate(expected):
                parent_event = exp['parent_event']
                time_cost = abs(event['req_ts'] - exp['expected_ts'])
                containment = 0.0
                if event['req_ts'] < parent_event['req_ts'] - req_tolerance:
                    containment += containment_penalty
                if event['res_ts'] > parent_event['res_ts'] + res_tolerance:
                    containment += containment_penalty
                cost[i, j] = time_cost + containment

        row_ind, col_ind = linear_sum_assignment(cost)
        predictions = {}
        errors = []
        outside_errors = []
        for row, col in zip(row_ind, col_ind):
            event = events[row]
            exp = expected[col]
            parent_event = exp['parent_event']
            outside = 0.0
            if event['req_ts'] < parent_event['req_ts']:
                outside += parent_event['req_ts'] - event['req_ts']
            if event['res_ts'] > parent_event['res_ts']:
                outside += event['res_ts'] - parent_event['res_ts']
            abs_error_ms = abs(event['req_ts'] - exp['expected_ts']) * 1000.0
            predictions[event['key']] = {
                'trace_id': exp['trace_id'],
                'parent_key': exp['parent_key'],
                'slot_idx': exp['child_slot'],
                'abs_error_ms': abs_error_ms,
                'outside_ms': outside * 1000.0,
            }
            errors.append(abs_error_ms)
            outside_errors.append(outside * 1000.0)

        if not errors:
            return {}, None
        profile_occurrences = sum(len(slots) for slots in profile.values())
        return predictions, {
            'profile_parent_slot_count': len(profile),
            'profile_occurrences_per_trace': profile_occurrences,
            'coverage_pct': len(predictions) / len(events) * 100.0 if events else 0.0,
            'median_abs_error_ms': float(np.percentile(errors, 50)),
            'p95_abs_error_ms': float(np.percentile(errors, 95)),
            'median_outside_ms': float(np.percentile(outside_errors, 50)),
            'p95_outside_ms': float(np.percentile(outside_errors, 95)),
        }

    slot_fallback_enabled = os.getenv("LINEAGE_GRAPH_SLOT_FALLBACK", "0") != "0"
    parent_slot_fallback_enabled = os.getenv("LINEAGE_GRAPH_PARENT_SLOT_FALLBACK", "0") != "0"
    slot_low_diversity_ratio = float(os.getenv("LINEAGE_GRAPH_SLOT_LOW_DIVERSITY_RATIO", "0.20"))
    slot_low_signal = float(os.getenv("LINEAGE_GRAPH_SLOT_LOW_SIGNAL", "0.50"))
    slot_max_p95_ms = float(os.getenv("LINEAGE_GRAPH_SLOT_MAX_P95_MS", "50"))
    slot_weak_signal_max_p95_ms = float(os.getenv("LINEAGE_GRAPH_SLOT_WEAK_SIGNAL_MAX_P95_MS", "65"))
    slot_root_repeated_max_p95_ms = float(os.getenv("LINEAGE_GRAPH_SLOT_ROOT_REPEATED_MAX_P95_MS", "70"))
    parent_slot_low_signal = float(os.getenv("LINEAGE_GRAPH_PARENT_SLOT_LOW_SIGNAL", "0.50"))
    parent_slot_max_outside_ms = float(os.getenv("LINEAGE_GRAPH_PARENT_SLOT_MAX_OUTSIDE_MS", "80"))
    slot_second_pass_iterations = int(os.getenv("LINEAGE_GRAPH_SLOT_SECOND_PASS_ITER", "6"))
    slot_max_occurrences_per_trace = int(os.getenv("LINEAGE_GRAPH_SLOT_MAX_OCCURRENCES_PER_TRACE", "1000000"))
    if loaded_calibration_profile:
        global_policy = loaded_calibration_profile.get('global_policy', {})
        slot_fallback_enabled = global_policy.get('slot_fallback_enabled', slot_fallback_enabled)
        slot_low_diversity_ratio = float(global_policy.get('slot_low_diversity_ratio', slot_low_diversity_ratio))
        slot_low_signal = float(global_policy.get('slot_low_signal', slot_low_signal))
        slot_max_p95_ms = float(global_policy.get('slot_max_p95_ms', slot_max_p95_ms))
        slot_weak_signal_max_p95_ms = float(global_policy.get(
            'slot_weak_signal_max_p95_ms',
            slot_weak_signal_max_p95_ms,
        ))
        slot_root_repeated_max_p95_ms = float(global_policy.get(
            'slot_root_repeated_max_p95_ms',
            slot_root_repeated_max_p95_ms,
        ))
        slot_second_pass_iterations = int(global_policy.get(
            'slot_second_pass_iterations',
            slot_second_pass_iterations,
        ))
        slot_max_occurrences_per_trace = int(global_policy.get(
            'slot_max_occurrences_per_trace',
            slot_max_occurrences_per_trace,
        ))

    profile_unseen_policy = os.getenv("LINEAGE_CALIBRATION_UNSEEN_POLICY", "disable")
    calibration_learning_enabled = calibration_profile_out is not None and loaded_calibration_profile is None
    calibration_policy_mode = os.getenv("LINEAGE_CALIBRATION_POLICY_MODE", "thresholds")
    calibration_slot_min_accuracy_pct = float(os.getenv("LINEAGE_CALIBRATION_MIN_SLOT_ACCURACY_PCT", "90"))
    calibration_slot_min_gain_pct = float(os.getenv("LINEAGE_CALIBRATION_MIN_SLOT_GAIN_PCT", "2"))
    calibration_slot_min_coverage_pct = float(os.getenv("LINEAGE_CALIBRATION_MIN_SLOT_COVERAGE_PCT", "95"))
    calibration_slot_low_info_ratio = float(os.getenv("LINEAGE_CALIBRATION_SLOT_LOW_INFO_RATIO", "0.35"))
    calibration_slot_max_p95_ms = float(os.getenv("LINEAGE_CALIBRATION_SLOT_MAX_P95_MS", "250"))
    unsupervised_auto_enabled = (
        (
            os.getenv("LINEAGE_GRAPH_UNSUPERVISED_GATE", "0") != "0"
            or os.getenv("LINEAGE_GRAPH_UNSUPERVISED_AUTO", "0") != "0"
        )
        and loaded_calibration_profile is None
    )
    learned_edge_policies = {}
    slot_fallback_summary = {}
    slot_candidate_by_edge = {}
    parent_slot_candidate_by_edge = {}
    unsupervised_slot_gate_by_edge = {}
    unsupervised_policy = {
        'enabled': unsupervised_auto_enabled,
        'source': 'disabled',
    }

    if slot_fallback_enabled:
        for edge, events in outgoing_by_edge.items():
            diversity = edge_token_diversity(events)
            graph_signal = edge_graph_signal(events)
            slot_predictions, slot_stats = slot_predictions_for_edge(edge, events)
            graph_accuracy = prediction_accuracy_for_events(events, graph_predicted_trace_by_key)
            slot_trace_predictions = {
                key: pred['trace_id']
                for key, pred in slot_predictions.items()
            }
            slot_accuracy = prediction_accuracy_for_events(events, slot_trace_predictions)
            slot_candidate_by_edge[edge] = {
                'predictions': slot_predictions,
                'stats': slot_stats,
                'token_diversity_ratio': diversity,
                'graph_signal': graph_signal,
                'graph_accuracy_pct': graph_accuracy['accuracy_pct'],
                'graph_accuracy_ok': graph_accuracy['accuracy_ok'],
                'slot_accuracy_pct': slot_accuracy['accuracy_pct'],
                'slot_accuracy_ok': slot_accuracy['accuracy_ok'],
                'total': graph_accuracy['total'],
            }
            if parent_slot_fallback_enabled and edge[0] != root_ip:
                parent_slot_predictions, parent_slot_stats = parent_slot_predictions_for_edge(
                    edge,
                    events,
                    graph_predicted_trace_by_key,
                )
                parent_slot_trace_predictions = {
                    key: pred['trace_id']
                    for key, pred in parent_slot_predictions.items()
                }
                parent_slot_accuracy = prediction_accuracy_for_events(
                    events,
                    parent_slot_trace_predictions,
                )
                parent_slot_candidate_by_edge[edge] = {
                    'predictions': parent_slot_predictions,
                    'stats': parent_slot_stats,
                    'parent_slot_accuracy_pct': parent_slot_accuracy['accuracy_pct'],
                    'parent_slot_accuracy_ok': parent_slot_accuracy['accuracy_ok'],
                }
        profile_mark("slot-candidates")

    def percentile_or(values, pct, default):
        values = [float(v) for v in values if v is not None and math.isfinite(float(v))]
        if not values:
            return default
        return float(np.percentile(values, pct))

    def root_interarrival_ms():
        gaps = [
            (root_events[i]['req_ts'] - root_events[i - 1]['req_ts']) * 1000.0
            for i in range(1, len(root_events))
            if root_events[i]['req_ts'] >= root_events[i - 1]['req_ts']
        ]
        return float(np.percentile(gaps, 50)) if gaps else 200.0

    if slot_fallback_enabled and unsupervised_auto_enabled:
        root_gap_ms = root_interarrival_ms()
        max_gate_p95_ms = min(
            float(os.getenv("LINEAGE_GRAPH_UNSUPERVISED_GATE_MAX_P95_MS", "120")),
            root_gap_ms * float(os.getenv("LINEAGE_GRAPH_UNSUPERVISED_GATE_MAX_P95_ROOT_RATIO", "0.45")),
        )
        max_gate_span_ms = root_gap_ms * float(
            os.getenv("LINEAGE_GRAPH_UNSUPERVISED_GATE_MAX_PROFILE_SPAN_ROOT_RATIO", "0.70")
        )
        max_gate_events_per_gap = float(os.getenv("LINEAGE_GRAPH_UNSUPERVISED_GATE_MAX_EVENTS_PER_ROOT_GAP", "0.12"))
        max_gate_token_diversity = float(os.getenv("LINEAGE_GRAPH_UNSUPERVISED_GATE_MAX_DIVERSITY", "0.35"))
        max_gate_graph_signal = float(os.getenv("LINEAGE_GRAPH_UNSUPERVISED_GATE_MAX_GRAPH_SIGNAL", "0.60"))
        gate_pass_count = 0
        for edge, candidate in slot_candidate_by_edge.items():
            stats = candidate.get('stats')
            if not stats:
                unsupervised_slot_gate_by_edge[edge] = (False, 'no-slot-profile')
                continue
            if stats.get('occurrences_per_trace', 0) <= 1:
                unsupervised_slot_gate_by_edge[edge] = (False, 'non-repeated-edge')
                continue
            if (
                stats.get('occurrences_per_trace', 0) > slot_max_occurrences_per_trace
                and edge[0] != root_ip
            ):
                unsupervised_slot_gate_by_edge[edge] = (False, 'too-many-occurrences-per-trace')
                continue
            if stats.get('coverage_pct', 0.0) < 95.0:
                unsupervised_slot_gate_by_edge[edge] = (False, 'low-slot-coverage')
                continue
            if stats.get('p95_abs_error_ms', float('inf')) > max_gate_p95_ms:
                unsupervised_slot_gate_by_edge[edge] = (False, 'unstable-slot-p95')
                continue
            if stats.get('profile_span_ms', 0.0) > max_gate_span_ms:
                unsupervised_slot_gate_by_edge[edge] = (False, 'slot-profile-overlaps-neighbor-roots')
                continue
            events_per_gap = (
                stats.get('occurrences_per_trace', 0) / root_gap_ms
                if root_gap_ms > 0 else float('inf')
            )
            if events_per_gap > max_gate_events_per_gap:
                unsupervised_slot_gate_by_edge[edge] = (False, 'too-dense-for-root-gap')
                continue
            low_info = (
                candidate.get('token_diversity_ratio', 1.0) <= max_gate_token_diversity
                or candidate.get('graph_signal', 1.0) <= max_gate_graph_signal
            )
            if not low_info:
                unsupervised_slot_gate_by_edge[edge] = (False, 'high-information-edge')
                continue
            unsupervised_slot_gate_by_edge[edge] = (True, 'conservative-gate-passed')
            gate_pass_count += 1
        unsupervised_policy = {
            'enabled': True,
            'source': 'conservative-per-edge-gate',
            'root_interarrival_median_ms': root_gap_ms,
            'gate_pass_count': gate_pass_count,
            'gate_total_count': len(slot_candidate_by_edge),
            'gate_max_p95_ms': max_gate_p95_ms,
            'gate_max_profile_span_ms': max_gate_span_ms,
            'gate_max_events_per_root_gap': max_gate_events_per_gap,
            'gate_max_token_diversity': max_gate_token_diversity,
            'gate_max_graph_signal': max_gate_graph_signal,
            'slot_max_occurrences_per_trace': slot_max_occurrences_per_trace,
            'uses_trace_id_for_learning': False,
        }

    slot_fixed_count = 0
    if slot_fallback_enabled:
        for edge, events in outgoing_by_edge.items():
            edge_key = f"{edge[0]}->{edge[1]}"
            candidate = slot_candidate_by_edge.get(edge)
            if candidate is None:
                continue
            diversity = candidate['token_diversity_ratio']
            graph_signal = candidate['graph_signal']
            slot_predictions = candidate['predictions']
            slot_stats = candidate['stats']
            graph_accuracy = {
                'accuracy_pct': candidate['graph_accuracy_pct'],
                'accuracy_ok': candidate['graph_accuracy_ok'],
                'total': candidate['total'],
            }
            slot_accuracy = {
                'accuracy_pct': candidate['slot_accuracy_pct'],
                'accuracy_ok': candidate['slot_accuracy_ok'],
                'total': candidate['total'],
            }
            parent_slot_candidate = parent_slot_candidate_by_edge.get(edge, {})
            parent_slot_predictions = parent_slot_candidate.get('predictions', {})
            parent_slot_stats = parent_slot_candidate.get('stats')
            parent_slot_accuracy = {
                'accuracy_pct': parent_slot_candidate.get('parent_slot_accuracy_pct', 0.0),
                'accuracy_ok': parent_slot_candidate.get('parent_slot_accuracy_ok', 0),
                'total': candidate['total'],
            }

            def default_slot_decision():
                if slot_stats is None:
                    return False, 'no-slot-profile'
                is_low_diversity = diversity <= slot_low_diversity_ratio
                is_repeated_edge = slot_stats.get('occurrences_per_trace', 0) > 1
                is_low_ambiguity_slot_edge = (
                    edge[0] == root_ip
                    or slot_stats.get('occurrences_per_trace', 0) <= slot_max_occurrences_per_trace
                )
                is_very_stable = slot_stats['p95_abs_error_ms'] <= slot_max_p95_ms
                is_weak_graph_stable = (
                    graph_signal <= slot_low_signal
                    and slot_stats['p95_abs_error_ms'] <= slot_weak_signal_max_p95_ms
                )
                is_repeated_root_edge = (
                    edge[0] == root_ip
                    and slot_stats.get('occurrences_per_trace', 0) > 1
                    and slot_stats['p95_abs_error_ms'] <= slot_root_repeated_max_p95_ms
                )
                apply = is_low_diversity and (
                    (
                        is_repeated_edge
                        and is_low_ambiguity_slot_edge
                        and (is_very_stable or is_weak_graph_stable)
                    )
                    or is_repeated_root_edge
                )
                if apply and unsupervised_auto_enabled:
                    gate_apply, gate_reason = unsupervised_slot_gate_by_edge.get(
                        edge,
                        (False, 'missing-unsupervised-gate'),
                    )
                    if not gate_apply:
                        return False, f'unsupervised-gate-rejected:{gate_reason}'
                return apply, 'default-rule' if apply else 'default-rule-rejected'

            def default_parent_slot_decision():
                if parent_slot_stats is None:
                    return False, 'no-parent-slot-profile'
                if parent_slot_stats.get('coverage_pct', 0.0) < 95.0:
                    return False, 'low-parent-slot-coverage'
                if parent_slot_stats.get('profile_occurrences_per_trace', 0) <= 1:
                    return False, 'non-repeated-parent-slot-edge'
                if parent_slot_stats.get('p95_outside_ms', float('inf')) > parent_slot_max_outside_ms:
                    return False, 'unstable-parent-containment'
                is_low_info = (
                    diversity <= slot_low_diversity_ratio
                    and graph_signal <= min(slot_low_signal, parent_slot_low_signal)
                )
                is_stable = parent_slot_stats['p95_abs_error_ms'] <= slot_weak_signal_max_p95_ms
                apply = is_low_info and is_stable
                if apply and unsupervised_auto_enabled:
                    gate_apply, gate_reason = unsupervised_slot_gate_by_edge.get(
                        edge,
                        (False, 'missing-unsupervised-gate'),
                    )
                    if not gate_apply:
                        return False, f'unsupervised-gate-rejected:{gate_reason}'
                return apply, 'parent-slot-rule' if apply else 'parent-slot-rule-rejected'

            def learned_slot_decision():
                if slot_stats is None:
                    return False, 'learned-no-slot-profile'
                is_repeated_edge = slot_stats.get('occurrences_per_trace', 0) > 1
                if not is_repeated_edge:
                    return False, 'learned-non-repeated-edge'
                if slot_stats.get('coverage_pct', 0.0) < calibration_slot_min_coverage_pct:
                    return False, 'learned-low-slot-coverage'
                if slot_stats['p95_abs_error_ms'] > calibration_slot_max_p95_ms:
                    return False, 'learned-unstable-slot'
                is_low_info = (
                    diversity <= calibration_slot_low_info_ratio
                    or graph_signal <= slot_low_signal
                )
                gain = slot_accuracy['accuracy_pct'] - graph_accuracy['accuracy_pct']
                if (
                    is_low_info
                    and slot_accuracy['accuracy_pct'] >= calibration_slot_min_accuracy_pct
                    and gain >= calibration_slot_min_gain_pct
                ):
                    return True, 'learned-slot-better-than-graph'
                return False, 'learned-slot-not-better'

            apply_slot = False
            decision_source = 'default'
            decision_reason = 'slot-disabled'
            learned_apply_slot = False
            learned_slot_reason = 'not-calibration-run'
            if calibration_learning_enabled:
                learned_apply_slot, learned_slot_reason = learned_slot_decision()

            if loaded_calibration_profile and profile_policy_mode == 'thresholds':
                apply_slot, decision_reason = default_slot_decision()
                decision_source = 'calibration-threshold-profile'
            elif loaded_calibration_profile:
                policy = profile_edge_policies.get(edge_key)
                if policy is not None:
                    apply_slot = bool(policy.get('slot_fallback', False))
                    decision_source = 'calibration-profile'
                    decision_reason = policy.get('slot_reason', 'profile')
                elif profile_unseen_policy == 'rules':
                    apply_slot, decision_reason = default_slot_decision()
                    decision_source = 'profile-unseen-rule'
                else:
                    apply_slot = False
                    decision_source = 'calibration-profile'
                    decision_reason = 'profile-unseen-edge-disabled'
            elif calibration_learning_enabled:
                if calibration_policy_mode == 'edge-policies':
                    apply_slot = learned_apply_slot
                    decision_reason = learned_slot_reason
                    decision_source = 'calibration-learned-edge-policy'
                else:
                    apply_slot, decision_reason = default_slot_decision()
                    decision_source = 'calibration-learned-thresholds'
            else:
                apply_slot, decision_reason = default_slot_decision()
            apply_parent_slot, parent_slot_reason = default_parent_slot_decision()
            if apply_parent_slot:
                apply_slot = False
                decision_reason = parent_slot_reason
            if apply_parent_slot:
                for event in events:
                    pred = parent_slot_predictions.get(event['key'])
                    if pred is None:
                        continue
                    predicted_trace_by_key[event['key']] = pred['trace_id']
                    predicted_parent_by_key[event['key']] = pred['parent_key']
                    prediction_score_by_key[event['key']] = float('inf')
                    prediction_meta_by_key[event['key']] = {
                        'source': 'parent-slot-fallback',
                        'edge': f"{edge[0]}->{edge[1]}",
                        'score': float('inf'),
                        'lineage_score': 0.0,
                        'trace_context_score': 0.0,
                        'slot_idx': pred['slot_idx'],
                        'abs_error_ms': pred['abs_error_ms'],
                        'outside_ms': pred['outside_ms'],
                    }
                    fixed_prediction_keys.add(event['key'])
                    slot_fixed_count += 1
            elif apply_slot:
                for event in events:
                    pred = slot_predictions.get(event['key'])
                    if pred is None:
                        continue
                    predicted_trace_by_key[event['key']] = pred['trace_id']
                    predicted_parent_by_key[event['key']] = pred['parent_key']
                    prediction_score_by_key[event['key']] = float('inf')
                    prediction_meta_by_key[event['key']] = {
                        'source': 'slot-fallback',
                        'edge': f"{edge[0]}->{edge[1]}",
                        'score': float('inf'),
                        'lineage_score': 0.0,
                        'trace_context_score': 0.0,
                        'slot_idx': pred['slot_idx'],
                        'abs_error_ms': pred['abs_error_ms'],
                    }
                    fixed_prediction_keys.add(event['key'])
                    slot_fixed_count += 1
            if calibration_learning_enabled:
                learned_edge_policies.setdefault(edge_key, {})['slot_fallback'] = learned_apply_slot
                learned_edge_policies[edge_key]['slot_reason'] = learned_slot_reason
            slot_fallback_summary[edge_key] = {
                'applied': apply_slot,
                'unsupervised_gate_applied': (
                    unsupervised_slot_gate_by_edge.get(edge, (None, None))[0]
                    if unsupervised_auto_enabled else None
                ),
                'unsupervised_gate_reason': (
                    unsupervised_slot_gate_by_edge.get(edge, (None, None))[1]
                    if unsupervised_auto_enabled else None
                ),
                'learned_slot_fallback': learned_apply_slot,
                'learned_slot_reason': learned_slot_reason,
                'decision_source': decision_source,
                'decision_reason': decision_reason,
                'parent_slot_applied': apply_parent_slot,
                'parent_slot_reason': parent_slot_reason,
                'parent_slot_accuracy_pct': parent_slot_accuracy['accuracy_pct'],
                'parent_slot_accuracy_ok': parent_slot_accuracy['accuracy_ok'],
                **{
                    f"parent_slot_{key}": value
                    for key, value in (parent_slot_stats or {}).items()
                },
                'token_diversity_ratio': diversity,
                'graph_signal': graph_signal,
                'graph_accuracy_pct': graph_accuracy['accuracy_pct'],
                'graph_accuracy_ok': graph_accuracy['accuracy_ok'],
                'slot_accuracy_pct': slot_accuracy['accuracy_pct'],
                'slot_accuracy_ok': slot_accuracy['accuracy_ok'],
                **(slot_stats or {}),
            }

        if slot_fixed_count > 0 and slot_second_pass_iterations > 0:
            iterations_run += propagate_graph_predictions(slot_second_pass_iterations)
        profile_mark("slot-apply")

    containment_fallback_enabled = os.getenv("LINEAGE_GRAPH_CONTAINMENT_FALLBACK", "0") != "0"
    containment_low_diversity_ratio = float(os.getenv(
        "LINEAGE_GRAPH_CONTAINMENT_LOW_DIVERSITY_RATIO",
        str(slot_low_diversity_ratio),
    ))
    containment_max_outside_ms = float(os.getenv("LINEAGE_GRAPH_CONTAINMENT_MAX_OUTSIDE_MS", "80"))
    containment_iterations = int(os.getenv("LINEAGE_GRAPH_CONTAINMENT_ITER", "8"))
    if loaded_calibration_profile:
        global_policy = loaded_calibration_profile.get('global_policy', {})
        containment_fallback_enabled = global_policy.get(
            'containment_fallback_enabled',
            containment_fallback_enabled,
        )
        containment_low_diversity_ratio = float(global_policy.get(
            'containment_low_diversity_ratio',
            containment_low_diversity_ratio,
        ))
        containment_max_outside_ms = float(global_policy.get(
            'containment_max_outside_ms',
            containment_max_outside_ms,
        ))
        containment_iterations = int(global_policy.get(
            'containment_iterations',
            containment_iterations,
        ))
    calibration_containment_min_accuracy_pct = float(os.getenv(
        "LINEAGE_CALIBRATION_MIN_CONTAINMENT_ACCURACY_PCT",
        "90",
    ))
    calibration_containment_min_gain_pct = float(os.getenv(
        "LINEAGE_CALIBRATION_MIN_CONTAINMENT_GAIN_PCT",
        "1",
    ))
    calibration_containment_min_coverage_pct = float(os.getenv(
        "LINEAGE_CALIBRATION_MIN_CONTAINMENT_COVERAGE_PCT",
        "80",
    ))
    containment_fixed_count = 0
    containment_edge_summary = {}
    containment_candidate_summary = {}

    def containing_parent_prediction(edge, child_event):
        parent_ip, _child_ip = edge
        best = None
        for parent_event in incoming_by_service.get(parent_ip, []):
            parent_tid = predicted_trace_by_key.get(parent_event['key'])
            if parent_tid is None:
                continue
            outside = 0.0
            if child_event['req_ts'] < parent_event['req_ts']:
                outside += parent_event['req_ts'] - child_event['req_ts']
            if child_event['res_ts'] > parent_event['res_ts']:
                outside += child_event['res_ts'] - parent_event['res_ts']
            if outside * 1000.0 > containment_max_outside_ms:
                continue
            parent_duration = max(parent_event['res_ts'] - parent_event['req_ts'], 0.0)
            start_gap = abs(child_event['req_ts'] - parent_event['req_ts'])
            score = (outside * 100.0) + parent_duration + (start_gap * 0.05)
            if best is None or score < best['score']:
                best = {
                    'score': score,
                    'trace_id': parent_tid,
                    'parent_key': parent_event['key'],
                    'outside_ms': outside * 1000.0,
                }
        return best

    if containment_fallback_enabled:
        containment_edges = set()
        for edge, events in outgoing_by_edge.items():
            key = f"{edge[0]}->{edge[1]}"
            slot_info = slot_fallback_summary.get(key, {})
            occurrences_per_trace = slot_info.get('occurrences_per_trace', 0)
            p95_ms = slot_info.get('p95_abs_error_ms', float('inf'))
            graph_signal = slot_info.get('graph_signal', edge_graph_signal(events))
            diversity = edge_token_diversity(events)

            candidate_trace_predictions = dict(predicted_trace_by_key)
            candidate_attempted = 0
            candidate_outside_ms = []
            for child_event in events:
                if child_event['server'] == root_ip and child_event['client'] in external_clients:
                    continue
                pred = containing_parent_prediction(edge, child_event)
                if pred is None:
                    continue
                candidate_attempted += 1
                candidate_trace_predictions[child_event['key']] = pred['trace_id']
                candidate_outside_ms.append(pred['outside_ms'])
            current_accuracy = prediction_accuracy_for_events(events, predicted_trace_by_key)
            containment_accuracy = prediction_accuracy_for_events(events, candidate_trace_predictions)
            containment_coverage_pct = candidate_attempted / len(events) * 100.0 if events else 0.0

            def default_containment_decision():
                if edge[0] == root_ip:
                    return False, 'root-edge-disabled'
                if diversity > containment_low_diversity_ratio:
                    return False, 'high-token-diversity'
                stable_repeated_slot = (
                    slot_info.get('applied', False)
                    and occurrences_per_trace >= 7
                    and p95_ms <= slot_max_p95_ms
                )
                weak_repeated_graph = (
                    graph_signal <= slot_low_signal
                    and occurrences_per_trace >= 3
                    and p95_ms <= slot_weak_signal_max_p95_ms
                )
                apply = stable_repeated_slot or weak_repeated_graph
                if apply and unsupervised_auto_enabled:
                    gate_apply, gate_reason = unsupervised_slot_gate_by_edge.get(
                        edge,
                        (False, 'missing-unsupervised-gate'),
                    )
                    if not gate_apply:
                        return False, f'unsupervised-gate-rejected:{gate_reason}'
                    if not slot_info.get('applied', False):
                        return False, 'unsupervised-gate-rejected:slot-not-applied'
                return apply, 'default-rule' if apply else 'default-rule-rejected'

            def learned_containment_decision():
                if edge[0] == root_ip:
                    return False, 'learned-root-edge-disabled'
                is_low_info = (
                    diversity <= calibration_slot_low_info_ratio
                    or graph_signal <= slot_low_signal
                )
                if not is_low_info:
                    return False, 'learned-high-information-edge'
                if containment_coverage_pct < calibration_containment_min_coverage_pct:
                    return False, 'learned-low-containment-coverage'
                gain = containment_accuracy['accuracy_pct'] - current_accuracy['accuracy_pct']
                if (
                    containment_accuracy['accuracy_pct'] >= calibration_containment_min_accuracy_pct
                    and gain >= calibration_containment_min_gain_pct
                ):
                    return True, 'learned-containment-better-than-current'
                return False, 'learned-containment-not-better'

            decision_source = 'default'
            learned_apply_containment = False
            learned_containment_reason = 'not-calibration-run'
            if calibration_learning_enabled:
                learned_apply_containment, learned_containment_reason = learned_containment_decision()

            if loaded_calibration_profile and profile_policy_mode == 'thresholds':
                apply_containment, decision_reason = default_containment_decision()
                decision_source = 'calibration-threshold-profile'
            elif loaded_calibration_profile:
                policy = profile_edge_policies.get(key)
                if policy is not None:
                    apply_containment = bool(policy.get('containment_fallback', False))
                    decision_source = 'calibration-profile'
                    decision_reason = policy.get('containment_reason', 'profile')
                elif profile_unseen_policy == 'rules':
                    apply_containment, decision_reason = default_containment_decision()
                    decision_source = 'profile-unseen-rule'
                else:
                    apply_containment = False
                    decision_source = 'calibration-profile'
                    decision_reason = 'profile-unseen-edge-disabled'
            elif calibration_learning_enabled:
                if calibration_policy_mode == 'edge-policies':
                    apply_containment = learned_apply_containment
                    decision_reason = learned_containment_reason
                    decision_source = 'calibration-learned-edge-policy'
                else:
                    apply_containment, decision_reason = default_containment_decision()
                    decision_source = 'calibration-learned-thresholds'
            else:
                apply_containment, decision_reason = default_containment_decision()

            if calibration_learning_enabled:
                learned_edge_policies.setdefault(key, {})['containment_fallback'] = learned_apply_containment
                learned_edge_policies[key]['containment_reason'] = learned_containment_reason

            containment_edge_summary[key] = {
                'applied': apply_containment,
                'learned_containment_fallback': learned_apply_containment,
                'learned_containment_reason': learned_containment_reason,
                'decision_source': decision_source,
                'decision_reason': decision_reason,
                'attempted': candidate_attempted,
                'updated': 0,
                'coverage_pct': containment_coverage_pct,
                'current_accuracy_pct': current_accuracy['accuracy_pct'],
                'containment_accuracy_pct': containment_accuracy['accuracy_pct'],
                'containment_accuracy_gain_pct': (
                    containment_accuracy['accuracy_pct'] - current_accuracy['accuracy_pct']
                ),
                'median_outside_ms': float(np.percentile(candidate_outside_ms, 50)) if candidate_outside_ms else None,
                'p95_outside_ms': float(np.percentile(candidate_outside_ms, 95)) if candidate_outside_ms else None,
                'token_diversity_ratio': diversity,
                'graph_signal': graph_signal,
            }
            containment_candidate_summary[key] = dict(containment_edge_summary[key])
            if apply_containment:
                containment_edges.add(edge)
        for _ in range(containment_iterations):
            changed = False
            for edge in sorted(containment_edges):
                events = outgoing_by_edge[edge]
                attempted = 0
                updated = 0
                for child_event in events:
                    if child_event['server'] == root_ip and child_event['client'] in external_clients:
                        continue
                    pred = containing_parent_prediction(edge, child_event)
                    if pred is None:
                        continue
                    attempted += 1
                    old = (
                        predicted_trace_by_key.get(child_event['key']),
                        predicted_parent_by_key.get(child_event['key']),
                    )
                    new = (pred['trace_id'], pred['parent_key'])
                    if old != new:
                        changed = True
                        updated += 1
                    predicted_trace_by_key[child_event['key']] = pred['trace_id']
                    predicted_parent_by_key[child_event['key']] = pred['parent_key']
                    prediction_score_by_key[child_event['key']] = float('inf')
                    prediction_meta_by_key[child_event['key']] = {
                        'source': 'containment-fallback',
                        'edge': f"{edge[0]}->{edge[1]}",
                        'score': float('inf'),
                        'lineage_score': 0.0,
                        'trace_context_score': 0.0,
                        'outside_ms': pred['outside_ms'],
                    }
                key = f"{edge[0]}->{edge[1]}"
                prev = containment_edge_summary.get(key, {'attempted': 0, 'updated': 0})
                containment_edge_summary[key] = {
                    **prev,
                    'attempted': max(prev.get('attempted', 0), attempted),
                    'updated': prev.get('updated', 0) + updated,
                    'token_diversity_ratio': edge_token_diversity(events),
                }
                containment_fixed_count += updated
            if not changed:
                break
        profile_mark("containment-fallback")

    root_event_keys = {
        e['key']
        for e in root_events
    }

    def select_causal_parent_from_candidates(child_event, candidates):
        if not candidates:
            return None

        containing = [
            event
            for event in candidates
            if event['req_ts'] - req_tolerance <= child_event['req_ts']
            and event['res_ts'] + res_tolerance >= child_event['res_ts']
        ]
        if containing:
            return min(
                containing,
                key=lambda event: (
                    event['res_ts'] - event['req_ts'],
                    abs(child_event['req_ts'] - event['req_ts']),
                    event['key'],
                ),
            )

        causal = [
            event
            for event in candidates
            if event['req_ts'] <= child_event['req_ts'] + req_tolerance
        ]
        if causal:
            return min(
                causal,
                key=lambda event: (
                    max(child_event['res_ts'] - event['res_ts'], 0.0),
                    abs(child_event['req_ts'] - event['req_ts']),
                    event['res_ts'] - event['req_ts'],
                    event['key'],
                ),
            )

        return min(
            candidates,
            key=lambda event: (
                abs(child_event['req_ts'] - event['req_ts']),
                event['res_ts'] - event['req_ts'],
                event['key'],
            ),
        )

    def reconstruct_predicted_parents_from_trace_labels():
        mode = os.getenv("LINEAGE_GRAPH_PARENT_RECONSTRUCTION", "causal").strip().lower()
        enabled = mode not in ("0", "off", "false", "none", "disabled")
        summary = {
            'enabled': enabled,
            'mode': mode,
            'attempted': 0,
            'updated': 0,
            'missing_candidate': 0,
        }
        if not enabled:
            return summary

        events_by_predicted_label = defaultdict(list)
        for event in all_relevant_events:
            predicted_label = predicted_trace_by_key.get(event['key'])
            if predicted_label is None:
                continue
            events_by_predicted_label[predicted_label].append(event)
        for events in events_by_predicted_label.values():
            events.sort(key=lambda e: (e['req_ts'], e['res_ts'], e['key']))

        for child_event in all_relevant_events:
            if child_event['key'] in root_event_keys or child_event['client'] in external_clients:
                continue
            child_label = predicted_trace_by_key.get(child_event['key'])
            if child_label is None:
                continue
            candidates = [
                event
                for event in events_by_predicted_label.get(child_label, [])
                if event['key'] != child_event['key'] and event['server'] == child_event['client']
            ]
            parent_event = select_causal_parent_from_candidates(child_event, candidates)
            if parent_event is None:
                summary['missing_candidate'] += 1
                continue
            summary['attempted'] += 1
            old_parent = predicted_parent_by_key.get(child_event['key'])
            if old_parent != parent_event['key']:
                summary['updated'] += 1
            predicted_parent_by_key[child_event['key']] = parent_event['key']
            prediction_meta_by_key[child_event['key']] = {
                **prediction_meta_by_key.get(child_event['key'], {}),
                'parent_reconstruction_source': 'predicted-trace-causal',
                'parent_reconstruction_mode': mode,
            }
        return summary

    parent_reconstruction_summary = reconstruct_predicted_parents_from_trace_labels()
    profile_mark("parent-reconstruction")

    edge_accuracy = {}
    per_trace_total = defaultdict(int)
    per_trace_correct = defaultdict(int)
    per_trace_incorrect_by_edge = defaultdict(lambda: defaultdict(int))
    total_events = 0
    correct_events = 0
    trace_ok = {tid: True for tid in root_trace_ids}
    root_direct_total = defaultdict(int)
    root_direct_ok = defaultdict(int)
    root_direct_all_ok = {tid: True for tid in root_trace_ids}
    unpredicted_events = 0
    error_events = []
    eval_events = [
        e
        for e in all_relevant_events
        if e['trace_id'] in root_eval_trace_set
    ]
    eval_event_by_key = {
        e['key']: e
        for e in eval_events
    }

    def first_payload_url(data_raw):
        if not data_raw:
            return ''
        try:
            parsed = json.loads(data_raw)
        except Exception:
            return str(data_raw)[:200]

        def walk(obj):
            if isinstance(obj, dict):
                if 'url' in obj:
                    return str(obj.get('url', ''))
                for value in obj.values():
                    found = walk(value)
                    if found:
                        return found
            elif isinstance(obj, list):
                for value in obj:
                    found = walk(value)
                    if found:
                        return found
            return ''

        return walk(parsed) or str(data_raw)[:200]

    for e in eval_events:
        total_events += 1
        predicted_label = predicted_trace_by_key.get(e['key'])
        predicted_tid = predicted_label_to_trace_id(predicted_label)
        is_ok = predicted_tid == e['trace_id']
        correct_events += int(is_ok)
        per_trace_total[e['trace_id']] += 1
        per_trace_correct[e['trace_id']] += int(is_ok)
        if predicted_tid is None:
            unpredicted_events += 1
        if not is_ok:
            trace_ok[e['trace_id']] = False
            per_trace_incorrect_by_edge[e['trace_id']][f"{e['client']}->{e['server']}"] += 1
            error_events.append({
                'trace_id': e['trace_id'],
                'predicted_trace_id': predicted_tid,
                'predicted_root_label': predicted_label,
                'edge': f"{e['client']}->{e['server']}",
                'client': e['client'],
                'server': e['server'],
                'req_ts': e['req_ts'],
                'res_ts': e['res_ts'],
                'url': first_payload_url(e.get('req_data_raw', '')),
                'prediction_source': prediction_meta_by_key.get(e['key'], {}).get('source', ''),
            })
        if e['client'] == root_ip:
            root_direct_total[e['trace_id']] += 1
            root_direct_ok[e['trace_id']] += int(is_ok)
            if not is_ok:
                root_direct_all_ok[e['trace_id']] = False

    for edge, events in outgoing_by_edge.items():
        edge_eval_events = [e for e in events if e['trace_id'] in root_eval_trace_set]
        ok = sum(
            1
            for e in edge_eval_events
            if predicted_label_to_trace_id(predicted_trace_by_key.get(e['key'])) == e['trace_id']
        )
        total = len(edge_eval_events)
        edge_accuracy[f"{edge[0]}->{edge[1]}"] = {
            'accuracy_pct': ok / total * 100.0 if total else 0.0,
            'accuracy_ok': ok,
            'total': total,
            'unpredicted': sum(1 for e in edge_eval_events if e['key'] not in predicted_trace_by_key),
        }

    span_accuracy_pct = correct_events / total_events * 100.0 if total_events else 0.0
    predicted_span_count = total_events - unpredicted_events
    coverage_pct = predicted_span_count / total_events * 100.0 if total_events else 0.0

    events_by_trace = defaultdict(list)
    for event in eval_events:
        events_by_trace[event['trace_id']].append(event)
    for events in events_by_trace.values():
        events.sort(key=lambda e: (e['req_ts'], e['res_ts'], e['key']))

    def select_ground_truth_parent(child_event, trace_events):
        if child_event['key'] in root_event_keys or child_event['client'] in external_clients:
            return None
        candidates = [
            event
            for event in trace_events
            if event['key'] != child_event['key'] and event['server'] == child_event['client']
        ]
        return select_causal_parent_from_candidates(child_event, candidates)

    ground_truth_parent_by_key = {}
    for trace_events in events_by_trace.values():
        for child_event in trace_events:
            parent_event = select_ground_truth_parent(child_event, trace_events)
            if parent_event is not None:
                ground_truth_parent_by_key[child_event['key']] = parent_event['key']

    ground_truth_parent_child_edges = {
        (parent_key, child_key)
        for child_key, parent_key in ground_truth_parent_by_key.items()
    }
    predicted_parent_child_edges = {
        (parent_key, child_key)
        for child_key, parent_key in predicted_parent_by_key.items()
        if child_key in eval_event_by_key
        and child_key not in root_event_keys
        and parent_key is not None
    }
    correct_parent_child_edges = predicted_parent_child_edges & ground_truth_parent_child_edges
    parent_child_precision = (
        len(correct_parent_child_edges) / len(predicted_parent_child_edges)
        if predicted_parent_child_edges else 0.0
    )
    parent_child_recall = (
        len(correct_parent_child_edges) / len(ground_truth_parent_child_edges)
        if ground_truth_parent_child_edges else 0.0
    )
    parent_child_f1 = (
        2.0 * parent_child_precision * parent_child_recall / (parent_child_precision + parent_child_recall)
        if parent_child_precision + parent_child_recall > 0.0 else 0.0
    )
    parent_child_unpredicted = sum(
        1
        for child_key in ground_truth_parent_by_key
        if child_key not in predicted_parent_by_key
    )

    trace_assignment_ok = sum(1 for tid in root_trace_ids if trace_ok.get(tid))
    ground_truth_parent_child_edges_by_trace = defaultdict(set)
    for parent_key, child_key in ground_truth_parent_child_edges:
        child_event = eval_event_by_key.get(child_key)
        if child_event is not None:
            ground_truth_parent_child_edges_by_trace[child_event['trace_id']].add((parent_key, child_key))
    predicted_parent_child_edges_by_trace = defaultdict(set)
    for parent_key, child_key in predicted_parent_child_edges:
        child_event = eval_event_by_key.get(child_key)
        if child_event is not None:
            predicted_parent_child_edges_by_trace[child_event['trace_id']].add((parent_key, child_key))
    structural_trace_ok = {}
    structural_trace_error_summary = {}
    for tid in root_trace_ids:
        gt_edges_for_trace = ground_truth_parent_child_edges_by_trace.get(tid, set())
        pred_edges_for_trace = predicted_parent_child_edges_by_trace.get(tid, set())
        missing_edges = gt_edges_for_trace - pred_edges_for_trace
        extra_edges = pred_edges_for_trace - gt_edges_for_trace
        span_trace_ok = trace_ok.get(tid, False)
        is_structural_ok = span_trace_ok and not missing_edges and not extra_edges
        structural_trace_ok[tid] = is_structural_ok
        if not is_structural_ok:
            structural_trace_error_summary[tid] = {
                'span_trace_ok': span_trace_ok,
                'span_errors': per_trace_total[tid] - per_trace_correct[tid],
                'missing_parent_child_edges': len(missing_edges),
                'extra_parent_child_edges': len(extra_edges),
            }
    full_ok = sum(1 for tid in root_trace_ids if structural_trace_ok.get(tid))
    root_direct_eval = sum(1 for tid in root_trace_ids if root_direct_total[tid] > 0)
    root_direct_full_ok = sum(
        1
        for tid in root_trace_ids
        if root_direct_total[tid] > 0 and root_direct_all_ok[tid]
    )
    root_direct_occ_total = sum(root_direct_total.values())
    root_direct_occ_ok = sum(root_direct_ok.values())
    per_trace_errors = {
        tid: per_trace_total[tid] - per_trace_correct[tid]
        for tid in root_trace_ids
    }
    error_values = list(per_trace_errors.values())
    per_trace_error_distribution = defaultdict(int)
    for err_count in error_values:
        per_trace_error_distribution[err_count] += 1
    worst_traces = sorted(
        (
            {
                'trace_id': tid,
                'span_total': per_trace_total[tid],
                'span_correct': per_trace_correct[tid],
                'span_errors': per_trace_errors[tid],
                'top_error_edges': dict(
                    sorted(
                        per_trace_incorrect_by_edge[tid].items(),
                        key=lambda item: item[1],
                        reverse=True,
                    )[:5]
                ),
            }
            for tid in root_trace_ids
        ),
        key=lambda item: item['span_errors'],
        reverse=True,
    )[:10]
    per_trace_error_edges = {
        tid: dict(
            sorted(
                per_trace_incorrect_by_edge[tid].items(),
                key=lambda item: item[1],
                reverse=True,
            )
        )
        for tid in root_trace_ids
        if per_trace_errors[tid] > 0
    }
    error_edge_trace_coverage = {}
    for tid, edge_counts in per_trace_error_edges.items():
        for edge_key, count in edge_counts.items():
            summary = error_edge_trace_coverage.setdefault(
                edge_key,
                {
                    'affected_trace_count': 0,
                    'span_error_count': 0,
                },
            )
            summary['affected_trace_count'] += 1
            summary['span_error_count'] += count
    for edge_key, summary in error_edge_trace_coverage.items():
        summary['affected_trace_pct'] = (
            summary['affected_trace_count'] / len(root_trace_ids) * 100.0
            if root_trace_ids else 0.0
        )

    edge_occurrence_vector = defaultdict(lambda: defaultdict(int))
    for edge, events in outgoing_by_edge.items():
        for e in events:
            if e['trace_id'] not in root_eval_trace_set:
                continue
            edge_occurrence_vector[e['trace_id']][edge] += 1
    span_distribution = defaultdict(int)
    for tid in root_trace_ids:
        span_distribution[1 + sum(edge_occurrence_vector[tid].values())] += 1

    calibration_profile = None
    if calibration_profile_out and calibration_learning_enabled:
        selected_slot = [
            slot_fallback_summary[key]
            for key, policy in learned_edge_policies.items()
            if policy.get('slot_fallback') and key in slot_fallback_summary
        ]
        selected_containment = [
            containment_edge_summary[key]
            for key, policy in learned_edge_policies.items()
            if policy.get('containment_fallback') and key in containment_edge_summary
        ]

        def max_stat(items, field, default):
            values = [
                item[field]
                for item in items
                if item.get(field) is not None
            ]
            return float(max(values)) if values else default

        learned_global_policy = {
            'slot_fallback_enabled': slot_fallback_enabled,
            'slot_low_diversity_ratio': max(
                slot_low_diversity_ratio,
                max_stat(selected_slot, 'token_diversity_ratio', slot_low_diversity_ratio),
            ),
            'slot_low_signal': max(
                slot_low_signal,
                max_stat(selected_slot, 'graph_signal', slot_low_signal),
            ),
            'slot_max_p95_ms': max(
                slot_max_p95_ms,
                max_stat(selected_slot, 'p95_abs_error_ms', slot_max_p95_ms),
            ),
            'slot_weak_signal_max_p95_ms': max(
                slot_weak_signal_max_p95_ms,
                max_stat(selected_slot, 'p95_abs_error_ms', slot_weak_signal_max_p95_ms),
            ),
            'slot_root_repeated_max_p95_ms': max(
                slot_root_repeated_max_p95_ms,
                max_stat([
                    summary
                    for key, summary in slot_fallback_summary.items()
                    if learned_edge_policies.get(key, {}).get('slot_fallback')
                    and key.startswith(f"{root_ip}->")
                ], 'p95_abs_error_ms', slot_root_repeated_max_p95_ms),
            ),
            'slot_second_pass_iterations': slot_second_pass_iterations,
            'slot_max_occurrences_per_trace': slot_max_occurrences_per_trace,
            'containment_fallback_enabled': containment_fallback_enabled,
            'containment_low_diversity_ratio': max(
                containment_low_diversity_ratio,
                max_stat(selected_containment, 'token_diversity_ratio', containment_low_diversity_ratio),
            ),
            'containment_max_outside_ms': max(
                containment_max_outside_ms,
                max_stat(selected_containment, 'p95_outside_ms', containment_max_outside_ms),
            ),
            'containment_iterations': containment_iterations,
        }
        use_learned_global_thresholds = os.getenv("LINEAGE_CALIBRATION_LEARN_GLOBAL_THRESHOLDS", "0") != "0"
        if not use_learned_global_thresholds:
            learned_global_policy = {
                'slot_fallback_enabled': slot_fallback_enabled,
                'slot_low_diversity_ratio': slot_low_diversity_ratio,
                'slot_low_signal': slot_low_signal,
                'slot_max_p95_ms': slot_max_p95_ms,
                'slot_weak_signal_max_p95_ms': slot_weak_signal_max_p95_ms,
                'slot_root_repeated_max_p95_ms': slot_root_repeated_max_p95_ms,
                'slot_second_pass_iterations': slot_second_pass_iterations,
                'slot_max_occurrences_per_trace': slot_max_occurrences_per_trace,
                'containment_fallback_enabled': containment_fallback_enabled,
                'containment_low_diversity_ratio': containment_low_diversity_ratio,
                'containment_max_outside_ms': containment_max_outside_ms,
                'containment_iterations': containment_iterations,
            }

        profile_edges = sorted(
            set(slot_fallback_summary)
            | set(containment_edge_summary)
            | set(learned_edge_policies)
        )
        calibration_profile = {
            'schema_version': 1,
            'mode': 'supervised-calibration',
            'policy_mode': calibration_policy_mode,
            'topology_mode': topology_mode,
            'child_order_mode': child_order_mode,
            'root_child_order_source': root_child_order_source,
            'trace_label_mode': 'root-label',
            'trace_context_mode': trace_context_mode,
            'algorithm_filters_by_root_trace_id': False,
            'created_from_csv': csv_path,
            'root_ip': root_ip,
            'root_trace_count': len(root_trace_ids),
            'global_policy': learned_global_policy,
            'learning_thresholds': {
                'slot_min_accuracy_pct': calibration_slot_min_accuracy_pct,
                'slot_min_gain_pct': calibration_slot_min_gain_pct,
                'slot_min_coverage_pct': calibration_slot_min_coverage_pct,
                'slot_low_info_ratio': calibration_slot_low_info_ratio,
                'slot_max_p95_ms': calibration_slot_max_p95_ms,
                'containment_min_accuracy_pct': calibration_containment_min_accuracy_pct,
                'containment_min_gain_pct': calibration_containment_min_gain_pct,
                'containment_min_coverage_pct': calibration_containment_min_coverage_pct,
                'learn_global_thresholds': use_learned_global_thresholds,
            },
            'edge_policies': {},
        }
        for key in profile_edges:
            policy = learned_edge_policies.get(key, {})
            calibration_profile['edge_policies'][key] = {
                'slot_fallback': bool(policy.get('slot_fallback', False)),
                'slot_reason': policy.get('slot_reason', 'not-selected'),
                'containment_fallback': bool(policy.get('containment_fallback', False)),
                'containment_reason': policy.get('containment_reason', 'not-selected'),
                'calibration': {
                    'slot': slot_fallback_summary.get(key, {}),
                    'containment': containment_edge_summary.get(key, {}),
                },
            }

    report = {
        'csv_path': csv_path,
        'root_ip': root_ip,
        'topology_mode': topology_mode,
        'child_order_mode': child_order_mode,
        'root_child_order_source': root_child_order_source,
        'root_child_order': root_child_order,
        'trace_label_mode': 'root-label',
        'trace_context_mode': trace_context_mode,
        'trace_context_rebuild_count': trace_context_rebuild_count,
        'trace_context_event_count': trace_context_event_count,
        'algorithm_filters_by_root_trace_id': False,
        'full_trace_accuracy_semantics': 'all spans assigned to correct trace and all parent-child edges correct',
        'accuracy_pct': full_ok / len(root_trace_ids) * 100.0 if root_trace_ids else 0.0,
        'accuracy_ok': full_ok,
        'root_trace_count': len(root_trace_ids),
        'full_trace_accuracy_pct': full_ok / len(root_trace_ids) * 100.0 if root_trace_ids else 0.0,
        'full_trace_accuracy_ok': full_ok,
        'full_trace_accuracy_total': len(root_trace_ids),
        'trace_assignment_accuracy_pct': trace_assignment_ok / len(root_trace_ids) * 100.0 if root_trace_ids else 0.0,
        'trace_assignment_accuracy_ok': trace_assignment_ok,
        'trace_assignment_accuracy_total': len(root_trace_ids),
        'root_direct_accuracy_pct': root_direct_full_ok / root_direct_eval * 100.0 if root_direct_eval else 0.0,
        'root_direct_accuracy_ok': root_direct_full_ok,
        'root_direct_evaluated_event_count': root_direct_eval,
        'root_direct_edge_occurrence_accuracy_pct': root_direct_occ_ok / root_direct_occ_total * 100.0 if root_direct_occ_total else 0.0,
        'root_direct_edge_occurrence_accuracy_ok': root_direct_occ_ok,
        'root_direct_edge_occurrence_accuracy_total': root_direct_occ_total,
        'edge_accuracy_pct': correct_events / total_events * 100.0 if total_events else 0.0,
        'edge_accuracy_ok': correct_events,
        'edge_accuracy_total': total_events,
        'span_accuracy_pct': span_accuracy_pct,
        'span_accuracy_ok': correct_events,
        'span_accuracy_total': total_events,
        'coverage_pct': coverage_pct,
        'coverage_ok': predicted_span_count,
        'coverage_total': total_events,
        'unpredicted_event_count': unpredicted_events,
        'parent_child_edge_precision_pct': parent_child_precision * 100.0,
        'parent_child_edge_recall_pct': parent_child_recall * 100.0,
        'parent_child_edge_f1_pct': parent_child_f1 * 100.0,
        'parent_child_edge_correct': len(correct_parent_child_edges),
        'parent_child_edge_predicted': len(predicted_parent_child_edges),
        'parent_child_edge_ground_truth': len(ground_truth_parent_child_edges),
        'parent_child_edge_false_positive': len(predicted_parent_child_edges - ground_truth_parent_child_edges),
        'parent_child_edge_false_negative': len(ground_truth_parent_child_edges - predicted_parent_child_edges),
        'parent_child_edge_unpredicted': parent_child_unpredicted,
        'parent_reconstruction': parent_reconstruction_summary,
        'structural_trace_error_count': len(structural_trace_error_summary),
        'structural_trace_errors': structural_trace_error_summary,
        'iterations': iterations_run,
        'root_seed_count': root_seed_count,
        'slot_fallback_fixed_count': slot_fixed_count,
        'containment_fallback_fixed_count': containment_fixed_count,
        'weights': {
            'time_weight': time_weight,
            'lineage_weight': lineage_weight,
            'trace_context_weight': trace_context_weight,
            'containment_penalty': containment_penalty,
            'req_tolerance_ms': req_tolerance * 1000.0,
            'res_tolerance_ms': res_tolerance * 1000.0,
            'fallback_window_ms': fallback_window * 1000.0,
            'max_iterations': max_iterations,
            'slot_fallback_enabled': slot_fallback_enabled,
            'slot_low_diversity_ratio': slot_low_diversity_ratio,
            'slot_low_signal': slot_low_signal,
            'slot_max_p95_ms': slot_max_p95_ms,
            'slot_weak_signal_max_p95_ms': slot_weak_signal_max_p95_ms,
            'slot_root_repeated_max_p95_ms': slot_root_repeated_max_p95_ms,
            'slot_second_pass_iterations': slot_second_pass_iterations,
            'slot_max_occurrences_per_trace': slot_max_occurrences_per_trace,
            'containment_fallback_enabled': containment_fallback_enabled,
            'containment_low_diversity_ratio': containment_low_diversity_ratio,
            'containment_max_outside_ms': containment_max_outside_ms,
            'containment_iterations': containment_iterations,
            'calibration_profile_in': calibration_profile_in,
            'calibration_profile_out': calibration_profile_out,
            'calibration_profile_loaded': loaded_calibration_profile is not None,
            'calibration_learning_enabled': calibration_learning_enabled,
            'calibration_policy_mode': calibration_policy_mode,
            'loaded_profile_policy_mode': profile_policy_mode,
            'profile_unseen_policy': profile_unseen_policy,
            'unsupervised_auto_enabled': unsupervised_auto_enabled,
            'unsupervised_gate_enabled': unsupervised_auto_enabled,
        },
        'unsupervised_policy': unsupervised_policy,
        'observed_graph': {
            f"{edge[0]}->{edge[1]}": {
                'event_count': len(events),
            }
            for edge, events in sorted(outgoing_by_edge.items())
        },
        'span_distribution': dict(sorted(span_distribution.items())),
        'per_trace_error_distribution': dict(sorted(per_trace_error_distribution.items())),
        'per_trace_errors': per_trace_errors,
        'per_trace_error_edges': per_trace_error_edges,
        'error_edge_trace_coverage': dict(
            sorted(
                error_edge_trace_coverage.items(),
                key=lambda item: (item[1]['affected_trace_count'], item[1]['span_error_count']),
                reverse=True,
            )
        ),
        'per_trace_error_summary': {
            'min': min(error_values) if error_values else 0,
            'p50': float(np.percentile(error_values, 50)) if error_values else 0.0,
            'p90': float(np.percentile(error_values, 90)) if error_values else 0.0,
            'p99': float(np.percentile(error_values, 99)) if error_values else 0.0,
            'max': max(error_values) if error_values else 0,
        },
        'worst_traces': worst_traces,
        'error_events': error_events,
        'observed_edge_accuracy': edge_accuracy,
        'slot_fallback': slot_fallback_summary,
        'containment_fallback': containment_edge_summary,
        'calibration_profile': {
            'loaded': loaded_calibration_profile is not None,
            'loaded_path': calibration_profile_in,
            'learned_path': calibration_profile_out if calibration_profile is not None else None,
        },
    }

    os.makedirs(os.path.dirname(json_out), exist_ok=True)
    with open(json_out, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    if calibration_profile is not None:
        profile_dir = os.path.dirname(calibration_profile_out)
        if profile_dir:
            os.makedirs(profile_dir, exist_ok=True)
        with open(calibration_profile_out, 'w', encoding='utf-8') as f:
            json.dump(calibration_profile, f, ensure_ascii=False, indent=2)

    print("service-graph occurrence-aware 检查:")
    print(f"  trace 数: {len(root_trace_ids)}")
    print(f"  每 trace span 数分布: {dict(sorted(span_distribution.items()))}")
    print(f"  observed service edge 数: {len(outgoing_by_edge)}")
    print(f"  root direct seed 数: {root_seed_count}")
    if parent_reconstruction_summary.get('enabled'):
        print(
            "  parent reconstruction: "
            f"mode={parent_reconstruction_summary.get('mode')}, "
            f"attempted={parent_reconstruction_summary.get('attempted')}, "
            f"updated={parent_reconstruction_summary.get('updated')}, "
            f"missing_candidate={parent_reconstruction_summary.get('missing_candidate')}"
        )
    print(f"  slot fallback fixed span 数: {slot_fixed_count}")
    print(f"  containment fallback 更新数: {containment_fixed_count}")
    print(f"  迭代轮数: {iterations_run}")
    print(
        "融合权重: "
        f"time={time_weight}, lineage={lineage_weight}, "
        f"trace_context={trace_context_weight}, "
        f"containment_penalty={containment_penalty}, "
        f"req_tol_ms={req_tolerance * 1000:.0f}, res_tol_ms={res_tolerance * 1000:.0f}, "
        f"fallback_ms={fallback_window * 1000:.0f}"
    )
    if unsupervised_policy.get('enabled'):
        print(
            "无监督参数: "
            f"root_gap_ms={unsupervised_policy.get('root_interarrival_median_ms', 0.0):.1f}, "
            f"stable_slot_edges={unsupervised_policy.get('stable_slot_candidate_count', 0)}, "
            f"diversity<={slot_low_diversity_ratio:.3f}, "
            f"signal<={slot_low_signal:.3f}, "
            f"slot_p95<={slot_max_p95_ms:.1f}ms, "
            f"weak_slot_p95<={slot_weak_signal_max_p95_ms:.1f}ms"
        )
    print("==================================================")
    print(f"根节点直接子调用一致率: {report['root_direct_accuracy_pct']:.2f}%   ({root_direct_full_ok}/{root_direct_eval})")
    print(f"Trace Assignment Accuracy: {report['trace_assignment_accuracy_pct']:.2f}%   ({trace_assignment_ok}/{len(root_trace_ids)})")
    print(f"Full-trace Accuracy(structural): {report['full_trace_accuracy_pct']:.2f}%   ({full_ok}/{len(root_trace_ids)})")
    print(f"Span Accuracy: {report['span_accuracy_pct']:.2f}%   ({correct_events}/{total_events})")
    print(f"Coverage: {report['coverage_pct']:.2f}%   ({predicted_span_count}/{total_events})")
    print(
        "Parent-child Edge P/R/F1: "
        f"{report['parent_child_edge_precision_pct']:.2f}% / "
        f"{report['parent_child_edge_recall_pct']:.2f}% / "
        f"{report['parent_child_edge_f1_pct']:.2f}%   "
        f"({report['parent_child_edge_correct']}/"
        f"{report['parent_child_edge_predicted']} predicted, "
        f"{report['parent_child_edge_ground_truth']} gt)"
    )
    print(f"未预测事件数: {unpredicted_events}")
    print("==================================================")
    print(f"结构化结果已写入: {json_out}")
    if calibration_profile is not None:
        print(f"calibration profile 已写入: {calibration_profile_out}")
    return report


def run_lineage_algorithm(
    csv_path='/home/wujian/trace-fusion/data/pcap_cleaned_data.csv',
    json_out='/home/wujian/trace-fusion/result/lineage_report.json',
    topology_mode=None,
    calibration_profile_in=None,
    calibration_profile_out=None,
    enable_db_lineage=None,
):
    if enable_db_lineage is None:
        enable_db_lineage = os.getenv("LINEAGE_ENABLE_DB", "0") != "0"
    # 解析 CSV
    ignored_ips = {
        ip.strip()
        for ip in os.getenv("LINEAGE_IGNORE_IPS", "").split(",")
        if ip.strip()
    }
    pairs = defaultdict(dict)
    db_pairs = defaultdict(dict)
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            client_ip = row.get('client', '').split(':')[0]
            server_ip = row.get('server', '').split(':')[0]
            if ignored_ips and (client_ip in ignored_ips or server_ip in ignored_ips):
                continue
            protocol = row.get('protocol_type', '')
            is_db = str(protocol).strip().lower() in {
                'db', 'sql', 'mysql', 'postgres', 'postgresql', 'mongodb', 'mongo'
            }
            key = (row['client'], row['server'], row['stream_id'])
            msg = row['msg_type']
            target_pairs = db_pairs if is_db else pairs
            target_pairs[key][msg] = ts_to_float(row['timestamp'])
            target_pairs[key]['trace_id'] = row.get('trace_id', '')
            target_pairs[key]['protocol'] = protocol
            
            if msg == 'Request':
                target_pairs[key]['req_data_raw'] = row['data']
            elif msg == 'Response':
                target_pairs[key]['res_data_raw'] = row['data']

    # 构建事件集合
    all_events = []
    for key, data in pairs.items():
        if 'Request' in data and 'Response' in data: 
            req_tokens = extract_lineage_tokens(data.get('req_data_raw', ''))
            res_tokens = extract_lineage_tokens(data.get('res_data_raw', ''))
            lineage_all_tokens = req_tokens | res_tokens
            lineage_parent_weights = merge_token_weight_maps(
                token_set_to_weight_map(req_tokens, 1.0),
                token_set_to_weight_map(res_tokens, 0.8),
            )
            all_events.append({
                'key': key,
                'req_ts': data['Request'],
                'res_ts': data['Response'],
                'trace_id': data['trace_id'],
                'protocol': data['protocol'],
                'client': key[0].split(':')[0],
                'server': key[1].split(':')[0],
                'req_data_raw': data.get('req_data_raw', ''),
                'res_data_raw': data.get('res_data_raw', ''),
                'lineage_req_tokens': req_tokens,
                'lineage_res_tokens': res_tokens,
                'lineage_all_tokens': lineage_all_tokens,
                'lineage_parent_weights': lineage_parent_weights,
            })

    if enable_db_lineage:
        db_events = []
        for key, data in db_pairs.items():
            if 'Request' in data and 'Response' in data:
                req_tokens = extract_db_lineage_tokens(data.get('req_data_raw', ''))
                res_tokens = filter_db_result_tokens(
                    req_tokens,
                    extract_db_lineage_tokens(data.get('res_data_raw', '')),
                )
                db_events.append({
                    'key': key,
                    'req_ts': data['Request'],
                    'res_ts': data['Response'],
                    'trace_id': data.get('trace_id', ''),
                    'protocol': data.get('protocol', 'DB'),
                    'client': key[0].split(':')[0],
                    'server': key[1].split(':')[0],
                    'req_data_raw': data.get('req_data_raw', ''),
                    'res_data_raw': data.get('res_data_raw', ''),
                    'lineage_req_tokens': req_tokens,
                    'lineage_res_tokens': res_tokens,
                    'lineage_all_tokens': req_tokens | res_tokens,
                })
        attached_db_count = attach_db_lineage_to_service_spans(all_events, db_events)
        if db_events:
            print(f"DB lineage enabled: db_events={len(db_events)}, attached={attached_db_count}")

    topology_mode = topology_mode or os.getenv("LINEAGE_TOPOLOGY_MODE", "service-graph")
    if topology_mode == "edge-slot":
        return run_edge_slot_algorithm(all_events, csv_path, json_out, topology_mode)
    if topology_mode == "service-tree-edge":
        return run_service_tree_edge_parent_slot_algorithm(all_events, csv_path, json_out, topology_mode)
    if topology_mode == "service-graph":
        return run_service_graph_algorithm(
            all_events,
            csv_path,
            json_out,
            topology_mode,
            calibration_profile_in=calibration_profile_in,
            calibration_profile_out=calibration_profile_out,
        )
    root_ip, tree = infer_topology(all_events)
    if not root_ip:
        print("未能从数据中自动推断出调用拓扑！")
        return
    child_order_mode = os.getenv(
        "LINEAGE_CHILD_ORDER_MODE",
        os.getenv("LINEAGE_TOPOLOGY_CHILD_ORDER", "trace"),
    ).strip().lower()
    if child_order_mode in ("trace", "first-trace", "first_trace"):
        first_trace_id = reorder_tree_by_trace(tree, root_ip)
        child_order_source = "first-trace"
    else:
        first_trace_id = None
        child_order_source = "temporal-gap"
        for parent_ip, node in tree.items():
            if len(node['children']) <= 1:
                continue
            children_events_map = {child_ip: tree[child_ip]['events'] for child_ip in node['children']}
            node['children'], _ = detect_child_call_order(node['events'], children_events_map)
    n_root = len(tree[root_ip]['events'])
    if n_root == 0:
        print("自动拓扑中根节点缺少事件或子节点，无法进行匹配！")
        return

    print("自动推断拓扑:")
    def print_tree(ip, indent=0):
        node = tree[ip]
        print(f"{'  ' * indent}{ip}  ({len(node['events'])} 条事件)")
        for child in node['children']:
            print_tree(child, indent + 1)
    print_tree(root_ip)
    if first_trace_id:
        print(f"\n基准链路 trace_id: {first_trace_id} (用于 children 顺序重排)")
    else:
        print(f"\nchildren 顺序来源: {child_order_source}")

    time_weight = float(os.getenv("LINEAGE_TIME_WEIGHT", "1.0"))
    lineage_weight = float(os.getenv("LINEAGE_DATA_WEIGHT", "20.0"))
    causal_penalty = float(os.getenv("LINEAGE_CAUSAL_PENALTY", "2.0"))
    cascade_gap_weight = float(os.getenv("LINEAGE_CASCADE_GAP_WEIGHT", "0.3"))
    cascade_negative_penalty = float(os.getenv("LINEAGE_CASCADE_NEG_PENALTY", "2.5"))
    context_decay = float(os.getenv("LINEAGE_CONTEXT_DECAY", "0.8"))
    context_mix_weight = float(os.getenv("LINEAGE_CONTEXT_MIX_WEIGHT", "0.5"))
    match_batch_size = int(os.getenv("LINEAGE_MATCH_BATCH_SIZE", "150"))
    match_window_seconds = float(os.getenv("LINEAGE_MATCH_WINDOW_MS", "150")) / 1000.0

    def initial_contexts(parent_events):
        return [
            merge_token_weight_maps(
                token_set_to_weight_map(parent_events[i].get('lineage_req_tokens', set()), 1.0),
                token_set_to_weight_map(parent_events[i].get('lineage_res_tokens', set()), 0.8),
            )
            for i in range(len(parent_events))
        ]

    def match_children_for_parent(parent_events, child_order):
        local_predict_map = defaultdict(dict)
        local_matched_map = {}
        local_contexts = initial_contexts(parent_events)
        prev_child = None
        for child_ip in child_order:
            child_events = children_events_map[child_ip]
            if not parent_events or not child_events:
                local_matched_map[child_ip] = [None] * len(parent_events)
                prev_child = child_ip
                continue

            prev_matched = local_matched_map.get(prev_child) if prev_child else None
            child_matched_list = match_child_events_windowed(
                parent_events,
                child_events,
                prev_sibling_matched=prev_matched,
                propagated_contexts=local_contexts,
                time_weight=time_weight,
                lineage_weight=lineage_weight,
                causal_penalty=causal_penalty,
                cascade_gap_weight=cascade_gap_weight,
                cascade_negative_penalty=cascade_negative_penalty,
                context_mix_weight=context_mix_weight,
                context_decay=context_decay,
                batch_size=match_batch_size,
                window_seconds=match_window_seconds,
            )
            for p_i, matched_child in enumerate(child_matched_list):
                if matched_child is not None:
                    local_predict_map[p_i][child_ip] = matched_child['trace_id']
            local_matched_map[child_ip] = child_matched_list
            prev_child = child_ip
        return local_predict_map

    def eval_predict_map(parent_events, child_order, local_predict_map):
        ok = 0
        for i in range(len(parent_events)):
            true_tid = parent_events[i]['trace_id']
            all_match = all(
                local_predict_map[i].get(child_ip) == true_tid
                for child_ip in child_order
            )
            if all_match:
                ok += 1
        pct = ok / len(parent_events) * 100 if parent_events else 0.0
        return ok, pct

    def eval_full_topology(all_predict_maps):
        root_trace_ids = [event['trace_id'] for event in root_events]
        parent_index_by_trace = {
            parent_ip: {
                event['trace_id']: idx
                for idx, event in enumerate(node['events'])
            }
            for parent_ip, node in tree.items()
            if node['children']
        }
        ok = 0
        total_edges = 0
        ok_edges = 0

        for trace_id in root_trace_ids:
            trace_ok = True
            for parent_ip, node in tree.items():
                children = node['children']
                if not children:
                    continue
                parent_idx = parent_index_by_trace.get(parent_ip, {}).get(trace_id)
                if parent_idx is None:
                    trace_ok = False
                    total_edges += len(children)
                    continue
                predict_map = all_predict_maps.get(parent_ip, {})
                for child_ip in children:
                    total_edges += 1
                    if predict_map.get(parent_idx, {}).get(child_ip) == trace_id:
                        ok_edges += 1
                    else:
                        trace_ok = False
            if trace_ok:
                ok += 1

        pct = ok / len(root_trace_ids) * 100 if root_trace_ids else 0.0
        edge_pct = ok_edges / total_edges * 100 if total_edges else 0.0
        return ok, pct, ok_edges, total_edges, edge_pct

    # 2. 在根节点层做跨链路（兄弟）血缘传递匹配
    root_events = tree[root_ip]['events']
    root_children = tree[root_ip]['children']
    print(
        "融合权重: "
        f"time={time_weight}, lineage={lineage_weight}, "
        f"causal_penalty={causal_penalty}, cascade_gap={cascade_gap_weight}, "
        f"cascade_neg_penalty={cascade_negative_penalty}, "
        f"context_decay={context_decay}, context_mix={context_mix_weight}, "
        f"match_batch={match_batch_size}, match_window_ms={match_window_seconds * 1000:.0f}"
    )

    all_predict_maps = {}
    node_accuracy = {}
    for parent_ip, node in tree.items():
        parent_children = node['children']
        if not parent_children:
            continue
        parent_events = node['events']
        children_events_map = {c: tree[c]['events'] for c in parent_children}
        order = list(parent_children)
        print(f"\n[{parent_ip}] 子调用顺序({child_order_source}): " + " -> ".join(order))
        predict_map = match_children_for_parent(parent_events, order)
        all_predict_maps[parent_ip] = predict_map
        ok_node, pct_node = eval_predict_map(parent_events, order, predict_map)
        node_accuracy[parent_ip] = {
            'accuracy_pct': pct_node,
            'accuracy_ok': ok_node,
            'event_count': len(parent_events),
            'children': order,
        }

    predict_prop = all_predict_maps.get(root_ip, {})
    ok_root_direct, pct_root_direct = eval_predict_map(root_events, root_children, predict_prop)
    ok_prop, pct_prop, ok_edges, total_edges, edge_pct = eval_full_topology(all_predict_maps)

    report = {
        'csv_path': csv_path,
        'root_ip': root_ip,
        'first_trace_id': first_trace_id,
        'child_order_mode': child_order_mode,
        'child_order_source': child_order_source,
        'accuracy_pct': pct_prop,
        'accuracy_ok': ok_prop,
        'root_trace_count': n_root,
        'root_direct_accuracy_pct': pct_root_direct,
        'root_direct_accuracy_ok': ok_root_direct,
        'edge_accuracy_pct': edge_pct,
        'edge_accuracy_ok': ok_edges,
        'edge_accuracy_total': total_edges,
        'node_accuracy': node_accuracy,
        'weights': {
            'time_weight': time_weight,
            'lineage_weight': lineage_weight,
            'causal_penalty': causal_penalty,
            'cascade_gap_weight': cascade_gap_weight,
            'cascade_negative_penalty': cascade_negative_penalty,
            'context_decay': context_decay,
            'context_mix_weight': context_mix_weight,
            'match_batch_size': match_batch_size,
            'match_window_ms': match_window_seconds * 1000.0,
        },
        'topology': tree_to_serializable(tree),
    }

    os.makedirs(os.path.dirname(json_out), exist_ok=True)

    with open(json_out, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print("==================================================")
    print(f"根节点直接子调用一致率: {pct_root_direct:.2f}%   ({ok_root_direct}/{n_root})")
    print(f"拓扑边级一致率: {edge_pct:.2f}%   ({ok_edges}/{total_edges})")
    print(f"完整拓扑调用链(时序与跨链路血缘传播)还原一致率: {pct_prop:.2f}%   ({ok_prop}/{n_root})")
    print("==================================================")
    print(f"结构化结果已写入: {json_out}")

    return report

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run lineage inference and export a JSON report.')
    parser.add_argument('--csv-path', default='/home/wujian/trace-fusion/data/pcap_cleaned_data.csv')
    parser.add_argument('--json-out', default='/home/wujian/trace-fusion/result/lineage_report.json')
    parser.add_argument(
        '--topology-mode',
        choices=['service-tree', 'edge-slot', 'service-tree-edge', 'service-graph'],
        default=os.getenv("LINEAGE_TOPOLOGY_MODE", "service-graph"),
    )
    parser.add_argument(
        '--calibration-profile-in',
        default=None,
        help='Load a frozen service-graph calibration profile generated by a previous run.',
    )
    parser.add_argument(
        '--calibration-profile-out',
        default=None,
        help='Write a supervised service-graph calibration profile from this run.',
    )
    parser.add_argument(
        '--enable-db-lineage',
        action='store_true',
        default=os.getenv("LINEAGE_ENABLE_DB", "0") != "0",
        help='Attach filtered database query/result business tokens to the containing service span lineage pool.',
    )
    args = parser.parse_args()
    run_lineage_algorithm(
        csv_path=args.csv_path,
        json_out=args.json_out,
        topology_mode=args.topology_mode,
        calibration_profile_in=args.calibration_profile_in,
        calibration_profile_out=args.calibration_profile_out,
        enable_db_lineage=args.enable_db_lineage,
    )
