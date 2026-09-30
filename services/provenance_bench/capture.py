"""Normalize HTTP/1.1 pcap into observations without reading oracle records.

Only this controlled benchmark's one-request-per-connection JSON protocol is supported.
"""
import json
import re
import subprocess
from decimal import Decimal
from common import ADDRESSES


def values(obj, key):
    result = []
    if isinstance(obj, dict):
        for name, value in obj.items():
            if name == key:
                result.extend(value if isinstance(value, list) else [value])
            elif isinstance(value, (dict, list)):
                result.extend(values(value, key))
    elif isinstance(obj, list):
        for value in obj:
            result.extend(values(value, key))
    return result


def first(obj, key):
    found = values(obj, key)
    return found[0] if found else None


def json_body(http):
    body = first(http, "http.file_data")
    if body is None:
        raise ValueError("HTTP JSON body missing; check tshark reassembly/version")
    try:
        return json.loads(body)
    except (TypeError, ValueError):
        # Some tshark versions expose byte data as colon-separated hex.
        return json.loads(bytes.fromhex(body.replace(":", "")).decode())


def normalize(packets):
    requests, responses = {}, {}
    role_by_ip = {ip: role for role, ip in ADDRESSES.items()}
    for packet in packets:
        layers = packet["_source"]["layers"]
        http = layers.get("http")
        if not http:
            continue
        stream = first(layers.get("tcp", {}), "tcp.stream")
        stamp = int(Decimal(first(layers.get("frame", {}), "frame.time_epoch")) * 1_000_000_000)
        if first(http, "http.request.method") == "POST":
            request = {
                "start_ns": stamp, "operation": first(http, "http.request.uri"),
                "caller": role_by_ip.get(first(layers.get("ip", {}), "ip.src"), "unknown"),
                "callee": role_by_ip.get(first(layers.get("ip", {}), "ip.dst"), "unknown"),
                "request": json_body(http),
            }
            if stream in requests:
                raise ValueError("multiple decoded requests in a TCP stream; benchmark requires connection close")
            requests[stream] = request
        if str(first(http, "http.response.code")) == "200":
            headers = "\n".join(str(v) for v in values(http, "http.response.line"))
            match = re.search(r"(?i)x-observation-id:\s*([0-9a-f]{32})", headers)
            if not match:  # health checks have no observation ID
                continue
            if stream in responses:
                raise ValueError("multiple decoded responses in a TCP stream")
            responses[stream] = {"event_id": match.group(1), "end_ns": stamp,
                                 "response": json_body(http)}
    records = [{**request, **responses[stream]} for stream, request in requests.items() if stream in responses]
    if any(r["caller"] == "unknown" or r["callee"] == "unknown" for r in records):
        raise ValueError("unknown benchmark endpoint")
    stats = {"requests": len(requests), "responses": len(responses), "paired": len(records),
             "unpaired_requests": len(set(requests) - set(responses)),
             "unpaired_responses": len(set(responses) - set(requests))}
    if not records:
        raise ValueError("no benchmark exchanges decoded from capture")
    return sorted(records, key=lambda r: (r["start_ns"], r["event_id"])), stats


def from_pcap(path, port):
    result = subprocess.run([
        "tshark", "-r", str(path), "-d", f"tcp.port=={port},http",
        "-o", "tcp.desegment_tcp_streams:TRUE", "-o", "http.desegment_body:TRUE",
        "-Y", "http", "-T", "json",
    ], capture_output=True, text=True, check=True)
    return normalize(json.loads(result.stdout))
