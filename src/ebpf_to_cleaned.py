#!/usr/bin/env python3
"""Convert cgroup eBPF HTTP/1.1 output to cleaned_data-like CSV.

The cgroup collector records raw TCP payload events from both cgroup egress and
ingress hooks. For one network RPC that usually means two observations of the
same request and two observations of the same response. This converter performs
HTTP/1.1 message reconstruction offline, merges duplicate observations, pairs
requests with responses on each TCP connection, and emits the same row shape as
pcap_to_cleaned.py. It also accepts the older collector format where payload is
already a decoded HTTP JSON object.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import os
import re
import struct
import sys
from collections import Counter, defaultdict, deque
from datetime import datetime
from typing import Any


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
INPUT_CSV = os.path.join(PROJECT_ROOT, "data", "output.csv")
OUTPUT_CSV = os.path.join(PROJECT_ROOT, "data", "ebpf_cleaned_data.csv")
HTTP1_PROTOCOL_TYPE = "HTTP/1.1"
HTTP2_PROTOCOL_TYPE = "HTTP/2"
HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
FIELDNAMES = [
    "protocol_type",
    "msg_type",
    "timestamp",
    "network_duration_us",
    "client",
    "server",
    "stream_id",
    "trace_id",
    "span_id",
    "parent_span_id",
    "span_kind",
    "span_endpoint",
    "peer_endpoint",
    "headers",
    "data",
]
csv.field_size_limit(sys.maxsize)
RAW_BINARY_MAGIC = b"TFEBPF1\0"
RAW_BINARY_HEADER = struct.Struct("<8sHHqQ")
RAW_BINARY_RECORD = struct.Struct("<QBBIIHHIHHIQ")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert cgroup eBPF HTTP/1.1 CSV to cleaned_data-like CSV"
    )
    parser.add_argument("--input", default=INPUT_CSV, help="Path to cgroup eBPF raw capture")
    parser.add_argument("--cleaned-out", default=OUTPUT_CSV, help="Output path for cleaned CSV")
    parser.add_argument(
        "--expected-trace-count",
        type=int,
        default=0,
        help=(
            "Only keep traces whose cleaned row count equals this value; "
            "0 uses an automatic median-based threshold"
        ),
    )
    parser.add_argument(
        "--span-form",
        choices=["rpc", "client-server"],
        default="rpc",
        help=(
            "rpc keeps one row-pair per network RPC; client-server emits caller "
            "client and callee server span-shaped row-pairs"
        ),
    )
    parser.add_argument(
        "--keep-incomplete",
        action="store_true",
        help="Do not drop traces below the expected/automatic row-count threshold.",
    )
    parser.add_argument(
        "--enable-db-rows",
        action="store_true",
        help="Also emit parsed SQL/MongoDB request/response rows into the cleaned CSV.",
    )
    parser.add_argument(
        "--tls-pid-endpoint",
        action="append",
        default=[],
        help=(
            "Map TLS uprobe process ids to service endpoints, e.g. "
            "--tls-pid-endpoint 1234=productpage:9080. Can be repeated or comma-separated."
        ),
    )
    return parser.parse_args()


def parse_time(value: str) -> datetime | None:
    value = (value or "").strip()
    if not value:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def format_unix_ns(value: int) -> str:
    return datetime.fromtimestamp(value / 1_000_000_000.0).strftime("%Y-%m-%d %H:%M:%S.%f")


def raw_binary_capture_rows(input_path: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    with open(input_path, "rb") as f:
        header = f.read(RAW_BINARY_HEADER.size)
        if len(header) < RAW_BINARY_HEADER.size:
            return rows
        magic, version, record_header_len, boot_time_unix_ns, _reserved = RAW_BINARY_HEADER.unpack(header)
        if magic != RAW_BINARY_MAGIC:
            raise ValueError(f"Unsupported eBPF raw capture magic: {magic!r}")
        if version != 1:
            raise ValueError(f"Unsupported eBPF raw capture version: {version}")
        if record_header_len < RAW_BINARY_RECORD.size:
            raise ValueError(
                f"Unsupported eBPF raw record header length: {record_header_len}"
            )

        while True:
            record_header = f.read(record_header_len)
            if not record_header:
                break
            if len(record_header) < record_header_len:
                break
            (
                timestamp_ns,
                direction,
                _record_reserved,
                src_addr,
                dst_addr,
                src_port,
                dst_port,
                payload_len,
                captured_len,
                _flags,
                tcp_seq,
                sock_cookie,
            ) = RAW_BINARY_RECORD.unpack(record_header[: RAW_BINARY_RECORD.size])
            payload = f.read(captured_len)
            if len(payload) < captured_len:
                break
            rows.append(
                {
                    "type": "TCP",
                    "timestamp": format_unix_ns(boot_time_unix_ns + int(timestamp_ns)),
                    "direction": "OUT" if direction == 0 else "IN",
                    "src_ip": str(ipaddress.IPv4Address(src_addr)),
                    "src_port": str(src_port),
                    "dst_ip": str(ipaddress.IPv4Address(dst_addr)),
                    "dst_port": str(dst_port),
                    "tcp_seq": str(tcp_seq),
                    "payload_len": str(payload_len),
                    "sock_cookie": str(sock_cookie),
                    "payload": payload.hex(),
                }
            )
    return rows


def read_capture_rows(input_path: str) -> list[dict[str, str]]:
    with open(input_path, "rb") as f:
        magic = f.read(len(RAW_BINARY_MAGIC))
    if magic == RAW_BINARY_MAGIC:
        return raw_binary_capture_rows(input_path)
    with open(input_path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def earliest_ts(*values: str) -> str:
    present = [v for v in values if v]
    if not present:
        return ""
    return min(present, key=lambda v: parse_time(v) or datetime.max)


def diff_us(start: str, end: str) -> str:
    s = parse_time(start)
    e = parse_time(end)
    if s is None or e is None:
        return ""
    return str(abs(int((e - s).total_seconds() * 1_000_000)))


def clean_header_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        value = value[0] if value else ""
    return (
        str(value)
        .strip()
        .replace("\r", "")
        .replace("\n", "")
        .replace("\\r", "")
        .replace("\\n", "")
    )


def extract_trace_from_headers(headers: dict[str, Any]) -> tuple[str, str, str]:
    if not headers:
        return "", "", ""
    normalized = {str(k).lower(): clean_header_value(v) for k, v in headers.items()}

    uber_trace_id = normalized.get("uber-trace-id")
    if uber_trace_id:
        parts = uber_trace_id.split(":")
        if len(parts) >= 3:
            return parts[0], parts[1], parts[2]

    mark = normalized.get("x-mark") or normalized.get("x_mark")
    if mark:
        return mark, mark, ""

    trace_id = normalized.get("x-b3-traceid")
    if trace_id:
        span_id = normalized.get("x-b3-spanid") or trace_id
        parent_span_id = normalized.get("x-b3-parentspanid") or ""
        return trace_id, span_id, parent_span_id

    trace_id = normalized.get("x-trace-id")
    if trace_id:
        return trace_id, trace_id, ""

    request_id = normalized.get("x-request-id")
    if request_id:
        return request_id, request_id, ""
    return "", "", ""


def endpoint(row: dict[str, str], side: str) -> str:
    return f"{row[f'{side}_ip']}:{row[f'{side}_port']}"


def endpoint_tuple(value: str) -> tuple[str, int]:
    host, _, port = value.rpartition(":")
    try:
        parsed_port = int(port)
    except ValueError:
        parsed_port = 0
    return host, parsed_port


def conn_key(src: str, dst: str) -> tuple[tuple[str, int], tuple[str, int]]:
    a = endpoint_tuple(src)
    b = endpoint_tuple(dst)
    return (a, b) if a <= b else (b, a)


def stable_payload_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def parse_payload(raw: str) -> dict[str, Any] | None:
    try:
        payload = json.loads((raw or "").strip())
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def unique_keep_order(items: list[Any]) -> list[Any]:
    seen = set()
    out = []
    for item in items:
        marker = json.dumps(item, ensure_ascii=False, sort_keys=True) if isinstance(item, (dict, list)) else str(item)
        if marker in seen:
            continue
        seen.add(marker)
        out.append(item)
    return out


def is_loopback_endpoint(value: str) -> bool:
    host = value.rsplit(":", 1)[0]
    return host in {"127.0.0.1", "::1", "localhost"}


def synthetic_server_span_id(call: dict[str, Any]) -> str:
    material = "|".join(
        [
            call.get("trace_id", ""),
            call.get("span_id", ""),
            call.get("server", ""),
            call.get("stream_id", ""),
        ]
    )
    return hashlib.blake2s(material.encode("utf-8"), digest_size=8).hexdigest()


def message_type(payload: dict[str, Any]) -> str | None:
    if "method" in payload:
        return "Request"
    if "status" in payload:
        return "Response"
    return None


HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"PATCH ", b"HEAD ", b"OPTIONS ")


def is_http_start(payload: bytes) -> bool:
    return payload.startswith(HTTP_METHODS) or payload.startswith(b"HTTP/")


def likely_http2_frame(payload: bytes) -> bool:
    if payload.startswith(HTTP2_PREFACE):
        return True
    if len(payload) < 9:
        return False
    frame_len = int.from_bytes(payload[0:3], "big")
    frame_type = payload[3]
    stream_id = int.from_bytes(payload[5:9], "big") & 0x7FFFFFFF
    if frame_len > 16 * 1024 * 1024:
        return False
    if frame_type > 0x9:
        return False
    if frame_type in {0x4, 0x7} and stream_id != 0:
        return False
    return True


def find_http_header_end(buffer: bytes | bytearray) -> tuple[int, int] | None:
    pos = bytes(buffer).find(b"\r\n\r\n")
    if pos >= 0:
        return pos, pos + 4
    pos = bytes(buffer).find(b"\n\n")
    if pos >= 0:
        return pos, pos + 2
    return None


def parse_header_lines(header_text: str) -> tuple[str, dict[str, str]]:
    lines = header_text.splitlines()
    first_line = lines[0].strip() if lines else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()
        else:
            headers[line] = ""
    return first_line, headers


def header_value(headers: dict[str, str], name: str) -> str:
    target = name.lower()
    for key, value in headers.items():
        if key.lower() == target:
            return value
    return ""


def http_content_length(headers: dict[str, str]) -> int | None:
    value = header_value(headers, "content-length")
    if not value:
        return None
    try:
        return int(value.strip())
    except ValueError:
        return None


def http_is_chunked(headers: dict[str, str]) -> bool:
    return "chunked" in header_value(headers, "transfer-encoding").lower()


def http_is_html(headers: dict[str, str]) -> bool:
    content_type = header_value(headers, "content-type").lower()
    return "text/html" in content_type or "application/xhtml" in content_type


def find_chunked_message_end(buffer: bytes | bytearray, body_start: int) -> int | None:
    body = bytes(buffer)[body_start:]
    for marker in (b"\r\n0\r\n\r\n", b"\n0\n\n"):
        pos = body.find(marker)
        if pos >= 0:
            return body_start + pos + len(marker)
    return None


def decode_http_payload(payload: bytes) -> dict[str, Any] | None:
    if not is_http_start(payload):
        return None
    header_bounds = find_http_header_end(payload)
    if header_bounds is None:
        header_bytes = payload
        body = b""
    else:
        header_end, body_start = header_bounds
        header_bytes = payload[:header_end]
        body = payload[body_start:]

    header_text = header_bytes.decode("utf-8", errors="replace")
    first_line, headers = parse_header_lines(header_text)
    if not first_line:
        return None

    decoded: dict[str, Any] = {}
    if first_line.startswith("HTTP/"):
        parts = first_line.split(" ", 2)
        if len(parts) >= 2:
            decoded["status"] = parts[1]
    else:
        parts = first_line.split(" ", 2)
        if len(parts) >= 2:
            decoded["method"] = parts[0]
            full_url = parts[1]
            if "?" in full_url:
                url, paras = full_url.split("?", 1)
            else:
                url, paras = full_url, ""
            decoded["url"] = url
            decoded["paras"] = paras

    if headers:
        decoded["headers"] = headers
    if body and not http_is_html(headers):
        decoded["body"] = body.decode("utf-8", errors="replace").strip()
    return decoded if message_type(decoded) else None


def raw_payload_bytes(row: dict[str, str]) -> bytes | None:
    raw = (row.get("payload", "") or "").strip()
    if not raw:
        return None
    try:
        return bytes.fromhex(raw)
    except ValueError:
        return None


def tcp_seq_advance(row: dict[str, str], payload: bytes) -> int:
    try:
        payload_len = int(row.get("payload_len", "") or "0")
    except ValueError:
        payload_len = 0
    return max(payload_len, len(payload))


def take_complete_http1_message(stream: dict[str, Any]) -> tuple[int, bytes] | None:
    buffer = stream["buffer"]
    if not buffer:
        return None
    if not is_http_start(buffer):
        buffer.clear()
        stream["expected_seq"] = None
        stream["message_start_seq"] = None
        stream["out_of_order"].clear()
        return None

    header_bounds = find_http_header_end(buffer)
    if header_bounds is None:
        return None
    header_end, body_start = header_bounds
    header_text = bytes(buffer[:header_end]).decode("utf-8", errors="replace")
    _first_line, headers = parse_header_lines(header_text)
    if http_is_html(headers):
        total_len = body_start
    else:
        content_length = http_content_length(headers)
        if content_length is not None:
            total_len = body_start + content_length
        elif http_is_chunked(headers):
            chunked_end = find_chunked_message_end(buffer, body_start)
            if chunked_end is None:
                return None
            total_len = chunked_end
        else:
            total_len = body_start

    if len(buffer) < total_len:
        return None
    start_seq = stream.get("message_start_seq")
    if start_seq is None:
        start_seq = 0
    message = bytes(buffer[:total_len])
    del buffer[:total_len]
    stream["message_start_seq"] = start_seq + len(message) if buffer else None
    return start_seq, message


def append_http1_payload(stream: dict[str, Any], tcp_seq: int, payload: bytes, seq_advance: int) -> None:
    expected = stream.get("expected_seq")
    out_of_order = stream["out_of_order"]
    buffer = stream["buffer"]

    if expected is None:
        if not is_http_start(payload):
            return
        buffer.clear()
        out_of_order.clear()
        buffer.extend(payload)
        stream["expected_seq"] = tcp_seq + seq_advance
        stream["message_start_seq"] = tcp_seq
        return

    if not buffer and is_http_start(payload):
        out_of_order.clear()
        buffer.extend(payload)
        stream["expected_seq"] = tcp_seq + seq_advance
        stream["message_start_seq"] = tcp_seq
        return

    if tcp_seq == expected:
        if not buffer and is_http_start(payload):
            stream["message_start_seq"] = tcp_seq
        buffer.extend(payload)
        stream["expected_seq"] = expected + seq_advance
    elif tcp_seq > expected:
        out_of_order[tcp_seq] = (payload, seq_advance)
    elif is_http_start(payload):
        buffer.clear()
        out_of_order.clear()
        buffer.extend(payload)
        stream["expected_seq"] = tcp_seq + seq_advance
        stream["message_start_seq"] = tcp_seq
    else:
        already_seen = expected - tcp_seq
        if 0 <= already_seen < len(payload):
            buffer.extend(payload[already_seen:])
            stream["expected_seq"] = expected + seq_advance

    while True:
        expected = stream.get("expected_seq")
        if expected not in out_of_order:
            break
        chunk, chunk_advance = out_of_order.pop(expected)
        buffer.extend(chunk)
        stream["expected_seq"] = expected + chunk_advance


def observation_from_payload(
    row: dict[str, str],
    payload: dict[str, Any],
    msg_type: str,
    tcp_seq: int | str,
) -> dict[str, Any]:
    src = endpoint(row, "src")
    dst = endpoint(row, "dst")
    payload_norm = stable_payload_json(payload)
    payload_sig = hashlib.blake2s(payload_norm.encode("utf-8"), digest_size=12).hexdigest()
    direction = str(row.get("direction", "")).strip().upper()
    ts = row.get("timestamp", "")
    return {
        "msg_type": msg_type,
        "src": src,
        "dst": dst,
        "conn": conn_key(src, dst),
        "payload": payload,
        "payload_sig": payload_sig,
        "out_ts": ts if direction == "OUT" else "",
        "in_ts": ts if direction == "IN" else "",
        "any_ts": ts,
        "row_count": 1,
        "tcp_seq": str(tcp_seq),
    }


def raw_rows_to_observations(raw_rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    streams: dict[tuple[Any, ...], dict[str, Any]] = {}
    observations: list[dict[str, Any]] = []

    for row in sorted(
        raw_rows,
        key=lambda item: (
            parse_time(item.get("timestamp", "")) or datetime.max,
            item.get("src_ip", ""),
            item.get("src_port", ""),
            item.get("dst_ip", ""),
            item.get("dst_port", ""),
            item.get("direction", ""),
            item.get("tcp_seq", ""),
        ),
    ):
        payload = raw_payload_bytes(row)
        if not payload:
            continue
        try:
            tcp_seq = int(row.get("tcp_seq", "") or "0")
        except ValueError:
            continue

        first_segment_payload = decode_http_payload(payload)
        if first_segment_payload is not None:
            msg_type = message_type(first_segment_payload)
            if msg_type:
                observations.append(observation_from_payload(row, first_segment_payload, msg_type, tcp_seq))

        stream_key = (
            row.get("src_ip", ""),
            row.get("src_port", ""),
            row.get("dst_ip", ""),
            row.get("dst_port", ""),
            row.get("direction", ""),
        )
        stream = streams.setdefault(
            stream_key,
            {
                "buffer": bytearray(),
                "expected_seq": None,
                "message_start_seq": None,
                "out_of_order": {},
            },
        )
        append_http1_payload(stream, tcp_seq, payload, tcp_seq_advance(row, payload))
        while True:
            completed = take_complete_http1_message(stream)
            if completed is None:
                break
            start_seq, message_bytes = completed
            decoded = decode_http_payload(message_bytes)
            if decoded is None:
                continue
            msg_type = message_type(decoded)
            if msg_type:
                observations.append(observation_from_payload(row, decoded, msg_type, start_seq))

    return observations


def h2_flow_key(row: dict[str, str]) -> tuple[str, str]:
    return endpoint(row, "src"), endpoint(row, "dst")


def h2_call_key(client: str, server: str, stream_id: int) -> tuple[tuple[tuple[str, int], tuple[str, int]], int]:
    return conn_key(client, server), stream_id


def h2_is_service_port(port: int) -> bool:
    return 0 < port < 32768


def parse_h2_frames_from_stream(
    stream: dict[str, Any],
    row: dict[str, str],
    payload: bytes,
    tcp_seq: int,
) -> list[dict[str, Any]]:
    frames: list[dict[str, Any]] = []
    buffer = stream["buffer"]
    expected = stream.get("expected_seq")
    seq_advance = tcp_seq_advance(row, payload)

    if expected is None:
        if not likely_http2_frame(payload):
            return frames
        buffer.clear()
        buffer.extend(payload)
        stream["expected_seq"] = tcp_seq + seq_advance
    elif tcp_seq == expected:
        buffer.extend(payload)
        stream["expected_seq"] = expected + seq_advance
    elif tcp_seq < expected:
        already_seen = expected - tcp_seq
        if 0 <= already_seen < len(payload):
            buffer.extend(payload[already_seen:])
            stream["expected_seq"] = expected + seq_advance
        else:
            return frames
    elif likely_http2_frame(payload):
        buffer.clear()
        buffer.extend(payload)
        stream["expected_seq"] = tcp_seq + seq_advance
    else:
        return frames

    if buffer.startswith(HTTP2_PREFACE):
        del buffer[:len(HTTP2_PREFACE)]

    while len(buffer) >= 9:
        frame_len = int.from_bytes(buffer[0:3], "big")
        frame_type = buffer[3]
        flags = buffer[4]
        stream_id = int.from_bytes(buffer[5:9], "big") & 0x7FFFFFFF
        total_len = 9 + frame_len
        if frame_len > 16 * 1024 * 1024:
            buffer.clear()
            stream["expected_seq"] = None
            break
        if len(buffer) < total_len:
            break
        frame_payload = bytes(buffer[9:total_len])
        del buffer[:total_len]
        frames.append({
            "timestamp": row.get("timestamp", ""),
            "src": endpoint(row, "src"),
            "dst": endpoint(row, "dst"),
            "frame_type": frame_type,
            "flags": flags,
            "stream_id": stream_id,
            "payload": frame_payload,
        })

    return frames


def decode_h2_data_payload(payload: bytes) -> str:
    if not payload:
        return ""
    return payload.decode("utf-8", errors="replace")


def parse_json_object(text: str) -> Any:
    text = (text or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def h2_body_id(value: Any) -> int | None:
    if isinstance(value, dict):
        raw_id = value.get("id")
        if isinstance(raw_id, int):
            return raw_id
        if isinstance(raw_id, str) and raw_id.isdigit():
            return int(raw_id)
    return None


def h2_request_path_from_body(body_obj: Any) -> str:
    if not isinstance(body_obj, dict):
        return "/"
    book_id = h2_body_id(body_obj)
    suffix = str(book_id if book_id is not None else 0)
    if body_obj.get("service") == "bookinfo-http2-productpage":
        return f"/productpage?id={suffix}"
    if "reviews" in body_obj and "ratings" in body_obj:
        return f"/reviews/{suffix}"
    if "ratings" in body_obj and "source" in body_obj:
        return f"/ratings/{suffix}"
    if "author" in body_obj or "ISBN-10" in body_obj or "ISBN-13" in body_obj:
        return f"/details/{suffix}"
    return f"/{suffix}"


def finalize_h2c_calls(calls: dict[tuple[Any, ...], dict[str, Any]]) -> list[dict[str, Any]]:
    finalized: list[dict[str, Any]] = []
    for call in calls.values():
        body_text = "".join(call.pop("_res_body_chunks", []))
        body_obj = parse_json_object(body_text)
        book_id = h2_body_id(body_obj)
        if book_id is None:
            continue
        trace_id = f"h2c-book-{book_id:08d}"
        stream_material = "|".join([
            trace_id,
            call.get("client", ""),
            call.get("server", ""),
            str(call.get("stream_id", "")),
        ])
        call["trace_id"] = trace_id
        call["span_id"] = hashlib.blake2s(stream_material.encode("utf-8"), digest_size=8).hexdigest()
        call["parent_span_id"] = ""
        request_path = h2_request_path_from_body(body_obj)
        call["req_data"] = [{
            "method": "GET",
            "url": request_path,
            "paras": request_path.split("?", 1)[1] if "?" in request_path else "",
        }]
        call["res_data"] = [{"status": "200", "body": body_text}]
        call["req_headers"] = {":method": "GET", ":path": request_path}
        call["res_headers"] = {":status": "200"}
        finalized.append(call)
    return finalized


def raw_rows_to_h2c_calls(raw_rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    deduped_rows: dict[tuple[str, str, str, str], dict[str, str]] = {}
    for row in raw_rows:
        payload = raw_payload_bytes(row)
        if not payload:
            continue
        key = (
            endpoint(row, "src"),
            endpoint(row, "dst"),
            row.get("tcp_seq", ""),
            row.get("payload", ""),
        )
        deduped_rows.setdefault(key, row)

    streams: dict[tuple[str, str], dict[str, Any]] = {}
    calls: dict[tuple[Any, ...], dict[str, Any]] = {}
    frame_count = 0
    data_frame_count = 0

    for row in sorted(
        deduped_rows.values(),
        key=lambda item: (
            parse_time(item.get("timestamp", "")) or datetime.max,
            item.get("src_ip", ""),
            item.get("src_port", ""),
            item.get("dst_ip", ""),
            item.get("dst_port", ""),
            item.get("tcp_seq", ""),
        ),
    ):
        payload = raw_payload_bytes(row)
        if not payload:
            continue
        try:
            tcp_seq = int(row.get("tcp_seq", "") or "0")
        except ValueError:
            continue

        stream = streams.setdefault(h2_flow_key(row), {"buffer": bytearray(), "expected_seq": None})
        frames = parse_h2_frames_from_stream(stream, row, payload, tcp_seq)
        frame_count += len(frames)
        for frame in frames:
            stream_id = int(frame["stream_id"])
            if stream_id <= 0:
                continue
            src = frame["src"]
            dst = frame["dst"]
            src_port = endpoint_tuple(src)[1]
            dst_port = endpoint_tuple(dst)[1]
            if frame["frame_type"] == 0x1 and h2_is_service_port(dst_port):
                key = h2_call_key(src, dst, stream_id)
                calls.setdefault(key, {
                    "protocol_type": HTTP2_PROTOCOL_TYPE,
                    "client": src,
                    "server": dst,
                    "stream_id": str(stream_id),
                    "trace_id": "",
                    "span_id": "",
                    "parent_span_id": "",
                    "req_out_time": "",
                    "req_in_time": frame["timestamp"],
                    "req_ts": frame["timestamp"],
                    "res_out_time": "",
                    "res_in_time": "",
                    "res_ts": "",
                    "req_headers": {},
                    "res_headers": {},
                    "req_data": [],
                    "res_data": [],
                    "_res_body_chunks": [],
                })
            elif frame["frame_type"] == 0x1 and h2_is_service_port(src_port):
                key = h2_call_key(dst, src, stream_id)
                call = calls.setdefault(key, {
                    "protocol_type": HTTP2_PROTOCOL_TYPE,
                    "client": dst,
                    "server": src,
                    "stream_id": str(stream_id),
                    "trace_id": "",
                    "span_id": "",
                    "parent_span_id": "",
                    "req_out_time": "",
                    "req_in_time": "",
                    "req_ts": frame["timestamp"],
                    "res_out_time": frame["timestamp"],
                    "res_in_time": "",
                    "res_ts": frame["timestamp"],
                    "req_headers": {},
                    "res_headers": {},
                    "req_data": [],
                    "res_data": [],
                    "_res_body_chunks": [],
                })
                call["res_out_time"] = earliest_ts(call.get("res_out_time", ""), frame["timestamp"]) or frame["timestamp"]
                call["res_ts"] = earliest_ts(call.get("res_ts", ""), frame["timestamp"]) or frame["timestamp"]
            elif frame["frame_type"] == 0x0 and h2_is_service_port(src_port):
                key = h2_call_key(dst, src, stream_id)
                call = calls.get(key)
                if call is None:
                    continue
                data_frame_count += 1
                text = decode_h2_data_payload(frame["payload"])
                if text:
                    call["_res_body_chunks"].append(text)
                call["res_out_time"] = earliest_ts(call.get("res_out_time", ""), frame["timestamp"]) or frame["timestamp"]
                call["res_ts"] = earliest_ts(call.get("res_ts", ""), frame["timestamp"]) or frame["timestamp"]

    finalized = finalize_h2c_calls(calls)
    if frame_count:
        print(f"eBPF decoded HTTP/2 frames: {frame_count}")
        print(f"eBPF decoded HTTP/2 response DATA frames: {data_frame_count}")
        print(f"paired HTTP/2 h2c calls: {len(finalized)}")
    return finalized


def parse_tls_pid_endpoint_map(values: list[str]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for value in values:
        for item in str(value).split(","):
            item = item.strip()
            if not item or "=" not in item:
                continue
            pid, endpoint_value = item.split("=", 1)
            pid = pid.strip()
            endpoint_value = endpoint_value.strip()
            if pid and endpoint_value:
                mapping[pid] = endpoint_value
    return mapping


def host_header_endpoint(headers: dict[str, str]) -> str:
    host = header_value(headers, "host").strip()
    if not host:
        return ""
    if ":" not in host:
        return f"{host}:443"
    return host


def synthetic_trace_from_http_payload(payload: dict[str, Any]) -> tuple[str, str, str]:
    headers = payload.get("headers") if isinstance(payload.get("headers"), dict) else {}
    trace_id, span_id, parent_span_id = extract_trace_from_headers(headers)
    if trace_id:
        return trace_id, span_id, parent_span_id

    book_id = business_id_from_http_payload(payload)
    if book_id is not None:
        trace_id = f"tls-book-{book_id:08d}"
        url = str(payload.get("url", "") or "")
        paras = str(payload.get("paras", "") or "")
        body = str(payload.get("body", "") or "")
        span_material = f"{trace_id}|{url}|{paras}|{body[:128]}"
        span_id = hashlib.blake2s(span_material.encode("utf-8"), digest_size=8).hexdigest()
        return trace_id, span_id, ""
    return "", "", ""


def business_id_from_http_payload(payload: dict[str, Any]) -> int | None:
    candidates = []
    url = str(payload.get("url", "") or "")
    paras = str(payload.get("paras", "") or "")
    if url:
        candidates.append(url)
    if paras:
        candidates.append(paras)
    for candidate in candidates:
        for pattern in (r"(?:^|[?&])id=(\d+)(?:$|&)", r"/(?:productpage|details|reviews|ratings)/(\d+)(?:$|[/?#])"):
            m = re.search(pattern, candidate)
            if m:
                return int(m.group(1))

    body_obj = parse_json_object(str(payload.get("body", "") or ""))
    return h2_body_id(body_obj)


def tls_response_is_likely_root(payload: dict[str, Any], server_endpoint: str) -> bool:
    body_obj = parse_json_object(str(payload.get("body", "") or ""))
    if not isinstance(body_obj, dict):
        return False
    endpoint = server_endpoint.lower()
    if "productpage" in endpoint or "frontend" in endpoint:
        return True
    return "title" in body_obj and ("details" in body_obj or "reviews" in body_obj)


def synthetic_root_request_data(payload: dict[str, Any]) -> dict[str, Any]:
    book_id = business_id_from_http_payload(payload)
    if book_id is None:
        return {"method": "GET", "url": "/productpage"}
    return {"method": "GET", "url": "/productpage", "paras": f"id={book_id}"}


def tls_request_is_external_root(payload: dict[str, Any], server_endpoint: str) -> bool:
    headers = payload.get("headers") if isinstance(payload.get("headers"), dict) else {}
    host = host_header_endpoint(headers)
    if not host:
        return False
    host_name, _, host_port = host.rpartition(":")
    server_name, _, server_port = server_endpoint.rpartition(":")
    if host_name in {"127.0.0.1", "localhost", "::1"}:
        return True
    return bool(host_port and server_port and host_port != server_port and host_name != server_name)


def tls_rows_to_messages(tls_rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    streams: dict[tuple[str, str, str], dict[str, Any]] = {}
    messages: list[dict[str, Any]] = []

    for row in sorted(
        tls_rows,
        key=lambda item: (
            parse_time(item.get("timestamp", "")) or datetime.max,
            item.get("pid", ""),
            item.get("tid", ""),
            item.get("ssl", ""),
            item.get("direction", ""),
        ),
    ):
        payload = raw_payload_bytes(row)
        if not payload:
            continue
        direction = str(row.get("direction", "")).strip().upper()
        stream_key = (row.get("pid", ""), row.get("ssl", ""), direction)
        stream = streams.setdefault(stream_key, {"buffer": bytearray(), "message_start_ts": ""})
        buffer = stream["buffer"]

        if not buffer and not is_http_start(payload):
            continue
        if not buffer:
            stream["message_start_ts"] = row.get("timestamp", "")
        buffer.extend(payload)

        while True:
            completed = take_complete_http1_message(stream)
            if completed is None:
                break
            _start_seq, message_bytes = completed
            decoded = decode_http_payload(message_bytes)
            if decoded is None:
                continue
            msg_type = message_type(decoded)
            if msg_type:
                messages.append({
                    "msg_type": msg_type,
                    "payload": decoded,
                    "pid": row.get("pid", ""),
                    "tid": row.get("tid", ""),
                    "ssl": row.get("ssl", ""),
                    "direction": direction,
                    "any_ts": stream.get("message_start_ts") or row.get("timestamp", ""),
                    "row": row,
                })
            if buffer:
                stream["message_start_ts"] = row.get("timestamp", "")
    return messages


def build_tls_calls(tls_rows: list[dict[str, str]], pid_endpoint_map: dict[str, str]) -> list[dict[str, Any]]:
    messages = tls_rows_to_messages(tls_rows)
    pending_by_stream: dict[tuple[str, str, str], deque[dict[str, Any]]] = defaultdict(deque)
    pending_by_server_trace: dict[tuple[str, str], deque[dict[str, Any]]] = defaultdict(deque)
    pending_by_server: dict[str, deque[dict[str, Any]]] = defaultdict(deque)
    calls: list[dict[str, Any]] = []
    stream_seq = 0
    orphan_responses = 0
    cross_process_responses = 0
    synthetic_root_responses = 0

    for message in messages:
        payload = message["payload"]
        direction = message["direction"]
        pid = str(message.get("pid", ""))
        self_endpoint = pid_endpoint_map.get(pid, f"pid-{pid}:0")
        headers = payload.get("headers") if isinstance(payload.get("headers"), dict) else {}
        host_endpoint = host_header_endpoint(headers)

        if message["msg_type"] == "Request":
            keep_request = False
            if direction == "WRITE":
                client = self_endpoint
                server = host_endpoint or "unknown:0"
                keep_request = True
                response_direction = "READ"
            elif direction == "READ" and tls_request_is_external_root(payload, self_endpoint):
                client = host_endpoint or "external:0"
                server = self_endpoint
                keep_request = True
                response_direction = "WRITE"
            else:
                continue

            if not keep_request:
                continue

            trace_id, span_id, parent_span_id = synthetic_trace_from_http_payload(payload)
            if not trace_id:
                continue

            stream_seq += 1
            call = {
                "protocol_type": HTTP1_PROTOCOL_TYPE,
                "client": client,
                "server": server,
                "stream_id": f"tls-{stream_seq}",
                "trace_id": trace_id,
                "span_id": span_id or hashlib.blake2s(f"{trace_id}|{stream_seq}".encode("utf-8"), digest_size=8).hexdigest(),
                "parent_span_id": parent_span_id,
                "req_out_time": message["any_ts"] if direction == "WRITE" else "",
                "req_in_time": message["any_ts"] if direction == "READ" else "",
                "req_ts": message["any_ts"],
                "res_out_time": "",
                "res_in_time": "",
                "res_ts": "",
                "req_headers": dict(headers),
                "res_headers": {},
                "req_data": [request_data_from_payload(payload)],
                "res_data": [],
            }
            calls.append(call)
            pending_by_stream[(pid, message["ssl"], response_direction)].append(call)
            if direction == "WRITE":
                pending_by_server_trace[(server, trace_id)].append(call)
                pending_by_server[server].append(call)
            continue

        call = None
        pending = pending_by_stream.get((pid, message["ssl"], direction))
        if pending:
            call = pending.popleft()
        elif direction == "WRITE":
            response_trace_id, _span_id, _parent_span_id = synthetic_trace_from_http_payload(payload)
            if response_trace_id:
                pending_trace = pending_by_server_trace.get((self_endpoint, response_trace_id))
                if pending_trace:
                    call = pending_trace.popleft()
            if call is None:
                pending_server = pending_by_server.get(self_endpoint)
                if pending_server:
                    while pending_server and parse_time(pending_server[0].get("req_ts", "")) and parse_time(pending_server[0].get("req_ts", "")) > (parse_time(message["any_ts"]) or datetime.min):
                        pending_server.popleft()
                    if pending_server:
                        call = pending_server.popleft()
            if call is not None:
                cross_process_responses += 1

        if call is None:
            if direction == "WRITE" and tls_response_is_likely_root(payload, self_endpoint):
                trace_id, span_id, parent_span_id = synthetic_trace_from_http_payload(payload)
                if trace_id:
                    stream_seq += 1
                    response_headers = payload.get("headers") if isinstance(payload.get("headers"), dict) else {}
                    res_data = response_data_from_payload(payload)
                    calls.append({
                        "protocol_type": HTTP1_PROTOCOL_TYPE,
                        "client": "external:0",
                        "server": self_endpoint,
                        "stream_id": f"tls-root-{stream_seq}",
                        "trace_id": trace_id,
                        "span_id": span_id,
                        "parent_span_id": parent_span_id,
                        "req_out_time": message["any_ts"],
                        "req_in_time": message["any_ts"],
                        "req_ts": message["any_ts"],
                        "res_out_time": message["any_ts"],
                        "res_in_time": message["any_ts"],
                        "res_ts": message["any_ts"],
                        "req_headers": {},
                        "res_headers": dict(response_headers),
                        "req_data": [synthetic_root_request_data(payload)],
                        "res_data": [res_data] if res_data else [],
                    })
                    synthetic_root_responses += 1
                    continue
            orphan_responses += 1
            continue

        if direction == "WRITE":
            call["res_out_time"] = message["any_ts"]
        else:
            call["res_in_time"] = message["any_ts"]
        call["res_ts"] = message["any_ts"]
        response_headers = payload.get("headers") if isinstance(payload.get("headers"), dict) else {}
        call["res_headers"].update(response_headers)
        res_data = response_data_from_payload(payload)
        if res_data:
            call["res_data"].append(res_data)

    print(f"TLS plaintext rows: {len(tls_rows)}")
    print(f"TLS decoded HTTP messages: {len(messages)}")
    print(f"paired TLS HTTP/1.1 calls: {len(calls)}")
    if cross_process_responses:
        print(f"TLS cross-process WRITE responses paired: {cross_process_responses}")
    if synthetic_root_responses:
        print(f"TLS synthetic root calls: {synthetic_root_responses}")
    if orphan_responses:
        print(f"TLS orphan responses dropped: {orphan_responses}")
    return calls


def payload_richness(payload: dict[str, Any]) -> tuple[int, int]:
    body = payload.get("body", "")
    headers = payload.get("headers")
    header_count = len(headers) if isinstance(headers, dict) else 0
    return (len(str(body)), header_count)


def dedupe_observations(input_csv: str) -> list[dict[str, Any]]:
    observations: dict[tuple[Any, ...], dict[str, Any]] = {}
    raw_rows = 0
    skipped_rows = 0
    raw_tcp_rows: list[dict[str, str]] = []

    for row in read_capture_rows(input_csv):
        raw_rows += 1
        row_type = str(row.get("type", "")).strip().lower()
        if row_type in {"tcp", "raw", "packet"}:
            raw_tcp_rows.append(row)
            continue
        if row_type not in {"http", "http/1.1", "http1", "http1.1"}:
            skipped_rows += 1
            continue

        payload = parse_payload(row.get("payload", ""))
        if payload is None:
            skipped_rows += 1
            continue

        msg_type = message_type(payload)
        if msg_type is None:
            skipped_rows += 1
            continue

        obs = observation_from_payload(row, payload, msg_type, row.get("tcp_seq", ""))
        key = (obs["msg_type"], obs["src"], obs["dst"], obs["tcp_seq"])
        if key not in observations:
            observations[key] = {**obs, "out_ts": "", "in_ts": "", "any_ts": "", "row_count": 0}
        obs = observations[key]
        if payload_richness(payload) > payload_richness(obs["payload"]):
            obs["payload"] = payload
            obs["payload_sig"] = hashlib.blake2s(
                stable_payload_json(payload).encode("utf-8"),
                digest_size=12,
            ).hexdigest()
        direction = str(row.get("direction", "")).strip().upper()
        ts = row.get("timestamp", "")
        if direction == "OUT":
            obs["out_ts"] = earliest_ts(obs["out_ts"], ts) or ts
        elif direction == "IN":
            obs["in_ts"] = earliest_ts(obs["in_ts"], ts) or ts
        obs["any_ts"] = earliest_ts(obs["any_ts"], ts) or ts
        obs["row_count"] += 1

    old_decoded_count = len(observations)
    raw_decoded = raw_rows_to_observations(raw_tcp_rows)
    for decoded_obs in raw_decoded:
        key = (
            decoded_obs["msg_type"],
            decoded_obs["src"],
            decoded_obs["dst"],
            decoded_obs["tcp_seq"],
        )
        if key not in observations:
            observations[key] = {
                **decoded_obs,
                "out_ts": "",
                "in_ts": "",
                "any_ts": "",
                "row_count": 0,
            }
        obs = observations[key]
        if payload_richness(decoded_obs["payload"]) > payload_richness(obs["payload"]):
            obs["payload"] = decoded_obs["payload"]
            obs["payload_sig"] = decoded_obs["payload_sig"]
        obs["out_ts"] = earliest_ts(obs["out_ts"], decoded_obs["out_ts"]) or decoded_obs["out_ts"]
        obs["in_ts"] = earliest_ts(obs["in_ts"], decoded_obs["in_ts"]) or decoded_obs["in_ts"]
        obs["any_ts"] = earliest_ts(obs["any_ts"], decoded_obs["any_ts"]) or decoded_obs["any_ts"]
        obs["row_count"] += decoded_obs.get("row_count", 1)

    print(f"eBPF raw rows: {raw_rows}")
    print(f"eBPF raw TCP rows: {len(raw_tcp_rows)}")
    print(f"eBPF decoded HTTP observations: {len(raw_decoded) + old_decoded_count}")
    print(f"eBPF non-HTTP/invalid rows skipped: {skipped_rows}")
    print(f"deduplicated HTTP messages: {len(observations)}")
    return sorted(
        observations.values(),
        key=lambda item: (
            parse_time(item.get("any_ts", "")) or datetime.max,
            item["msg_type"] != "Request",
            item["src"],
            item["dst"],
        ),
    )


def request_data_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for key in ("method", "url", "paras", "body"):
        if key in payload and payload[key] not in (None, ""):
            data[key] = payload[key]
    return data


def response_data_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for key in ("status", "body"):
        if key in payload and payload[key] not in (None, ""):
            data[key] = payload[key]
    return data


def is_mysql_com_query(payload: bytes) -> bool:
    if len(payload) < 6:
        return False
    packet_len = payload[0] | (payload[1] << 8) | (payload[2] << 16)
    if packet_len <= 1 or packet_len + 4 > len(payload):
        return False
    return payload[4] == 0x03


def mysql_query_from_payload(payload: bytes) -> str:
    packet_len = payload[0] | (payload[1] << 8) | (payload[2] << 16)
    query_bytes = payload[5:4 + packet_len]
    return query_bytes.decode("utf-8", errors="replace").strip()


def mysql_payload_to_text(payload: bytes) -> str:
    chunks: list[str] = []
    pos = 0
    while pos + 4 <= len(payload):
        packet_len = payload[pos] | (payload[pos + 1] << 8) | (payload[pos + 2] << 16)
        if packet_len <= 0 or pos + 4 + packet_len > len(payload):
            break
        body = payload[pos + 4:pos + 4 + packet_len]
        text = "".join(chr(b) if 32 <= b <= 126 else " " for b in body)
        text = " ".join(text.split())
        if text:
            chunks.append(text)
        pos += 4 + packet_len
    if not chunks:
        text = "".join(chr(b) if 32 <= b <= 126 else " " for b in payload)
        return " ".join(text.split())
    return " | ".join(chunks)


def read_i32_le(data: bytes, pos: int) -> int | None:
    if pos + 4 > len(data):
        return None
    return int.from_bytes(data[pos:pos + 4], "little", signed=True)


def read_i64_le(data: bytes, pos: int) -> int | None:
    if pos + 8 > len(data):
        return None
    return int.from_bytes(data[pos:pos + 8], "little", signed=True)


def read_f64_le(data: bytes, pos: int) -> float | None:
    if pos + 8 > len(data):
        return None
    import struct
    return struct.unpack("<d", data[pos:pos + 8])[0]


def read_cstring(data: bytes, pos: int, end: int | None = None) -> tuple[str, int]:
    limit = len(data) if end is None else min(end, len(data))
    nul = data.find(b"\x00", pos, limit)
    if nul < 0:
        return data[pos:limit].decode("utf-8", errors="replace"), limit
    return data[pos:nul].decode("utf-8", errors="replace"), nul + 1


def parse_bson_value(data: bytes, pos: int, end: int, value_type: int, depth: int) -> tuple[Any, int]:
    if depth <= 0 or pos >= end:
        return None, end
    if value_type == 0x01:
        value = read_f64_le(data, pos)
        return value, min(pos + 8, end)
    if value_type == 0x02:
        strlen = read_i32_le(data, pos)
        if strlen is None or strlen <= 0:
            return "", end
        start = pos + 4
        stop = min(start + strlen - 1, end)
        return data[start:stop].decode("utf-8", errors="replace"), min(start + strlen, end)
    if value_type in (0x03, 0x04):
        value, next_pos = parse_bson_document(data, pos, depth - 1)
        return value, next_pos
    if value_type == 0x05:
        length = read_i32_le(data, pos)
        if length is None or length < 0:
            return "", end
        subtype_pos = pos + 4
        value_start = subtype_pos + 1
        value_end = min(value_start + length, end)
        return data[value_start:value_end].hex(), value_end
    if value_type == 0x07:
        return data[pos:min(pos + 12, end)].hex(), min(pos + 12, end)
    if value_type == 0x08:
        return bool(data[pos]) if pos < end else None, min(pos + 1, end)
    if value_type == 0x09:
        value = read_i64_le(data, pos)
        return value, min(pos + 8, end)
    if value_type == 0x0A:
        return None, pos
    if value_type == 0x10:
        value = read_i32_le(data, pos)
        return value, min(pos + 4, end)
    if value_type == 0x12:
        value = read_i64_le(data, pos)
        return value, min(pos + 8, end)
    return None, end


def parse_bson_document(data: bytes, pos: int, depth: int = 4) -> tuple[dict[str, Any], int]:
    if pos + 4 > len(data) or depth <= 0:
        return {}, len(data)
    doc_len = read_i32_le(data, pos)
    if doc_len is None or doc_len < 5:
        return {}, len(data)
    end = min(pos + doc_len, len(data))
    cur = pos + 4
    out: dict[str, Any] = {}
    while cur < end - 1:
        value_type = data[cur]
        cur += 1
        if value_type == 0:
            break
        key, cur = read_cstring(data, cur, end)
        if not key:
            break
        value, cur = parse_bson_value(data, cur, end, value_type, depth)
        if value is not None:
            out[key] = value
    return out, end


def compact_json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def printable_payload_text(payload: bytes) -> str:
    text = "".join(chr(b) if 32 <= b <= 126 else " " for b in payload)
    return " ".join(text.split())


MONGO_OPCODES = {1, 2004, 2013}


def parse_mongo_messages(payload: bytes) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    pos = 0
    while pos + 16 <= len(payload):
        message_len = read_i32_le(payload, pos)
        request_id = read_i32_le(payload, pos + 4)
        response_to = read_i32_le(payload, pos + 8)
        opcode = read_i32_le(payload, pos + 12)
        if (
            message_len is None
            or request_id is None
            or response_to is None
            or opcode not in MONGO_OPCODES
            or message_len < 16
        ):
            break
        available_end = min(pos + message_len, len(payload))
        body = payload[pos + 16:available_end]
        docs: list[Any] = []
        collection = ""
        command = ""

        if opcode == 2004 and len(body) >= 12:
            collection, after_collection = read_cstring(body, 4)
            doc_pos = after_collection + 8
            query_doc, _ = parse_bson_document(body, doc_pos)
            if query_doc:
                docs.append(query_doc)
                command = next(iter(query_doc), "")
        elif opcode == 1 and len(body) >= 20:
            doc_pos = 20
            while doc_pos + 4 <= len(body):
                doc, next_pos = parse_bson_document(body, doc_pos)
                if not doc or next_pos <= doc_pos:
                    break
                docs.append(doc)
                doc_pos = next_pos
        elif opcode == 2013 and len(body) >= 5:
            cur = 4
            while cur < len(body):
                kind = body[cur]
                cur += 1
                if kind == 0:
                    doc, next_pos = parse_bson_document(body, cur)
                    if doc:
                        docs.append(doc)
                        command = next(iter(doc), command)
                    if next_pos <= cur:
                        break
                    cur = next_pos
                elif kind == 1 and cur + 4 <= len(body):
                    section_size = read_i32_le(body, cur)
                    if section_size is None or section_size <= 4:
                        break
                    section_end = min(cur + section_size, len(body))
                    identifier, doc_pos = read_cstring(body, cur + 4, section_end)
                    collection = collection or identifier
                    while doc_pos + 4 <= section_end:
                        doc, next_pos = parse_bson_document(body, doc_pos)
                        if not doc or next_pos <= doc_pos:
                            break
                        docs.append(doc)
                        doc_pos = next_pos
                    cur = section_end
                else:
                    break

        text = compact_json_text(docs) if docs else printable_payload_text(body)
        if text:
            messages.append({
                "request_id": request_id,
                "response_to": response_to,
                "opcode": opcode,
                "collection": collection,
                "command": command,
                "text": text,
            })

        if message_len <= 0 or pos + message_len > len(payload):
            break
        pos += message_len
    return messages


def raw_rows_to_sql_calls(raw_rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    pending_by_conn: dict[tuple[Any, ...], deque[dict[str, Any]]] = defaultdict(deque)
    calls: list[dict[str, Any]] = []
    stream_seq = 0

    for row in sorted(
        raw_rows,
        key=lambda item: (
            parse_time(item.get("timestamp", "")) or datetime.max,
            item.get("src_ip", ""),
            item.get("src_port", ""),
            item.get("dst_ip", ""),
            item.get("dst_port", ""),
            item.get("direction", ""),
            item.get("tcp_seq", ""),
        ),
    ):
        payload = raw_payload_bytes(row)
        if not payload:
            continue
        src = endpoint(row, "src")
        dst = endpoint(row, "dst")
        conn = conn_key(src, dst)
        ts = row.get("timestamp", "")

        if is_mysql_com_query(payload):
            query = mysql_query_from_payload(payload)
            if not query:
                continue
            stream_seq += 1
            call = {
                "protocol_type": "SQL",
                "client": src,
                "server": dst,
                "stream_id": f"sql-{stream_seq}",
                "trace_id": "",
                "span_id": "",
                "parent_span_id": "",
                "req_out_time": ts if str(row.get("direction", "")).strip().upper() == "OUT" else "",
                "req_in_time": ts if str(row.get("direction", "")).strip().upper() == "IN" else "",
                "req_ts": ts,
                "res_out_time": "",
                "res_in_time": "",
                "res_ts": "",
                "req_headers": {},
                "res_headers": {},
                "req_data": [{"query": query}],
                "res_data": [],
            }
            calls.append(call)
            pending_by_conn[conn].append(call)
            continue

        pending = pending_by_conn.get(conn)
        if not pending:
            continue
        matched = None
        for idx, candidate in enumerate(pending):
            if candidate["client"] == dst and candidate["server"] == src:
                matched = candidate
                del pending[idx]
                break
        if matched is None:
            continue
        result_text = mysql_payload_to_text(payload)
        if result_text:
            matched["res_data"].append({"result": result_text})
        direction = str(row.get("direction", "")).strip().upper()
        matched["res_out_time"] = ts if direction == "OUT" else matched["res_out_time"]
        matched["res_in_time"] = ts if direction == "IN" else matched["res_in_time"]
        matched["res_ts"] = ts

    return calls


def raw_rows_to_mongodb_calls(raw_rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    calls_by_key: dict[tuple[Any, ...], dict[str, Any]] = {}
    pending_by_request: dict[tuple[Any, ...], dict[str, Any]] = {}
    stream_seq = 0

    for row in sorted(
        raw_rows,
        key=lambda item: (
            parse_time(item.get("timestamp", "")) or datetime.max,
            item.get("src_ip", ""),
            item.get("src_port", ""),
            item.get("dst_ip", ""),
            item.get("dst_port", ""),
            item.get("direction", ""),
            item.get("tcp_seq", ""),
        ),
    ):
        payload = raw_payload_bytes(row)
        if not payload:
            continue
        messages = parse_mongo_messages(payload)
        if not messages:
            continue

        src = endpoint(row, "src")
        dst = endpoint(row, "dst")
        conn = conn_key(src, dst)
        ts = row.get("timestamp", "")
        direction = str(row.get("direction", "")).strip().upper()

        for message in messages:
            if message["response_to"] == 0:
                query_text = message.get("text", "")
                if not query_text:
                    continue
                call_key = (conn, src, dst, message["request_id"], query_text)
                call = calls_by_key.get(call_key)
                if call is None:
                    stream_seq += 1
                    call = {
                        "protocol_type": "MongoDB",
                        "client": src,
                        "server": dst,
                        "stream_id": f"mongodb-{stream_seq}",
                        "trace_id": "",
                        "span_id": "",
                        "parent_span_id": "",
                        "req_out_time": "",
                        "req_in_time": "",
                        "req_ts": "",
                        "res_out_time": "",
                        "res_in_time": "",
                        "res_ts": "",
                        "req_headers": {},
                        "res_headers": {},
                        "req_data": [{
                            "query": query_text,
                            "collection": message.get("collection", ""),
                            "command": message.get("command", ""),
                        }],
                        "res_data": [],
                    }
                    calls_by_key[call_key] = call
                    pending_by_request[(conn, message["request_id"])] = call
                call["req_out_time"] = earliest_ts(call.get("req_out_time", ""), ts) if direction == "OUT" else call.get("req_out_time", "")
                call["req_in_time"] = earliest_ts(call.get("req_in_time", ""), ts) if direction == "IN" else call.get("req_in_time", "")
                call["req_ts"] = earliest_ts(call.get("req_ts", ""), ts) or ts
                continue

            call = pending_by_request.get((conn, message["response_to"]))
            if call is None:
                continue
            result_text = message.get("text", "")
            if result_text:
                result_entry = {"result": result_text}
                if result_entry not in call["res_data"]:
                    call["res_data"].append(result_entry)
            call["res_out_time"] = earliest_ts(call.get("res_out_time", ""), ts) if direction == "OUT" else call.get("res_out_time", "")
            call["res_in_time"] = earliest_ts(call.get("res_in_time", ""), ts) if direction == "IN" else call.get("res_in_time", "")
            call["res_ts"] = earliest_ts(call.get("res_ts", ""), ts) or ts

    return list(calls_by_key.values())


def make_call(stream_id: int, request: dict[str, Any]) -> dict[str, Any]:
    payload = request["payload"]
    headers = payload.get("headers") if isinstance(payload.get("headers"), dict) else {}
    trace_id, span_id, parent_span_id = extract_trace_from_headers(headers)
    return {
        "protocol_type": HTTP1_PROTOCOL_TYPE,
        "client": request["src"],
        "server": request["dst"],
        "stream_id": str(stream_id),
        "trace_id": trace_id,
        "span_id": span_id,
        "parent_span_id": parent_span_id,
        "req_out_time": request.get("out_ts", ""),
        "req_in_time": request.get("in_ts", ""),
        "req_ts": request.get("out_ts") or request.get("in_ts") or request.get("any_ts", ""),
        "res_out_time": "",
        "res_in_time": "",
        "res_ts": "",
        "req_headers": dict(headers),
        "res_headers": {},
        "req_data": [request_data_from_payload(payload)],
        "res_data": [],
    }


def attach_response(call: dict[str, Any], response: dict[str, Any]) -> None:
    payload = response["payload"]
    headers = payload.get("headers") if isinstance(payload.get("headers"), dict) else {}
    call["res_out_time"] = response.get("out_ts", "")
    call["res_in_time"] = response.get("in_ts", "")
    call["res_ts"] = response.get("out_ts") or response.get("in_ts") or response.get("any_ts", "")
    call["res_headers"].update(headers)
    res_data = response_data_from_payload(payload)
    if res_data:
        call["res_data"].append(res_data)

    if not call.get("trace_id"):
        trace_id, span_id, parent_span_id = extract_trace_from_headers(headers)
        if trace_id:
            call["trace_id"] = trace_id
            call["span_id"] = span_id
            call["parent_span_id"] = parent_span_id


def build_calls(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    pending_by_conn: dict[tuple[Any, ...], deque[dict[str, Any]]] = defaultdict(deque)
    calls: list[dict[str, Any]] = []
    stream_seq = 0
    orphan_responses = 0

    for message in messages:
        if message["msg_type"] == "Request":
            stream_seq += 1
            call = make_call(stream_seq, message)
            calls.append(call)
            pending_by_conn[message["conn"]].append(call)
            continue

        pending = pending_by_conn.get(message["conn"])
        matched = None
        if pending:
            for idx, candidate in enumerate(pending):
                if candidate["client"] == message["dst"] and candidate["server"] == message["src"]:
                    matched = candidate
                    del pending[idx]
                    break
        if matched is None:
            orphan_responses += 1
            continue
        attach_response(matched, message)

    filtered = [
        call
        for call in calls
        if not (is_loopback_endpoint(call.get("client", "")) and is_loopback_endpoint(call.get("server", "")))
    ]
    print(f"paired HTTP/1.1 calls: {len(filtered)}")
    if orphan_responses:
        print(f"orphan responses dropped: {orphan_responses}")
    return filtered


def make_cleaned_row(
    call: dict[str, Any],
    msg_type: str,
    span_kind: str = "",
    span_endpoint: str = "",
    peer_endpoint: str = "",
    span_id: str | None = None,
    parent_span_id: str | None = None,
) -> dict[str, Any]:
    is_request = msg_type == "Request"
    req_data = unique_keep_order([item for item in call.get("req_data", []) if item])
    res_data = unique_keep_order([item for item in call.get("res_data", []) if item])
    network_duration_us = (
        diff_us(call.get("req_out_time", ""), call.get("req_in_time", ""))
        if is_request
        else diff_us(call.get("res_out_time", ""), call.get("res_in_time", ""))
    )
    return {
        "protocol_type": call["protocol_type"],
        "msg_type": msg_type,
        "timestamp": call["req_ts"] if is_request else call["res_ts"],
        "network_duration_us": network_duration_us,
        "client": call["client"],
        "server": call["server"],
        "stream_id": call["stream_id"],
        "trace_id": call["trace_id"],
        "span_id": call["span_id"] if span_id is None else span_id,
        "parent_span_id": call["parent_span_id"] if parent_span_id is None else parent_span_id,
        "span_kind": span_kind,
        "span_endpoint": span_endpoint,
        "peer_endpoint": peer_endpoint,
        "headers": json.dumps(call["req_headers"] if is_request else call["res_headers"], ensure_ascii=False),
        "data": json.dumps(req_data if is_request else res_data, ensure_ascii=False),
    }


def append_request_response_rows(rows: list[dict[str, Any]], call: dict[str, Any], **kwargs: Any) -> None:
    if call["req_ts"] or call["req_headers"] or call.get("req_data"):
        rows.append(make_cleaned_row(call, "Request", **kwargs))
    if call["res_ts"] or call["res_headers"] or call.get("res_data"):
        rows.append(make_cleaned_row(call, "Response", **kwargs))


def build_cleaned_like_rows(calls: list[dict[str, Any]], span_form: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    ordered_calls = sorted(
        calls,
        key=lambda call: (
            parse_time(call.get("req_ts", "")) or datetime.max,
            call.get("stream_id", ""),
        ),
    )

    for call in ordered_calls:
        if str(call.get("protocol_type", "")).lower() in {"db", "sql", "mysql", "postgresql", "postgres", "mongodb", "mongo"}:
            append_request_response_rows(
                rows,
                call,
                span_kind="client",
                span_endpoint=call["client"],
                peer_endpoint=call["server"],
            )
            continue

        if not call.get("trace_id"):
            continue

        if span_form == "rpc":
            span_kind = "client" if call.get("parent_span_id") else "server"
            span_endpoint = call["client"] if span_kind == "client" else call["server"]
            peer_endpoint = call["server"] if span_kind == "client" else call["client"]
            append_request_response_rows(
                rows,
                call,
                span_kind=span_kind,
                span_endpoint=span_endpoint,
                peer_endpoint=peer_endpoint,
            )
            continue

        if span_form != "client-server":
            raise ValueError(f"unsupported span_form: {span_form}")

        if call.get("parent_span_id"):
            append_request_response_rows(
                rows,
                call,
                span_kind="client",
                span_endpoint=call["client"],
                peer_endpoint=call["server"],
                span_id=call["span_id"],
                parent_span_id=call["parent_span_id"],
            )

        server_span_id = call["span_id"] if not call.get("parent_span_id") else synthetic_server_span_id(call)
        server_parent_span_id = call["parent_span_id"] if not call.get("parent_span_id") else call["span_id"]
        append_request_response_rows(
            rows,
            call,
            span_kind="server",
            span_endpoint=call["server"],
            peer_endpoint=call["client"],
            span_id=server_span_id,
            parent_span_id=server_parent_span_id,
        )

    return rows


def filter_complete_trace_rows(
    rows: list[dict[str, Any]],
    expected_count: int,
    keep_incomplete: bool,
) -> tuple[list[dict[str, Any]], int, int]:
    if keep_incomplete:
        return rows, 0, 0

    trace_counter = Counter(row.get("trace_id", "") for row in rows if row.get("trace_id"))
    if expected_count > 0:
        min_valid_count = expected_count
        keep_trace_ids = {tid for tid, count in trace_counter.items() if count == expected_count}
        dropped_trace_ids = sum(1 for count in trace_counter.values() if count != expected_count)
    else:
        counts = sorted(trace_counter.values())
        median_count = counts[len(counts) // 2] if counts else 0
        min_valid_count = int(median_count * 0.75)
        keep_trace_ids = {tid for tid, count in trace_counter.items() if count >= min_valid_count}
        dropped_trace_ids = sum(1 for count in trace_counter.values() if count < min_valid_count)

    kept = [
        row
        for row in rows
        if row.get("trace_id") in keep_trace_ids
        or str(row.get("protocol_type", "")).lower() in {"db", "sql", "mysql", "postgresql", "postgres", "mongodb", "mongo"}
    ]
    return kept, min_valid_count, dropped_trace_ids


def write_cleaned_like(rows: list[dict[str, Any]], output_csv: str) -> None:
    parent = os.path.dirname(output_csv)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in FIELDNAMES})


def main() -> int:
    args = parse_args()
    input_csv = os.path.abspath(args.input)
    output_csv = os.path.abspath(args.cleaned_out)

    if not os.path.exists(input_csv):
        raise FileNotFoundError(f"eBPF raw capture not found: {input_csv}")

    raw_tcp_rows: list[dict[str, str]] = []
    tls_rows: list[dict[str, str]] = []
    for row in read_capture_rows(input_csv):
        row_type = str(row.get("type", "")).strip().lower()
        if row_type in {"tcp", "raw", "packet"}:
            raw_tcp_rows.append(row)
        elif row_type in {"tls_plaintext", "tls"}:
            tls_rows.append(row)

    if tls_rows:
        calls = build_tls_calls(tls_rows, parse_tls_pid_endpoint_map(args.tls_pid_endpoint))
    else:
        messages = dedupe_observations(input_csv)
        calls = build_calls(messages)
        h2c_calls = raw_rows_to_h2c_calls(raw_tcp_rows)
        if h2c_calls:
            calls.extend(h2c_calls)
    if args.enable_db_rows:
        sql_calls = raw_rows_to_sql_calls(raw_tcp_rows)
        if sql_calls:
            print(f"paired SQL calls: {sum(1 for call in sql_calls if call.get('res_ts'))}/{len(sql_calls)}")
            calls.extend(sql_calls)
        mongodb_calls = raw_rows_to_mongodb_calls(raw_tcp_rows)
        if mongodb_calls:
            print(f"paired MongoDB calls: {sum(1 for call in mongodb_calls if call.get('res_ts'))}/{len(mongodb_calls)}")
            calls.extend(mongodb_calls)
    rows = build_cleaned_like_rows(calls, args.span_form)
    kept_rows, min_valid_count, dropped_trace_ids = filter_complete_trace_rows(
        rows,
        expected_count=args.expected_trace_count,
        keep_incomplete=args.keep_incomplete,
    )
    write_cleaned_like(kept_rows, output_csv)

    total_trace_ids = len({row.get("trace_id", "") for row in rows if row.get("trace_id")})
    print(f"span form: {args.span_form}")
    print(f"minimum valid records per trace threshold: {min_valid_count}")
    print(f"kept cleaned rows: {len(kept_rows)}")
    print(f"dropped cleaned rows: {len(rows) - len(kept_rows)}")
    print(f"dropped trace_ids: {dropped_trace_ids}/{total_trace_ids}")
    print(f"saved to {output_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
