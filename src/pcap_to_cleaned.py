#!/usr/bin/env python3
import argparse
import csv
import hashlib
import json
import os
import re
import sys
import struct
import subprocess
from collections import Counter, defaultdict, deque
from datetime import datetime
from urllib.parse import parse_qsl, urlparse


HTTP2_PORTS = [8080, 8081, 8082, 8083, 8084, 8086, 8087]
HTTP1_PORTS = [5000]
HTTP1_PROTOCOL_TYPE = "HTTP/1.1"
HTTP2_PROTOCOL_TYPE = "HTTP/2"
csv.field_size_limit(sys.maxsize)
HTTP1_METHOD_PREFIXES = (
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"PATCH ",
    b"HEAD ",
    b"OPTIONS ",
)
HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
HTTP2_FRAME_TYPES = {0x0, 0x1, 0x4, 0x7, 0x8, 0x9}


def format_ts(epoch_str):
    if not epoch_str:
        return ""
    try:
        ts = datetime.fromtimestamp(float(epoch_str))
        return ts.strftime("%Y-%m-%d %H:%M:%S.%f")
    except ValueError:
        return ""


def split_multi(value):
    if not value:
        return []
    return [x for x in value.split("|") if x != ""]


def parse_header_lines(lines):
    headers = {}
    for line in lines:
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip().replace("\r", "").replace("\n", "")
        v = v.strip().replace("\r", "").replace("\n", "")
        if k:
            headers[k] = v
    return headers


def parse_ports(value, default):
    if value is None:
        return list(default)
    if str(value).strip().lower() == "auto":
        return None
    ports = []
    for item in str(value).split(","):
        item = item.strip()
        if not item:
            continue
        ports.append(int(item))
    return ports


def decode_tcp_payload(payload_hex):
    if not payload_hex:
        return b""
    normalized = payload_hex.replace(":", "").strip()
    if not normalized or len(normalized) % 2 != 0:
        return b""
    try:
        return bytes.fromhex(normalized)
    except ValueError:
        return b""


def infer_protocol_ports(pcap_path):
    cmd = [
        "tshark",
        "-r",
        pcap_path,
        "-Y",
        "tcp.payload",
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-e",
        "tcp.srcport",
        "-e",
        "tcp.dstport",
        "-e",
        "tcp.payload",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "tshark failed while inferring protocol ports")

    http1_ports = set()
    http2_ports = set()
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        src_port, dst_port, payload_hex = parts[:3]
        payload = decode_tcp_payload(payload_hex)
        if not payload:
            continue

        if payload.startswith(HTTP1_METHOD_PREFIXES):
            if dst_port.isdigit():
                http1_ports.add(int(dst_port))
        elif payload.startswith(b"HTTP/1."):
            if src_port.isdigit():
                http1_ports.add(int(src_port))

        if HTTP2_PREFACE in payload:
            if dst_port.isdigit():
                http2_ports.add(int(dst_port))
        elif likely_http2_frame(payload):
            numeric_ports = [int(p) for p in (src_port, dst_port) if p.isdigit()]
            service_ports = [p for p in numeric_ports if p < 32768]
            if service_ports:
                http2_ports.add(min(service_ports))

    http1_ports -= http2_ports
    return sorted(http1_ports), sorted(http2_ports)


def likely_http2_frame(payload):
    if len(payload) < 9:
        return False
    length = int.from_bytes(payload[0:3], "big")
    frame_type = payload[3]
    stream_id = int.from_bytes(payload[5:9], "big") & 0x7FFFFFFF
    if frame_type not in HTTP2_FRAME_TYPES:
        return False
    if length > len(payload) - 9:
        return False
    if frame_type in {0x4, 0x7} and stream_id != 0:
        return False
    return True


def clean_header_value(value):
    return (
        str(value or "")
        .strip()
        .replace("\r", "")
        .replace("\n", "")
        .replace("\\r", "")
        .replace("\\n", "")
    )


def extract_trace_from_headers(headers):
    normalized = {str(hk).lower(): clean_header_value(hv) for hk, hv in headers.items()}

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


def is_truthy_flag(value):
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes"}


def is_http1_event(event):
    return event.get("protocol_type") in {"HTTP", HTTP1_PROTOCOL_TYPE}


def is_http2_event(event):
    return event.get("protocol_type") in {"gRPC", HTTP2_PROTOCOL_TYPE}


def decode_http_body(body_value):
    if not body_value:
        return ""

    raw = str(body_value).strip()
    if not raw:
        return ""

    normalized = raw.replace(" ", "").replace(":", "")
    if len(normalized) % 2 != 0:
        return raw
    if not re.fullmatch(r"[0-9a-fA-F]+", normalized):
        return raw

    try:
        decoded = bytes.fromhex(normalized).decode("utf-8")
        return decoded
    except (ValueError, UnicodeDecodeError):
        return raw


def parse_varint(buf, idx):
    value = 0
    shift = 0
    while idx < len(buf):
        b = buf[idx]
        idx += 1
        value |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return value, idx
        shift += 7
        if shift > 63:
            break
    raise ValueError("invalid varint")


def likely_utf8_text(data):
    if not data:
        return ""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return ""

    if any((ord(ch) < 32 and ch not in "\r\n\t") for ch in text):
        return ""
    return text


def extract_printable_strings(data, min_len=4, max_count=8):
    if not data:
        return []
    found = re.findall(rb"[ -~]{%d,}" % min_len, data)
    out = []
    for s in found:
        try:
            text = s.decode("utf-8", errors="ignore").strip()
        except UnicodeDecodeError:
            continue
        if text:
            out.append(text)
        if len(out) >= max_count:
            break
    return out


def compact_scalar(value):
    if isinstance(value, str):
        s = value.strip()
        if re.fullmatch(r"-?\d+", s):
            try:
                return int(s)
            except ValueError:
                return value
        if re.fullmatch(r"-?\d+\.\d+", s):
            try:
                return float(s)
            except ValueError:
                return value
    return value


def compact_proto_value(value):
    if isinstance(value, list):
        if not value:
            return value

        compacted_items = [compact_proto_value(item) for item in value]

        simple_text_fields = []
        same_field = None
        same_wire_type = None
        compressible = True
        for item in value:
            if not isinstance(item, dict):
                compressible = False
                break
            if set(item.keys()) != {"field", "wire_type", "text"}:
                compressible = False
                break
            if same_field is None:
                same_field = item["field"]
                same_wire_type = item["wire_type"]
            elif item["field"] != same_field or item["wire_type"] != same_wire_type:
                compressible = False
                break
            simple_text_fields.append(compact_scalar(item["text"]))

        if compressible and len(simple_text_fields) > 1:
            return simple_text_fields

        simple_scalar_fields = []
        compressible = True
        for item in value:
            if not isinstance(item, dict):
                compressible = False
                break

            scalar_value = None
            if "text" in item and set(item.keys()) == {"field", "wire_type", "text"}:
                scalar_value = item["text"]
            elif "value_f32" in item and set(item.keys()) == {"field", "wire_type", "value_u32", "value_f32"}:
                scalar_value = item["value_f32"]
            elif "value_f64" in item and set(item.keys()) == {"field", "wire_type", "value_u64", "value_f64"}:
                scalar_value = item["value_f64"]
            elif "value" in item and set(item.keys()) == {"field", "wire_type", "value"}:
                scalar_value = item["value"]
            elif "value_u32" in item and set(item.keys()) == {"field", "wire_type", "value_u32"}:
                scalar_value = item["value_u32"]
            elif "value_u64" in item and set(item.keys()) == {"field", "wire_type", "value_u64"}:
                scalar_value = item["value_u64"]

            if isinstance(scalar_value, (dict, list)) or scalar_value is None:
                compressible = False
                break

            simple_scalar_fields.append(compact_scalar(scalar_value))

        if compressible:
            return simple_scalar_fields
        return compacted_items

    if isinstance(value, dict):
        compacted = {}
        for k, v in value.items():
            if k == "text":
                compacted[k] = compact_scalar(v)
            else:
                compacted[k] = compact_proto_value(v)
        return compacted

    return compact_scalar(value)


def decode_proto_fields(payload, depth=0, max_fields=64):
    if depth > 4 or not payload:
        return []

    idx = 0
    fields = []
    parsed_count = 0
    while idx < len(payload) and parsed_count < max_fields:
        try:
            key, idx = parse_varint(payload, idx)
        except ValueError:
            break
        field_no = key >> 3
        wire_type = key & 0x7
        if field_no == 0:
            break

        item = {"field": field_no, "wire_type": wire_type}
        try:
            if wire_type == 0:
                v, idx = parse_varint(payload, idx)
                item["value"] = v
            elif wire_type == 1:
                if idx + 8 > len(payload):
                    break
                chunk = payload[idx : idx + 8]
                idx += 8
                item["value_u64"] = int.from_bytes(chunk, "little", signed=False)
                item["value_f64"] = struct.unpack("<d", chunk)[0]
            elif wire_type == 2:
                ln, idx = parse_varint(payload, idx)
                if idx + ln > len(payload):
                    break
                chunk = payload[idx : idx + ln]
                idx += ln

                text = likely_utf8_text(chunk)
                if text:
                    item["text"] = text
                else:
                    # Even for large length-delimited fields, try nested protobuf parsing first.
                    # Many gRPC responses are "repeated embedded message" and were previously
                    # reduced to hex_prefix only due the old length threshold.
                    nested_max_fields = max_fields if ln <= 512 else min(max_fields, 48)
                    nested = decode_proto_fields(chunk, depth=depth + 1, max_fields=nested_max_fields)
                    if nested:
                        item["nested"] = nested
                        item["length"] = ln
                    elif ln <= 128:
                        item["hex"] = chunk.hex()
                    else:
                        item["hex_prefix"] = chunk[:64].hex()
                        item["length"] = ln
                        strings = extract_printable_strings(chunk)
                        if strings:
                            item["strings_preview"] = strings
            elif wire_type == 5:
                if idx + 4 > len(payload):
                    break
                chunk = payload[idx : idx + 4]
                idx += 4
                item["value_u32"] = int.from_bytes(chunk, "little", signed=False)
                item["value_f32"] = struct.unpack("<f", chunk)[0]
            else:
                break
        except (ValueError, struct.error):
            break

        fields.append(item)
        parsed_count += 1

    return fields


def decode_grpc_message_payload(raw_message):
    if not raw_message:
        return raw_message

    if isinstance(raw_message, (list, dict)):
        return compact_proto_value(raw_message)

    msg = str(raw_message).strip()
    if len(msg) % 2 != 0 or not re.fullmatch(r"[0-9a-fA-F]+", msg):
        return raw_message

    try:
        payload = bytes.fromhex(msg)
    except ValueError:
        return raw_message

    parsed = compact_proto_value(decode_proto_fields(payload))
    text = likely_utf8_text(payload)

    out = {}
    if text:
        out["utf8"] = text
    if parsed:
        out["proto_fields"] = parsed

    # If binary payload cannot be decoded into meaningful fields/text,
    # keep original value to avoid writing an empty object.
    if text:
        return out if out else raw_message
    if parsed:
        return parsed if isinstance(parsed, list) else out
    return raw_message


def split_h2_header_blocks(names, values):
    pairs = []
    for idx in range(min(len(names), len(values))):
        k = names[idx].strip().replace("\r", "").replace("\n", "")
        v = values[idx].strip().replace("\r", "").replace("\n", "")
        if k:
            pairs.append((k, v))

    if not pairs:
        return []

    blocks = []
    cur = []
    for k, v in pairs:
        # In this capture, each header block starts with :method or :status.
        if k in {":method", ":status"} and cur:
            blocks.append(cur)
            cur = []
        cur.append((k, v))
    if cur:
        blocks.append(cur)

    return blocks


def build_tshark_cmd(pcap_path, http1_ports=None, http2_ports=None):
    cmd = ["tshark", "-r", pcap_path]
    if http1_ports is None:
        http1_ports = HTTP1_PORTS
    if http2_ports is None:
        http2_ports = HTTP2_PORTS

    for port in http1_ports:
        cmd.extend(["-d", f"tcp.port=={port},http"])
    for port in http2_ports:
        cmd.extend(["-d", f"tcp.port=={port},http2"])

    cmd.extend(
        [
            "-Y",
            "http || http2 || grpc",
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-E",
            "quote=d",
            "-E",
            "occurrence=a",
            "-E",
            "aggregator=|",
            "-e",
            "frame.time_epoch",
            "-e",
            "ip.src",
            "-e",
            "tcp.srcport",
            "-e",
            "ip.dst",
            "-e",
            "tcp.dstport",
            "-e",
            "tcp.stream",
            "-e",
            "http.request",
            "-e",
            "http.response",
            "-e",
            "http.request.method",
            "-e",
            "http.request.full_uri",
            "-e",
            "http.request.uri",
            "-e",
            "http.host",
            "-e",
            "http.request.line",
            "-e",
            "http.response.code",
            "-e",
            "http.response.line",
            "-e",
            "http.file_data",
            "-e",
            "http2.streamid",
            "-e",
            "http2.type",
            "-e",
            "http2.header.name",
            "-e",
            "http2.header.value",
            "-e",
            "grpc.message_data",
        ]
    )
    return cmd


def parse_pcap_events(pcap_path, http1_ports=None, http2_ports=None):
    cmd = build_tshark_cmd(pcap_path, http1_ports=http1_ports, http2_ports=http2_ports)
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "tshark failed")

    events = []
    reader = csv.reader(proc.stdout.splitlines(), delimiter="\t", quotechar='"')
    for row in reader:
        row += [""] * (21 - len(row))
        (
            epoch,
            ip_src,
            src_port,
            ip_dst,
            dst_port,
            tcp_stream,
            http_req,
            http_res,
            http_method,
            http_full_uri,
            http_uri,
            http_host,
            http_req_lines,
            http_status,
            http_res_lines,
            http_file_data,
            h2_stream_ids,
            h2_types,
            h2_header_names,
            h2_header_values,
            grpc_messages,
        ) = row[:21]

        ts = format_ts(epoch)
        src = f"{ip_src}:{src_port}" if ip_src and src_port else ""
        dst = f"{ip_dst}:{dst_port}" if ip_dst and dst_port else ""

        if is_truthy_flag(http_req):
            req_lines = split_multi(http_req_lines)
            headers = parse_header_lines(req_lines)
            full_uri = http_full_uri
            if not full_uri and http_host and http_uri:
                full_uri = f"http://{http_host}{http_uri}"

            paras = ""
            if full_uri:
                parsed = urlparse(full_uri)
                paras = "&".join([f"{k}={v}" for k, v in parse_qsl(parsed.query)])

            body = decode_http_body(http_file_data)
            request_data = {"method": http_method or "", "url": full_uri or "", "paras": paras}
            if body:
                request_data["body"] = body
            data = [request_data]
            events.append(
                {
                    "protocol_type": HTTP1_PROTOCOL_TYPE,
                    "msg_type": "Request",
                    "timestamp": ts,
                    "client": src,
                    "server": dst,
                    "tcp_stream": tcp_stream,
                    "stream_id": "",
                    "headers": headers,
                    "data": data,
                }
            )

        if is_truthy_flag(http_res):
            res_lines = split_multi(http_res_lines)
            headers = parse_header_lines(res_lines)
            body = decode_http_body(http_file_data)
            data = [{"status": http_status or "", "body": body}] if (http_status or body) else []
            events.append(
                {
                    "protocol_type": HTTP1_PROTOCOL_TYPE,
                    "msg_type": "Response",
                    "timestamp": ts,
                    "client": dst,
                    "server": src,
                    "tcp_stream": tcp_stream,
                    "stream_id": "",
                    "headers": headers,
                    "data": data,
                }
            )

        stream_ids = split_multi(h2_stream_ids)
        if stream_ids:
            h2_type_list = split_multi(h2_types)
            h2_names = split_multi(h2_header_names)
            h2_values = split_multi(h2_header_values)
            grpc_msgs = split_multi(grpc_messages)

            sid_type_pairs = list(zip(stream_ids, h2_type_list))
            header_stream_ids = [sid for sid, t in sid_type_pairs if sid not in ("", "0") and t == "1"]
            data_stream_ids = [sid for sid, t in sid_type_pairs if sid not in ("", "0") and t == "0"]

            header_blocks = split_h2_header_blocks(h2_names, h2_values)
            sid_headers = {}
            # tshark may emit repeated HEADERS frame entries for the same stream
            # within one packet (for example: 15,15,3,3). Collapse adjacent
            # duplicates so each decoded header block is matched to its stream.
            header_stream_order = []
            for sid in header_stream_ids:
                if not header_stream_order or header_stream_order[-1] != sid:
                    header_stream_order.append(sid)

            if len(header_stream_order) >= len(header_blocks):
                mapped_header_stream_ids = header_stream_order
            else:
                mapped_header_stream_ids = header_stream_ids

            for idx, block in enumerate(header_blocks):
                if idx >= len(mapped_header_stream_ids):
                    break
                sid = mapped_header_stream_ids[idx]
                hmap = {k: v for k, v in block}
                sid_headers[sid] = hmap

            sid_data = defaultdict(list)
            # Keep all DATA-frame stream IDs even if tshark did not decode
            # grpc.message_data for each of them in a mixed multi-stream packet.
            for sid in data_stream_ids:
                sid_data.setdefault(sid, [])

            for idx, gm in enumerate(grpc_msgs):
                gm = gm.strip()
                if not gm:
                    continue
                try:
                    parsed_value = json.loads(gm)
                except json.JSONDecodeError:
                    parsed_value = gm

                if idx < len(data_stream_ids):
                    sid_data[data_stream_ids[idx]].append(parsed_value)
                elif len(data_stream_ids) == 1:
                    sid_data[data_stream_ids[0]].append(parsed_value)

            all_sids = sorted(set(header_stream_ids + data_stream_ids), key=lambda x: int(x) if x.isdigit() else x)
            for sid in all_sids:
                headers_map = sid_headers.get(sid, {})
                msg_type = ""
                if headers_map.get(":method") == "POST":
                    msg_type = "Request"
                elif ":status" in headers_map:
                    msg_type = "Response"
                elif sid in sid_data:
                    msg_type = "Data"

                if not msg_type:
                    continue

                parsed_grpc_messages = sid_data.get(sid, [])
                if msg_type in {"Request", "Response", "Data"}:
                    parsed_grpc_messages = [decode_grpc_message_payload(x) for x in parsed_grpc_messages]

                events.append(
                    {
                        "protocol_type": HTTP2_PROTOCOL_TYPE,
                        "msg_type": msg_type,
                        "timestamp": ts,
                        "client": src,
                        "server": dst,
                        "tcp_stream": tcp_stream,
                        "stream_id": sid,
                        "headers": headers_map,
                        "data": parsed_grpc_messages,
                    }
                )

    return events


def unique_keep_order(items):
    seen = set()
    out = []
    for item in items:
        key = json.dumps(item, ensure_ascii=False, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def is_loopback_endpoint(endpoint):
    if not endpoint:
        return False
    host = endpoint.rsplit(":", 1)[0]
    return host == "127.0.0.1"


def build_calls(events):
    http_req_queue = defaultdict(deque)
    grpc_calls = {}
    http_calls = {}
    http_seq = 0

    for e in events:
        if is_http1_event(e):
            tstream = e.get("tcp_stream", "")
            if e["msg_type"] == "Request":
                http_seq += 1
                sid = str(http_seq)
                key = (tstream, sid)
                http_req_queue[tstream].append(sid)
                trace_id, span_id, parent_span_id = extract_trace_from_headers(e["headers"])
                http_calls[key] = {
                    "protocol_type": HTTP1_PROTOCOL_TYPE,
                    "stream_id": sid,
                    "client": e["client"],
                    "server": e["server"],
                    "trace_id": trace_id,
                    "span_id": span_id,
                    "parent_span_id": parent_span_id,
                    "req_ts": e["timestamp"],
                    "res_ts": "",
                    "req_headers": e["headers"],
                    "res_headers": {},
                    "req_data": e["data"],
                    "res_data": [],
                }
            elif e["msg_type"] == "Response" and http_req_queue[tstream]:
                sid = http_req_queue[tstream].popleft()
                key = (tstream, sid)
                if key in http_calls:
                    http_calls[key]["res_ts"] = e["timestamp"]
                    http_calls[key]["res_headers"] = e["headers"]
                    http_calls[key]["res_data"] = e["data"]

                    trace_id, span_id, parent_span_id = extract_trace_from_headers(e["headers"])
                    if trace_id:
                        http_calls[key]["trace_id"] = trace_id
                        http_calls[key]["span_id"] = span_id
                        http_calls[key]["parent_span_id"] = parent_span_id

        elif is_http2_event(e):
            sid = e.get("stream_id", "")
            if not sid:
                continue

            req_key = (e.get("client", ""), e.get("server", ""), sid)
            res_key = (e.get("server", ""), e.get("client", ""), sid)

            if e["msg_type"] == "Request" and e["headers"].get(":method") == "POST":
                if req_key not in grpc_calls:
                    grpc_calls[req_key] = {
                        "protocol_type": HTTP2_PROTOCOL_TYPE,
                        "stream_id": sid,
                        "client": e["client"],
                        "server": e["server"],
                        "trace_id": "",
                        "span_id": "",
                        "parent_span_id": "",
                        "req_ts": e["timestamp"],
                        "res_ts": "",
                        "req_headers": e["headers"],
                        "res_headers": {},
                        "req_data": [],
                        "res_data": [],
                    }

                uber = e["headers"].get("uber-trace-id", "")
                if uber:
                    parts = uber.split(":")
                    if len(parts) >= 3:
                        grpc_calls[req_key]["trace_id"] = parts[0]
                        grpc_calls[req_key]["span_id"] = parts[1]
                        grpc_calls[req_key]["parent_span_id"] = parts[2]

                if e["data"]:
                    grpc_calls[req_key]["req_data"].extend(e["data"])

            elif e["msg_type"] == "Response":
                if res_key not in grpc_calls:
                    grpc_calls[res_key] = {
                        "protocol_type": HTTP2_PROTOCOL_TYPE,
                        "stream_id": sid,
                        "client": e.get("server", ""),
                        "server": e.get("client", ""),
                        "trace_id": "",
                        "span_id": "",
                        "parent_span_id": "",
                        "req_ts": "",
                        "res_ts": e["timestamp"],
                        "req_headers": {},
                        "res_headers": {},
                        "req_data": [],
                        "res_data": [],
                    }

                if e["headers"]:
                    grpc_calls[res_key]["res_headers"].update(e["headers"])
                    if not grpc_calls[res_key]["res_ts"]:
                        grpc_calls[res_key]["res_ts"] = e["timestamp"]

                if e["data"]:
                    grpc_calls[res_key]["res_data"].extend(e["data"])

            elif e["msg_type"] == "Data":
                # DATA frame belongs to whichever request/response direction was already observed.
                if req_key in grpc_calls:
                    if e["data"]:
                        grpc_calls[req_key]["req_data"].extend(e["data"])
                elif res_key in grpc_calls:
                    if e["data"]:
                        grpc_calls[res_key]["res_data"].extend(e["data"])
                    # Even when payload decoding is empty, a DATA frame in the
                    # response direction is sufficient to mark response observed.
                    if not grpc_calls[res_key]["res_ts"]:
                        grpc_calls[res_key]["res_ts"] = e["timestamp"]

    all_calls = list(http_calls.values()) + list(grpc_calls.values())
    filtered_calls = []
    for c in all_calls:
        if is_loopback_endpoint(c.get("client", "")) and is_loopback_endpoint(c.get("server", "")):
            continue
        filtered_calls.append(c)
    return filtered_calls


def synthetic_server_span_id(call):
    material = "|".join(
        [
            call.get("trace_id", ""),
            call.get("span_id", ""),
            call.get("server", ""),
            call.get("stream_id", ""),
        ]
    )
    return hashlib.blake2s(material.encode("utf-8"), digest_size=8).hexdigest()


def make_cleaned_row(call, msg_type, span_kind="", span_endpoint="", peer_endpoint="", span_id=None, parent_span_id=None):
    req_data = unique_keep_order(call.get("req_data", []))
    res_data = unique_keep_order(call.get("res_data", []))
    is_request = msg_type == "Request"
    return {
        "protocol_type": call["protocol_type"],
        "msg_type": msg_type,
        "timestamp": call["req_ts"] if is_request else call["res_ts"],
        "network_duration_us": "",
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


def append_request_response_rows(rows, call, **kwargs):
    if call["req_ts"] or call["req_headers"] or call.get("req_data"):
        rows.append(make_cleaned_row(call, "Request", **kwargs))
    if call["res_ts"] or call["res_headers"] or call.get("res_data"):
        rows.append(make_cleaned_row(call, "Response", **kwargs))


def build_cleaned_like_rows(calls, span_form="rpc"):
    rows = []
    ordered_calls = sorted(
        calls,
        key=lambda c: (
            c.get("req_ts") or c.get("res_ts") or "",
            c.get("protocol_type", ""),
            c.get("stream_id", ""),
        ),
    )

    for c in ordered_calls:
        if span_form == "rpc":
            # Wire context names the caller-side client span for service-to-service
            # requests. Root external requests have no propagated parent and are
            # treated as server spans.
            span_kind = "client" if c.get("parent_span_id") else "server"
            span_endpoint = c["client"] if span_kind == "client" else c["server"]
            peer_endpoint = c["server"] if span_kind == "client" else c["client"]
            append_request_response_rows(
                rows,
                c,
                span_kind=span_kind,
                span_endpoint=span_endpoint,
                peer_endpoint=peer_endpoint,
            )
            continue

        if span_form != "client-server":
            raise ValueError(f"unsupported span_form: {span_form}")

        if c.get("parent_span_id"):
            append_request_response_rows(
                rows,
                c,
                span_kind="client",
                span_endpoint=c["client"],
                peer_endpoint=c["server"],
                span_id=c["span_id"],
                parent_span_id=c["parent_span_id"],
            )

        server_span_id = c["span_id"] if not c.get("parent_span_id") else synthetic_server_span_id(c)
        server_parent_span_id = c["parent_span_id"] if not c.get("parent_span_id") else c["span_id"]
        append_request_response_rows(
            rows,
            c,
            span_kind="server",
            span_endpoint=c["server"],
            peer_endpoint=c["client"],
            span_id=server_span_id,
            parent_span_id=server_parent_span_id,
        )

    return rows


def build_paired_rows(calls):
    rows = []
    for c in calls:
        req_data = unique_keep_order(c.get("req_data", []))
        res_data = unique_keep_order(c.get("res_data", []))

        rows.append(
            {
                "protocol_type": c.get("protocol_type", ""),
                "client": c.get("client", ""),
                "server": c.get("server", ""),
                "stream_id": c.get("stream_id", ""),
                "trace_id": c.get("trace_id", ""),
                "span_id": c.get("span_id", ""),
                "parent_span_id": c.get("parent_span_id", ""),
                "req_timestamp": c.get("req_ts", ""),
                "res_timestamp": c.get("res_ts", ""),
                "request_headers": json.dumps(c.get("req_headers", {}), ensure_ascii=False),
                "response_headers": json.dumps(c.get("res_headers", {}), ensure_ascii=False),
                "request_data": json.dumps(req_data, ensure_ascii=False),
                "response_data": json.dumps(res_data, ensure_ascii=False),
            }
        )

    rows.sort(key=lambda x: (x.get("req_timestamp", ""), x.get("res_timestamp", "")))
    return rows


def filter_complete_trace_rows(rows, expected_count=12):
    trace_counter = Counter()
    for r in rows:
        tid = (r.get("trace_id") or "").strip()
        if tid:
            trace_counter[tid] += 1

    if expected_count and expected_count > 0:
        min_valid_count = expected_count
        complete_trace_ids = {tid for tid, cnt in trace_counter.items() if cnt == expected_count}
    else:
        counts = sorted(trace_counter.values())
        median_count = counts[len(counts) // 2] if counts else 0
        min_valid_count = int(median_count * 0.75)
        complete_trace_ids = {tid for tid, cnt in trace_counter.items() if cnt >= min_valid_count}

    kept_rows = []
    removed_rows = []
    for r in rows:
        tid = (r.get("trace_id") or "").strip()
        if tid and tid in complete_trace_ids:
            kept_rows.append(r)
        else:
            removed_rows.append(r)

    if expected_count and expected_count > 0:
        removed_trace_ids = {tid for tid, cnt in trace_counter.items() if cnt != expected_count}
    else:
        removed_trace_ids = {tid for tid, cnt in trace_counter.items() if cnt < min_valid_count}
    return kept_rows, removed_rows, complete_trace_ids, removed_trace_ids, min_valid_count


def write_raw_events(events, out_path):
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    fieldnames = [
        "protocol_type",
        "msg_type",
        "timestamp",
        "client",
        "server",
        "tcp_stream",
        "stream_id",
        "headers",
        "data",
    ]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for e in events:
            row = dict(e)
            row["headers"] = json.dumps(row.get("headers", {}), ensure_ascii=False)
            row["data"] = json.dumps(row.get("data", []), ensure_ascii=False)
            w.writerow({k: row.get(k, "") for k in fieldnames})


def write_cleaned_like(rows, out_path):
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    fieldnames = [
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
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def write_paired(rows, out_path):
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    fieldnames = [
        "protocol_type",
        "client",
        "server",
        "stream_id",
        "trace_id",
        "span_id",
        "parent_span_id",
        "req_timestamp",
        "res_timestamp",
        "request_headers",
        "response_headers",
        "request_data",
        "response_data",
    ]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def main():
    parser = argparse.ArgumentParser(
        description="Parse PCAP to HTTP/gRPC events and generate cleaned_data-like CSV"
    )
    parser.add_argument("--pcap", default="paper_baseline.pcap", help="Path to input PCAP file")
    parser.add_argument(
        "--cleaned-out", default="data/pcap_cleaned_data.csv", help="Output path for cleaned_data-like CSV"
    )
    parser.add_argument(
        "--expected-trace-count",
        type=int,
        default=12,
        help="Only keep traces whose row count equals this value; 0 uses an automatic median-based threshold",
    )
    parser.add_argument(
        "--span-form",
        choices=["rpc", "client-server"],
        default="rpc",
        help=(
            "rpc keeps one row-pair per network RPC; client-server emits caller client "
            "and callee server span-shaped row-pairs"
        ),
    )
    parser.add_argument(
        "--http1-ports",
        default="auto",
        help="Comma-separated TCP ports to decode as HTTP/1.1, or auto",
    )
    parser.add_argument(
        "--http2-ports",
        default="auto",
        help="Comma-separated TCP ports to decode as HTTP/2/gRPC, auto, or an empty string for none",
    )
    args = parser.parse_args()

    pcap_path = os.path.abspath(args.pcap)
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")

    http1_ports = parse_ports(args.http1_ports, HTTP1_PORTS)
    http2_ports = parse_ports(args.http2_ports, HTTP2_PORTS)
    if http1_ports is None or http2_ports is None:
        inferred_http1_ports, inferred_http2_ports = infer_protocol_ports(pcap_path)
        if http1_ports is None:
            http1_ports = inferred_http1_ports or list(HTTP1_PORTS)
        if http2_ports is None:
            http2_ports = inferred_http2_ports
        http1_ports = sorted(set(http1_ports) - set(http2_ports))

    print(f"HTTP/1.1 decode ports: {','.join(map(str, http1_ports)) or '(none)'}")
    print(f"HTTP/2 decode ports: {','.join(map(str, http2_ports)) or '(none)'}")

    events = parse_pcap_events(pcap_path, http1_ports=http1_ports, http2_ports=http2_ports)
    calls = build_calls(events)
    rows = build_cleaned_like_rows(calls, span_form=args.span_form)
    kept_rows, removed_rows, kept_trace_ids, removed_trace_ids, min_valid_count = filter_complete_trace_rows(
        rows, expected_count=args.expected_trace_count
    )

    write_cleaned_like(kept_rows, os.path.abspath(args.cleaned_out))

    print(f"记录总数(过滤前): {len(rows)}")
    print(f"链路总数(过滤前): {len(kept_trace_ids) + len(removed_trace_ids)}")
    print(f"每条链路保留阈值: {min_valid_count}")
    print(f"span form: {args.span_form}")
    print(f"保留记录数(过滤后): {len(kept_rows)}")
    print(f"保留链路数(过滤后): {len(kept_trace_ids)}")
    print(f"删除不完整记录数: {len(removed_rows)}")
    print(f"删除不完整链路数: {len(removed_trace_ids)}")
    print(f"cleaned CSV: {os.path.abspath(args.cleaned_out)}")


if __name__ == "__main__":
    main()
