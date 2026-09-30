"""Wire/record helpers. No oracle data is transmitted to downstream services."""
import http.client
import json
import threading
from pathlib import Path

ADDRESSES = {
    "loadgen": "127.0.0.1",
    "api": "127.0.0.2",
    "profile": "127.0.0.3",
    "decoy": "127.0.0.4",
    "store": "127.0.0.5",
}
ROLES = ("api", "profile", "decoy", "store")
SCENARIOS = ("basic", "same_value_concurrent", "same_user_concurrent",
             "decoy_different", "decoy_same")
_write_lock = threading.Lock()


def append_json(path, record):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _write_lock, path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def read_jsonl(path):
    with Path(path).open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def node(event_id, field="phone"):
    return {"event_id": event_id, "location": "response", "field": field}


def node_key(value):
    return (value["event_id"], value["location"], value["field"])


def call(caller, callee, port, path, payload=None):
    conn = http.client.HTTPConnection(
        ADDRESSES[callee], port, timeout=15,
        source_address=(ADDRESSES[caller], 0),
    )
    try:
        data = None if payload is None else json.dumps(payload).encode()
        conn.request("GET" if payload is None else "POST", path, body=data,
                     headers={"Content-Type": "application/json", "Connection": "close"})
        response = conn.getresponse()
        body = response.read()
        if response.status != 200:
            raise RuntimeError(f"{callee} {path}: HTTP {response.status}: {body!r}")
        return json.loads(body), response.getheader("X-Observation-ID")
    finally:
        conn.close()
