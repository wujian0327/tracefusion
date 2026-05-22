import os

import requests
from flask import Flask, jsonify, request


app = Flask(__name__)
BOOK_COUNT = int(os.getenv("BOOK_COUNT", "100"))
DETAILS_HOSTNAME = os.getenv("DETAILS_HOSTNAME", "details")
DETAILS_SERVICE_PORT = os.getenv("DETAILS_SERVICE_PORT", "9080")
REVIEWS_HOSTNAME = os.getenv("REVIEWS_HOSTNAME", "reviews")
REVIEWS_SERVICE_PORT = os.getenv("REVIEWS_SERVICE_PORT", "9080")
VERIFY_TLS = os.getenv("VERIFY_TLS", "false").lower() == "true"

DETAILS_URL = f"https://{DETAILS_HOSTNAME}:{DETAILS_SERVICE_PORT}"
REVIEWS_URL = f"https://{REVIEWS_HOSTNAME}:{REVIEWS_SERVICE_PORT}"


def forward_headers():
    headers = {}
    for name in ("x-mark", "user-agent", "x-request-id", "traceparent", "tracestate"):
        value = request.headers.get(name)
        if value:
            headers[name] = value
    return headers


def selected_book_id():
    raw_id = request.args.get("id", "0")
    try:
        return int(raw_id) % BOOK_COUNT
    except ValueError:
        return 0


@app.get("/")
@app.get("/index.html")
@app.get("/productpage")
def productpage():
    book_id = selected_book_id()
    headers = forward_headers()
    details = requests.get(
        f"{DETAILS_URL}/details/{book_id}",
        headers=headers,
        timeout=3,
        verify=VERIFY_TLS,
    ).json()
    reviews = requests.get(
        f"{REVIEWS_URL}/reviews/{book_id}",
        headers=headers,
        timeout=3,
        verify=VERIFY_TLS,
    ).json()
    return jsonify({
        "id": book_id,
        "title": f"TLS Book {book_id:03d}",
        "details": details,
        "reviews": reviews,
        "service": "bookinfo-tls-openssl-productpage",
    })


@app.get("/health")
def health():
    return jsonify({"status": "Productpage is healthy"})


if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    app.run(
        host="0.0.0.0",
        port=9080,
        ssl_context=("/certs/cert.pem", "/certs/key.pem"),
        threaded=True,
    )
