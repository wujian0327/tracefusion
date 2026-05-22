import os

import requests
from flask import Flask, jsonify, request


app = Flask(__name__)
RATINGS_HOSTNAME = os.getenv("RATINGS_HOSTNAME", "ratings")
RATINGS_SERVICE_PORT = os.getenv("RATINGS_SERVICE_PORT", "9080")
RATINGS_URL = f"https://{RATINGS_HOSTNAME}:{RATINGS_SERVICE_PORT}"
VERIFY_TLS = os.getenv("VERIFY_TLS", "false").lower() == "true"


def forward_headers():
    headers = {}
    for name in ("x-mark", "user-agent", "x-request-id", "traceparent", "tracestate"):
        value = request.headers.get(name)
        if value:
            headers[name] = value
    return headers


@app.get("/health")
def health():
    return jsonify({"status": "Reviews is healthy"})


@app.get("/reviews/<int:product_id>")
def reviews(product_id):
    ratings = requests.get(
        f"{RATINGS_URL}/ratings/{product_id}",
        headers=forward_headers(),
        timeout=3,
        verify=VERIFY_TLS,
    ).json()
    stars = ratings.get("ratings", {})
    return jsonify({
        "id": product_id,
        "reviews": [
            {
                "reviewer": "Reviewer1",
                "text": f"TLS/OpenSSL review one for book {product_id}",
                "rating": stars.get("Reviewer1"),
            },
            {
                "reviewer": "Reviewer2",
                "text": f"TLS/OpenSSL review two for book {product_id}",
                "rating": stars.get("Reviewer2"),
            },
        ],
        "ratings": ratings,
    })


if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    app.run(
        host="0.0.0.0",
        port=9080,
        ssl_context=("/certs/cert.pem", "/certs/key.pem"),
        threaded=True,
    )
