from __future__ import annotations

import html
import json
import os
import socket
from typing import Any

import requests
from flask import Flask, Response, jsonify, request


app = Flask(__name__)

FORWARDED_HEADERS = {
    "x-request-id",
    "x-ot-span-context",
    "x-datadog-trace-id",
    "x-datadog-parent-id",
    "x-datadog-sampling-priority",
    "traceparent",
    "tracestate",
    "x-cloud-trace-context",
    "grpc-trace-bin",
    "x-b3-traceid",
    "x-b3-spanid",
    "x-b3-parentspanid",
    "x-b3-sampled",
    "x-b3-flags",
    "sw8",
    "end-user",
    "x-mark",
    "user-agent",
    "cookie",
    "authorization",
    "jwt",
}

SERVICE_ROLE = os.getenv("SERVICE_ROLE", "productpage")
BOOK_COUNT = max(1, int(os.getenv("BOOK_COUNT", "100")))
DETAILS_BASE_URL = f"http://{os.getenv('DETAILS_HOSTNAME', 'details')}:{os.getenv('DETAILS_SERVICE_PORT', '9080')}/details"
REVIEWS_BASE_URL = f"http://{os.getenv('REVIEWS_HOSTNAME', 'reviews')}:{os.getenv('REVIEWS_SERVICE_PORT', '9080')}/reviews"
RATINGS_BASE_URL = f"http://{os.getenv('RATINGS_HOSTNAME', 'ratings')}:{os.getenv('RATINGS_SERVICE_PORT', '9080')}/ratings"
RATINGS_ENABLED = os.getenv("ENABLE_RATINGS", "true").lower() in {"1", "true", "yes", "on"}
STAR_COLOR = os.getenv("STAR_COLOR", "black")
HOSTNAME = socket.gethostname()
USER_RATINGS: dict[int, dict[str, Any]] = {}


def parse_id(raw: str | None) -> int:
    try:
        return int(raw or "0")
    except ValueError:
        return 0


def normalize(product_id: int) -> int:
    return product_id % BOOK_COUNT


def forward_headers() -> dict[str, str]:
    headers: dict[str, str] = {}
    for name, value in request.headers.items():
        if name.lower() in FORWARDED_HEADERS:
            headers[name] = value
    return headers


def fallback(message: str) -> dict[str, Any]:
    return {"error": message}


def get_json(url: str, headers: dict[str, str], default: dict[str, Any]) -> dict[str, Any]:
    try:
        response = requests.get(url, headers=headers, timeout=3.0)
        if not 200 <= response.status_code < 300:
            return default
        data = response.json()
        if isinstance(data, dict):
            return data
    except Exception:
        return default
    return default


def product(product_id: int) -> dict[str, Any]:
    normalized = normalize(product_id)
    return {
        "id": normalized,
        "title": f"Microservice Field Notes {normalized:03d}",
        "descriptionHtml": f"Synthetic Bookinfo record {normalized:03d} for trace and lineage experiments.",
    }


def get_reviews_with_retry(product_id: int, headers: dict[str, str]) -> dict[str, Any]:
    default = fallback("reviews unavailable")
    result = default
    for _ in range(2):
        result = get_json(f"{REVIEWS_BASE_URL}/{product_id}", headers, default)
        if "error" not in result:
            return result
    return result


def review(reviewer: str, text: str, stars: int) -> dict[str, Any]:
    item: dict[str, Any] = {"reviewer": reviewer, "text": text}
    if RATINGS_ENABLED:
        if stars >= 0:
            item["rating"] = {"stars": stars, "color": STAR_COLOR}
        else:
            item["rating"] = {"error": "Ratings service is currently unavailable"}
    return item


def reviews_response(product_id: int, stars_reviewer_1: int, stars_reviewer_2: int) -> dict[str, Any]:
    return {
        "id": str(product_id),
        "podname": HOSTNAME,
        "clustername": os.getenv("CLUSTER_NAME", ""),
        "reviews": [
            review(
                "Reviewer1",
                "An extremely entertaining play by Shakespeare. The slapstick humour is refreshing!",
                stars_reviewer_1,
            ),
            review(
                "Reviewer2",
                "Absolutely fun and entertaining. The play lacks thematic depth when compared to other plays by Shakespeare.",
                stars_reviewer_2,
            ),
        ],
    }


def get_local_ratings(product_id: int) -> dict[str, Any]:
    normalized = normalize(product_id)
    if normalized in USER_RATINGS:
        return USER_RATINGS[normalized]
    return {
        "id": normalized,
        "ratings": {
            "Reviewer1": 1 + (normalized % 5),
            "Reviewer2": 1 + ((normalized + 3) % 5),
        },
    }


@app.get("/health")
def health() -> Response:
    return jsonify({"status": f"{SERVICE_ROLE.capitalize()} is healthy"})


@app.get("/productpage")
def product_page() -> Response:
    product_id = parse_id(request.args.get("id", "0"))
    headers = forward_headers()

    product_data = product(product_id)
    details_data = get_json(f"{DETAILS_BASE_URL}/{product_id}", headers, fallback("details unavailable"))
    reviews_data = get_reviews_with_retry(product_id, headers)

    body = f"""<!doctype html>
<html>
  <head><title>Bookinfo Python</title></head>
  <body>
    <h1>{html.escape(str(product_data["title"]))}</h1>
    <h2>Details</h2>
    <pre>{html.escape(json.dumps(details_data, sort_keys=True, separators=(",", ":")))}</pre>
    <h2>Reviews</h2>
    <pre>{html.escape(json.dumps(reviews_data, sort_keys=True, separators=(",", ":")))}</pre>
  </body>
</html>
"""
    return Response(body, content_type="text/html; charset=utf-8")


@app.get("/api/v1/products")
def products() -> Response:
    return jsonify([product(i) for i in range(BOOK_COUNT)])


@app.get("/api/v1/products/<product_id>")
def product_route(product_id: str) -> Response:
    item_id = parse_id(product_id)
    return jsonify(get_json(f"{DETAILS_BASE_URL}/{item_id}", forward_headers(), fallback("details unavailable")))


@app.get("/api/v1/products/<product_id>/reviews")
def reviews_route(product_id: str) -> Response:
    return jsonify(get_reviews_with_retry(parse_id(product_id), forward_headers()))


@app.get("/api/v1/products/<product_id>/ratings")
def ratings_route(product_id: str) -> Response:
    item_id = parse_id(product_id)
    return jsonify(get_json(f"{RATINGS_BASE_URL}/{item_id}", forward_headers(), fallback("ratings unavailable")))


@app.get("/details/<product_id>")
def details(product_id: str) -> Response:
    item_id = normalize(parse_id(product_id))
    genres = [
        "distributed systems",
        "database internals",
        "observability",
        "networking",
        "cloud architecture",
        "debugging",
        "operating systems",
        "performance engineering",
    ]
    return jsonify(
        {
            "id": item_id,
            "author": f"Author {item_id % 17:02d}",
            "year": 2000 + (item_id % 24),
            "type": "paperback",
            "pages": 120 + ((item_id * 7) % 420),
            "publisher": f"Publisher{item_id % 9:02d}",
            "language": "English",
            "genre": genres[item_id % len(genres)],
            "ISBN-10": f"{1234567890 + item_id:010d}",
            "ISBN-13": f"978-1-4028-{item_id:04d}-{item_id % 10}",
        }
    )


@app.get("/reviews/<product_id>")
def reviews(product_id: str) -> Response:
    item_id = parse_id(product_id)
    stars_reviewer_1 = -1
    stars_reviewer_2 = -1
    if RATINGS_ENABLED:
        url = f"{RATINGS_BASE_URL}/{item_id}"
        rid = request.args.get("rid")
        if rid:
            url = f"{url}?rid={rid}"
        ratings_data = get_json(url, forward_headers(), {})
        ratings = ratings_data.get("ratings", {})
        if isinstance(ratings, dict):
            stars_reviewer_1 = int(ratings.get("Reviewer1", -1))
            stars_reviewer_2 = int(ratings.get("Reviewer2", -1))
    return jsonify(reviews_response(item_id, stars_reviewer_1, stars_reviewer_2))


@app.get("/ratings/<product_id>")
def ratings(product_id: str) -> Response:
    return jsonify(get_local_ratings(parse_id(product_id)))


@app.post("/ratings/<product_id>")
def put_ratings(product_id: str) -> Response:
    item_id = normalize(parse_id(product_id))
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "please provide valid ratings JSON"}), 400
    result = {"id": item_id, "ratings": body}
    USER_RATINGS[item_id] = result
    return jsonify(result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("SERVER_PORT", "9080")))
