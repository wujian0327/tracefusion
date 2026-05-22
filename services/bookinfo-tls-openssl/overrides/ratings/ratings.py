import os

from flask import Flask, jsonify, request


app = Flask(__name__)
BOOK_COUNT = int(os.getenv("BOOK_COUNT", "100"))


@app.get("/health")
def health():
    return jsonify({"status": "Ratings is healthy"})


@app.get("/ratings/<int:product_id>")
def ratings(product_id):
    book_id = product_id % BOOK_COUNT
    return jsonify({
        "id": book_id,
        "ratings": {
            "Reviewer1": 1 + (book_id % 5),
            "Reviewer2": 1 + ((book_id * 3) % 5),
        },
        "source": "openssl-python-ratings",
    })


@app.post("/ratings/<int:product_id>")
def put_ratings(product_id):
    payload = request.get_json(silent=True) or {}
    return jsonify({
        "id": product_id % BOOK_COUNT,
        "stored": payload,
        "source": "openssl-python-ratings",
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=9080,
        ssl_context=("/certs/cert.pem", "/certs/key.pem"),
        threaded=True,
    )
