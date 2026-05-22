import os

from flask import Flask, jsonify


app = Flask(__name__)
BOOK_COUNT = int(os.getenv("BOOK_COUNT", "100"))
GENRES = [
    "distributed systems",
    "database internals",
    "observability",
    "networking",
    "cloud architecture",
    "debugging",
    "operating systems",
    "performance engineering",
]


@app.get("/health")
def health():
    return jsonify({"status": "Details is healthy"})


@app.get("/details/<int:product_id>")
def details(product_id):
    book_id = product_id % BOOK_COUNT
    return jsonify({
        "id": book_id,
        "author": f"Author {book_id % 17:02d}",
        "year": 2000 + (book_id % 24),
        "type": "paperback",
        "pages": 120 + ((book_id * 7) % 420),
        "publisher": f"Publisher{book_id % 9:02d}",
        "language": "English",
        "genre": GENRES[book_id % len(GENRES)],
        "ISBN-10": f"{1234567890 + book_id:010d}",
        "ISBN-13": f"978-1-4028-{book_id:04d}-{book_id % 10}",
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=9080,
        ssl_context=("/certs/cert.pem", "/certs/key.pem"),
        threaded=True,
    )
