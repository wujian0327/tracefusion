FROM python:3.11-slim

WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir flask requests
RUN mkdir -p /certs \
    && openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout /certs/key.pem \
      -out /certs/cert.pem \
      -days 3650 \
      -subj "/CN=bookinfo-tls-openssl"
COPY reviews.py /app/reviews.py

EXPOSE 9080
CMD ["python", "/app/reviews.py"]
