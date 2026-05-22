FROM trace-fusion-bookinfo-productpage:extended

WORKDIR /app
COPY app.py /app/app.py

ENV SERVER_PORT=9080
EXPOSE 9080

CMD ["gunicorn", "-b", "[::]:9080", "app:app", "-w", "8", "--keep-alive", "2", "-k", "gevent"]
