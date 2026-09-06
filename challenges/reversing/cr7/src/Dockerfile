FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY src/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/server.py /app/server.py
COPY keys/private.pem /app/keys/private.pem
COPY keys/public.pem  /app/keys/public.pem
COPY flag.txt /app/flag.txt

ENV LAB_KEYS=/app/keys
ENV PORT=8080
EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s \
  CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1

CMD ["gunicorn", "-b", "0.0.0.0:8080", "-w", "1", "--threads", "8", \
     "--timeout", "30", "server:app"]
