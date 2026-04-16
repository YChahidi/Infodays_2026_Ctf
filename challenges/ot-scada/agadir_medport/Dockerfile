FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        mosquitto mosquitto-clients \
        coreutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY simulator.py entrypoint.sh ./
COPY broker/mosquitto.conf /etc/mosquitto/mosquitto.conf
COPY broker/acl /etc/mosquitto/acl
RUN chmod +x entrypoint.sh

EXPOSE 1883

CMD ["./entrypoint.sh"]
