FROM registry.digitalocean.com/infodays-registry/base:misc

USER root

# mosquitto broker + clients for the MQTT challenge.
RUN apk add --no-cache bash mosquitto mosquitto-clients

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY simulator.py entrypoint.sh ./
COPY broker/mosquitto.conf /etc/mosquitto/mosquitto.conf
COPY broker/acl /etc/mosquitto/acl
RUN chmod +x entrypoint.sh

EXPOSE 1883

# Runs as root to manage mosquitto passwd, then launches broker + simulator.
CMD ["./entrypoint.sh"]
