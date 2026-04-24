FROM registry.digitalocean.com/infodays-registry/base:misc

USER root

RUN apk add --no-cache bash \
    && pip install --no-cache-dir pycryptodome==3.20.0

WORKDIR /app
COPY server/ /app/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh \
    && chmod +x /app/challenge.py

EXPOSE 1337

ENTRYPOINT ["/entrypoint.sh"]
