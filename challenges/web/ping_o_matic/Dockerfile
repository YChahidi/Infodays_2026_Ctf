FROM registry.digitalocean.com/infodays-registry/base:web

USER root
RUN apk add --no-cache iputils-ping
USER 1000

COPY app.py .
COPY static ./static
COPY entrypoint.sh .

USER root
RUN chmod +x entrypoint.sh
USER 1000

EXPOSE 8080
ENTRYPOINT ["./entrypoint.sh"]
