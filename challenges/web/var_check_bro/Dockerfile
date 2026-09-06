FROM registry.digitalocean.com/infodays-registry/base:web

USER root
RUN apk add --no-cache xxd
USER 1000

COPY requirements.txt .

USER root
RUN pip install --no-cache-dir -r requirements.txt
USER 1000

COPY frontend ./frontend
COPY internal ./internal
COPY entrypoint.sh .

USER root
RUN chmod +x entrypoint.sh
USER 1000

EXPOSE 8080
ENTRYPOINT ["./entrypoint.sh"]
