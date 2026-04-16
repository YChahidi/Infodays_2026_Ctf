FROM registry.digitalocean.com/infodays-registry/base:web

COPY gen.py .
COPY entrypoint.sh .

USER root
RUN chmod +x entrypoint.sh
USER 1000

COPY app.py .
COPY templates/ templates/
COPY static/ static/

EXPOSE 8080
ENTRYPOINT ["./entrypoint.sh"]
