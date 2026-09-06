FROM registry.digitalocean.com/infodays-registry/base:web

USER root

WORKDIR /app

COPY gen.py .
RUN python3 gen.py

COPY app.py .
COPY templates/ templates/
COPY static/ static/

USER 1000

EXPOSE 8080

CMD ["python3", "app.py"]
