FROM registry.digitalocean.com/infodays-registry/base:web

COPY requirements.txt .

USER root
RUN pip install --no-cache-dir -r requirements.txt && \
    mkdir -p /tmp/backups /tmp/reports && \
    chown -R 1000:1000 /tmp/backups /tmp/reports
USER 1000

COPY app.py .
COPY static ./static
COPY entrypoint.sh .

USER root
RUN chmod +x entrypoint.sh
USER 1000

EXPOSE 8080
ENTRYPOINT ["./entrypoint.sh"]
