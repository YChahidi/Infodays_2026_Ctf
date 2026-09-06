FROM registry.digitalocean.com/infodays-registry/base:web

COPY app.py .
COPY news.txt .
COPY static ./static
COPY entrypoint.sh .

USER root
RUN chmod +x entrypoint.sh
USER 1000

EXPOSE 8080
ENTRYPOINT ["./entrypoint.sh"]
