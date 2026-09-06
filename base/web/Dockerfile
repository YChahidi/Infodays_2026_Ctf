FROM python:3.11-alpine
RUN adduser -D -u 1000 ctf \
    && pip install --no-cache-dir flask gunicorn
WORKDIR /app
EXPOSE 8080
USER 1000
