FROM python:3.11-alpine
RUN apk add --no-cache socat \
    && adduser -D -u 1000 ctf
WORKDIR /app
EXPOSE 4444
USER 1000
