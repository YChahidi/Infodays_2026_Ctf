FROM python:3.11-alpine AS builder
WORKDIR /install
COPY requirements.txt .
RUN pip install --prefix=/install/deps --no-cache-dir -r requirements.txt

FROM python:3.11-alpine
RUN apk add --no-cache socat
RUN adduser -D -u 1000 appuser
RUN mkdir -p /tmp && chmod 1777 /tmp
WORKDIR /app
COPY --from=builder /install/deps /usr/local
COPY --chown=1000:1000 entrypoint.sh /entrypoint.sh
COPY --chown=1000:1000 penalty_shootout.py .
USER 1000
EXPOSE 4444
ENTRYPOINT ["/entrypoint.sh"]
CMD ["socat", "-T60", "TCP-LISTEN:4444,reuseaddr,fork", "EXEC:python3 /app/penalty_shootout.py,nofork"]
