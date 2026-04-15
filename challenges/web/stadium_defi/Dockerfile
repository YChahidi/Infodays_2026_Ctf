FROM ghcr.io/foundry-rs/foundry:latest

USER root
WORKDIR /app

RUN apk add --no-cache python3 py3-pip bash curl jq

COPY frontend/requirements.txt /app/frontend/requirements.txt
RUN pip install --no-cache-dir --break-system-packages -r /app/frontend/requirements.txt

COPY foundry.toml /app/foundry.toml
COPY contracts /app/contracts
COPY script /app/script
COPY frontend /app/frontend
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

RUN mkdir -p /app/state && \
    cd /app && forge install --no-git foundry-rs/forge-std@v1.9.4 && \
    forge build

EXPOSE 5000 8545

ENTRYPOINT ["/app/entrypoint.sh"]
