FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        findutils util-linux \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash -u 1000 referee

RUN mkdir -p /app/reports /app/secrets
COPY server/server.py /app/server.py
COPY server/reports/ /app/reports/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Reports are world-readable briefing docs.
RUN chown -R referee:referee /app && chmod -R 755 /app/reports

# Classic GTFOBins privesc seed: suid find. Marketed in the writeup
# as "legacy referee search wrapper we never got around to removing."
RUN chmod u+s /usr/bin/find

EXPOSE 8008
ENTRYPOINT ["/entrypoint.sh"]
