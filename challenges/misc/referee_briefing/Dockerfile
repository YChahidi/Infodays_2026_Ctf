FROM registry.digitalocean.com/infodays-registry/base:misc

USER root

# findutils for SUID find (GTFOBins privesc — intentional security exception),
# util-linux for runuser.
RUN apk add --no-cache bash findutils util-linux

RUN adduser -D -s /bin/bash -u 1000 referee

RUN mkdir -p /app/reports /app/secrets
COPY server/server.py /app/server.py
COPY server/reports/ /app/reports/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Reports are world-readable briefing docs.
RUN chown -R referee:referee /app && chmod -R 755 /app/reports

# SECURITY EXCEPTION: SUID find is required for the GTFOBins privesc
# challenge path. This is the intended exploit vector.
RUN chmod u+s /usr/bin/find

EXPOSE 4444

# Entrypoint runs as root initially to plant flags, then drops to referee.
ENTRYPOINT ["/entrypoint.sh"]
