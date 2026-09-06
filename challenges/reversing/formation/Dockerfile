FROM ubuntu:22.04 AS builder
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libc6-dev make && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY src/formation.c .
RUN gcc -O2 -Wall -static -o formation formation.c

FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends socat && \
    rm -rf /var/lib/apt/lists/*
RUN groupadd -g 1000 appuser && useradd -u 1000 -g 1000 -M appuser
COPY --from=builder --chown=1000:1000 /build/formation /usr/local/bin/formation
COPY --chown=root:root entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
USER 1000
EXPOSE 1337
ENTRYPOINT ["/entrypoint.sh"]
CMD ["socat", "-T60", "TCP-LISTEN:1337,reuseaddr,fork", \
     "EXEC:/usr/local/bin/formation,nofork"]
