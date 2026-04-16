FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends socat \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -s /bin/bash -u 1000 ctf
WORKDIR /home/ctf
EXPOSE 1337
USER 1000
