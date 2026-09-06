# ── Stage 1: build ──────────────────────────────────────────────
FROM ubuntu:22.04 AS build

RUN apt-get update && apt-get install -y \
        gcc \
        libc6-dev \
        binutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY shanks.c .

RUN gcc -O1 -o shanks shanks.c \
        -fstack-protector-all \
        -Wl,-z,relro,-z,now \
        -pie -fPIE \
        -U_FORTIFY_SOURCE \
    && strip --strip-all shanks

# ── Stage 2: runtime ───────────────────────────────────────────
FROM registry.digitalocean.com/infodays-registry/base:pwn

WORKDIR /home/ctf
COPY --from=build /build/shanks .
COPY entrypoint.sh .
RUN chmod 755 shanks entrypoint.sh

USER 1000
EXPOSE 1337

ENTRYPOINT ["./entrypoint.sh"]
