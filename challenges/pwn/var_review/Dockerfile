# ── Stage 1: build ──────────────────────────────────────────────
FROM ubuntu:22.04 AS build

RUN apt-get update && apt-get install -y \
        gcc \
        libc6-dev \
        binutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY var_review.c .

RUN gcc -o var_review var_review.c \
        -fstack-protector-all \
        -Wl,-z,relro,-z,now \
        -pie -fPIE \
        -D_FORTIFY_SOURCE=2 \
    && strip --strip-all var_review

# ── Stage 2: runtime ───────────────────────────────────────────
FROM registry.digitalocean.com/infodays-registry/base:pwn

WORKDIR /home/ctf
COPY --from=build /build/var_review .
COPY entrypoint.sh .
RUN chmod 755 var_review entrypoint.sh

USER 1000
EXPOSE 1337

ENTRYPOINT ["./entrypoint.sh"]
