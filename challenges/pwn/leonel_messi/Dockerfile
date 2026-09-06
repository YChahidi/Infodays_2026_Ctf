# ── Stage 1: build ──────────────────────────────────────────────
FROM ubuntu:22.04 AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libc6-dev libseccomp-dev binutils ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY leonel_messi.c .

# Full RELRO, PIE, stack canary, FORTIFY=2, NX (default), seccomp linked in.
RUN gcc -O2 -o leonel_messi leonel_messi.c \
        -Wl,-z,now -Wl,-z,relro \
        -pie -fPIE \
        -fstack-protector-strong \
        -D_FORTIFY_SOURCE=2 \
        -lseccomp \
    && strip --strip-all leonel_messi

# ── Stage 2: runtime ────────────────────────────────────────────
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates libseccomp2 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -s /bin/bash -u 1000 ctf

WORKDIR /home/ctf
COPY --from=build /build/leonel_messi .
COPY entrypoint.sh .
RUN chmod 755 leonel_messi entrypoint.sh \
    && chown -R 1000:1000 /home/ctf

USER 1000
EXPOSE 1337

ENTRYPOINT ["./entrypoint.sh"]
