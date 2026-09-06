# ── Stage 1: build ──────────────────────────────────────────────
FROM ubuntu:22.04 AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libc6-dev binutils ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY shanks_v2.c .

# Canary + PIE + partial RELRO + NX. Explicit flag choices:
#   -Wl,-z,lazy  → partial RELRO (GOT writable, lazy PLT binding)
#   -fcf-protection=none  → disable Intel CET (SHSTK / IBT) so the
#     intended ROP chain can return into non-endbr gadgets
#   -fno-stack-clash-protection  → keep the prologue identical to the
#     Old-Bridge-era layout so the leave;ret pivot arithmetic lines up
#   -U_FORTIFY_SOURCE  → don't replace read() with __read_chk()
RUN gcc -O1 -o shanks_v2 shanks_v2.c \
        -fstack-protector-all \
        -fno-omit-frame-pointer \
        -Wl,-z,lazy \
        -pie -fPIE \
        -fcf-protection=none \
        -fno-stack-clash-protection \
        -U_FORTIFY_SOURCE \
    && strip --strip-all shanks_v2

# ── Stage 2: runtime ───────────────────────────────────────────
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -s /bin/bash -u 1000 ctf

WORKDIR /home/ctf
COPY --from=build /build/shanks_v2 .
COPY entrypoint.sh .
RUN chmod 755 shanks_v2 entrypoint.sh \
    && chown -R 1000:1000 /home/ctf

USER 1000
EXPOSE 1337

ENTRYPOINT ["./entrypoint.sh"]
