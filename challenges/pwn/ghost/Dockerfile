# ── Ghost Protocol — CTF Pwn Challenge ──────────────────────────────────────
# Ubuntu 22.04 gives us a known libc (2.35) with predictable gadgets.
# ASLR is enabled at container runtime via /proc/sys/kernel/randomize_va_space.
# PIE is disabled at compile time so binary gadget addresses are fixed.
# NX is ON — no shellcode.
# Stack canary is OFF — clean ROP.
# ─────────────────────────────────────────────────────────────────────────────

FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY ghost.c .

# -fno-pie / -no-pie   → fixed binary base (stable ROP gadgets)
# -fno-stack-protector → no canary
# NX is on by default (no -z execstack)
# -O0                  → no optimisation, keeps stack layout predictable
RUN gcc -o ghost ghost.c \
        -fno-pie -no-pie \
        -fno-stack-protector \
        -m64 -O0

# ── Runtime image ─────────────────────────────────────────────────────────────
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        socat \
        libc6 \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN groupadd -g 1000 ghost && useradd -u 1000 -g 1000 -M -s /bin/sh ghost

# Binary
COPY --from=builder --chown=root:root /build/ghost /usr/local/bin/ghost
RUN chmod 755 /usr/local/bin/ghost

# Entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Flag is injected by the CTF controller as FLAG env var
# and written to /flag.txt by entrypoint.sh at runtime.
# The file is world-readable so the user can cat it after getting a shell.

USER ghost
EXPOSE 1337

ENTRYPOINT ["/entrypoint.sh"]
CMD ["socat", "-T120", "TCP-LISTEN:1337,reuseaddr,fork", \
     "EXEC:/usr/local/bin/ghost,nofork"]
