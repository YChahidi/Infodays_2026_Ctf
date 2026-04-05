FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    socat \
    gcc \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY var_review.c .
COPY flag.txt .

# Compile with FULL MITIGATIONS:
# - Stack canary enabled (default)
# - PIE enabled
# - Full RELRO
RUN gcc -o var_review var_review.c \
    -fstack-protector-all \
    -Wl,-z,relro,-z,now \
    -pie \
    -fPIE \
    -D_FORTIFY_SOURCE=2

RUN chmod 755 var_review
RUN rm var_review.c

EXPOSE 8006

CMD ["socat", "TCP-LISTEN:8006,reuseaddr,fork", "EXEC:./var_review"]
