FROM ubuntu:22.04

# Install socat AND gcc (plus libc-dev for standard headers)
RUN apt-get update && apt-get install -y \
    socat \
    gcc \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY var_review.c .
COPY flag.txt .

# Now gcc will be available to run this command
RUN gcc -fno-stack-protector -no-pie -o var_review var_review.c

EXPOSE 8006

CMD ["socat", "TCP-LISTEN:8006,reuseaddr,fork", "EXEC:./var_review"]
