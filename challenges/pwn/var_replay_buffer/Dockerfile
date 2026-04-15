FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
        gcc \
        libc6-dev \
        socat \
        binutils \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash ctf

WORKDIR /home/ctf
COPY var_replay_buffer.c .
COPY entrypoint.sh .

RUN gcc -O1 -o var_replay_buffer var_replay_buffer.c \
        -fstack-protector-all \
        -Wl,-z,relro,-z,now \
        -pie -fPIE \
        -U_FORTIFY_SOURCE \
    && strip --strip-all var_replay_buffer \
    && rm var_replay_buffer.c \
    && chmod 755 var_replay_buffer entrypoint.sh \
    && chown -R root:ctf /home/ctf \
    && chmod 750 /home/ctf

EXPOSE 8011

CMD ["./entrypoint.sh"]
