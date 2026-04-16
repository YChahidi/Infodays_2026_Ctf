FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
        gcc \
        libc6-dev \
        socat \
        binutils \
        python3 \
        python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install flask 2>/dev/null || \
    pip3 install --break-system-packages flask

RUN useradd -m -s /bin/bash ctf

WORKDIR /home/ctf
COPY shanks.c .
COPY entrypoint.sh .
COPY splash.py .
COPY static ./static

RUN gcc -O1 -o shanks shanks.c \
        -fstack-protector-all \
        -Wl,-z,relro,-z,now \
        -pie -fPIE \
        -U_FORTIFY_SOURCE \
    && strip --strip-all shanks \
    && rm shanks.c \
    && chmod 755 shanks entrypoint.sh splash.py \
    && chown -R root:ctf /home/ctf \
    && chmod 750 /home/ctf

EXPOSE 8019 5000

CMD ["bash", "-c", "python3 /home/ctf/splash.py & exec /home/ctf/entrypoint.sh"]
