FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server procps \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/sshd /var/run/sshd

# Create the IR analyst user (no sudo on purpose).
RUN useradd -m -s /bin/bash -u 1000 analyst && \
    echo 'analyst:analyst123' | chpasswd

# Harden sshd for the CTF: password auth for analyst only, no root.
RUN sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/'            /etc/ssh/sshd_config && \
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/^#*KbdInteractiveAuthentication.*/KbdInteractiveAuthentication no/' /etc/ssh/sshd_config && \
    echo 'AllowUsers analyst' >> /etc/ssh/sshd_config

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

CMD ["/entrypoint.sh"]
