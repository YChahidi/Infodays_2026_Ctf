# BATISTUTA — single-container port of the full multi-stage chain.
# Needs mariadb + p7zip + gcc at build time, all running as UID 1000 at runtime.
FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        mariadb-server mariadb-client \
        p7zip-full \
        gcc libc6-dev \
        supervisor procps ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -u 1000 -m -s /bin/bash batistuta

WORKDIR /opt/app

COPY requirements.txt /opt/app/requirements.txt
RUN pip install --no-cache-dir -r /opt/app/requirements.txt

COPY app       /opt/app
COPY db        /opt/db
COPY bin       /opt/bin
COPY supervisord.conf /etc/supervisor/conf.d/batistuta.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Compile the password generator at build time — attacker downloads & REs it.
RUN gcc -O2 -o /opt/bin/batistuta-pwgen /opt/bin/batistuta-pwgen.c \
    && strip /opt/bin/batistuta-pwgen

# Pre-bake MariaDB datadir (as root); chown to UID 1000 first so mariadbd can write.
RUN mkdir -p /var/lib/mysql /var/run/mysqld /var/log/supervisor /data /flags \
    && chown -R 1000:1000 /opt/app /opt/db /opt/bin /data /flags \
         /var/lib/mysql /var/run/mysqld /var/log/supervisor /etc/supervisor/conf.d \
    && su batistuta -s /bin/bash -c "mariadb-install-db --user=batistuta \
         --datadir=/var/lib/mysql \
         --auth-root-authentication-method=normal >/dev/null 2>&1" \
    && su batistuta -s /bin/bash -c "mariadbd --user=batistuta --datadir=/var/lib/mysql \
         --socket=/var/run/mysqld/mysqld.sock --skip-networking \
         --skip-log-bin >/tmp/_mb.log 2>&1 &" \
    && for i in $(seq 1 30); do \
         mariadb -S /var/run/mysqld/mysqld.sock -u root -e 'SELECT 1' >/dev/null 2>&1 && break; \
         sleep 1; \
       done \
    && mariadb -S /var/run/mysqld/mysqld.sock -u root < /opt/db/init.sql \
    && mariadb-admin -S /var/run/mysqld/mysqld.sock -u root shutdown \
    && sleep 2

USER 1000
EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
