# YAMI SUKEHIRO — custom base (needs mariadb + mercurial + supervisor, all UID 1000)
FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        mariadb-server mariadb-client \
        mercurial \
        supervisor \
        procps \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -u 1000 -m -s /bin/bash yami

WORKDIR /opt/app

COPY requirements.txt /opt/app/requirements.txt
RUN pip install --no-cache-dir -r /opt/app/requirements.txt

COPY app /opt/app
COPY db /opt/db
COPY scripts /data/scripts
COPY hg_repo_seed /opt/hg_repo_seed
COPY supervisord.conf /etc/supervisor/conf.d/yami.conf
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh /data/scripts/*.sh 2>/dev/null || true

# Informational crontab — attacker finds this via the directory-traversal read
# and learns about the fixer-v* pipeline.
RUN cat > /etc/crontab <<'CRON'
# /etc/crontab: system-wide crontab

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

#
*/1 * * * *  yami  /bin/bash /data/scripts/app_backup.sh
*/15 * * * * yuno  /bin/bash /data/scripts/table_cleanup.sh
* * * * *    yuno  /bin/bash /data/scripts/dbmonitor.sh
CRON

# Pre-bake MariaDB datadir at BUILD time (as root) so runtime has a ready DB
# owned by UID 1000 with no need to re-initialise.
RUN mkdir -p /var/lib/mysql /var/run/mysqld /var/log/supervisor /data/state /opt/hg_repo \
    && chown -R 1000:1000 /opt/app /opt/db /data /opt/hg_repo /opt/hg_repo_seed \
         /var/lib/mysql /var/run/mysqld /var/log/supervisor /etc/supervisor/conf.d \
    && su yami -s /bin/bash -c "mariadb-install-db --user=yami \
         --datadir=/var/lib/mysql \
         --auth-root-authentication-method=normal >/dev/null 2>&1" \
    && su yami -s /bin/bash -c "mariadbd --user=yami --datadir=/var/lib/mysql \
         --socket=/var/run/mysqld/mysqld.sock --skip-networking \
         --skip-log-bin >/tmp/_mb.log 2>&1 &"  \
    && for i in $(seq 1 30); do \
         mariadb -S /var/run/mysqld/mysqld.sock -u root -e 'SELECT 1' >/dev/null 2>&1 && break; \
         sleep 1; \
       done \
    && mariadb -S /var/run/mysqld/mysqld.sock -u root < /opt/db/init.sql \
    && mariadb-admin -S /var/run/mysqld/mysqld.sock -u root shutdown \
    && sleep 2

# sanity: make flag paths owned by UID 1000 (entrypoint writes them)
RUN mkdir -p /flags && chown -R 1000:1000 /flags

USER 1000
EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
