#!/bin/sh
# runs every 15 minutes
/usr/bin/mariadb -S /var/run/mysqld/mysqld.sock -u yuno -p'3wDo7gSRZIwIHRxZ!' mana_db < /data/scripts/sqlappointments.sql
