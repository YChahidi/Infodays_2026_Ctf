#!/bin/bash
# runs every 60s as "yami" (knight)
cd /opt/app
/usr/bin/rm -f backupapp.zip
/usr/bin/zip -r backupapp.zip /opt/app
