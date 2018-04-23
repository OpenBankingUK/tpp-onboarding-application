#!/bin/sh
chown -R openbanking /var/log/openbanking
cd /var/projects/openbanking
supervisord -n -c /etc/supervisor/supervisord.conf