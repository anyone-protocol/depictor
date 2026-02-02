#!/bin/bash
set -e

# Default to running every hour if not specified
CRON_SCHEDULE="${CRON_SCHEDULE:-0 * * * *}"

# Set up cron job to run write_website.py
echo "$CRON_SCHEDULE /app/run_write_website.sh" > /etc/cron.d/write_website
chmod 0644 /etc/cron.d/write_website
crontab /etc/cron.d/write_website
touch /var/log/cron.log

# Start cron daemon
cron

# Start nginx in foreground
exec nginx -g "daemon off;"
