#!/bin/bash

# Log to both file and container stdout (PID 1's stdout)
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a /var/log/cron.log > /proc/1/fd/1
}

log "Starting write_website.py"

cd /app
if /usr/bin/python3 /app/write_website.py 2>&1 | tee -a /var/log/cron.log > /proc/1/fd/1; then
    log "write_website.py completed successfully"
else
    log "write_website.py failed with exit code $?"
fi
