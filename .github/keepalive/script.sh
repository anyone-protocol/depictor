#!/bin/bash

set -e

# Configure git
git config user.name "github-actions"
git config user.email "github-actions@github.com"

# Get the timestamp of the last commit
LAST_COMMIT_TIME=$(git log -1 --format=%ct)
NOW_TIME=$(date +%s)

# Calculate time difference
SECONDS_DIFF=$((NOW_TIME - LAST_COMMIT_TIME))

# 30 days = 2592000 seconds
# First we use 1 to test it works on github
if [ "$SECONDS_DIFF" -gt 1 ]; then
  echo "Keepalive run at $(date)" > .github/keepalive/file.txt
  git add .github/keepalive/file.txt
  git commit -m "Keepalive commit at $(date)"
  git push
else
  echo "No keepalive needed. Last commit was $((SECONDS_DIFF/86400)) days ago."
fi
