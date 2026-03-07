#!/bin/bash

# this script will archive Axigen logs and remove logs older than 90 days

LOG_DIR="/var/opt/axigen/log"
ARCHIVE_DIR="$LOG_DIR/archive"
DAYS_TO_KEEP=90
DATE=$(date +%Y-%m-%d)

# Create archive directory if it doesn't exist
mkdir -p "$ARCHIVE_DIR"

# checking if its the last day of the month to archive logs
if [ "$(date +%d -d tomorrow)" == "01" ]; then
    # Archive logs
    cd "$LOG_DIR"
    tar -czf "$ARCHIVE_DIR/axigen_logs_$DATE.tar.gz" --exclude="archive" * --remove-files

    echo "Axigen logs archived to $ARCHIVE_DIR/axigen_logs_$DATE.tar.gz"

    # restarting Axigen service to create new log files
    systemctl restart axigen
    echo "Axigen service restarted to generate new log files"
else
    echo "Today is not the last day of the month. No archiving performed."
fi

# removing log archive files older than 90 days
find "$ARCHIVE_DIR" -type f -name "axigen_logs_*.tar.gz" -mtime +$DAYS_TO_KEEP -exec rm {} \;