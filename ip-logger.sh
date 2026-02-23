#!/bin/bash

# Security script for log review and IP address extraction

# Get all IP addresses of all logs in /var/log folder, ignore binary files
ips=$(find /var/log -type f -exec grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' {} \; | sort -u 2>/dev/null)

echo "IP addresses found in /var/log:"
printf "%s\n" "$ips"
