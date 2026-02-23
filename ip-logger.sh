#!/bin/bash

# Security script for log review and IP address extraction

# Set DEV to true for development environment, false for production
# In development, logs will be read from the current directory's "logs" folder.
DEV=true

# Set COLLECT_EVIDENCE to true to collect evidence
COLLECT_EVIDENCE=true

# checking if geoiplookup is installed for geolocation of IP addresses
if ! command -v geoiplookup &> /dev/null; then
    echo "geoiplookup could not be found. Please install it to get geolocation information for IP addresses."
    echo "On Debian/Ubuntu: sudo apt-get install geoip-bin"
    echo "On Arch Linux: sudo pacman -S geoip"
    exit 1
fi

# checking if iso-codes is installed for getting country name from country code
if [[ ! -d "/usr/share/iso-codes" ]]; then
    echo "iso-codes data directory could not be found. Please install iso-codes to get country codes for IP addresses."
    echo "On Debian/Ubuntu: sudo apt-get install iso-codes"
    echo "On Arch Linux: sudo pacman -S iso-codes"
    exit 1
fi

ISO_FILE="/usr/share/iso-codes/json/iso_3166-1.json"

# jq
if ! command -v jq &> /dev/null; then
    echo "jq could not be found. Please install it to parse JSON data."
    echo "On Debian/Ubuntu: sudo apt-get install jq"
    echo "On Arch Linux: sudo pacman -S jq"
    exit 1
fi

if [ "$COLLECT_EVIDENCE" = true ]; then
    echo -e "\033[1;38mEvidence collection: \033[0;32mENABLED\033[0m"
else
    echo -e "\033[1;38mEvidence collection: \033[0;31mDISABLED\033[0m"
fi

declare -A IP_COUNTS
declare -A IP_LOCATIONS

# Blacklist of IP addresses to ignore (e.g., local IPs)
BLACKLIST=(
    "0.0.0.0"
    "127.0.0.1"
    "::1"
)

if [ "$DEV" = true ]; then
    LOG_FOLDER="./logs"
else
    LOG_FOLDER="/var/log"
fi

echo "Using log folder: $LOG_FOLDER"

logs=$(egrep -rni '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' "$LOG_FOLDER")

# Get all IP addresses of all logs in the folder
logs_ips=$(echo "$logs" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')

# Remove blacklisted IP addresses
for ip in "${BLACKLIST[@]}"; do
    logs_ips=$(echo "$logs_ips" | grep -v "$ip")
done

# Count occurrences of each IP address
while read -r ip; do
    echo -n "."
    if [[ -n "$ip" ]]; then
        ((IP_COUNTS["$ip"]++))
        if [[ -z "${IP_LOCATIONS[$ip]}" ]]; then
            # getting country name from geoiplookup
            location=$(geoiplookup "$ip" | awk -F ': ' '{print $2}' | awk -F ', ' '{print $2}')
            if [[ -z "$location" ]]; then
                # getting country code from whois lookup and then getting country name from iso-codes
                country_code=$(whois "$ip" | grep -i "country:" | head -n 1 | awk '{print $2}')
                location=$(jq -r '.["3166-1"][] | select(.alpha_2=="'"$country_code"'") | .name // "Unknown"' "$ISO_FILE")
            fi
            IP_LOCATIONS["$ip"]="$location"
        fi
    fi
done <<< "$logs_ips"

# clear terminal
clear

echo -e "\e[38;5;141m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo -e "\e[1;38;5;141m               RESULTS\e[0m"
echo -e "\e[38;5;141m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"

collect_evidence() {
    local ip="$1"

    # extracting info
    local evidence=$(echo "$logs" | grep "$ip")
    local first_line=$(echo "$evidence" | head -1)

    # format date
    local date=$(echo "$first_line" \
        | sed 's/^[^:]*:[0-9]*://' \
        | awk '{print $1, $2, $3}')
    local current_year=$(date +"%Y")
    local formatted_date=$(date -d "$date $current_year" +"%d/%m/%YT%H:%M:%S")

    # format evidence
    local evidence_final=$(echo "$evidence" | sed -E 's/^.*sshd[^:]*: //' | sed -E 's/ port [0-9]+//' | sort -u | head -3)
    IP_EVIDENCE["$ip"]="$evidence_final"
    echo -e "\e[38;5;141m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
    echo -e "\e[1;38;5;141m              -Evidence-\e[0m"
    echo -e "\e[38;5;141mFirst seen:\e[0m  \e[38;5;250m$formatted_date\e[0m"
    echo -e "\e[38;5;141mEvidence logs:\e[0m"

    # indent each log line
    while IFS= read -r line; do
        echo -e "  \e[38;5;250m$line\e[0m"
    done <<< "$evidence_final"

    echo -e "\e[38;5;141m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m\n"
}

if [ "$COLLECT_EVIDENCE" = true ]; then
    declare -A IP_EVIDENCE
    echo "Collecting evidence for each IP address..."
fi

CONTINUE_PROMPTED=false

# Sort by count (descending), then by IP
for ip in $(for k in "${!IP_COUNTS[@]}"; do echo "${IP_COUNTS[$k]} $k"; done | sort -nr | cut -d' ' -f2-); do
    count=${IP_COUNTS[$ip]}
    location=${IP_LOCATIONS[$ip]}

    # when the count starts to be low, asking if the user wants to continue
    if [ "$count" -le 1 ] && [ "$CONTINUE_PROMPTED" = false ]; then
        read -p "The count of next IP addreses is below 2, do you want to continue (y/n) " answer
        if [[ "$answer" != "y" ]]; then
            break
        fi
        CONTINUE_PROMPTED=true
    fi

    # evidence collection
    if [ "$COLLECT_EVIDENCE" = true ]; then
        evidence=$(collect_evidence "$ip")
    else
        evidence=""
    fi 
    printf "\033[1;35m%s\033[0m (%s) \033[1;39mCOUNT-%d\033[0m\n%s\n\n" "$ip" "$location" "$count" "$evidence"
done