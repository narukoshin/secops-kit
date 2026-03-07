#!/bin/bash

# Security script for log review and IP address extraction

# Set COLLECT_EVIDENCE to true to collect evidence
COLLECT_EVIDENCE=true

# checking if geoiplookup is installed for geolocation of IP addresses
if ! command -v geoiplookup &> /dev/null; then
    echo "geoiplookup could not be found. Please install it to get geolocation information for IP addresses."
    echo "On Debian/Ubuntu: sudo apt-get install geoip-bin"
    echo "On Arch Linux: sudo pacman -S geoip"
    exit 1
fi

# checking if the whois command is installed
if ! command -v whois &> /dev/null; then
    echo "whois could not be found. Please install it to get country codes for IP addresses."
    echo "On Debian/Ubuntu: sudo apt-get install whois"
    echo "On Arch Linux: sudo pacman -S whois"
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

declare -A IP_COUNTS
declare -A IP_LOCATIONS
declare -A IP_ABUSE_EMAILS

# Blacklist of IP addresses to ignore (e.g., local IPs)
BLACKLIST=(
    "0.0.0.0"
    "127.0.0.1"
    "::1"
)

output_file=""
blacklist_file=""
LOGS_SOURCE="/var/log"
NO_STDOUT=false
SKIP_SINGLE=false

# parsing arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        # result output file argument
        -o|--output)
            output_file="$2"
            shift 2
            ;;
        # blacklist file argument
        -b|--blacklist)
            blacklist_file="$2"
            if [[ -f "$blacklist_file" ]]; then
                while IFS= read -r line; do
                    BLACKLIST+=("$line")
                done < "$blacklist_file"
            else
                echo "error: Blacklist file not found: $blacklist_file"
                exit 1
            fi
            shift 2
            ;;
        # log folder
        -l|--log-source)
            LOGS_SOURCE="$2"
            if [[ ! -d "$LOGS_SOURCE" && ! -f "$LOGS_SOURCE" ]]; then
                echo "error: Log source not found: $LOGS_SOURCE"
                exit 1
            fi
            shift 2
            ;;
        # no evidence collection argument
        -nE|--no-evidence)
            COLLECT_EVIDENCE=false
            shift 1
            ;;
        # no stdout argument (write only to file)
        -nS|--no-stdout)
            NO_STDOUT=true
            shift 1
            ;;
        --skip-single)
            SKIP_SINGLE=true
            shift 1
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [-o|--output <output_file>] [-b|--blacklist <blacklist_file>] [-l|--log-source <log_source>] [-nE|--no-evidence] [-nS|--no-stdout] [--skip-single]"
            exit 1
            ;;
    esac
done

if [[ "$NO_STDOUT" = true && -z "$output_file" ]]; then
    echo "error: --no-stdout requires --output to be specified"
    exit 1
fi

if [ "$COLLECT_EVIDENCE" = true ]; then
    echo -e "\033[1;38mEvidence collection: \033[0;32mENABLED\033[0m"
else
    echo -e "\033[1;38mEvidence collection: \033[0;31mDISABLED\033[0m"
fi

if [[ "$NO_STDOUT" = true ]]; then
    echo -e "\033[1;38mOutput mode: \033[0;31mFILE ONLY\033[0m"
fi

# debug
echo "Log source: $LOGS_SOURCE"

# Cheking if LOGS_SOURCE is file or folder
if [[ -f "$LOGS_SOURCE" ]]; then
    echo "Using log file: $LOGS_SOURCE"
elif [[ -d "$LOGS_SOURCE" ]]; then
    echo "Using log folder: $LOGS_SOURCE"
else
    echo "error: Log source not found: $LOGS_SOURCE"
    exit 1
fi

# if output file is specified
if [[ -n "$output_file" ]]; then
    echo "Output will be written to: $output_file"
    # create or clear the output file
    > "$output_file"
fi

# if logs source is a folder, then using grep with resurcive search

if [[ -d "$LOGS_SOURCE" ]]; then
    echo "Searching for IP addresses in log folder..."
    logs=$(egrep -rniI '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' "$LOGS_SOURCE" 2>/dev/null)
fi

# if logs source is a file, then using grep to search for IP addresses in the file

if [[ -f "$LOGS_SOURCE" ]]; then
    echo "Searching for IP addresses in log file..."
    logs=$(egrep -niI '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' "$LOGS_SOURCE" 2>/dev/null)
fi


# Get all IP addresses of all logs in the folder
logs_ips=$(echo "$logs" | grep -oE '(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])')

# Remove blacklisted IP addresses
blacklist_pattern=$(printf '%s\n' "${BLACKLIST[@]}" | paste -sd '|')
logs_ips=$(echo "$logs_ips" | grep -vE "^($blacklist_pattern)$")

# Count occurrences of each IP address (keep duplicates for count)
while read -r ip; do
    [[ "$NO_STDOUT" = false ]] && echo -n "."
    if [[ -n "$ip" ]]; then
        ((IP_COUNTS["$ip"]++))
    fi
done <<< "$logs_ips"

# Get unique IPs for geolocation
unique_ips=($(echo "${!IP_COUNTS[@]}"))

# Get geolocation of an IP address in the background
#
# Parameters:
#   $1 - IP address
#
# Return:
#   IP address and its geolocation separated by '|'
#
# Description:
#   This function uses geoiplookup and whois commands to get the geolocation of an IP address in the background.
#   If geoiplookup does not return a geolocation, the function will use whois command to get the country code of the IP address and then use jq command to get the country name from the country code.
get_location_bg() {
    local ip="$1"
    local location=$(geoiplookup "$ip" 2>/dev/null | awk -F ': ' '{print $2}' | awk -F ', ' '{print $2}')
    if [[ -z "$location" ]]; then
        local country_code=$(whois "$ip" 2>/dev/null | grep -i "^country:" | head -n1 | awk '{print $2}')
        location=$(jq -r '.["3166-1"][] | select(.alpha_2=="'"$country_code"'") | .name // "Unknown"' "$ISO_FILE")
    fi
    echo "$ip|$location"
}

get_abuse_email_bg() {
    local ip="$1"
    local email=$(curl -s "https://rest.db.ripe.net/abuse-contact/${ip}.json" 2>/dev/null | jq -r '.["abuse-contacts"].email // empty')
    if [[ -z "$email" ]]; then
        email=$(whois "$ip" 2>/dev/null | grep -iE "^abuse-mailbox:|^abuse-email:|^org-abuse-email:" | head -n1 | awk -F ': ' '{print $2}' | xargs)
    fi
    echo "$ip|$email"
}

export -f get_location_bg
export -f get_abuse_email_bg
export ISO_FILE

tmpfile=$(mktemp)
max_jobs=8
for ip in "${unique_ips[@]}"; do
    while [[ $(jobs -r | wc -l) -ge $max_jobs ]]; do
        sleep 0.1
    done
    (get_location_bg "$ip" >> "$tmpfile") &
done
wait

while IFS='|' read -r ip location; do
    IP_LOCATIONS["$ip"]="$location"
done < "$tmpfile"
rm -f "$tmpfile"

tmpfile_abuse=$(mktemp)
for ip in "${unique_ips[@]}"; do
    while [[ $(jobs -r | wc -l) -ge $max_jobs ]]; do
        sleep 0.1
    done
    (get_abuse_email_bg "$ip" >> "$tmpfile_abuse") &
done
wait

while IFS='|' read -r ip email; do
    IP_ABUSE_EMAILS["$ip"]="$email"
done < "$tmpfile_abuse"
rm -f "$tmpfile_abuse"

[[ "$NO_STDOUT" = false ]] && clear

# Collect evidence for a given IP address
# 
# Parameters:
#   ip: IP address to collect evidence for
# 
# Description:
#   This function collects evidence for a given IP address by 
#   extracting relevant information from the logs. The evidence 
#   is formatted and stored in the IP_EVIDENCE associative array.
#   The function also prints the collected evidence in a human-readable 
#   format.
collect_evidence() {
    local ip="$1"

    # extracting info
    local evidence=$(echo "$logs" | grep "$ip")
    local first_line=$(echo "$evidence" | head -1)

    # format date - extract syslog format (Month DD HH:MM:SS) or ISO format (YYYY-MM-DD HH:MM:SS)
    local date_part=$(echo "$first_line" | grep -oE '([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}|[A-Z][a-z]{2} [0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2})' | head -1)
    local formatted_date=""
    if [[ -n "$date_part" ]]; then
        # Check if syslog format (no year) - add current year
        if [[ ! "$date_part" =~ ^[0-9]{4} ]]; then
            local current_year=$(date +"%Y")
            date_part="$date_part $current_year"
        fi
        formatted_date=$(date -d "${date_part}" +"%d/%m/%YT%H:%M:%S" 2>/dev/null) || formatted_date="$date_part"
    else
        # Try with comma (milliseconds): YYYY-MM-DD HH:MM:SS,mmm
        date_part=$(echo "$first_line" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]{3}' | head -1)
        if [[ -n "$date_part" ]]; then
            date_part=${date_part%,*}  # remove milliseconds
            formatted_date=$(date -d "${date_part}" +"%d/%m/%YT%H:%M:%S" 2>/dev/null) || formatted_date="$date_part"
        fi
    fi

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

# Write the output of the command to a file or to stdout
# Description:
#   This function writes the output to a file and/or stdout.
#   When NO_STDOUT is true, only writes to file.
write_file() {
    if [[ "$NO_STDOUT" = true ]]; then
        cat >> "$output_file"
    elif [[ -n "$output_file" ]]; then
        tee -a "$output_file"
    else
        cat
    fi
}

echo -e "\e[38;5;141m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m" | write_file
echo -e "\e[1;38;5;141m               RESULTS\e[0m" | write_file
echo -e "\e[38;5;141m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m\n" | write_file

if [ "$COLLECT_EVIDENCE" = true ]; then
    declare -A IP_EVIDENCE
    echo "Collecting evidence for each IP address..."
fi

CONTINUE_PROMPTED=false

# Sort by count (descending), then by IP
for ip in $(for k in "${!IP_COUNTS[@]}"; do echo "${IP_COUNTS[$k]} $k"; done | sort -nr | cut -d' ' -f2-); do
    count=${IP_COUNTS[$ip]}
    location=${IP_LOCATIONS[$ip]}

    # skip single occurrence if --skip-single is specified
    if [ "$count" -eq 1 ] && [ "$SKIP_SINGLE" = true ]; then
        continue
    fi

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
    printf "\033[1;35m%s\033[0m (%s) \033[1;39mCOUNT-%d %s\033[0m\n%s\n\n" "$ip" "$location" "$count" "${IP_ABUSE_EMAILS[$ip]}" "$evidence" | write_file
done

# Group IPs by abuse email
declare -A ABUSE_EMAIL_IPS
for ip in "${!IP_ABUSE_EMAILS[@]}"; do
    email="${IP_ABUSE_EMAILS[$ip]}"
    if [[ -n "$email" ]]; then
        ABUSE_EMAIL_IPS["$email"]+="${ip}(${IP_COUNTS[$ip]}) "
    fi
done

# Print summary by abuse email
if [[ ${#ABUSE_EMAIL_IPS[@]} -gt 0 ]]; then
    echo -e "\e[38;5;141m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m" | write_file
    echo -e "\e[1;38;5;141m          ABUSE EMAIL SUMMARY\e[0m" | write_file
    echo -e "\e[38;5;141m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m\n" | write_file

    for email in "${!ABUSE_EMAIL_IPS[@]}"; do
        ips=${ABUSE_EMAIL_IPS[$email]}
        echo -e "\e[38;5;141mAbuse Email:\e[0m \033[1;39m$email\e[0m" | write_file
        echo -e "\e[38;5;141mIPs:\e[0m \e[38;5;250m$ips\e[0m" | write_file
        echo "" | write_file
    done
fi