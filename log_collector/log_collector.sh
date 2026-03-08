#!/bin/bash

# ;Purpose;
#   Collects logs from /var/www/*/logs/
#   and saves them to a folder
#   for analyze - foxwatch
# ;Author; 
#   Naru Koshin (https://github.com/narukoshin)

OUTPUT_DIR="collected_logs_$(date +%Y%m%d_%H%M%s)"
mkdir -p "$OUTPUT_DIR"

echo "[*] Collecting logs to $OUTPUT_DIR..."

if [ ! -d "/var/www" ]; then
    echo "[-] /var/www not found"
    exit 1
fi

total=0

for domain_dir in /var/www/*/logs; do
    domain=$(basename $(dirname "$domain_dir"))

    for log in access.log error.log; do
        log_path="$domain_dir/$log"
        if [ -f "$log_path" ]; then
            output_file="$OUTPUT_DIR/${domain}_${log}"

            case "$log" in
                access.log)
                    while IFS= read -r line; do
                        echo "$domain|$line"
                    done < "$log_path" > "$output_file"
                    ;;
                error.log)
                    while IFS= read -r line; do
                        echo "$domain|$line"
                    done < "$log_path" > "$output_file"
                    ;;
            esac

            count=$(wc -l < "$output_file")
            total=$((total + count))
            echo "[+] $domain/$log -> $count lines"
        fi
    done
done

echo ""
echo "[*] Total lines collected: $total"
echo "[*] Format: domain|original_log_line"
echo "[*] Logs saved in: $OUTPUT_DIR/"