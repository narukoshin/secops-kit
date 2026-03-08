from datetime import datetime
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv
import requests
import os
import re
import argparse

VERSION = "v1.0.0"

load_dotenv()

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
MAGENTA = "\033[35m"
BLUE = "\033[34m"
WHITE = "\033[37m"

# Load environment variables
# FoxWHOIS-API integration
# https://github.com/narukoshin/FoxWHOIS-API
FOXWHOIS_API_URL = os.getenv("FOXWHOIS_API_URL", "") # e.g. "https://api.foxwhois.com/v1/whois/{ip}"
FOXWHOIS_USER = os.getenv("FOXWHOIS_USER", "") # e.g. "username"
FOXWHOIS_PASS = os.getenv("FOXWHOIS_PASS", "") # e.g. "password"
FOXWHOIS_AUTH = (FOXWHOIS_USER, FOXWHOIS_PASS)

LOG_PATTERN = re.compile(
    r'^(?P<domain>[^|]+)\|(?P<ip>[^ ]+) - - \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\w+) (?P<path>[^ ]+) [^"]+" (?P<status>\d+) (?P<size>\d+) '
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"$'
)

def parse_log_line(line):
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None
    data = match.groupdict()
    try:
        data["status"] = int(data["status"])
        data["size"] = int(data["size"])
    except ValueError:
        pass
    return data

def parse_log_file(filepath):
    entries = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            entry = parse_log_line(line)
            if entry:
                entries.append(entry)
    return entries

def get_logs_from_folder(folder_path):
    all_entries = []
    
    if os.path.isfile(folder_path):
        entries = parse_log_file(folder_path)
        for entry in entries:
            entry["source_file"] = os.path.basename(folder_path)
        return entries
    
    for filename in os.listdir(folder_path):
        if filename.endswith("_access.log"):
            filepath = os.path.join(folder_path, filename)
            entries = parse_log_file(filepath)
            for entry in entries:
                entry["source_file"] = filename
            all_entries.extend(entries)
    return all_entries

def group_by_ip(entries):
    grouped = defaultdict(list)
    for entry in entries:
        grouped[entry["ip"]].append(entry)
    return grouped

def query_foxwhois(ip, enabled=True):
    if not enabled:
        return {}
    try:
        response = requests.get(
            FOXWHOIS_API_URL.format(ip=ip),
            auth=FOXWHOIS_AUTH,
            timeout=2
        )
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        pass
    return {}

def query_foxwhois_batch(ips, max_workers=20):
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(query_foxwhois, ip, True): ip for ip in ips}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                results[ip] = future.result()
            except Exception:
                results[ip] = {}
    return results

def format_time(ts):
    if ts is None:
        return ""
    return ts.strftime("%H:%M %Y-%m-%d")

def generate_report(ips_data, output_file, use_color=True):
    c = lambda x: x if use_color else ""
    lines = []
    lines.append(f"{c(CYAN)}╭────────────────────────────────────────────────────────────╮{c(RESET)}")
    lines.append(f"{c(CYAN)}│{c(RESET)}            {c(BOLD)}FoxLog – HTTP Traffic Watch{c(RESET)}                    {c(CYAN)}│{c(RESET)}")
    lines.append(f"{c(CYAN)}│{c(RESET)}                 {c(DIM)}generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}{c(RESET)}            {c(CYAN)}│{c(RESET)}")
    lines.append(f"{c(CYAN)}╰────────────────────────────────────────────────────────────╯{c(RESET)}")
    lines.append("")

    sorted_ips = sorted(ips_data.items(), key=lambda x: -x[1]['total_requests'])

    for ip, data in sorted_ips:
        lines.append(f"{c(MAGENTA)}🦊{c(RESET)} {c(BOLD)}{ip}{c(RESET)}")
        
        owner = data.get('owner')
        country = data.get('country')
        if owner or country:
            lines.append(f"    {c(DIM)}{owner or 'Unknown'}  •  {country}{c(RESET)}")
        
        domains = data.get('logged_domains', [])
        if len(domains) == 1:
            lines.append(f"    {c(YELLOW)}domains:{c(RESET)} \"{domains[0]}\"")
        else:
            domains_str = " + ".join(domains[:3])
            if len(domains) > 3:
                domains_str += f" +{len(domains)-3} more"
            lines.append(f"    {c(YELLOW)}domains:{c(RESET)} \"{domains_str}\"")
        
        abuse = data.get('abuse_email', 'N/A')
        abuse_color = GREEN if abuse and abuse != 'N/A' else DIM
        lines.append(f"    {c(YELLOW)}abuse  :{c(RESET)} {c(abuse_color)}\"{abuse}\"{c(RESET)}")

        lines.append("")
        lines.append(f"    {c(BOLD)}traffic{c(RESET)}")
        lines.append(f"    {c(DIM)}──────────────────────────────────────────────────────{c(RESET)}")
        lines.append(f"    {c(YELLOW)}requests       {c(RESET)}\"{data['total_requests']:,}\"")
        
        data_mb = data.get('data_served_bytes', 0) / (1024 * 1024)
        if data_mb >= 1024:
            data_str = f"~{data_mb/1024:.2f} GB"
        else:
            data_str = f"~{data_mb:.1f} MB"
        lines.append(f"    data served     \"{data_str}\"")
        lines.append(f"    unique ua       \"{data.get('unique_user_agents', 0)}\"")
        lines.append(f"    unique paths    \"{data.get('unique_paths', 0)}\"")

        if data.get('start_time') and data.get('end_time'):
            lines.append(f"    time window     \"{format_time(data['start_time'])} → {format_time(data['end_time'])}\"")

        lines.append("")
        lines.append(f"    {c(BOLD)}status{c(RESET)}")
        status_counts = data.get('status_breakdown', {})
        total = sum(status_counts.values())
        
        status_labels = {
            200: "200 OK", 201: "201 Created", 204: "204 No Content",
            301: "301 Moved", 302: "302 Found", 304: "304 Not Modified",
            400: "400 Bad Req", 401: "401 Unauthorized", 403: "403 Forbidden", 404: "404 Not Found",
            405: "405 Not Allowed", 429: "429 Rate Limit", 500: "500 Server Err", 502: "502 Bad Gateway", 503: "503 Unavailable"
        }
        
        for status in sorted(status_counts.keys()):
            count = status_counts[status]
            pct = (count / total * 100) if total > 0 else 0
            label = status_labels.get(status, str(status))
            bar = ""
            if pct > 0:
                bar_len = min(20, int(pct / 4))
                bar = " " + "█" * bar_len
            
            if status == 200:
                status_color = GREEN
            elif status == 404:
                status_color = YELLOW
            elif status in (403, 401, 429):
                status_color = RED
            elif status >= 500:
                status_color = RED
            else:
                status_color = WHITE
            
            lines.append(f"      {c(status_color)}{label:<14}{c(RESET)} {count:>5}  {pct:>5.1f}%{c(CYAN)}{bar}{c(RESET)}")

        lines.append("")
        lines.append(f"    {c(BOLD)}favorite paths{c(RESET)}")
        top_paths = data.get('top_paths', {})
        notable_paths = ['/wp-login.php', '/xmlrpc.php', '/.env', '/admin', '/administrator', '/phpinfo']
        for path, count in list(top_paths.items())[:5]:
            is_notable = any(p in path for p in notable_paths)
            note_color = RED if is_notable else ''
            note = f" {c(note_color)}← notable{c(RESET)}" if is_notable else ""
            lines.append(f"      {count:>3}×  {path}{note}")

        lines.append("")
        lines.append(f"    {c(BOLD)}user agents{c(RESET)}")
        top_uas = data.get('top_user_agents', {})
        for ua, count in top_uas.items():
            ua_short = ua[:50] + "..." if len(ua) > 50 else ua
            lines.append(f"      {count:>3}×  {c(DIM)}{ua_short}{c(RESET)}")

        lines.append("")
        lines.append(f"    {c(BOLD)}recent logs{c(RESET)}")
        sample = data.get('sample_entries', [])
        for entry in sample[:5]:
            ts = entry.get('timestamp', '')[:17]
            method = entry.get('method', '')
            path = entry.get('path', '')[:20]
            status = entry.get('status', '')
            ua = entry.get('user_agent', '')[:20]
            
            if status == 200:
                status_color = GREEN
            elif status == 404:
                status_color = YELLOW
            elif status in (403, 401, 429):
                status_color = RED
            elif status >= 500:
                status_color = RED
            else:
                status_color = WHITE
            
            lines.append(f"      {c(DIM)}{ts}{c(RESET)}  {c(BOLD)}{method:<4}{c(RESET)} {path:<20} {c(status_color)}{status:<3}{c(RESET)} {c(DIM)}{ua}{c(RESET)}")

        lines.append("")
        lines.append(f"    {c(DIM)}──────────────────────────────────────────────────────{c(RESET)}")
        lines.append("")

    lines.append("")
    lines.append(f"{c(CYAN)}┌{'─'*60}┐{c(RESET)}")
    lines.append(f"{c(CYAN)}│{c(RESET)}  🦊  Fox Summary{c(RESET)}{' '*(43)} {c(CYAN)}│{c(RESET)}")
    lines.append(f"{c(CYAN)}├{'─'*60}┤{c(RESET)}")
    
    top_3 = sorted_ips[:3]
    for i, (ip, data) in enumerate(top_3):
        req_str = f"{data['total_requests']:,}"
        pad = 20 - len(req_str)
        lines.append(f"{c(CYAN)}│{c(RESET)}  busiest IP  {c(BOLD)}{ip:<18}{c(RESET)} {req_str} requests{' '*pad} {c(CYAN)}│{c(RESET)}")
    
    lines.append(f"{c(CYAN)}├{'─'*60}┤{c(RESET)}")
    total_req = sum(d['total_requests'] for d in ips_data.values())
    lines.append(f"{c(CYAN)}│{c(RESET)}  total IPs      {len(ips_data):>6}{' '*44} {c(CYAN)}│{c(RESET)}")
    lines.append(f"{c(CYAN)}│{c(RESET)}  total requests {total_req:>6}                           {c(CYAN)}│{c(RESET)}")
    lines.append(f"{c(CYAN)}└{'─'*60}┘{c(RESET)}")
    lines.append("")
    lines.append(f"            {c(MAGENTA)}🦊 fox is watching the logs...{c(RESET)}")

    output_path = os.path.abspath(output_file)
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"{GREEN}✓{RESET} Report written to: {output_path}")

def process_logs(log_folder, output_file="log_report.txt", use_whois=False, limit=None, use_color=True, min_requests=None, exclude_list=None):
    print(f"{CYAN}▸{RESET} Processing logs from: {log_folder}")
    
    entries = get_logs_from_folder(log_folder)
    print(f"{CYAN}▸{RESET} Parsed {len(entries):,} log entries")
    
    grouped = group_by_ip(entries)
    print(f"{CYAN}▸{RESET} Found {len(grouped):,} unique IPs")
    
    localhost_ips = {"127.0.0.1", "::1", "localhost", "0.0.0.0", "::", "fe80::1"}
    
    for ip in list(grouped.keys()):
        if ip in localhost_ips:
            del grouped[ip]
    
    excluded_from_list = 0
    if exclude_list and os.path.isfile(exclude_list):
        with open(exclude_list, "r") as f:
            for line in f:
                ip = line.strip()
                if ip and not ip.startswith("#"):
                    if ip in grouped:
                        del grouped[ip]
                        excluded_from_list += 1
        if excluded_from_list > 0:
            print(f"{YELLOW}▸{RESET} Excluded {excluded_from_list} IPs from exclude list")
    
    sorted_ips = sorted(grouped.items(), key=lambda x: -len(x[1]))
    if limit:
        sorted_ips = sorted_ips[:limit]
        print(f"{CYAN}▸{RESET} Limited to top {limit} IPs")
    
    total_ips = len(sorted_ips)
    default_min = 10
    
    if min_requests is None and total_ips > 0:
        low_count = sum(1 for _, entries in sorted_ips if len(entries) < default_min)
        if low_count > 0:
            print(f"\n{YELLOW}▸{RESET} {total_ips} IPs total, {low_count} have < {default_min} requests")
            response = input(f"Include IPs with < {default_min} requests in report? [y/N]: ").strip().lower()
            if response != "y":
                min_requests = default_min
    
    if min_requests and min_requests > 1:
        sorted_ips = [(ip, entries) for ip, entries in sorted_ips if len(entries) >= min_requests]
        print(f"{CYAN}▸{RESET} Filtered to {len(sorted_ips)} IPs with >= {min_requests} requests")
    
    ip_list = [ip for ip, _ in sorted_ips]
    
    whois_results = {}
    if use_whois:
        print(f"{CYAN}▸{RESET} Querying FoxWHOIS for {len(ip_list)} IPs...")
        whois_results = query_foxwhois_batch(ip_list)
        print(f"{GREEN}✓{RESET} FoxWHOIS queries complete")
    
    ips_data = {}
    for ip, ip_entries in sorted_ips:
        ip_entries = sorted(ip_entries, key=lambda e: e.get("timestamp", ""), reverse=True)
        
        whois_data = whois_results.get(ip, {})
        
        timestamps = []
        for e in ip_entries:
            try:
                ts = datetime.strptime(e["timestamp"], "%d/%b/%Y:%H:%M:%S %z")
                timestamps.append(ts)
            except ValueError:
                pass
        
        start_time = min(timestamps) if timestamps else None
        end_time = max(timestamps) if timestamps else None
        
        domains = list(set(e["domain"] for e in ip_entries))
        
        status_counts = defaultdict(int)
        path_counts = defaultdict(int)
        user_agent_counts = defaultdict(int)
        user_agents = set()
        total_size = 0
        
        for e in ip_entries:
            status_counts[e["status"]] += 1
            path_counts[e["path"]] += 1
            total_size += e.get("size", 0)
            ua = e.get("user_agent", "")
            if ua:
                user_agents.add(ua)
                user_agent_counts[ua] += 1
        
        ips_data[ip] = {
            "ip": ip,
            "logged_domains": domains,
            "start_time": start_time,
            "end_time": end_time,
            "total_requests": len(ip_entries),
            "data_served_bytes": total_size,
            "unique_user_agents": len(user_agents),
            "unique_paths": len(path_counts),
            "abuse_email": whois_data.get("abuse_email"),
            "country": whois_data.get("country"),
            "owner": whois_data.get("owner"),
            "subnet": whois_data.get("subnet"),
            "status_breakdown": dict(status_counts),
            "top_paths": dict(sorted(path_counts.items(), key=lambda x: -x[1])[:10]),
            "top_user_agents": dict(sorted(user_agent_counts.items(), key=lambda x: -x[1])[:5]),
            "sample_entries": ip_entries[:10]
        }
    
    generate_report(ips_data, output_file, use_color)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HTTP Log Parser - Generate traffic reports from access logs")
    parser.add_argument("-l", "--log", dest="log_path", default="collected_logs_20260307_17491772898549",
                        help="Log folder or file path (default: collected_logs_20260307_17491772898549)")
    parser.add_argument("-o", "--output", default="report.txt",
                        help="Output file path (default: report.txt)")
    parser.add_argument("-w", "--whois", action="store_true",
                        help="Query FoxWHOIS for abuse information")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable color output")
    parser.add_argument("--limit", type=int, default=None,
                        help="Limit number of IPs in report")
    parser.add_argument("--min-requests", type=int, default=None,
                        help="Minimum requests per IP to include")
    parser.add_argument("--exclude-list", type=str, default=None,
                        help="File containing IPs to exclude (one per line)")
    
    args = parser.parse_args()
    
    process_logs(args.log_path, args.output, args.whois, args.limit, not args.no_color, args.min_requests, args.exclude_list)
