#!/usr/bin/env python3
import json
import os
import glob
import sys
import urllib.request
from collections import defaultdict
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

LOG_FILES = glob.glob("cowrie.json*")
OUTPUT_COMBINED = "cowrie_combined.json"

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"

def color(text, color_code):
    return f"{color_code}{text}{RESET}"

def input_with_default(prompt, default="n"):
    try:
        response = input(f"{prompt} [{default}]: ").strip().lower()
        return response if response else default
    except (EOFError, KeyboardInterrupt):
        print(color("\n[!] Exiting...", RED))
        sys.exit(0)

def combine_logs():
    print(color(f"[*] Combining {len(LOG_FILES)} log files...", CYAN))
    
    with open(OUTPUT_COMBINED, 'w') as outfile:
        for log_file in sorted(LOG_FILES):
            if log_file == OUTPUT_COMBINED:
                continue
            print(color(f"    Processing: {log_file}", DIM))
            with open(log_file, 'r') as infile:
                for line in infile:
                    line = line.strip()
                    if line:
                        try:
                            obj = json.loads(line)
                            outfile.write(json.dumps(obj) + '\n')
                        except json.JSONDecodeError:
                            pass
    
    print(color(f"[+] Combined logs saved to: {OUTPUT_COMBINED}", GREEN))
    return OUTPUT_COMBINED

def get_abuse_info(ip):
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,abuseEmails"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
            if data.get('status') == 'success':
                abuse_email = data.get('abuseEmails', '')
                if not abuse_email:
                    isp = data.get('isp', data.get('org', ''))
                    abuse_email = guess_abuse_email(isp)
                return {
                    'isp': data.get('isp', 'N/A'),
                    'org': data.get('org', 'N/A'),
                    'country': data.get('country', 'N/A'),
                    'abuse_email': abuse_email
                }
    except Exception:
        pass
    return {'isp': 'N/A', 'org': 'N/A', 'country': 'N/A', 'abuse_email': 'N/A'}

def guess_abuse_email(isp):
    isp_lower = isp.lower()
    if 'digitalocean' in isp_lower:
        return 'abuse@digitalocean.com'
    elif 'linode' in isp_lower:
        return 'abuse@linode.com'
    elif 'aws' in isp_lower or 'amazon' in isp_lower:
        return 'abuse@amazonaws.com'
    elif 'google' in isp_lower:
        return 'abuse@google.com'
    elif 'azure' in isp_lower or 'microsoft' in isp_lower:
        return 'abuse@microsoft.com'
    elif 'ovh' in isp_lower:
        return 'abuse@ovh.net'
    elif 'hetzner' in isp_lower:
        return 'abuse@hetzner.com'
    elif 'vultr' in isp_lower:
        return 'abuse@vultr.com'
    elif 'alibaba' in isp_lower:
        return 'abuse@alibaba-inc.com'
    elif 'tencent' in isp_lower:
        return 'abuse@tencent.com'
    elif 'huawei' in isp_lower:
        return 'abuse@huawei.com'
    elif 'chinanet' in isp_lower or 'china telecom' in isp_lower:
        return 'anti-spam@ctc.net.cn'
    elif 'kakao' in isp_lower:
        return 'abuse@kakao.com'
    elif 'contabo' in isp_lower:
        return 'abuse@contabo.de'
    return 'abuse@<isp>.com'

def lookup_ips_concurrent(ips_list):
    print(color("\n[*] Looking up IP abuse information...", CYAN))
    ip_info = {}
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_ip = {executor.submit(get_abuse_info, ip): ip for ip in ips_list}
        completed = 0
        total = len(future_to_ip)
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                ip_info[ip] = future.result()
            except Exception:
                ip_info[ip] = {'isp': 'N/A', 'org': 'N/A', 'country': 'N/A', 'abuse_email': 'N/A'}
            completed += 1
            if completed % 10 == 0 or completed == total:
                print(color(f"    Progress: {completed}/{total}", DIM))
    return ip_info

def get_country_flag(country_code):
    flags = {
        'US': 'US', 'CN': 'CN', 'RU': 'RU', 'DE': 'DE', 'NL': 'NL',
        'GB': 'GB', 'FR': 'FR', 'JP': 'JP', 'KR': 'KR', 'IN': 'IN',
        'BR': 'BR', 'CA': 'CA', 'AU': 'AU', 'IT': 'IT', 'ES': 'ES',
        'TW': 'TW', 'HK': 'HK', 'SG': 'SG', 'UA': 'UA', 'PL': 'PL',
    }
    return flags.get(country_code, '--')

def parse_logs(combined_file):
    print(color(f"\n[*] Parsing: {combined_file}", CYAN))
    
    stats = {
        'connections': 0,
        'successful_logins': 0,
        'failed_logins': 0,
        'commands_executed': 0,
        'files_uploaded': 0,
        'files_downloaded': 0,
    }
    
    ips = defaultdict(int)
    commands = []
    files_uploaded = []
    files_downloaded = []
    successful_logins = []
    failed_logins = []
    credentials = defaultdict(lambda: {'success': 0, 'failed': 0})
    sessions = defaultdict(lambda: {'commands': [], 'files': [], 'login': None, 'ip': None, 'timestamp': None})
    
    timestamps = []
    
    with open(combined_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            
            eventid = event.get('eventid', '')
            src_ip = event.get('src_ip', 'unknown')
            session = event.get('session', 'unknown')
            timestamp = event.get('timestamp', '')
            
            if timestamp:
                timestamps.append(timestamp)
            
            if eventid == 'cowrie.session.connect':
                stats['connections'] += 1
                ips[src_ip] += 1
                sessions[session]['ip'] = src_ip
                sessions[session]['timestamp'] = timestamp
            
            elif eventid == 'cowrie.login.success':
                stats['successful_logins'] += 1
                username = event.get('username', 'unknown')
                password = event.get('password', '')
                successful_logins.append({
                    'ip': src_ip,
                    'username': username,
                    'password': password,
                    'timestamp': timestamp
                })
                credentials[username]['success'] += 1
                sessions[session]['login'] = 'success'
            
            elif eventid == 'cowrie.login.failed':
                stats['failed_logins'] += 1
                username = event.get('username', 'unknown')
                password = event.get('password', '')
                failed_logins.append({
                    'ip': src_ip,
                    'username': username,
                    'password': password,
                    'timestamp': timestamp
                })
                credentials[username]['failed'] += 1
            
            elif eventid == 'cowrie.command.input':
                stats['commands_executed'] += 1
                cmd = event.get('input', '')
                commands.append({
                    'ip': src_ip,
                    'command': cmd,
                    'timestamp': timestamp
                })
                sessions[session]['commands'].append(cmd)
            
            elif eventid == 'cowrie.session.file_upload':
                stats['files_uploaded'] += 1
                filename = event.get('filename', 'unknown')
                shasum = event.get('shasum', '')
                files_uploaded.append({
                    'ip': src_ip,
                    'filename': filename,
                    'shasum': shasum,
                    'timestamp': timestamp
                })
                sessions[session]['files'].append(filename)
            
            elif eventid == 'cowrie.session.file_download':
                stats['files_downloaded'] += 1
                filename = event.get('filename', 'unknown')
                files_downloaded.append({
                    'ip': src_ip,
                    'filename': filename,
                    'timestamp': timestamp
                })
    
    date_range = None
    if timestamps:
        sorted_ts = sorted(timestamps)
        start_date = sorted_ts[0][:10] if sorted_ts[0] else 'N/A'
        end_date = sorted_ts[-1][:10] if sorted_ts[-1] else 'N/A'
        if start_date == end_date:
            date_range = start_date
        else:
            date_range = f"{start_date} to {end_date}"
    
    return {
        'stats': stats,
        'ips': dict(ips),
        'commands': commands,
        'files_uploaded': files_uploaded,
        'files_downloaded': files_downloaded,
        'successful_logins': successful_logins,
        'failed_logins': failed_logins,
        'credentials': dict(credentials),
        'sessions': dict(sessions),
        'date_range': date_range
    }

def print_report(data, ip_info=None):
    stats = data['stats']
    ips = data['ips']
    commands = data['commands']
    files_uploaded = data['files_uploaded']
    successful_logins = data['successful_logins']
    failed_logins = data['failed_logins']
    credentials = data['credentials']
    date_range = data.get('date_range', 'N/A')
    
    print(f"\n{BOLD}{'='*75}")
    print(f"{BOLD}                      COWRIE HONEYPOT LOG ANALYSIS")
    if date_range:
        print(f"{BOLD}                           Activity: {date_range}")
    print(f"{BOLD}{'='*75}{RESET}")
    
    print(color("\n### OVERALL STATISTICS ###", YELLOW))
    print(f"  {color('Total Connections:', WHITE):<25} {color(str(stats['connections']), GREEN)}")
    print(f"  {color('Successful Logins:', WHITE):<25} {color(str(stats['successful_logins']), GREEN)}")
    print(f"  {color('Failed Logins:', WHITE):<25} {color(str(stats['failed_logins']), RED)}")
    print(f"  {color('Commands Executed:', WHITE):<25} {color(str(stats['commands_executed']), CYAN)}")
    print(f"  {color('Files Uploaded:', WHITE):<25} {color(str(stats['files_uploaded']), MAGENTA)}")
    print(f"  {color('Files Downloaded:', WHITE):<25} {color(str(stats['files_downloaded']), MAGENTA)}")
    print(f"  {color('Unique IPs:', WHITE):<25} {color(str(len(ips)), YELLOW)}")
    
    if ip_info:
        print(color("\n### TOP ATTACKER IPs WITH ABUSE CONTACTS ###", YELLOW))
        sorted_ips_list = sorted(ips.items(), key=lambda x: x[1], reverse=True)[:20]
        
        abuse_groups = defaultdict(list)
        for ip, count in sorted_ips_list:
            info = ip_info.get(ip, {})
            abuse_email = info.get('abuse_email', 'N/A')
            abuse_groups[abuse_email].append((ip, count, info.get('isp', 'N/A'), info.get('country', 'N/A')))
        
        for abuse_email, ip_list in sorted(abuse_groups.items(), key=lambda x: sum(i[1] for i in x[1]), reverse=True):
            if abuse_email == 'N/A':
                print(color(f"\n  [Unknown Abuse Contact]", RED))
            else:
                print(color(f"\n  [{abuse_email}]", CYAN))
            print(f"  {'Country':<8} {'IP':<20} {'Connections':<12} ISP")
            print(f"  {'-'*8} {'-'*20} {'-'*12} {'-'*35}")
            for ip, count, isp, country in sorted(ip_list, key=lambda x: x[1], reverse=True):
                country_flag = get_country_flag(country)
                print(f"  {country_flag:<8} {ip:<20} {count:<12} {isp[:35]}")
    
    print(color("\n### SUCCESSFUL LOGINS ###", YELLOW))
    if successful_logins:
        print(f"  {'Timestamp':<20} {'IP':<18} {'Username':<15} {'Password':<20}")
        print(f"  {'-'*20} {'-'*18} {'-'*15} {'-'*20}")
        for login in successful_logins[:15]:
            ts = login['timestamp'][:19] if login['timestamp'] else 'N/A'
            pw = login['password'][:20] if login['password'] else 'N/A'
            print(f"  {ts:<20} {login['ip']:<18} {login['username']:<15} {color(pw, RED)}")
        if len(successful_logins) > 15:
            more = len(successful_logins) - 15
            choice = input_with_default(color(f"\n  Show all {len(successful_logins)} successful logins? (y/n)", YELLOW))
            if choice == 'y':
                for login in successful_logins[15:]:
                    ts = login['timestamp'][:19] if login['timestamp'] else 'N/A'
                    pw = login['password'][:20] if login['password'] else 'N/A'
                    print(f"  {ts:<20} {login['ip']:<18} {login['username']:<15} {color(pw, RED)}")
            else:
                print(color(f"  ... and {more} more", DIM))
    else:
        print(color("  No successful logins", DIM))
    
    print(color("\n### FAILED LOGINS ###", YELLOW))
    if failed_logins:
        print(f"  {'Timestamp':<20} {'IP':<18} {'Username':<15} {'Password':<20}")
        print(f"  {'-'*20} {'-'*18} {'-'*15} {'-'*20}")
        for login in failed_logins[:15]:
            ts = login['timestamp'][:19] if login['timestamp'] else 'N/A'
            pw = login['password'][:20] if login['password'] else 'N/A'
            print(f"  {ts:<20} {login['ip']:<18} {login['username']:<15} {pw}")
        if len(failed_logins) > 15:
            more = len(failed_logins) - 15
            choice = input_with_default(color(f"\n  Show all {len(failed_logins)} failed logins? (y/n)", YELLOW))
            if choice == 'y':
                for login in failed_logins[15:]:
                    ts = login['timestamp'][:19] if login['timestamp'] else 'N/A'
                    pw = login['password'][:20] if login['password'] else 'N/A'
                    print(f"  {ts:<20} {login['ip']:<18} {login['username']:<15} {pw}")
            else:
                print(color(f"  ... and {more} more", DIM))
    else:
        print(color("  No failed logins", DIM))
    
    print(color("\n### USERNAME STATISTICS (Top 15) ###", YELLOW))
    print(f"  {'Username':<25} {'Success':<12} {'Failed':<10}")
    print(f"  {'-'*25} {'-'*12} {'-'*10}")
    sorted_creds = sorted(credentials.items(), key=lambda x: x[1]['success'], reverse=True)
    for user, data in sorted_creds[:15]:
        success_color = GREEN if data['success'] > 0 else DIM
        fail_color = RED if data['failed'] > 0 else DIM
        print(f"  {user:<25} {color(str(data['success']), success_color):<12} {color(str(data['failed']), fail_color):<10}")
    
    print(color("\n### EXECUTED COMMANDS (Sample) ###", YELLOW))
    if commands:
        unique_cmds = len(set(c['command'] for c in commands))
        print(f"  {color('Total unique commands:', WHITE)} {unique_cmds}")
        print(f"\n  {'IP':<18} {'Timestamp':<19} {'Command':<40}")
        print(f"  {'-'*18} {'-'*19} {'-'*40}")
        for cmd in commands[:25]:
            ts = cmd['timestamp'][:19] if cmd['timestamp'] else 'N/A'
            command = cmd['command'][:40] + ('...' if len(cmd['command']) > 40 else '')
            print(f"  {cmd['ip']:<18} {ts:<19} {command}")
        if len(commands) > 25:
            more = len(commands) - 25
            choice = input_with_default(color(f"\n  Show all {len(commands)} commands? (y/n)", YELLOW))
            if choice == 'y':
                for cmd in commands[25:]:
                    ts = cmd['timestamp'][:19] if cmd['timestamp'] else 'N/A'
                    command = cmd['command'][:40] + ('...' if len(cmd['command']) > 40 else '')
                    print(f"  {cmd['ip']:<18} {ts:<19} {command}")
            else:
                print(color(f"  ... and {more} more", DIM))
    else:
        print(color("  No commands executed", DIM))
    
    print(color("\n### UPLOADED FILES ###", YELLOW))
    if files_uploaded:
        print(f"  {'Filename':<30} {'SHA256 (first 20)':<22} {'IP':<18} {'Timestamp':<20}")
        print(f"  {'-'*30} {'-'*22} {'-'*18} {'-'*20}")
        for f in files_uploaded[:15]:
            sha = f['shasum'][:20] if f['shasum'] else 'N/A'
            fname = f['filename'][:30] if f['filename'] else 'N/A'
            ts = f['timestamp'][:19] if f['timestamp'] else 'N/A'
            print(f"  {fname:<30} {sha:<22} {f['ip']:<18} {ts}")
        if len(files_uploaded) > 15:
            more = len(files_uploaded) - 15
            choice = input_with_default(color(f"\n  Show all {len(files_uploaded)} uploaded files? (y/n)", YELLOW))
            if choice == 'y':
                for f in files_uploaded[15:]:
                    sha = f['shasum'][:20] if f['shasum'] else 'N/A'
                    fname = f['filename'][:30] if f['filename'] else 'N/A'
                    ts = f['timestamp'][:19] if f['timestamp'] else 'N/A'
                    print(f"  {fname:<30} {sha:<22} {f['ip']:<18} {ts}")
            else:
                print(color(f"  ... and {more} more", DIM))
    else:
        print(color("  No files uploaded", DIM))

def main():
    try:
        combined_file = combine_logs()
        data = parse_logs(combined_file)
        
        sorted_ips_list = sorted(data['ips'].keys(), key=lambda x: data['ips'][x], reverse=True)
        ip_info = lookup_ips_concurrent(sorted_ips_list)
        
        print_report(data, ip_info)
    except KeyboardInterrupt:
        print(color("\n\n[!] Interrupted by user. Exiting...", RED))
        sys.exit(0)

if __name__ == "__main__":
    main()
