import json
import os
import glob
import urllib.request
from collections import defaultdict
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


class CowrieLogParser:
    VERSION = "1.0.1"

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

    # Written report
    REPORT = []
    output_report = "cowrie_report.log"

    def __init__(self, log_files_pattern="cowrie.json*", output_combined="cowrie_combined.json"):
        self.log_files_pattern = log_files_pattern
        self.output_combined = output_combined
        self.log_files = glob.glob(self.log_files_pattern)
        

    def write_report(self, content) -> None:
        """
        Write a line to the report.

        Args:
            content (str): The content to be written to the report.

        Returns:
            None
        """
        self.REPORT.append(content)
        print(content)

    def color(self, text, color_code):
        return f"{color_code}{text}{self.RESET}"

    def input_with_default(self, prompt, default="n"):
        import sys
        try:
            response = input(f"{prompt} [{default}]: ").strip().lower()
            return response if response else default
        except (EOFError, KeyboardInterrupt):
            print(self.color("\n[!] Exiting...", self.RED))
            sys.exit(0)

    def combine_logs(self):
        print(self.color(f"[*] Combining {len(self.log_files)} log files...", self.CYAN))

        if not self.log_files:
            log_dir = self.input_with_default(self.color("    Please enter the directory containing the log files", self.WHITE), ".")
            self.log_files.extend(glob.glob(os.path.join(log_dir, "cowrie.json*")))

            if not self.log_files:
                print(self.color("[!] No log files found matching the pattern.", self.RED))
                import sys
                sys.exit(1)

        with open(self.output_combined, 'w') as outfile:
            for log_file in sorted(self.log_files):
                if log_file == self.output_combined:
                    continue
                print(self.color(f"    Processing: {log_file}", self.DIM))
                with open(log_file, 'r') as infile:
                    for line in infile:
                        line = line.strip()
                        if line:
                            try:
                                obj = json.loads(line)
                                outfile.write(json.dumps(obj) + '\n')
                            except json.JSONDecodeError:
                                pass
        
        print(self.color(f"[+] Combined logs saved to: {self.output_combined}", self.GREEN))
        return self.output_combined

    def get_abuse_info(self, ip):
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,abuseEmails"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode())
                if data.get('status') == 'success':
                    abuse_email = data.get('abuseEmails', '')
                    if not abuse_email:
                        isp = data.get('isp', data.get('org', ''))
                        abuse_email = self.guess_abuse_email(isp)
                    return {
                        'isp': data.get('isp', 'N/A'),
                        'org': data.get('org', 'N/A'),
                        'country': data.get('country', 'N/A'),
                        'abuse_email': abuse_email
                    }
        except Exception:
            pass
        return {'isp': 'N/A', 'org': 'N/A', 'country': 'N/A', 'abuse_email': 'N/A'}

    def guess_abuse_email(self, isp):
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

    def lookup_ips_concurrent(self, ips_list):
        print(self.color("\n[*] Looking up IP abuse information...", self.CYAN))
        ip_info = {}
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_ip = {executor.submit(self.get_abuse_info, ip): ip for ip in ips_list}
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
                    print(self.color(f"    Progress: {completed}/{total}", self.DIM))
        return ip_info

    def get_country_flag(self, country_code):
        flags = {
            'US': 'US', 'CN': 'CN', 'RU': 'RU', 'DE': 'DE', 'NL': 'NL',
            'GB': 'GB', 'FR': 'FR', 'JP': 'JP', 'KR': 'KR', 'IN': 'IN',
            'BR': 'BR', 'CA': 'CA', 'AU': 'AU', 'IT': 'IT', 'ES': 'ES',
            'TW': 'TW', 'HK': 'HK', 'SG': 'SG', 'UA': 'UA', 'PL': 'PL',
        }
        return flags.get(country_code, '--')

    def parse_logs(self, combined_file):
        print(self.color(f"\n[*] Parsing: {combined_file}", self.CYAN))
        
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
        evidence = []
        
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
                
                message = event.get('message', '')
                if message:
                    evidence.append({
                        'ip': src_ip,
                        'timestamp': timestamp,
                        'eventid': eventid,
                        'message': message
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
            'date_range': date_range,
            'evidence': evidence
        }

    def print_report(self, data, ip_info=None):
        stats = data['stats']
        ips = data['ips']
        commands = data['commands']
        files_uploaded = data['files_uploaded']
        successful_logins = data['successful_logins']
        failed_logins = data['failed_logins']
        credentials = data['credentials']
        date_range = data.get('date_range', 'N/A')
        evidence = data.get('evidence', [])
        
        self.write_report(f"\n{self.BOLD}{'='*75}")
        self.write_report(f"{self.BOLD}                      COWRIE HONEYPOT LOG ANALYSIS v{self.VERSION}{self.RESET}")
        if date_range:
            self.write_report(f"{self.BOLD}                           Activity: {date_range}")
        self.write_report(f"{self.BOLD}{'='*75}{self.RESET}")
        
        self.write_report(self.color("\n### OVERALL STATISTICS ###", self.YELLOW))
        self.write_report(f"  {self.color('Total Connections:', self.WHITE):<25} {self.color(str(stats['connections']), self.GREEN)}")
        self.write_report(f"  {self.color('Successful Logins:', self.WHITE):<25} {self.color(str(stats['successful_logins']), self.GREEN)}")
        self.write_report(f"  {self.color('Failed Logins:', self.WHITE):<25} {self.color(str(stats['failed_logins']), self.RED)}")
        self.write_report(f"  {self.color('Commands Executed:', self.WHITE):<25} {self.color(str(stats['commands_executed']), self.CYAN)}")
        self.write_report(f"  {self.color('Files Uploaded:', self.WHITE):<25} {self.color(str(stats['files_uploaded']), self.MAGENTA)}")
        self.write_report(f"  {self.color('Files Downloaded:', self.WHITE):<25} {self.color(str(stats['files_downloaded']), self.MAGENTA)}")
        self.write_report(f"  {self.color('Unique IPs:', self.WHITE):<25} {self.color(str(len(ips)), self.YELLOW)}")
        
        if ip_info:
            self.write_report(self.color("\n### TOP ATTACKER IPs WITH ABUSE CONTACTS ###", self.YELLOW))
            sorted_ips_list = sorted(ips.items(), key=lambda x: x[1], reverse=True)[:20]
            
            abuse_groups = defaultdict(list)
            for ip, count in sorted_ips_list:
                info = ip_info.get(ip, {})
                abuse_email = info.get('abuse_email', 'N/A')
                abuse_groups[abuse_email].append((ip, count, info.get('isp', 'N/A'), info.get('country', 'N/A')))
            
            for abuse_email, ip_list in sorted(abuse_groups.items(), key=lambda x: sum(i[1] for i in x[1]), reverse=True):
                if abuse_email == 'N/A':
                    self.write_report(self.color(f"\n  [Unknown Abuse Contact]", self.RED))
                else:
                    self.write_report(self.color(f"\n  [{abuse_email}]", self.CYAN))
                self.write_report(f"  {'Country':<8} {'IP':<20} {'Connections':<12} ISP")
                self.write_report(f"  {'-'*8} {'-'*20} {'-'*12} {'-'*35}")
                for ip, count, isp, country in sorted(ip_list, key=lambda x: x[1], reverse=True):
                    country_flag = self.get_country_flag(country)
                    self.write_report(f"  {country_flag:<8} {ip:<20} {count:<12} {isp[:35]}")
        
        self.write_report(self.color("\n### SUCCESSFUL LOGINS ###", self.YELLOW))
        if successful_logins:
            self.write_report(f"  {'Timestamp':<20} {'IP':<18} {'Username':<15} {'Password':<20}")
            self.write_report(f"  {'-'*20} {'-'*18} {'-'*15} {'-'*20}")
            for login in successful_logins[:15]:
                ts = login['timestamp'][:19] if login['timestamp'] else 'N/A'
                pw = login['password'][:20] if login['password'] else 'N/A'
                self.write_report(f"  {ts:<20} {login['ip']:<18} {login['username']:<15} {self.color(pw, self.RED)}")
            if len(successful_logins) > 15:
                more = len(successful_logins) - 15
                choice = self.input_with_default(self.color(f"\n  Show all {len(successful_logins)} successful logins? (y/n)", self.YELLOW))
                if choice == 'y':
                    for login in successful_logins[15:]:
                        ts = login['timestamp'][:19] if login['timestamp'] else 'N/A'
                        pw = login['password'][:20] if login['password'] else 'N/A'
                        self.write_report(f"  {ts:<20} {login['ip']:<18} {login['username']:<15} {self.color(pw, self.RED)}")
                else:
                    self.write_report(self.color(f"  ... and {more} more", self.DIM))
        else:
            self.write_report(self.color("  No successful logins", self.DIM))
        
        self.write_report(self.color("\n### FAILED LOGINS ###", self.YELLOW))
        if failed_logins:
            self.write_report(f"  {'Timestamp':<20} {'IP':<18} {'Username':<15} {'Password':<20}")
            self.write_report(f"  {'-'*20} {'-'*18} {'-'*15} {'-'*20}")
            for login in failed_logins[:15]:
                ts = login['timestamp'][:19] if login['timestamp'] else 'N/A'
                pw = login['password'][:20] if login['password'] else 'N/A'
                self.write_report(f"  {ts:<20} {login['ip']:<18} {login['username']:<15} {pw}")
            if len(failed_logins) > 15:
                more = len(failed_logins) - 15
                choice = self.input_with_default(self.color(f"\n  Show all {len(failed_logins)} failed logins? (y/n)", self.YELLOW))
                if choice == 'y':
                    for login in failed_logins[15:]:
                        ts = login['timestamp'][:19] if login['timestamp'] else 'N/A'
                        pw = login['password'][:20] if login['password'] else 'N/A'
                        self.write_report(f"  {ts:<20} {login['ip']:<18} {login['username']:<15} {pw}")
                else:
                    self.write_report(self.color(f"  ... and {more} more", self.DIM))
        else:
            self.write_report(self.color("  No failed logins", self.DIM))
        
        self.write_report(self.color("\n### USERNAME STATISTICS (Top 15) ###", self.YELLOW))
        self.write_report(f"  {'Username':<25} {'Success':<15} {'Failed':<15}")
        self.write_report(f"  {'-'*25} {'-'*15} {'-'*15}")
        sorted_creds = sorted(credentials.items(), key=lambda x: x[1]['success'], reverse=True)
        for user, data in sorted_creds[:15]:
            success_color = self.GREEN if data['success'] > 0 else self.DIM
            fail_color = self.RED if data['failed'] > 0 else self.DIM
            # right-align the numbers for better readability
            success_str = str(data['success']).rjust(9)
            fail_str = str(data['failed']).rjust(13)
            self.write_report(f"  {user:<25} {self.color(success_str, success_color)} {self.color(fail_str, fail_color)}")
        
        self.write_report(self.color("\n### EXECUTED COMMANDS (Sample) ###", self.YELLOW))
        if commands:
            unique_cmds = len(set(c['command'] for c in commands))
            self.write_report(f"  {self.color('Total unique commands:', self.WHITE)} {unique_cmds}")
            self.write_report(f"\n  {'IP':<18} {'Timestamp':<19} {'Command':<40}")
            self.write_report(f"  {'-'*18} {'-'*19} {'-'*40}")
            for cmd in commands[:25]:
                ts = cmd['timestamp'][:19] if cmd['timestamp'] else 'N/A'
                command = cmd['command'][:40] + ('...' if len(cmd['command']) > 40 else '')
                self.write_report(f"  {cmd['ip']:<18} {ts:<19} {command}")
            if len(commands) > 25:
                more = len(commands) - 25
                choice = self.input_with_default(self.color(f"\n  Show all {len(commands)} commands? (y/n)", self.YELLOW))
                if choice == 'y':
                    for cmd in commands[25:]:
                        ts = cmd['timestamp'][:19] if cmd['timestamp'] else 'N/A'
                        command = cmd['command'][:40] + ('...' if len(cmd['command']) > 40 else '')
                        self.write_report(f"  {cmd['ip']:<18} {ts:<19} {command}")
                else:
                    self.write_report(self.color(f"  ... and {more} more", self.DIM))
        else:
            self.write_report(self.color("  No commands executed", self.DIM))
        
        self.write_report(self.color("\n### UPLOADED FILES ###", self.YELLOW))
        if files_uploaded:
            self.write_report(f"  {'Filename':<30} {'SHA256 (first 20)':<22} {'IP':<18} {'Timestamp':<20}")
            self.write_report(f"  {'-'*30} {'-'*22} {'-'*18} {'-'*20}")
            for f in files_uploaded[:15]:
                sha = f['shasum'][:20] if f['shasum'] else 'N/A'
                fname = f['filename'][:30] if f['filename'] else 'N/A'
                ts = f['timestamp'][:19] if f['timestamp'] else 'N/A'
                self.write_report(f"  {fname:<30} {sha:<22} {f['ip']:<18} {ts}")
            if len(files_uploaded) > 15:
                more = len(files_uploaded) - 15
                choice = self.input_with_default(self.color(f"\n  Show all {len(files_uploaded)} uploaded files? (y/n)", self.YELLOW))
                if choice == 'y':
                    for f in files_uploaded[15:]:
                        sha = f['shasum'][:20] if f['shasum'] else 'N/A'
                        fname = f['filename'][:30] if f['filename'] else 'N/A'
                        ts = f['timestamp'][:19] if f['timestamp'] else 'N/A'
                        self.write_report(f"  {fname:<30} {sha:<22} {f['ip']:<18} {ts}")
                else:
                    self.write_report(self.color(f"  ... and {more} more", self.DIM))
        else:
            self.write_report(self.color("  No files uploaded", self.DIM))

        self.write_report(self.color("\n### EVIDENCE (Messages) ###", self.YELLOW))
        if evidence:
            self.write_report(f"  {self.color('Total events with messages:', self.WHITE)} {len(evidence)}")
            self.write_report(f"\n  {'Timestamp':<20} {'IP':<18} {'Event':<30} Message")
            self.write_report(f"  {'-'*20} {'-'*18} {'-'*30} {'-'*40}")
            for ev in evidence[:25]:
                ts = ev['timestamp'][:19] if ev['timestamp'] else 'N/A'
                ip = ev['ip'] if ev['ip'] else 'N/A'
                eventid = ev['eventid'][:30] if ev['eventid'] else 'N/A'
                msg = ev['message'] if ev['message'] else 'N/A'
                self.write_report(f"  {ts:<20} {ip:<18} {eventid:<30} {msg}")
            if len(evidence) > 25:
                more = len(evidence) - 25
                choice = self.input_with_default(self.color(f"\n  Show all {len(evidence)} evidence messages? (y/n)", self.YELLOW))
                if choice == 'y':
                    for ev in evidence[25:]:
                        ts = ev['timestamp'][:19] if ev['timestamp'] else 'N/A'
                        ip = ev['ip'] if ev['ip'] else 'N/A'
                        eventid = ev['eventid'][:30] if ev['eventid'] else 'N/A'
                        msg = ev['message'] if ev['message'] else 'N/A'
                        self.write_report(f"  {ts:<20} {ip:<18} {eventid:<30} {msg}")
                else:
                    self.write_report(self.color(f"  ... and {more} more", self.DIM))
        else:
            self.write_report(self.color("  No evidence messages", self.DIM))

        # write report to the file
        with open(self.output_report, 'w') as f:
            f.write('\n'.join(self.REPORT))
            print(self.color(f"\n[+] Report saved to: {self.output_report}", self.GREEN))

    def run(self):
        import sys
        try:
            combined_file = self.combine_logs()
            data = self.parse_logs(combined_file)
            
            sorted_ips_list = sorted(data['ips'].keys(), key=lambda x: data['ips'][x], reverse=True)
            ip_info = self.lookup_ips_concurrent(sorted_ips_list)
            
            self.print_report(data, ip_info)
        except KeyboardInterrupt:
            print(self.color("\n\n[!] Interrupted by user. Exiting...", self.RED))
            sys.exit(0)

parser = CowrieLogParser()
parser.run()