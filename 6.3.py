import subprocess
from subprocess import PIPE, Popen
from scapy.all import Raw, IP, TCP, rdpcap, Scapy_Exception
import re
import datetime
import time
import os
import requests
import hashlib

if os.geteuid() != 0:
    print(" Must run as root.")
    exit()

auth_log = "/home/crown/auth.log"
ban_log = "/home/crown/ban.log"
alert_log = "/home/crown/alert.log"
pcap_file = "/home/crown/file.pcap"

suspicious_ports = [4444, 1337, 9001, 31337, 12345]
keywords = [
    r"bash\s+-i", r"python\s+-c", r"nc\s+-e", r"base64\s+-d",
    r"wget\s+http", r"curl\s+http", r"/cmd\.php\?cmd=", r"socat"
]

date = lambda: datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def ban(ip):
    cmd = f"iptables -A INPUT -s {ip} -j DROP"
    try:
        subprocess.run(cmd, shell=True, check=True)
        print(f"[{date()}] IP BANNED: {ip}")
        with open(ban_log, "a") as b_log:
            b_log.write(f"{date()} {ip} BANNED\n")
    except subprocess.CalledProcessError as e:
        print(f"[{date()}] FAILED TO BAN {ip}: {e}")
        with open(ban_log, "a") as b_log:
            b_log.write(f"{date()} FAILED TO BAN {ip}: {e}\n")

def unban(ip):
    cmd = f"iptables -D INPUT -s {ip} -j DROP"
    try:
        subprocess.run(cmd, shell=True, check=True)
        print(f"{date()} UNBANNED {ip}")
        with open(ban_log, "a") as b:
            b.write(f"{date()} UNBANNED {ip}\n")
    except subprocess.CalledProcessError as e:
        print(f"{date()} FAILED TO UNBAN {ip} ERROR: {e}")

def geo(ip):
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = resp.json()
        if data.get("status") == "success":
            return f"{data.get('country', 'Unknown')} - {data.get('city', 'Unknown')} - {data.get('isp', 'Unknown')}"
        else:
            return "Geolocation lookup failed"
    except:
        return "Geolocation request failed"

def log_alert(level, message):
    with open(alert_log, "a") as a_log:
        a_log.write(f"{date()} [{level}] {message}\n")

def calculate_file_hash(file_path):
    hasher = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                hasher.update(chunk)
        return hasher.hexdigest()
    except:
        return None

last_auth_log_position = 0
old_auth_log_hash = calculate_file_hash(auth_log)

print(f"[{date()}] SYSTEM ACTIVE – WATCHING LOGS + PCAP...\n")

while True:
    try:
        with open(auth_log, "r") as f:
            f.seek(last_auth_log_position)
            new_lines = f.readlines()
            last_auth_log_position = f.tell()

            for line in new_lines:
                if re.search(r"Failed password for", line, re.IGNORECASE):
                    match = re.search(r"from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                    if match:
                        ip = match.group(1)
                        print(f"[{date()}]  ALERT: Failed SSH login attempt from {ip}")
                        log_alert("ALERT", f"Failed SSH login from {ip} | GEO: {geo(ip)} | LINE: {line.strip()}")
    except:
        pass

    try:
        if os.path.exists(pcap_file):
            packets = rdpcap(pcap_file)
            for p in packets:
                if p.haslayer(Raw) and p.haslayer(TCP) and p.haslayer(IP):
                    try:
                        payload = p[Raw].load.decode(errors='ignore')
                    except:
                        continue

                    for pattern in keywords:
                        if re.search(pattern, payload, re.IGNORECASE):
                            ip = p[IP].src
                            port = p[TCP].dport
                            msg = f"PATTERN MATCH: {pattern} | IP: {ip} | PORT: {port} | GEO: {geo(ip)} | PAYLOAD: {payload[:100]}"
                            print(f"[{date()}] {msg}")
                            log_alert("ALERT", msg)

                            choice = input("1. BAN IP  2. UNBAN IP  3. SKIP  4. EXIT: ").strip()
                            if choice == "1":
                                ban(ip)
                            elif choice == "2":
                                unban(ip)
                            elif choice == "4":
                                exit()
    except:
        pass

    current_auth_log_hash = calculate_file_hash(auth_log)
    if current_auth_log_hash and old_auth_log_hash and current_auth_log_hash != old_auth_log_hash:
        print(f"[{date()}]  WARNING: auth.log file integrity changed!")
        log_alert("TRIPWIRE", "auth.log file integrity changed!")
        old_auth_log_hash = current_auth_log_hash

    time.sleep(5)
