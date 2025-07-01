#!/usr/bin/env python3
import os
import re
import socket
import requests
import whois
from email import policy
from email.parser import BytesParser
from colorama import Fore, init
from datetime import datetime
from pathlib import Path

init(autoreset=True)

API_KEY = "db9d3c30d8da72"
IPINFO_URL = "https://ipinfo.io/{ip}?token=" + API_KEY
LOG_PATH = str(Path.home() / ".calebsec.log")

INVESTIGATION_NAME = None
REPORT_PATH = None

def banner():
    print(Fore.CYAN + r"""
   ______      _     _           _____                 
  / ____/___  (_)___(_)___ ___  / ___/_________  ____ _
 / /   / __ \/ / ___/ / __ `__ \/ __ \/ ___/ __ \/ __ `/
/ /___/ /_/ / / /__/ / / / / / / /_/ / /  / /_/ / /_/ / 
\____/\____/_/\___/_/_/ /_/ /_/\____/_/   \____/\__,_/  
                          CalebSec v1.3 – Investigator Suite
""")
    print(Fore.YELLOW + f"[✓] Logs: {LOG_PATH}")
    if INVESTIGATION_NAME:
        print(Fore.YELLOW + f"[✓] Current Investigation: {INVESTIGATION_NAME}")
        print(Fore.YELLOW + f"[✓] Report Path: {REPORT_PATH}")
    print("")

def log(message):
    with open(LOG_PATH, "a") as f:
        f.write(f"[{datetime.now()}] {message}\n")

def set_investigation_name():
    global INVESTIGATION_NAME, REPORT_PATH
    name = input("Enter a name for this investigation (type 'back' to cancel): ").strip()
    if name.lower() == "back":
        return
    if not name:
        print(Fore.RED + "Name cannot be empty.")
        return
    INVESTIGATION_NAME = name
    REPORT_PATH = str(Path.home() / "Documents" / f"{INVESTIGATION_NAME}.txt")
    print(Fore.GREEN + f"[✓] Investigation name set to '{INVESTIGATION_NAME}'")

def save_to_report(content):
    if REPORT_PATH:
        with open(REPORT_PATH, "a") as f:
            f.write("="*50 + "\n")
            f.write(f"INVESTIGATION: {INVESTIGATION_NAME}\n")
            f.write(f"DATE: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*50 + "\n\n")
            f.write(content + "\n\n")

def ask_to_download():
    if not REPORT_PATH:
        print(Fore.RED + "You must name the investigation first (Option 1).")
        return
    choice = input("Do you want to copy this report to your Desktop? (y/n): ").strip().lower()
    if choice == "y":
        dest = Path.home() / "Desktop" / f"{INVESTIGATION_NAME}.txt"
        os.system(f"cp '{REPORT_PATH}' '{dest}'")
        print(Fore.GREEN + f"[✓] Copied to Desktop: {dest}")
    else:
        print(Fore.YELLOW + "[!] Skipped download.")

def validate_ip(ip):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip)

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "N/A"

def analyze_eml(path):
    if path.lower() == "back": return
    if not os.path.exists(path):
        print(Fore.RED + "[!] File does not exist.")
        return
    try:
        with open(path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)

        from_addr = msg.get("From")
        to_addr = msg.get("To")
        subject = msg.get("Subject")
        date = msg.get("Date")
        return_path = msg.get("Return-Path")
        message_id = msg.get("Message-ID")
        received = msg.get_all("Received", [])

        sender_ip = None
        for header in reversed(received):
            match = re.search(r'\[([\d\.]+)\]', header)
            if match:
                sender_ip = match.group(1)
                break

        content = f"""PHISHING EMAIL ANALYSIS
-------------------------
From          : {from_addr}
To            : {to_addr}
Subject       : {subject}
Date          : {date}
Return-Path   : {return_path}
Message-ID    : {message_id}
Sender IP     : {sender_ip or 'Not found'}
Received Chain:
{chr(10).join(received)}
"""
        print(Fore.MAGENTA + content)
        save_to_report(content)
        log(f"Analyzed EML: {path}")
    except Exception as e:
        print(Fore.RED + f"[!] Error analyzing EML: {e}")

def analyze_ipinfo(ip):
    if ip.lower() == "back": return
    if not validate_ip(ip):
        print(Fore.RED + "[!] Invalid IP address.")
        return
    try:
        res = requests.get(IPINFO_URL.format(ip=ip)).json()
        w = whois.whois(ip)

        proxy = res.get("privacy", {}).get("proxy", False)
        vpn = res.get("privacy", {}).get("vpn", False)
        org = res.get("org", "N/A")
        asn = res.get("asn", {}).get("asn", "N/A") if "asn" in res else "N/A"
        net_range = res.get("readme", "N/A")
        country = res.get("country", "N/A")
        loc = res.get("loc", "N/A")
        latlong = loc if loc else "N/A"
        timezone = res.get("timezone", "N/A")
        abuse = w.emails if w and w.emails else "N/A"
        r_dns = reverse_dns(ip)

        score = 0
        if vpn: score += 4
        if proxy: score += 3
        if "vultr" in org.lower() or "digitalocean" in org.lower(): score += 2
        level = "HIGH" if score >= 6 else "MEDIUM" if score >= 3 else "LOW"

        content = f"""WHOIS + IPINFO INTELLIGENCE
-------------------------
IP Address     : {ip}
Reverse DNS    : {r_dns}
Org / ISP      : {org}
ASN            : {asn}
Country        : {country}
Coordinates    : {latlong}
Time Zone      : {timezone}
Net Range/CIDR : {net_range}

ANONYMITY INDICATORS
-------------------------
VPN Detected   : {"Yes" if vpn else "No"}
Proxy Detected : {"Yes" if proxy else "No"}
Proxy Org      : {org if proxy else "N/A"}
Risk Score     : {score}/10
Risk Level     : {level}

WHOIS REGISTRATION
-------------------------
Registrar      : {w.registrar}
Name Servers   : {", ".join(w.name_servers) if w.name_servers else "N/A"}
WHOIS Org      : {w.org}
Abuse Contact  : {abuse}
Creation Date  : {w.creation_date}
Updated Date   : {w.updated_date}
Expiration     : {w.expiration_date}
"""
        print(Fore.CYAN + content)
        save_to_report(content)
        log(f"WHOIS/IPINFO enriched analysis for {ip}")
    except Exception as e:
        print(Fore.RED + f"[!] WHOIS/IPINFO error: {e}")

def analyze_rdp(ip):
    if ip.lower() == "back": return
    if not validate_ip(ip):
        print(Fore.RED + "[!] Invalid IP address.")
        return
    try:
        result = os.popen(f"nmap -Pn -sV -p 3389 {ip}").read()
        open_status = "3389/tcp open" in result
        banner_match = re.search(r"3389/tcp open\s+(\S+)", result)
        banner = banner_match.group(1) if banner_match else "Unknown"

        content = f"""RDP PORT SCAN
-------------------------
IP Address     : {ip}
RDP Port 3389  : {"Open" if open_status else "Closed"}
Service        : {banner}
Suspicion      : {"HIGH" if open_status else "LOW"}
"""
        print(Fore.YELLOW + content)
        save_to_report(content)
        log(f"RDP check on {ip}")
    except Exception as e:
        print(Fore.RED + f"[!] RDP scan failed: {e}")

def run_tool():
    while True:
        os.system("clear")
        banner()
        print(Fore.GREEN + """
1. Name Investigation
2. Analyze Phishing Email (.eml)
3. WHOIS + IP Intelligence
4. Scan IP for RDP (3389)
5. Export Report to Desktop
6. Exit
""")
        choice = input("Select an option (1–6): ").strip()
        if choice == '1':
            set_investigation_name()
        elif choice in ['2', '3', '4', '5'] and not INVESTIGATION_NAME:
            print(Fore.RED + "Please name your investigation first (Option 1).")
            input("Press Enter to return to menu...")
        elif choice == '2':
            path = input("Enter path to .eml file (or 'back'): ").strip()
            analyze_eml(path)
            input("\nPress Enter to return to menu...")
        elif choice == '3':
            ip = input("Enter IP address (or 'back'): ").strip()
            analyze_ipinfo(ip)
            input("\nPress Enter to return to menu...")
        elif choice == '4':
            ip = input("Enter IP to scan RDP (or 'back'): ").strip()
            analyze_rdp(ip)
            input("\nPress Enter to return to menu...")
        elif choice == '5':
            ask_to_download()
            input("\nPress Enter to return to menu...")
        elif choice == '6':
            print(Fore.RED + "Exiting CalebSec. Stay sharp.")
            break
        else:
            print(Fore.RED + "Invalid option.")
            input("Press Enter to return to menu...")

if __name__ == "__main__":
    run_tool()
