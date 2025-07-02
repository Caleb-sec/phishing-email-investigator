# 🛡️ CalebSec v1.3 – Phishing Email Investigator

CalebSec v1.3 is a professional Command-Line Investigation Toolkit designed for analyzing phishing emails, IP intelligence, RDP vulnerability, and exporting investigation reports. Built for use in Kali Linux, this tool empowers cybersecurity analysts and digital forensics teams to quickly assess and document email-based threats.

---

## 🔍 Features

1. **Name Your Investigation**
   - Custom name assigned at the beginning of each session (e.g., `invest_bob_phish`)
   - Automatically used to save logs and final reports

2. **Analyze Phishing Email (.eml)**
   - Parses .eml headers, body, links, and attachments
   - Extracts sender, reply-to, X-Mailer, IPs, and potential spoof indicators
   - Flags suspicious patterns, links, spoofing signs, and malformed headers

3. **WHOIS + IP Intelligence**
   - WHOIS lookup
   - Reverse DNS, ASN, geolocation, and hosting provider
   - Detects proxy/VPN usage and owner (e.g., "Cloudflare Inc.")
   - Public blacklist reputation check

4. **Scan IP for RDP Exposure**
   - Checks if RDP port 3389 is open (attack surface detection)
   - Useful in phishing cases targeting remote access

5. **Export Investigation Report**
   - Saves all findings to `~/Documents/<investigation_name>.txt`
   - Auto-formatted with timestamp and metadata
   - Future versions will also export PDF and send Telegram/email alerts


 **Developer
- Name: Caleb Ehichioya
- Role: Cybersecurity Analyst & Tool Developer
- Email: admin@calebsec.com
- GitHub: Caleb-sec

🔐 License
This tool is released for ethical and educational use only. Redistribution or misuse for malicious purposes is prohibited.
© 2025 CalebSec. All rights reserved.

---

## 📦 Installation Instructions (Kali Linux)

```bash
# 1. Clone from GitHub
git clone https://github.com/Caleb-sec/phishing-email-investigator.git
cd phishing-email-investigator

# 2. Install the tool
sudo dpkg -i calebsec-installer.deb

# 3. Launch from anywhere
calebsec

