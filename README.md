# 🍯 SSH Honeypot

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white) ![License](https://img.shields.io/badge/License-MIT-green) ![Tests](https://img.shields.io/badge/tests-passing-success) ![Status](https://img.shields.io/badge/status-active-brightgreen)

Realistic SSH honeypot built with Paramiko. Captures attacker credentials and commands, geolocates IPs, sends Telegram alerts.

## Features
- Emulates OpenSSH server (customizable banner)
- Logs: IP, username, password, timestamp → SQLite
- GeoIP enrichment (country, city, ASN)
- Telegram bot alerts
- Fake interactive shell post-auth
- CLI statistics dashboard

## Setup
```bash
pip install -r requirements.txt
ssh-keygen -t rsa -b 2048 -f honeypot_rsa -N ""

# Run on port 2222
python honeypot.py --port 2222

# With Telegram
python honeypot.py --port 2222 --telegram-token TOKEN --chat-id CHATID

# Stats
python honeypot.py --stats
```

## iptables redirect port 22 → 2222
```bash
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
```

## Responsible use

This project is published for **defensive research, education, and authorized security testing only**.
Use it exclusively on systems you own or have explicit written permission to assess. The author
assumes no liability for misuse. See `SECURITY.md` for the disclosure policy.
