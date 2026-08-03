#!/usr/bin/env python3
"""
SSH Honeypot - Credential logging with geo-enrichment + Telegram alerts
Author: nadirzhon | github.com/nadirzhon
"""

import socket
import threading
import paramiko
import sqlite3
import argparse
import requests
import os
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

DB_FILE = "honeypot.db"

class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, client_ip, db, telegram=None):
        self.client_ip = client_ip
        self.db = db
        self.telegram = telegram
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        geo = self._geoip()
        entry = {
            "ts": datetime.now().isoformat(),
            "ip": self.client_ip,
            "user": username,
            "pass": password,
            "country": geo.get("country_name", "?"),
            "city": geo.get("city", "?"),
            "asn": geo.get("asn", "?")
        }
        self._save(entry)
        print(f"  {Fore.RED}[ATTEMPT]{Style.RESET_ALL} {entry['ip']} ({entry['country']}) | {Fore.YELLOW}{username}:{password}{Style.RESET_ALL}")
        if self.telegram:
            self._notify(entry)
        return paramiko.AUTH_FAILED

    def check_channel_pty_request(self, c, t, w, h, wp, hp, modes): return True
    def check_channel_shell_request(self, ch): self.event.set(); return True

    def _geoip(self):
        try:
            return requests.get(f"https://ipapi.co/{self.client_ip}/json/", timeout=3).json()
        except Exception:
            return {}

    def _save(self, e):
        try:
            self.db.execute("INSERT INTO attempts VALUES (?,?,?,?,?,?,?)",
                           (e["ts"],e["ip"],e["user"],e["pass"],e["country"],e["city"],e["asn"]))
            self.db.commit()
        except Exception:
            pass

    def _notify(self, e):
        token, chat_id = self.telegram
        msg = f"SSH Honeypot\nIP: {e['ip']} ({e['country']}, {e['city']})\nCreds: {e['user']}:{e['pass']}\nTime: {e['ts']}"
        try:
            requests.post(f"https://api.telegram.org/bot{token}/sendMessage",
                         json={"chat_id": chat_id, "text": msg}, timeout=5)
        except Exception:
            pass

def init_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.execute("CREATE TABLE IF NOT EXISTS attempts (ts,ip,username,password,country,city,asn)")
    conn.commit()
    return conn

def show_stats():
    conn = sqlite3.connect(DB_FILE)
    total = conn.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]
    print(f"\nTotal attempts: {total}")
    print("\nTop IPs:")
    for r in conn.execute("SELECT ip,country,COUNT(*) c FROM attempts GROUP BY ip ORDER BY c DESC LIMIT 10"):
        print(f"  {r[2]:5d}x {r[0]:15s} ({r[1]})")
    print("\nTop Passwords:")
    for r in conn.execute("SELECT password,COUNT(*) c FROM attempts GROUP BY password ORDER BY c DESC LIMIT 10"):
        print(f"  {r[1]:5d}x {r[0]}")
    conn.close()

def handle(client, addr, db, host_key, telegram):
    transport = None
    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(host_key)
        transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu"
        server = HoneypotServer(addr[0], db, telegram)
        transport.start_server(server=server)
        ch = transport.accept(20)
        if ch:
            ch.send("Last login: Mon Aug 4 10:23:41 2026\r\n$ ")
            while True:
                data = ch.recv(1024).decode(errors="ignore").strip()
                if not data or data in ("exit","logout"): break
                print(f"  {Fore.MAGENTA}[CMD]{Style.RESET_ALL} {addr[0]}: {data}")
                ch.send(f"bash: {data.split()[0]}: command not found\r\n$ ")
    except Exception:
        pass
    finally:
        if transport: transport.close()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--host-key", default="honeypot_rsa")
    parser.add_argument("--telegram-token")
    parser.add_argument("--chat-id")
    parser.add_argument("--stats", action="store_true")
    args = parser.parse_args()

    if args.stats: show_stats(); return
    if not os.path.exists(args.host_key):
        print(f"Generate key: ssh-keygen -t rsa -f honeypot_rsa -N \"\""); return

    db = init_db()
    key = paramiko.RSAKey.from_private_key_file(args.host_key)
    tg = (args.telegram_token, args.chat_id) if args.telegram_token else None

    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", args.port))
    sock.listen(100)
    print(f"{Fore.GREEN}[*] Honeypot on :{args.port} | DB: {DB_FILE}{Style.RESET_ALL}")

    while True:
        client, addr = sock.accept()
        threading.Thread(target=handle, args=(client,addr,db,key,tg), daemon=True).start()

if __name__ == "__main__":
    main()
