#!/usr/bin/env python3

import requests
import subprocess
import sys
import re

gtfobin = []
gtfobin2 = []
url = 'https://gtfobins.github.io2'
check_suid = []

def check_file():
    with open('gtfobins.txt', 'r') as file:
        response = file.read()
        regels = response.splitlines()
        return regels
try:
    response = requests.get(url)
    response.raise_for_status()
    regels = response.text.splitlines()
except requests.exceptions.RequestException as e:
    regels = check_file()
    

arg_present = len(sys.argv) > 1

for line in regels:
    if 'a href' in line and (not arg_present or '#suid' in line):
        gtfobin.append(line.strip())
    elif 'a href' in line and arg_present:
        gtfobin2.append(line.strip())


result = subprocess.run(['find','/','-perm','-u=s'], capture_output=True,text=True)
suid_files = {line.split('/')[-1] for line in result.stdout.splitlines()}

if not arg_present:
    check_suid = sorted({suid for suid in suid_files if any(suid in line for line in gtfobin)})

    if check_suid:
        print('[+]Check SUIDS:')
        print(f'{url}/gtfobins/{check_suid[0]}')
    else:
        print('[-]No matches')
    exit(0)


for line in gtfobin2:
    if sys.argv[1] in line and 'class' in line:
        match = re.search(r'href\s*=\s*["\'](.*?)["\']',line)
        if match:
            url2 = match.group(1)
            if sys.argv[1] == url2.split('/')[-2]:
                print(f'{url}{url2}')   