#!/usr/bin/env python3

import requests
import subprocess
import sys
import re

gtfobin = []
url = 'https://gtfobins.github.io'
check_suid = []
response = requests.get(url)
regels = response.text.splitlines()

arg_present = len(sys.argv) > 1

for line in regels:
    if 'a href' in line and (not arg_present or '#suid' in line):
        gtfobin.append(line.strip())

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

for line in gtfobin:
    if sys.argv[1] in line and 'class' in line:
        regel = line
        match = re.search(r'href\s*=\s*["\'](.*?)["\']',regel)
        if match:
            url2 = match.group(1)
            print(f'{url}{url2}')