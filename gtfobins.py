#!/usr/bin/env python3

import requests
import subprocess
import sys
import re

gtfobin = []
url = 'https://gtfobins.github.io'
check_suid = []
response = requests.get(url)
file = response.text
regels = file.splitlines()

for line in regels:
    if line.strip() != "":
        if len(sys.argv) == 1:
            if 'a href' and '#suid' in line:
                gtfobin.append(line.strip())
        else:
            if 'a href' in line:
                gtfobin.append(line.strip())

result = subprocess.run(['find','/','-perm','-u=s'], capture_output=True,text=True)
output = result.stdout
output_lines = output.splitlines()
suid_files = {line.split('/')[-1] for line in output_lines}

if len(sys.argv)==1:
    for suid in sorted(suid_files):
        for line in gtfobin:
            #print(line,suid)
            if suid in line:
                check_suid.append(suid)
                break

    if check_suid:
        print('[+]Check SUIDS:')
        print(f'{url}/gtfobins/{check_suid[0]}')
    else:
        print('[-]No matches')
    exit(0)

for line in gtfobin:
    if sys.argv[1] in line:
        if 'class' in line:
            regel = line
            match = re.search(r'href\s*=\s*["\'](.*?)["\']',regel)
            if match:
                url2 = match.group(1)
                print(f'{url}{url2}')