#!/usr/bin/env python3

import requests
import subprocess
import sys
import re
import os

gtfobin = []
gtfobin2 = []
url = 'https://gtfobins.github.io2'
check_suid = []
local_file = 'gtfobins.txt'

def check_local_file():
    if not os.path.isfile(local_file):
        print(f'[ERROR]Local file {local_file} does not exist')
        exit(1)
    


def check_file():
    print(f'[!]No online resource {url} found, checking with local file {local_file}...')
    check_local_file()
    with open(local_file, 'r') as file:
        response = file.read()
        regels = response.splitlines()
        return regels
    

def read_gtfobin(regels,arg_present):
    for line in regels:
        if 'a href' in line and (not arg_present or '#suid' in line):
            gtfobin.append(line.strip())
        elif 'a href' in line and arg_present:
            gtfobin2.append(line.strip())


def find_suids(arg_present):
    result = subprocess.run(['find','/','-perm','-u=s'], capture_output=True,text=True)
    suid_files = {line.split('/')[-1] for line in result.stdout.splitlines()}

    if not arg_present:
        check_suid = sorted({suid for suid in suid_files if any(suid in line for line in gtfobin)})

        if check_suid:
            print('[+]Check SUIDS:')
            print(f'[FOUND] {url}/gtfobins/{check_suid[0]}')
        else:
            print('[-]No matches')
        exit(0)


def find_all():
    for line in gtfobin2:
        if sys.argv[1] in line and 'class' in line:
            match = re.search(r'href\s*=\s*["\'](.*?)["\']',line)
            if match:
                url2 = match.group(1)
                if sys.argv[1] == url2.split('/')[-2]:
                    print(f'{url}{url2}')
                    exit(0) 
            
    print(f'[-]No matches for {sys.argv[1]} ')


def main():
    arg_present = len(sys.argv) > 1

    try:
        response = requests.get(url)
        response.raise_for_status()
        regels = response.text.splitlines()
    except requests.exceptions.RequestException as e:
        regels = check_file()
    read_gtfobin(regels,arg_present)
    
    if arg_present:
        find_all()
    else:
        find_suids(arg_present)
    

if __name__=='__main__':
    main()