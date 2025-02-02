#!/usr/bin/env python3

import sys
import os

def scan_hosts(ip_range):
    print(f'\n[START] start nmap scan on the live hosts... ')
    for item in ip_range:
        print(f'\n ----{item}-nmap.txt---')
        try:
            os.system(f'nmap -Pn -n -p- -A {item} > {item}-nmap.txt')
            os.system(f'cat {item}-nmap.txt')
            print(f'\n[INFO] starting UDP scan top25 for {item}...')
            os.system(f'sudo nmap -Pn -sU --top-ports 25 {item} --open >> {item}-nmap.txt')
        except Exception as e:
            print(e)
            exit(1)
    
    print(f'[DONE] scanning of hosts is complete!')

def fping_scan(network_range):
    ip_range = []    
    try:
        os.system(f'fping -ag {network_range} > networkscan.txt')

        with open('networkscan.txt','r') as file:
            filetext = file.readlines()
            for text in filetext:
                if text.strip().split('.')[3] != ('254' or '1'):
                    ip_range.append(text.strip())
    except Exception as e:
        print(f'[ERROR] {e}')
        exit(1)
    
    print('[INFO] found live hosts:')
    for item in ip_range:
        print(f'[+] {item}')

    scan_hosts(ip_range)

def main(network):
    print(f'[INFO] scanning {network}/24 ...')
    network_range=f'{network}/24'
    fping_scan(network_range)
    os.system('rm -rf networkscan.txt')


if __name__=='__main__':
    
    if len(sys.argv) >= 2:
        network=sys.argv[1]
        main(network)
    else:
        print('[ERROR] usage: python3 scan-network.py 192.168.244.153')
        exit(1)

