#!/usr/bin/env python3
# (c) 2025 Ankesh Anand <ankesh@bharatdatacenter.com>
# Script: fortios-irr-updater.py
#
# Usage: fortios-irrupdater.py --router <router_ip> --asn <asn> --slug <slug> --afi <ipv4|ipv6>

import sys
import configparser
import argparse
import paramiko
import time
import os
import socket

path = "/usr/share/fortios-irrupdater"

parser = argparse.ArgumentParser()
parser.add_argument("--router", help="IP address or hostname of the router", required=True)
parser.add_argument("--asn", help="ASN number", required=True)
parser.add_argument("--slug", help="Peer slug name", required=True)
parser.add_argument("--afi", help="Address family: ipv4 or ipv6", choices=['ipv4', 'ipv6'], required=True)
args = parser.parse_args()

ROUTER_IP = args.router
ASN = args.asn
SLUG = args.slug
PREFIX_LIST_NAME = f"as{ASN}-{SLUG}"

config = configparser.ConfigParser()
config_file = f"{path}/config/routers.conf"
if not os.path.exists(config_file):
    print(f"Error: Configuration file not found: {config_file}")
    sys.exit(1)

config.read(config_file)

if not config.has_section('SSH'):
    print("Error: [SSH] section not found in routers.conf")
    sys.exit(1)

try:
    username = config.get('SSH', 'username')
except configparser.NoOptionError:
    print("Error: 'username' not found in [SSH] section of routers.conf")
    sys.exit(1)

port = config.getint('SSH', 'port', fallback=22)

password = None
key_file = None
key_passphrase = None

if config.has_option('SSH', 'password'):
    password = config.get('SSH', 'password')
    if password and password != '<password>':
        auth_method = 'password'
    else:
        password = None

if config.has_option('SSH', 'key_file'):
    key_file = config.get('SSH', 'key_file')
    if key_file:
        auth_method = 'key'
        if config.has_option('SSH', 'key_passphrase'):
            key_passphrase = config.get('SSH', 'key_passphrase')
            if not key_passphrase:
                key_passphrase = None

if not password and not key_file:
    print("Error: No authentication method configured in routers.conf")
    sys.exit(1)

def cidr_to_netmask(cidr):

    mask = (0xffffffff >> (32 - cidr)) << (32 - cidr)
    return f"{(mask >> 24) & 0xff}.{(mask >> 16) & 0xff}.{(mask >> 8) & 0xff}.{mask & 0xff}"

def netmask_to_cidr(netmask):

    return sum([bin(int(x)).count('1') for x in netmask.split('.')])

def read_prefixes_from_db(asn, ip_version):

    filename = f"{path}/db/{asn}.{ip_version}.agg"
    prefixes = set()
    
    if not os.path.exists(filename):
        return prefixes
    
    with open(filename, 'r') as f:
        for line in f:
            prefix = line.strip()
            if prefix:
                prefixes.add(prefix)
    
    return prefixes

def get_le_value(prefix, is_ipv6=False):
    """Calculate le (less than) value for a prefix"""
    if is_ipv6:
        masklength = int(prefix.split('/')[1])
        if masklength == 48:
            # Exact match /48, no le needed
            return ''
        elif masklength < 48:
            # Allow subnets up to /48
            return '48'
        else:
            # Larger than /48, no le needed
            return ''
    else:
        masklength = int(prefix.split('/')[1])
        if masklength == 24:
            # Exact match /24, no le needed
            return ''
        elif masklength < 24:
            # Allow subnets up to /24
            return '24'
        else:
            # Larger than /24, no le needed
            return ''

def get_current_prefix_list(ssh_client, prefix_list_name, is_ipv6=False):
    if is_ipv6:
        cmd = f"show full-configuration router prefix-list6 {prefix_list_name}"
    else:
        cmd = f"show full-configuration router prefix-list {prefix_list_name}"
    
    stdin, stdout, stderr = ssh_client.exec_command(cmd)
    
    output = b""
    stdout.channel.settimeout(0.5)
    while True:
        try:
            data = stdout.channel.recv(8192)
            if not data:
                break
            output += data
        except socket.timeout:
            try:
                data = stdout.channel.recv(8192)
                if data:
                    output += data
                else:
                    break
            except:
                break
    
    text_output = output.decode('utf-8')
    
    prefixes = set()
    prefix_to_seq = {} 
    max_seq_num = 0
    current_seq = None
    lines = text_output.strip().split('\n')
    
    for line in lines:
        line = line.strip()
        if line.startswith('edit '):
            try:
                current_seq = int(line.split()[1])
                max_seq_num = max(max_seq_num, current_seq)
            except:
                pass
        elif line.startswith('set prefix '):
            if current_seq is not None:
                parts = line.split(maxsplit=2)[2].strip().split()
                if len(parts) == 2:
                    ip, netmask = parts
                    cidr = netmask_to_cidr(netmask)
                    prefix = f"{ip}/{cidr}"
                else:
                    prefix = parts[0]
                prefixes.add(prefix)
                prefix_to_seq[prefix] = current_seq
        elif line.startswith('set prefix6 '):
            if current_seq is not None:
                prefix = line.split(maxsplit=2)[2].strip()
                prefixes.add(prefix)
                prefix_to_seq[prefix] = current_seq
    
    return (prefixes, max_seq_num, prefix_to_seq)

def recv_until_prompt(shell, timeout=10):
    """Receive data until prompt is detected"""
    output = b""
    shell.settimeout(0.1)
    start = time.time()
    while time.time() - start < timeout:
        try:
            data = shell.recv(4096)
            if data:
                output += data
            if output.endswith(b"#") or output.endswith(b">"):
                break
        except:
            if output:
                break
    shell.settimeout(None)
    return output.decode('utf-8', errors='ignore')

def apply_updates(shell, prefix_list_name, to_add, to_delete, prefix_to_seq, is_ipv6=False, start_seq=10):
    shell.send(f"config router prefix-list{'6' if is_ipv6 else ''}\n")
    recv_until_prompt(shell)
    
    shell.send(f'edit "{prefix_list_name}"\n')
    recv_until_prompt(shell)
    
    shell.send("config rule\n")
    recv_until_prompt(shell)
    
    if to_delete:
        for prefix in to_delete:
            seq_num = prefix_to_seq.get(prefix)
            if seq_num:
                shell.send(f"delete {seq_num}\n")
                recv_until_prompt(shell)
    
    if to_add:
        seq_num = start_seq
        for prefix in to_add:
            shell.send(f"edit {seq_num}\n")
            recv_until_prompt(shell)
            
            if is_ipv6:
                shell.send(f"set prefix6 {prefix}\n")
            else:
                ip, cidr_str = prefix.split('/')
                cidr = int(cidr_str)
                netmask = cidr_to_netmask(cidr)
                shell.send(f"set prefix {ip} {netmask}\n")
            recv_until_prompt(shell)
            
            le = get_le_value(prefix, is_ipv6)
            if le:
                shell.send(f"set le {le}\n")
                recv_until_prompt(shell)
            
            shell.send("set action permit\n")
            recv_until_prompt(shell)
            
            shell.send("next\n")
            recv_until_prompt(shell)
            
            seq_num += 1
    
    shell.send("end\n")
    recv_until_prompt(shell)
    
    shell.send("end\n")
    recv_until_prompt(shell)

print(f"Connecting to {ROUTER_IP}...")
ssh_client = paramiko.SSHClient()
ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

try:
    if key_file:
        ssh_client.connect(hostname=ROUTER_IP, port=port, username=username, 
                           key_filename=key_file, passphrase=key_passphrase, timeout=10)
    else:
        ssh_client.connect(hostname=ROUTER_IP, port=port, username=username, password=password, timeout=10)
    
    print(f"Connected to {ROUTER_IP}\n")
    
    if args.afi == 'ipv4':
        print(f"Processing {PREFIX_LIST_NAME} (IPv4)...")
        desired_ipv4 = read_prefixes_from_db(ASN, '4')
        current_ipv4, max_seq_ipv4, prefix_to_seq_ipv4 = get_current_prefix_list(ssh_client, PREFIX_LIST_NAME, is_ipv6=False)
        
        print(f"  Desired: {len(desired_ipv4)}, Current: {len(current_ipv4)}")
        
        to_add_ipv4 = list(desired_ipv4 - current_ipv4)
        to_delete_ipv4 = list(current_ipv4 - desired_ipv4)
        
        if to_add_ipv4 or to_delete_ipv4:
            print(f"  Changes: +{len(to_add_ipv4)}, -{len(to_delete_ipv4)}")
            shell = ssh_client.invoke_shell()
            recv_until_prompt(shell)
            
            start_seq = max_seq_ipv4 + 1
            apply_updates(shell, PREFIX_LIST_NAME, to_add_ipv4, to_delete_ipv4, prefix_to_seq_ipv4, is_ipv6=False, start_seq=start_seq)
            print(f"  Updated")
        else:
            print(f"  No changes")

    elif args.afi == 'ipv6':
        print(f"Processing {PREFIX_LIST_NAME} (IPv6)...")
        desired_ipv6 = read_prefixes_from_db(ASN, '6')
        current_ipv6, max_seq_ipv6, prefix_to_seq_ipv6 = get_current_prefix_list(ssh_client, PREFIX_LIST_NAME, is_ipv6=True)
        
        print(f"  Desired: {len(desired_ipv6)}, Current: {len(current_ipv6)}")
        
        to_add_ipv6 = list(desired_ipv6 - current_ipv6)
        to_delete_ipv6 = list(current_ipv6 - desired_ipv6)
        
        if to_add_ipv6 or to_delete_ipv6:
            print(f"  Changes: +{len(to_add_ipv6)}, -{len(to_delete_ipv6)}")
            shell = ssh_client.invoke_shell()
            recv_until_prompt(shell)
            
            start_seq = max_seq_ipv6 + 1
            apply_updates(shell, PREFIX_LIST_NAME, to_add_ipv6, to_delete_ipv6, prefix_to_seq_ipv6, is_ipv6=True, start_seq=start_seq)
            print(f"  Updated")
        else:
            print(f"  No changes")

except paramiko.AuthenticationException:
    print(f"Authentication failed for {ROUTER_IP}")
    sys.exit(1)
except socket.gaierror as e:
    print(f"DNS/Connection error for {ROUTER_IP}: {e}")
    sys.exit(1)
except Exception as e:
    print(f"Error connecting to {ROUTER_IP}: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
finally:
    ssh_client.close()
    print(f"\nDisconnected from {ROUTER_IP}")
