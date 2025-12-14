#!/usr/bin/env python3
# Script for generating BGP prefix-list for FortiOS 7
# (c) 2025 Ankesh Anand <ankesh@bharatdatacenter.com>

import os
import sys

path = "/usr/share/fortios-irrupdater"

def cidr_to_netmask(cidr):
    """Convert CIDR prefix length to dotted decimal netmask"""
    mask = (0xffffffff >> (32 - cidr)) << (32 - cidr)
    return f"{(mask >> 24) & 0xff}.{(mask >> 16) & 0xff}.{(mask >> 8) & 0xff}.{mask & 0xff}"

def generate_ipv4_filter(slug, asn):
    """Generate FortiOS prefix-list configuration for IPv4"""
    with open(f"{path}/filters/as{asn}-{slug}-ipv4.txt", "w") as f:
        f.write(f"config router prefix-list\n")
        f.write(f"    edit \"as{asn}-{slug}\"\n")
        f.write(f"        config rule\n")
        
        with open(f"{path}/db/{asn}.4.agg", "r") as prefixes:
            for prefix in prefixes:
                prefix = prefix.strip()
                if not prefix:
                    continue
                ip, cidr_str = prefix.split("/")
                masklength = int(cidr_str)
                netmask = cidr_to_netmask(masklength)
                
                f.write(f"            edit\n")
                if masklength == 24:
                    # Prefix is a /24 - exact match
                    f.write(f"                set prefix {ip} {netmask}\n")
                    f.write(f"                unset ge\n")
                    f.write(f"                unset le\n")
                elif masklength < 24:
                    # Prefix is less specific than /24 - allow up to /24
                    f.write(f"                set prefix {ip} {netmask}\n")
                    f.write(f"                set ge {masklength}\n")
                    f.write(f"                set le 24\n")
                else:
                    # Prefix is more specific than /24 - exact match only
                    f.write(f"                set prefix {ip} {netmask}\n")
                    f.write(f"                unset ge\n")
                    f.write(f"                unset le\n")
                
                f.write(f"            next\n")
        
        f.write(f"        end\n")
        f.write(f"    next\n")
        f.write(f"end\n")

def generate_ipv6_filter(slug, asn):
    """Generate FortiOS prefix-list configuration for IPv6"""
    with open(f"{path}/filters/as{asn}-{slug}-ipv6.txt", "w") as f:
        f.write(f"config router prefix-list6\n")
        f.write(f"    edit \"as{asn}-{slug}\"\n")
        f.write(f"        config rule\n")
        
        with open(f"{path}/db/{asn}.6.agg", "r") as prefixes6:
            for prefix6 in prefixes6:
                prefix6 = prefix6.strip()
                if not prefix6:
                    continue
                masklength6 = int(prefix6.split("/")[1])
                
                f.write(f"            edit\n")
                if masklength6 == 48:
                    # Prefix is a /48 - exact match
                    f.write(f"                set prefix6 {prefix6}\n")
                    f.write(f"                unset ge\n")
                    f.write(f"                unset le\n")
                elif masklength6 < 48:
                    # Prefix is less specific than /48 - allow up to /48
                    f.write(f"                set prefix6 {prefix6}\n")
                    f.write(f"                set ge {masklength6}\n")
                    f.write(f"                set le 48\n")
                else:
                    # Prefix is more specific than /48 - exact match only
                    f.write(f"                set prefix6 {prefix6}\n")
                    f.write(f"                unset ge\n")
                    f.write(f"                unset le\n")
                
                f.write(f"            next\n")
        
        f.write(f"        end\n")
        f.write(f"    next\n")
        f.write(f"end\n")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 fortios-filtergen.py <slug> <ASN>")
        sys.exit(1)

    slug = sys.argv[1]
    asn = sys.argv[2]

    generate_ipv4_filter(slug, asn)
    generate_ipv6_filter(slug, asn)
    print(f"Generated FortiOS prefix-lists for AS{asn} with slug '{slug}'")
