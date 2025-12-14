#!/bin/bash
# Script for fetching BGP prefixes from IRR database
# (c) 2025 Ankesh Anand <ankesh@bharatdatacenter.com>

path=/usr/share/fortios-irrupdater

if [ ! -f $path/config/peers.conf ]; then
    echo "Configuration File 'peers.conf' not found."
    exit 1
fi

while IFS=',' read -r param1 param2; do
    if [ -n "$param1" ] && [ -n "$param2" ]; then
        $path/bin/fetchprefixes.sh "$param1" "$param2"
    fi
done < $path/config/peers.conf
