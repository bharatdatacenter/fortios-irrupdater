#!/bin/sh
# Script for pushing BGP prefix-lists to FortiOS routers
# (c) 2025 Ankesh Anand <ankesh@bharatdatacenter.com>

path=/usr/share/fortios-irrupdater

# Check if the configuration file exists
if [ ! -f $path/config/sessions.conf ]; then
    echo "Configuration File 'sessions.conf' not found."
    exit 1
fi

# Read the input file line by line
while IFS=',' read -r asn slug router afi; do
    afi=$(echo "$afi" | tr -d ' \r\n')
    
    if [ -n "$asn" ] && [ -n "$slug" ] && [ -n "$router" ] && [ -n "$afi" ]; then
        if [ "$afi" = "ipv4" ]; then
            # Run for IPv4 only
            python3 $path/bin/fortios-irrupdater.py --router $router --asn $asn --slug $slug --afi $afi
        elif [ "$afi" = "ipv6" ]; then
            # Run for IPv6 only
            python3 $path/bin/fortios-irrupdater.py --router $router --asn $asn --slug $slug --afi $afi
        else
            echo "Invalid value for AFI: $afi"
        fi
    fi
done < $path/config/sessions.conf
