#!/bin/bash
# Script for fetching BGP prefixes using BGPQ4
# Adapted from MikroTik IRR Updater (c) 2023 Lee Hetherington <lee@edgenative.net>
# (c) 2025 Ankesh Anand <ankesh@bharatdatacenter.com>

path=/usr/share/fortios-irrupdater

bgpq4 -F '%n/%l \n' -4 -A $2 > $path/db/$1.4.agg
bgpq4 -F '%n/%l \n' -6 -A $2 > $path/db/$1.6.agg
