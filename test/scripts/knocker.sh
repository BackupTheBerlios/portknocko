#!/bin/bash
# $1 -> IP src
# $2 -> PORT dst
# $3 -> digest file
# $4 -> udp or tcp
# $5 -> IP dst
# hping $5 -a $1 -p $2 -c 1 -S -q -d 65 -E $3 --fast $4 2> /dev/null 1> /dev/null
nemesis $4 -S $1 -D $5 -y $2 -P $3 2> /dev/null 1> /dev/null
