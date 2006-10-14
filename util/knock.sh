#!/bin/bash
# $1 -> IP src
# $2 -> PORT dst
# $3 -> secret
# $4 -> IP dst

if [ -z $4 ]; then 
    echo "usage: $0 <IP src> <PORT dst> <secret> <IP dst>"
    exit 1
fi

digest_file="/tmp/digest.txt"

scripts/build_digest.sh $3 $1 $digest_file
scripts/knocker.sh $1 $2 $digest_file udp $4
