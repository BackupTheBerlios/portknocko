#!/bin/bash
# $1 -> IP src
# $2 -> PORT dst
# $3 -> secret

if [ -z $3 ]; then 
    echo "usage: $0 <IP src> <PORT dst> <secret>"
    exit 1
fi

digest_file="cache/digest.txt"

scripts/build_digest.sh $3 $1 $digest_file
scripts/knocker.sh $1 $2 $digest_file -2
