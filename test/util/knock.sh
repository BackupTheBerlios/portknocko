#!/bin/bash
# $1 -> IP src
# $2 -> PORT dst
# $3 -> secret

if [ -z $3 ]; then 
    echo "usage: $0 <IP src> <PORT dst> <secret>"
    exit 1
fi

scripts/build_digest.sh $3 $1
scripts/knocker.sh $1 $2
