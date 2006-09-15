#!/bin/bash
# $1 -> secret
# $2 -> IP src
python py/gen_hmac.py $1 $2 > "cache/digest.txt"
