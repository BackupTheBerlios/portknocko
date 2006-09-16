#!/bin/bash
# $1 -> secret
# $2 -> IP src
# $3 -> digest file
python py/gen_hmac.py $1 $2 > $3
