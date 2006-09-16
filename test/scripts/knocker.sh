#!/bin/bash
# $1 -> IP src
# $2 -> PORT dst
# $3 -> digest file
hping localhost -a $1 -p $2 -c 1 -S -2 -q -d 32 -E $3 --fast 2> /dev/null 1> /dev/null
