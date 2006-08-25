#!/bin/sh

./reset.sh

iptables -P INPUT DROP
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

dmesg -c 2> /dev/null 1> /dev/null

# what about this?:
#iptables -A INPUT -m state --state NEW -m pknock --knockports 2000,2001 -p udp --dport 22 --secure --name SSH -j ACCEPT
