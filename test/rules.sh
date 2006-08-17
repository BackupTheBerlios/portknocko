#!/bin/sh

./reset.sh

iptables -P INPUT DROP
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# what about this?:
# iptables -A INPUT -p tcp -m state --state NEW -m pknock --knock-ports 2000,2001 --door-port 22 --name SSH -j ACCEPT
