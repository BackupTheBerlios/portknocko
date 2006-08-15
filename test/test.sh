#!/bin/sh

iptables -P INPUT DROP

iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -A INPUT -p tcp -m state --state NEW -m pknock --dports 2000,2001 --setip --time 10 --name SSH -j DROP
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -m pknock --chkip --name SSH -j ACCEPT

# what about this?:
# iptables -A INPUT -p tcp -m state --state NEW -m pknock --knock-ports 2000,2001 --door-port 22 --name SSH -j ACCEPT
