#!/bin/sh

iptables -P INPUT DROP

iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -A INPUT -p tcp -m state --state NEW -m pknock --dports 2002,2000 --setip --name SSH -j DROP
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -m pknock --chkip --name SSH -j ACCEPT
