#!/bin/sh

iptables -P INPUT DROP

iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -A INPUT -p tcp -m state --state NEW -m pknock --knockports 3000,2000,4000 --time 10 --name SSH \
	-m tcp --dport 22 -j ACCEPT
