#!/bin/sh

if [ -z $2 ]; then
	echo "usage: $0 <opensecret> <closesecret>"
	exit 1
fi

iptables -P INPUT DROP

iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -A INPUT -p udp -m state --state NEW \
	-m pknock --knockports 2000 --name SSH --opensecret $1 --closesecret $2 -j DROP

iptables -A INPUT -p tcp -m state --state NEW -m pknock --checkip --name SSH -m tcp --dport 22 -j ACCEPT
