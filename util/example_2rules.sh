#!/bin/sh

if [ -z $2 ]; then
	echo "usage: $0 <opensecret> <closesecret>"
	exit 1
fi

./init.sh

iptables -A INPUT -p udp -m state --state NEW \
			-m pknock --opensecret $1 --closesecret $2 --knockports 2000 --name SSH -j DROP

iptables -A INPUT -p tcp -m state --state NEW \
			-m pknock --checkip --name SSH \
			-m tcp --dport 22 -j ACCEPT
