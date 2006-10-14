#!/bin/sh

if [ -z $2 ]; then
	echo "usage: $0 <opensecret> <closesecret>"
	exit 1
fi

scripts/init.sh

insmod ../kernel/ipt_pknock.ko
		
iptables -A INPUT -m state --state NEW -m pknock --name SSH --opensecret $1 --closesecret $2 --time 10 --knockports 2000 -p udp -j DROP

iptables -A INPUT -m state --state NEW -m pknock --name SSH --checkip -p tcp --dport 22 -j ACCEPT
