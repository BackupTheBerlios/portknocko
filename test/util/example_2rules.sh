#!/bin/sh

if [ -z $1 ]; then
	echo "usage: $0 <secret>"
	exit 1
fi

scripts/init.sh

insmod ../kernel/ipt_pknock.ko
		
iptables -A INPUT -m state --state NEW -m pknock --name SSH --secure qweasd --time 10 --knockports 2000,2001 -p udp -j DROP

iptables -A INPUT -m state --state NEW -m pknock --name SSH --checkip -p tcp --dport 22 -j ACCEPT
