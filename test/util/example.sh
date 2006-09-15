#!/bin/sh

if [ -z $1 ]; then
	echo "usage: $0 <secret>"
	exit 1
fi

scripts/init.sh

insmod ../kernel/ipt_pknock.ko secret=$1
		
iptables -A INPUT -m state --state NEW -m pknock --secure --name SSH --time 5 --knockports 2000 -p udp --dport 22 -j ACCEPT
