#!/bin/sh

scripts/init.sh

insmod ../kernel/ipt_pknock.ko
		
iptables -A INPUT -m state --state NEW -m pknock --name SSH --time 10 --knockports 2003,2001,2005 -p tcp --dport 22 -j ACCEPT
