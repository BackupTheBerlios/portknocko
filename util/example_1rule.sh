#!/bin/sh

./init.sh

iptables -A INPUT -p tcp -m state --state NEW \
			-m pknock --knockports 2003,2001,2005 --time 10 --name SSH \
			-m tcp --dport 22 -j ACCEPT
