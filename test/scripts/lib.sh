#!/bin/bash

function load() {
	#modprobe cn
	#modprobe sha256
	modprobe ipt_pknock
}

function unload() {
	scripts/reset.sh
}

function rule_only() {
	iptables -A INPUT -m state --state NEW -m pknock $4 --name $1 --knockports $2 -p udp --dport $3 -j ACCEPT 1> /dev/null
}

function rule_set() {
	iptables -A INPUT -m state --state NEW -m pknock $3 --name $1 --knockports $2 -p udp -j DROP 1> /dev/null
}

function rule_check() {
	iptables -A INPUT -m state --state NEW -m pknock --name $1 --checkip -p tcp --dport $2 -j ACCEPT 1> /dev/null
}

function expect() {
	dmesg | grep ipt_pknock | tail -n 1 >> $result_file
	echo $1 >> $result_file
	echo -n '.'
}

function knock_udp() {
	scripts/knocker.sh $1 $2 $digest_file udp "localhost"
}

function knock_tcp() {
	scripts/knocker.sh $1 $2 $digest_file tcp "localhost"
}

function set_hmac() {
	scripts/build_digest.sh $1 $2 $digest_file
}

function init() {
	../util/init.sh 2> /dev/null 1> /dev/null
	> $1
	echo '' > $2
}
