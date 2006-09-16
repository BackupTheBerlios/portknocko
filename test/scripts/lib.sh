#!/bin/bash

function load() {
	modprobe cn
	insmod ../kernel/ipt_pknock.ko
}

function unload() {
	scripts/reset.sh
}

function rule() {
	iptables -A INPUT -m state --state NEW -m pknock $4 --name $1 --time 5 --knockports $2 -p udp --dport $3 -j ACCEPT 1> /dev/null
}

function expect() {
	dmesg | grep ipt_pknock | tail -n 1 >> $result_file
	echo $1 >> $result_file
	echo -n '.'
}

function knock() {
	scripts/knocker.sh $1 $2 $digest_file
}

function set_hmac() {
	scripts/build_digest.sh $1 $2 $digest_file
}

function init() {
	scripts/init.sh 2> /dev/null 1> /dev/null
	> $1
	echo '' > $2
}
