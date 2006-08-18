#!/bin/bash

function load() {
	insmod ../kernel/ipt_pknock.ko
}

function unload() {
	./reset.sh
}

function rule_set() {
	iptables -A INPUT -m state --state NEW -m pknock --dports $2 --setip --time 10 --name $1 -j DROP 1> /dev/null
}

function rule_check() {
	iptables -A INPUT -p tcp --dport $2 -m state --state NEW -m pknock --chkip --name $1 -j ACCEPT 1> /dev/null
	iptables -A INPUT -p udp --dport $2 -m state --state NEW -m pknock --chkip --name $1 -j ACCEPT 1> /dev/null
}

function expect() {
	dmesg | grep ipt_pknock | tail -n 1 >> $file
	echo $1 >> $file
}

function knock() {
	hping localhost -a $1 -p $2 -c 1 -S -2 -q --fast 2> /dev/null 1> /dev/null
}

function run() {
	testcase=$(cat $1)
	eval "$testcase"
}

function init() {
	./init.sh 2> /dev/null 1> /dev/null
	> $1
}

if [ -z $1 ]; then 
    echo "usage: ./testrunner.sh <testfile>"
    exit 1
fi

testsuite=$1

file="result.txt"

init $file

run $testsuite

python tester.py $file
