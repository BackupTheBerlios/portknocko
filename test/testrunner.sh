#!/bin/bash

function load() {
	insmod ../kernel/ipt_pknock.ko
}

function unload() {
	./reset.sh
}

function rule() {
	iptables -A INPUT -m state --state NEW -m pknock $4 --name $1 --knockports $2 -p udp --dport $3 -j ACCEPT 1> /dev/null
}

function expect() {
	dmesg | grep ipt_pknock | tail -n 1 >> $file
	echo $1 >> $file
}

function knock() {
	hping localhost -a $1 -p $2 -c 1 -S -2 -q -d 8 -E secret.txt --fast 2> /dev/null 1> /dev/null
}

function run() {
	testcase=$(cat $1)
	eval "$testcase"
}

function init() {
	./init.sh 2> /dev/null 1> /dev/null
	> $1
	echo '' > "secret.txt"
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
