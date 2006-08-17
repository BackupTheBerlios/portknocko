#!/bin/bash

function load() {
	insmod ../kernel/ipt_pknock.ko	
}

function rule1() {
	iptables -A INPUT -m state --state NEW -m pknock --dports $2,$3 --setip --time 10 --name $1 -j DROP 1> /dev/null
}

function rule2() {
	iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport $2 -m pknock --chkip --name $1 -j ACCEPT 1> /dev/null
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
	./rules.sh 2> /dev/null 1> /dev/null
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
