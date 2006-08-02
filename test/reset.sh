#!/bin/sh

make clean
iptables -F INPUT
iptables -P INPUT ACCEPT
rmmod ipt_pknock
