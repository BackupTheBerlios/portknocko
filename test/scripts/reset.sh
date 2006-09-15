#!/bin/bash
iptables -F INPUT
iptables -P INPUT ACCEPT

rmmod ipt_pknock 2> /dev/null 1> /dev/null
