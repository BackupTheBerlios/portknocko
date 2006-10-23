#!/bin/bash

iptables -P INPUT ACCEPT
iptables -F INPUT

rmmod ipt_pknock 2> /dev/null 1> /dev/null
