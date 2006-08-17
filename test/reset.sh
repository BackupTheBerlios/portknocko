iptables -F INPUT
iptables -P INPUT ACCEPT

rmmod ipt_pknock 2> /dev/null 1> /dev/null

dmesg -c 2> /dev/null 1> /dev/null
