INSTALLATION
------------

cd portknocko

cd iptables
make clean
make
make install
cd ..

cd kernel
make clean
make
make install

depmod -Ae

note: if you use: "insmod ./ipt_pknock.ko", first you should do "modprobe cn" to load the netlink connector.


USAGE:
------

We will show you some different possibilites on how to use this module:

1) "the simplest way", one rule portknocking:

$ iptables -P INPUT DROP
$ iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
$ iptables -A INPUT -m state --state NEW -m pknock --name SSH --knockports 2000,2001 -p tcp --dport 22 -j ACCEPT

$ telnet yourserver 2000 # first knock
$ telnet yourserver 2001 # last knock

$ ssh user@yourserver

all knocks and traffic must be TCP packets.

options:
--------

[--time] 	-> max time between knocks.
[--strict] 	-> if the peer fails one knock during the sequence, must start over.	


2) "the crypt way", hmac auth with two rules:

$ iptables -P INPUT DROP
$ iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
$ iptables -A INPUT -m state --state NEW -m pknock --name SSH --knockports 2000,2001 --secure your_secret -p udp -j DROP
$ iptables -A INPUT -m state --state NEW -m pknock --name SSH --checkip -p tcp --dport 22 -j ACCEPT

this way you must send each UDP knock packet with a payload containing a md5 hmac digest:

	md5_hmac(your_secret, your_ip)

after the sequence is complete, you can begin the TCP traffic through port 22.

We provide you a client for knocking the crypt way:

$ cd test
$ util/knock.sh <IP src> <PORT dst> <secret>

e.g: util/knock.sh 127.0.0.1 2000 your_secret


TESTS: (be careful, it will erase your loaded iptables rules)
------

if you are a developer you want to run these while you refactor the code.

cd test/
./testrunner.sh all.test

note: we use a modified hping version that does not wait 1 sec for each sent packet as the original version, so tests can run much faster.
