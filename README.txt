how to use it:
--------------

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


iptables -P INPUT DROP
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -m state --state NEW -m pknock --knockports 2000,2001 --time 10 --name SSH -p tcp --dport 22 -j ACCEPT

finally:

telnet yourserver 2000
telnet yourserver 2001

ssh user@yourserver


how to run the tests: (be careful, it will erase your loaded iptables rules)
---------------------

cd test/
./testrunner.sh all.test
