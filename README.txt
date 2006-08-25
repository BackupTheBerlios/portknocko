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

iptables -P INPUT DROP
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -p tcp -m pknock --knockports 2000,2001 --time 10 --name SSH --dport 22 -j ACCEPT

finally:

telnet yourserver 2000
telnet yourserver 2001

ssh user@yourserver
