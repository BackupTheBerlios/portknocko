KERNEL_DIR_INC=/usr/src/linux
IPT_LIB_DIR=/lib/iptables/
IPTABLES_VERSION=$(shell iptables -V | sed 's/iptables v//')

CC=cc
LD=cc
CFLAGS=-O2 -Wall -Wunused -I$(KERNEL_DIR_INC) -Iinclude/ -DIPTABLES_VERSION=\"$(IPTABLES_VERSION)\"  -fPIC
LDFLAGS=-shared

OBJS=libipt_pknock_sh.o
LIBS=libipt_pknock.so

all : $(OBJS) $(LIBS)

$(OBJS): libipt_pknock.c
	$(CC) $(CFLAGS) -o $@ -c $^

$(LIBS): libipt_pknock_sh.o
	$(LD) $(LDFLAGS) -o $@ $^

install:
	cp libipt_pknock.so $(IPT_LIB_DIR)

uninstall:
	rm -fv $(IPT_LIB_DIR)$(LIBS)

clean:
	rm -fv $(OBJS) $(LIBS) *.o *.so *.so.* *~

