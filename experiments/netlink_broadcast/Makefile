KERNEL_DIR=/usr/src/linux-$(shell uname -r)

TARGET=kernel.o

obj-m:=$(TARGET)
kernel-objs:=$(OBJS)
TARGETS := $(obj-m:.o=.ko)

all:		
	$(MAKE) -C $(KERNEL_DIR) SUBDIRS=$$PWD modules

$(TARGETS): all

clean:		
	rm -f .*.cmd *.mod.c *.ko *.o core user $(TARGETS)
	rm -fr .tmp_versions
