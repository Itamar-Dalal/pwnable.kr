obj-m += anti_rootkit.o

KDIR := /lib/modules/3.7.1-030701-generic/build
PWD := $(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean