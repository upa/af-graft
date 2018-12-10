KERNELSRCDIR := /lib/modules/$(shell uname -r)/build
BUILD_DIR := $(shell pwd)
VERBOSE = 0

obj-m := af_graft.o

ccflags-y := -I$(src)/../include/

all:
	echo $(ccflags-y)
	make -C $(KERNELSRCDIR) M=$(BUILD_DIR) V=$(VERBOSE) modules

install:
	install -m 644 -D ./af_graft.ko \
		/lib/modules/$(shell uname -r)/kernel/drivers/misc/
	depmod -a

clean:
	make -C $(KERNELSRCDIR) M=$(BUILD_DIR) clean
