ifeq ($(KERNELRELEASE),)  

#########################################
# To support cross-compiling for the ARM:
# For ARM, invoke make as:
# make ARCH=arm CROSS_COMPILE=<cross-compile-prefix>
#  Eg. make ARCH=arm CROSS_COMPILE=arm-linux-gnueabi-
ifeq ($(ARCH),arm)
   # *UPDATE* 'KDIR' below to point to the ARM Linux kernel source tree
   KDIR ?= ~/big/scratchpad/SEALS_staging/SEALS_staging_vexpress/linux-4.14.52/
   #KDIR ?= ~/DG-L3/RPi/kernel_RPi/linux-3.6.11-rpi
   #KDIR ?= ~/DG-L3/pandaboard/custom/kernel/linux-3.1.5
else
   KDIR ?= /lib/modules/$(shell uname -r)/build 
endif
#########################################

PWD := $(shell pwd)  

.PHONY: build clean  

build:
	$(MAKE) -Wall -C $(KDIR) M=$(PWD) modules
install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

else

# Uncomment the -DDEBUG_PRINT directive to actiavte the 'MSG' macro...
EXTRA_CFLAGS += -g -ggdb -DDEBUG_PRINT #-DUSE_FTRACE_PRINT

$(info Building\: ARCH=${ARCH}, CROSS_COMPILE=${CROSS_COMPILE}, KERNELRELEASE=${KERNELRELEASE} and EXTRA_CFLAGS=${EXTRA_CFLAGS})

obj-m := devmem_rw.o
devmem_rw-objs := rwmem.o debugfs_hooks.o

endif
