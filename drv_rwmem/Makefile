ifeq ($(KERNELRELEASE),)  

#########################################
# To support cross-compiling for the ARM:
# For ARM, invoke make as:
# make ARCH=arm CROSS_COMPILE=arm-none-linux-gnueabi- 
# -or-
# make ARCH=arm CROSS_COMPILE=arm-buildroot-linux-uclibcgnueabi-      <-- for the R Pi!
# (or whatever CROSS_COMPILE should be...)
ifeq ($(ARCH),arm)
   # *UPDATE* 'KDIR' below to point to the ARM Linux kernel source tree
   KDIR ?= ~/DG-L3/RPi/kernel_RPi/linux-3.6.11-rpi
   #KDIR ?= ~/DG-L3/pandaboard/custom/kernel/linux-3.1.5
   #KDIR ?= ~/DG-L3/linux-3.2.21 # for QEMU ARM/Linux
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

$(info Building with KERNELRELEASE = ${KERNELRELEASE}) 
# Uncomment the -DDEBUG_PRINT directive to actiavte the 'MSG' macro...
EXTRA_CFLAGS += -DDEBUG #-DDEBUG_PRINT
obj-m :=    rwmem.o  

endif
