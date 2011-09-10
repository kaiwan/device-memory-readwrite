ifeq ($(KERNELRELEASE),)  

#########################################
# To support cross-compiling for the ARM:
# For ARM, invoke make as:
# make ARCH=arm CROSS_COMPILE=arm-none-linux-gnueabi- 
ifeq ($(ARCH),arm)
# Update 'KDIR' below to point to the ARM Linux kernel source tree
KDIR ?= ~/trg/beagleboard/linux-2.6.33.2
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
	find . -name \*.o -exec rm -rf '{}' ';'
	find . -name .\*.o.cmd -exec rm -rf '{}' ';'
	find . -name \*.*~ -exec rm -rf '{}' ';'
	find . -name \*.*.bak -exec rm -rf '{}' ';'
	rm -f *.ko *.o *.mod.* .*.cmd
	rm -rf Module.symvers
	rm -rf modules.order
	rm -rf .tmp_versions

else

$(info Building with KERNELRELEASE = ${KERNELRELEASE}) 
# Uncomment the -DDEBUG_PRINT directive to actiavte the 'MSG' macro...
EXTRA_CFLAGS += -DDEBUG #-DDEBUG_PRINT
obj-m :=    rwmem.o  

endif
