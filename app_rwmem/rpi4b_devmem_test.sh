#!/bin/bash
# R Pi 4B: devmem_rw load helper script
### NOTE ###
# The values in this test script are particular to the hardware;
# the Raspberry Pi 4B
############
KDRV=devmem_rw
BASE_ADDR=0xfe00b880    # R Pi 3B interrupt registers, as an example region to view...
OFFSET=0                # offset from base address to start mapping
   # Ref: Broadcom 2835 (/2837) ARM Peripherals.pdf doc
LEN=64                  # bytes
IOMEM_NAME=mailbox      # in /proc/iomem
FORCE_REL=0

sudo rmmod ${KDRV} 2>/dev/null
sudo dmesg -C
BUSADDR=$((${BASE_ADDR}+${OFFSET}))

CMD=$(printf "sudo insmod ../drv_rwmem/${KDRV}.ko iobase_start=0x%x iobase_len=%d reg_name=%s force_rel=${FORCE_REL}\n" \
	${BUSADDR} ${LEN} ${IOMEM_NAME})
echo ${CMD}

eval ${cmd} || exit 1
lsmod|grep ${KDRV}
sudo dmesg
sudo grep "${IOMEM_NAME}" /proc/iomem
