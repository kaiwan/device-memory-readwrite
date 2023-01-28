#!/bin/bash
# R Pi 3B[+]: devmem_rw load helper script
### NOTE ###
# The values in this test script are particular to the hardware;
# the Raspberry Pi 3B[+]
############
BASE_ADDR=0x7e00b000    # R Pi 3B interrupt registers, as an example region to view...
OFFSET=0x200            # offset from base address to start mapping
   # Ref: Broadcom 2835 (/2837) ARM Peripherals.pdf doc
LEN=0x28            # bytes
IOMEM_NAME=rpi_intr  # in /proc/iomem
FORCE_REL=0

sudo rmmod devmem_rw 2>/dev/null
sudo dmesg -C
let BUSADDR=${BASE_ADDR}+${OFFSET}
printf "devmem_rw: BASEADDR = 0x%x, len=%d bytes, name=%s\n" ${BUSADDR} ${LEN} ${IOMEM_NAME}
cmd="sudo insmod ../drv_rwmem/devmem_rw.ko iobase_start=${BUSADDR} iobase_len=${LEN} reg_name=${IOMEM_LBL} force_rel=${FORCE_REL}"
#echo ${cmd}
sudo rmmod devmem_rw >/dev/null 2>&1
eval ${cmd} || exit 1
lsmod|grep devmem_rw
sudo dmesg
sudo grep "${IOMEM_NAME}" /proc/iomem
