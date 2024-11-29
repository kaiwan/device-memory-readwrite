#!/bin/bash
# R Pi 4B: devmem_rw load helper script
### NOTE ###
# The values in this test script are particular to the hardware;
# the Raspberry Pi 4B
############
KDRV_LOC=../drv_rwmem
KDRV=devmem_rw
BASE_ADDR=0xfe00b880   # one of the R Pi 4B mailbox registers, as an example region to view...
OFFSET=0               # offset from base address to start mapping
   # Ref: Broadcom 2835 (/2837) ARM Peripherals.pdf doc
LEN=64                 # bytes
IOMEM_NAME=my_mailbox  # in /proc/iomem
FORCE_REL=1

BASE_ADDR2=${BASE_ADDR:2}
sudo grep "${BASE_ADDR2}" /proc/iomem || {
  echo "MMIO region from ${BASE_ADDR} not found? aborting..." ; exit 1
}

sudo rmmod ${KDRV} 2>/dev/null
sudo dmesg -C

BUSADDR=$((${BASE_ADDR}+${OFFSET}))
CMD=$(printf "sudo insmod ${KDRV_LOC}/${KDRV}.ko iobase_start=0x%x iobase_len=%d reg_name=%s force_rel=${FORCE_REL}\n" ${BUSADDR} ${LEN} ${IOMEM_NAME})
echo ${CMD}

#sudo sh -c "${cmd}" || exit 1
eval "${CMD}" || {
  sudo dmesg ; exit 1
}
lsmod|grep ${KDRV}
sudo dmesg
sudo grep "${IOMEM_NAME}" /proc/iomem
sudo ../app_rwmem/rdmem -o 0 ${LEN} || {
  sudo rmmod ${KDRV} 2>/dev/null
  echo "*fail*" ; exit 1
}
sudo rmmod ${KDRV} 2>/dev/null
echo "Success"
exit 0
