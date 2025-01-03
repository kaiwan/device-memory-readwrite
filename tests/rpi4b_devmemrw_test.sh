#!/bin/bash
# R Pi 4B: devmem_rw load helper script
### NOTE ###
# The values in this test script are particular to the hardware;
# the Raspberry Pi 4B
############
die()
{
echo >&2 "FATAL: $*" ; exit 1
}

KDRV_LOC=../drv_rwmem
KDRV=devmem_rw
APP_LOC=../app_rwmem
RDMEM=${APP_LOC}/rdmem
WRMEM=${APP_LOC}/wrmem
[[ ! -f ${KDRV_LOC}/${KDRV}.ko ]] && die "First build the ${KDRV_LOC}/${KDRV}.ko module"
[[ ! -f ${RDMEM} ]] && die "First build the ${RDMEM} app"
#[[ ! -f ${WRMEM} ]] && die "First build the ${WRMEM} app"

REGION=watchdog
   # Ref: Broadcom 2835 (/2837) ARM Peripherals.pdf doc
IOMEM_NAME=my_${REGION}  # in /proc/iomem
OFFSET=0               # offset from base address to start mapping
FORCE_REL=1

sudo grep ${REGION} /proc/iomem |tail -n1 || die "can't find appropriate IO region (${REGION})"
BASE_ADDR=$(sudo grep watchdog /proc/iomem |tail -n1|cut -d: -f1|cut -d- -f1|xargs)
BASE_ADDR_END=$(sudo grep watchdog /proc/iomem |tail -n1|cut -d: -f1|cut -d- -f2|xargs)
BASE_ADDR=0x${BASE_ADDR^^}
BASE_ADDR_END=0x${BASE_ADDR_END^^}
LEN=$(printf "%u" $((${BASE_ADDR_END}-${BASE_ADDR}+1)))

#sudo grep "${BASE_ADDR2}" /proc/iomem || {
#  echo "MMIO region from ${BASE_ADDR} not found? aborting..." ; exit 1
#}

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
sudo ${RDMEM} -o 0 ${LEN} || {
  sudo rmmod ${KDRV} 2>/dev/null
  echo "*fail*" ; exit 1
}
sudo rmmod ${KDRV} 2>/dev/null
echo "Success"
exit 0
