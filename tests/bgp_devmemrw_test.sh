#!/bin/bash
# For the TI BGP (BeaglePlay) AM625 SoC platform: devmem_rw load helper script
### NOTE ###
# The values in this test script are particular to the hardware;
# the TI BGP AM625 SoC
############
APP_LOC=../app_rwmem
RDMEM=rdmem
KDRV_LOC=../drv_rwmem
KDRV=devmem_rw
#-----------------------------------------------------------------------------
# Details:
# Ref: TI AM62x TRM (spruiv7b)
#  https://www.ti.com/lit/ug/spruiv7a/spruiv7a.pdf
# Ref Summary Table on pg 5433 : 14.2.1.1.3 WKUP_CTRL_MMR Registers
#  Table 14-5430. cfg0, WKUP_CTRL_MMR0_CFG0 Registers, Base Address=4300 0000H, Length=131072
# 
#   0h 32 WKUP_CTRL_MMR_PID PID register 4300 0000h
#   8h 32 WKUP_CTRL_MMR_MMR_CFG1         4300 0008h
#     [ ... ]
# 200h 32 WKUP_CTRL_MMR_MAC_ID0          4300 0200h   <-- targeting this and
# 204h 32 WKUP_CTRL_MMR_MAC_ID1          4300 0204h   <-- this one
#     [ ... ]

BASE_ADDR=0x43000000
OFFSET=0x200                # offset from base address to start mapping
LEN=8                       # bytes
IOMEM_NAME=bgp_mac_id0_id1  # in /proc/iomem
FORCE_REL=0

sudo rmmod ${KDRV} 2>/dev/null
sudo dmesg -C

BUSADDR=$((${BASE_ADDR}+${OFFSET}))
CMD=$(printf "sudo insmod ${KDRV_LOC}/${KDRV}.ko iobase_start=0x%x iobase_len=%d reg_name=%s force_rel=%d\n" ${BUSADDR} ${LEN} ${IOMEM_NAME} ${FORCE_REL})
echo ${CMD}

eval "${CMD}" || {
  echo "*kdrv insmod fail*"
  sudo dmesg ; exit 1
}
lsmod|grep ${KDRV}
sudo dmesg
sudo grep "${IOMEM_NAME}" /proc/iomem

echo "
Reading the BGP's two MAC ID registers here:
Offset Length         Register Name         WKUP_CTRL_MMR0 Physical Address
200h       32    WKUP_CTRL_MMR_MAC_ID0                  4300 0200h
    15-0 :   32 lsbs of MAC address
204h       32    WKUP_CTRL_MMR_MAC_ID1                  4300 0204h
    15-0 :   32 msbs of MAC address
"

sudo ${APP_LOC}/${RDMEM} -o 0 ${LEN} || {
  sudo rmmod ${KDRV} 2>/dev/null
  echo "*rdmem failed*" ; exit 1
}
sudo rmmod ${KDRV} 2>/dev/null

INTF=eth0
echo "
Read successful; expected data (the ${INTF} network interface's MAC address):
$(ip a|grep -w -A1 ${INTF}|head -n2|awk '{print $2}'|tail -n1)
(Take the endian-ness - little-endian - into account and it works)"
exit 0
