#!/bin/bash
# FOr the TI BBB (Beagle Bone Black): devmem_rw load helper script
### NOTE ###
# The values in this test script are particular to the hardware;
# the TI BBB
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

#-----------------------------------------------------------------------------
BASE_ADDR=0x44E10600   # the TI BBB Device_ID register !
# Details:
# Ref: TI AM335x TRM (spruh73q) pg 174
# Table 1-1. Device_ID (Address 0x44E10600) Bit Field Descriptions
# Bit     Field     Value Description
# ---     -----     ----- -----------
# 31-28   DEVREV      	Device revision
# 	                  0000b - Silicon Revision 1.0
#      	 	          0001b - Silicon Revision 2.0
#      	       	  	  0010b - Silicon Revision 2.1
#                	 See device errata for detailed information on
# 		       	 functionality in each device revision.
# 			Reset value is revision-dependent.
# 27-12   PARTNUM       Device part number 
# 			 0xB944
# 11-1    MFGR 		Manufacturer's ID
# 			 0x017
# 0       Reserved	Read always as 0
# 			 0x0
#-----------------------------------------------------------------------------

OFFSET=0               # offset from base address to start mapping
LEN=4                  # bytes
IOMEM_NAME=bbb_devid   # in /proc/iomem
FORCE_REL=0

#BASE_ADDR2=${BASE_ADDR:2}
#sudo grep -i "${BASE_ADDR2}" /proc/iomem || {
#  echo "MMIO region from ${BASE_ADDR} not found? aborting..." ; exit 1
#}

sudo rmmod ${KDRV} 2>/dev/null
sudo dmesg -C

echo "Having devmem_rw hook into the TI BBB Device_ID register at ${BASE_ADDR} now..."
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
sudo ${RDMEM} -o 0 ${LEN} || {
  sudo rmmod ${KDRV} 2>/dev/null
  echo "*fail*" ; exit 1
}
sudo rmmod ${KDRV} 2>/dev/null

echo "
Read successful; expected data (reversed on little-endian of course):
2b 94 40 2e

Interpret it as shown:
Ref: TI AM335x TRM (spruh73q) pg 174
Table 1-1. Device_ID (Address 0x44E10600) Bit Field Descriptions
Bit     Field     Value Description
---     ------    ----- -----------
31-28   DEVREV      	Device revision
	                  0000b - Silicon Revision 1.0
	     	          0001b - Silicon Revision 2.0
     	       	  	  0010b - Silicon Revision 2.1
        	       	 See device errata for detailed information on
		       	 functionality in each device revision.
			 Reset value is revision-dependent.
27-12   PARTNUM         Device part number 
			 0xB944
11-1    MFGR 		Manufacturer's ID
			 0x017
0       Reserved	Read always as 0
			 0x0
"
exit 0
