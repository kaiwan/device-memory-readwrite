#!/bin/bash
# For the devmem_rw project
# Test Case:
# Here, we want to read & write some kernel memory..
# This implies we need to know where it is! So we have this test module
# - kmod_rw_test.ko - to do this for us...
# It allocates 2 pages of RAM and fills it with the pattern 0xdead face !
# We then use our rdmem / wrmem apps to read/write it via the devmem_rw.ko
# driver of course...

die()
{
echo >&2 "FATAL: $*" ; exit 1
}

KDRV_LOC=../../drv_rwmem
KDRV=devmem_rw
KMOD_TEST=kmod_rw_test

APP_LOC=../../app_rwmem
RDMEM=${APP_LOC}/rdmem
WRMEM=${APP_LOC}/wrmem
#-----------------------------------------------------------------------------

# Parameters
#  $1 : pathname to kernel module to load
load_module()
{
sudo rmmod ${1} 2>/dev/null
sudo dmesg -C
CMD="sudo insmod ${1}"
echo ${CMD}

eval "${CMD}" || {
  echo "*kmod $1 insmod fail*"
  sudo dmesg ; exit 1
}
lsmod|head
sudo dmesg
}


#--- 'main'
[[ ! -f ${KDRV_LOC}/${KDRV}.ko ]] && die "First build the ${KDRV_LOC}/${KDRV}.ko module"
[[ ! -f ${KMOD_TEST}.ko ]] && die "First build the ${KMOD_TEST}.ko module"
[[ ! -f ${RDMEM} ]] && die "First build the ${RDMEM} app"
[[ ! -f ${WRMEM} ]] && die "First build the ${WRMEM} app"

load_module ${KDRV_LOC}/${KDRV}.ko
load_module ./${KMOD_TEST}.ko

# extract the kva where RAM is alloc'ed & 'poisoned'
kva=$(sudo dmesg |grep "allocated 8192 bytes of RAM at kernel va"|awk '{print $NF}')
[[ -z "${kva}" ]] && die "couldn't get the kva where ${KMOD_TEST}.ko alloc'ed 2 pages"

echo
echo "Target kernel va (virtual address) is ${kva}"

# rdmem test
NUM=100
CMD="sudo ${RDMEM} ${kva} ${NUM} | tee /tmp/rwmem.out"
echo "
------------- RDMEM TEST --------------"
echo "${CMD}"
eval "${CMD}"
grep "de ad fa ce de ad fa ce" /tmp/rwmem.out >/dev/null && echo "${RDMEM} PASSED" || echo "*FAIL*"

# wrmem test
echo "
------------- WRMEM TEST --------------"
TOWRITE=1122eeff
CMD="sudo ${WRMEM} ${kva} ${TOWRITE}"
echo "${CMD}"
eval "${CMD}"
sudo ${RDMEM} ${kva} ${NUM} | tee /tmp/rwmem2.out
grep "ff ee 22 11 de ad fa ce" /tmp/rwmem2.out >/dev/null && echo "${WRMEM} PASSED" || echo "*FAIL*"
echo "(NOTE: on little-endian systems the chars \"${TOWRITE}\" appear reversed in memory
 ('deadface' appears 'normally' as our ${KMOD_TEST}.ko driver took the trouble to detect endian-ness and accordingly byte-swap as required, but this isn't how it usually works))"

exit 0



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
