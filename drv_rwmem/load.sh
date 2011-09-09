#!/bin/sh
DRV=rwmem
export PATH=/sbin:/bin:$PATH

[ `id -u` -ne 0 ] && {
  echo "Need to be root."
  exit 1
}
# remove any stale driver instance
lsmod|grep $DRV >/dev/null && rmmod $DRV
make clean; sync
make || exit 1
dmesg -c
sync

# Use a pathname, as new modutils don't look in the current dir by default
insmod ./$DRV.ko $*
