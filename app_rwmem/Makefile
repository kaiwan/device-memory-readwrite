# By default, build for the ARM
ALL := rdmem wrmem #x86_rdmem x86_wrmem
GCC := gcc
all: ${ALL}

#-----------------------
# Cross toolchain compile for the utils on BeagleBoard (or whatever)
# Update XTOOL var below to your toolchain prefix
#  Buildroot's uClibc toolchain
XTOOL := arm-none-linux-gnueabi-
#  CodeSourcery q3-2009 glibc toolchain
#XTOOL := arm-none-linux-gnueabi-
# Also, you must ensure that the above toolchain is in your PATH
#-----------------------

rdmem: rdmem.c ../common.h
# Uncomment the -DDEBUG_PRINT directive to actiavte the 'MSG' macro...
	${GCC} -Wall rdmem.c -o rdmem #-DDEBUG_PRINT
wrmem: wrmem.c ../common.h
	${GCC} -Wall wrmem.c -o wrmem #-DDEBUG_PRINT
#	${GCC} -Wall rdmem.c -o rdmem -DDEBUG_PRINT
#wrmem: wrmem.c ../common.h
#	${GCC} -Wall wrmem.c -o wrmem -DDEBUG_PRINT

# Uncomment the rules below for cross-compilation (for ARM-32)
#rdmem: rdmem.c ../common.h
#	${XTOOL}gcc -Wall rdmem.c -o rdmem #-DDEBUG_PRINT
#wrmem: wrmem.c ../common.h
#	${XTOOL}gcc -Wall wrmem.c -o wrmem #-DDEBUG_PRINT

clean:
	rm -f *.o ${ALL}
