# By default, build for the ARM
ALL := rdmem wrmem x86_rdmem x86_wrmem
GCC := gcc
all: ${ALL}

#-----------------------
# Cross toolchain compile for the utils on BeagleBoard (or whatever)
# Update XTOOL var below to your toolchain prefix
#  Buildroot's uClibc toolchain
XTOOL := arm-unknown-linux-uclibcgnueabi-
#  CodeSourcery q3-2009 glibc toolchain
#XTOOL := arm-none-linux-gnueabi-
# Also, you must ensure that the above toolchain is in your PATH
#-----------------------

x86_rdmem: rdmem.c ../common.h
# Uncomment the -DDEBUG_PRINT directive to actiavte the 'MSG' macro...
	${GCC} -Wall rdmem.c -o x86_rdmem #-DDEBUG_PRINT
x86_wrmem: wrmem.c ../common.h
	${GCC} -Wall wrmem.c -o x86_wrmem #-DDEBUG_PRINT
rdmem: rdmem.c ../common.h
	${XTOOL}gcc -Wall rdmem.c -o rdmem #-DDEBUG_PRINT
wrmem: wrmem.c ../common.h
	${XTOOL}gcc -Wall wrmem.c -o wrmem #-DDEBUG_PRINT

clean:
	rm -f *.o ${ALL}
