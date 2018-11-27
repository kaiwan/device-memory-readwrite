# Makefile
# Cross toolchain compile for the utils on BeagleBoard (or whatever)
# Pass env var CROSS_COMPILE to the required toolchain prefix
# Also, you must ensure that the above toolchain is in your PATH
GCC := ${CROSS_COMPILE}gcc
CFLAGS=-O2 -Wall -UDEBUG
CFLAGS_DBG=-g -ggdb -gdwarf-4 -O0 -Wall -Wextra -DDEBUG_PRINT

ALL := rdmem wrmem
all: ${ALL}

rdmem: rdmem.c ../common.h
	${GCC} ${CFLAGS} rdmem.c -o rdmem
rdmem_dbg: rdmem.c ../common.h
	${GCC} ${CFLAGS_DBG} rdmem.c -o rdmem_dbg
wrmem: wrmem.c ../common.h
	${GCC} ${CFLAGS} wrmem.c -o wrmem
wrmem_dbg: wrmem.c ../common.h
	${GCC} ${CFLAGS_DBG} wrmem.c -o wrmem_dbg

clean:
	rm -fv *.o ${ALL} *~
