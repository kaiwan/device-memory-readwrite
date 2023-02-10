# Makefile
# Cross toolchain compile for the utils on BeagleBoard (or whatever)
# Pass env var CROSS_COMPILE to the required toolchain prefix
# Also, you must ensure that the above toolchain is in your PATH
GCC := ${CROSS_COMPILE}gcc
STRIP := ${CROSS_COMPILE}strip
CFLAGS=-O2 -Wall -UDEBUG
CFLAGS_DBG=-DDEBUG -g -ggdb -gdwarf-4 -O0 -Wall -Wextra -DDEBUG_PRINT -fsanitize=address

ALL := rdmem wrmem rdmem_dbg wrmem_dbg
all: ${ALL}

rdmem: rdmem.c ../common.h
	${GCC} ${CFLAGS} rdmem.c -o rdmem
	${STRIP} --strip-all rdmem
rdmem_dbg: rdmem.c ../common.h
	${GCC} ${CFLAGS_DBG} rdmem.c -o rdmem_dbg
rdmem_dbg_static: rdmem.c ../common.h
	${GCC} ${CFLAGS_DBG} rdmem.c -o rdmem_dbg_static -static

wrmem: wrmem.c ../common.h
	${GCC} ${CFLAGS} wrmem.c -o wrmem
	${STRIP} --strip-all wrmem
wrmem_dbg: wrmem.c ../common.h
	${GCC} ${CFLAGS_DBG} wrmem.c -o wrmem_dbg
wrmem_dbg_static: wrmem.c ../common.h
	${GCC} ${CFLAGS_DBG} wrmem.c -o wrmem_dbg_static -static

clean:
	rm -fv *.o ${ALL} *~
