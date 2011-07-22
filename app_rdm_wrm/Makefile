ALL := rdm wrm xrdm xwrm
GCC := gcc
all: ${ALL}

# Cross toolchain compile for the utils on BeagleBoard
# Update XTOOL var below to your toolchain prefix
#XTOOL := /media/Data_150GB/CodeSourcery_toolchain/bin/arm-none-linux-gnueabi-
XTOOL := arm-none-linux-gnueabi-

rdm: rdm.c ../common.h
	${GCC} -Wall rdm.c -o rdm
wrm: wrm.c ../common.h
	${GCC} -Wall wrm.c -o wrm
xrdm: rdm.c ../common.h
	${XTOOL}gcc -Wall rdm.c -o xrdm
xwrm: wrm.c ../common.h
	${XTOOL}gcc -Wall wrm.c -o xwrm

clean:
	rm -f *.o ${ALL}
