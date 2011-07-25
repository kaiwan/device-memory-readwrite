ALL := rdmem wrmem xrdmem xwrmem
GCC := gcc
all: ${ALL}

# Cross toolchain compile for the utils on BeagleBoard (or whatever)
# Update XTOOL var below to your toolchain prefix
XTOOL := arm-none-linux-gnueabi-

rdmem: rdmem.c ../common.h
	${GCC} -Wall rdmem.c -o rdmem
wrmem: wrmem.c ../common.h
	${GCC} -Wall wrmem.c -o wrmem
xrdmem: rdmem.c ../common.h
	${XTOOL}gcc -Wall rdmem.c -o xrdmem
xwrmem: wrmem.c ../common.h
	${XTOOL}gcc -Wall wrmem.c -o xwrmem

clean:
	rm -f *.o ${ALL}
