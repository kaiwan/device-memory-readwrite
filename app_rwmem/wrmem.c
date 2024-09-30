/*
 * wrmem.c
 *
 * Part of the DEVMEM-RW opensource project - a simple 
 * utility to read / write [I/O] memory and display it.
 * This is the 'write' functionality app.
 * We assume the corresponding device driver is loaded when you run this...
 *
 * Project home: 
 * https://github.com/kaiwan/device-memory-readwrite
 *
 * Pl see detailed overview and usage PDF doc here:
 * https://github.com/kaiwan/device-memory-readwrite/blob/master/Devmem_HOWTO.pdf
 * 
 * License: Dual MIT/GPL
 * Author: (c) Kaiwan N Billimoria, kaiwanTECH
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "../common.h"

int main(int argc, char **argv)
{
	int fd;
	ST_WRM st_wrm;

	if (syscheck() == -1) {
		fprintf(stderr, "%s: System check failed, aborting..\n"
			"(As of now, this implies you do not have udev support\n"
			"This project requires the kernel and userspace to support udev).\n",
			argv[0]);
		exit(EXIT_FAILURE);
	}
	if (0 != geteuid()) {
		fprintf(stderr, "%s: This app requires root access.\n",
			argv[0]);
		exit(EXIT_FAILURE);
	}
#ifdef DEBUG
	// to allow testing of rdmem / wrmem for usermode virtual addresses (uva's)
	memtest();
#endif
	if (argc < 3) {
		fprintf(stderr,
"Usage: %s [-o] <address/offset> <value>\n"
"[-o]: optional parameter:\n"
" : '-o' present implies the next parameter is an OFFSET and NOT an absolute address [HEX]\n"
" (this is the typical usage for writing to hardware registers that are offset from an IO base..)\n"
" : absence of '-o' implies that the next parameter is an ADDRESS [HEX]\n"
"offset -or- address : required parameter:\n"
" memory offset or address to write to (HEX).\n"
"\n"
"value: required parameter:\n"
" data to write to above address/offset (4 bytes) (HEX).\n"
 "\n%s\n"
 "\n%s\n",
	argv[0], usage_warning_msg, rdwrmem_tips_msg);
		exit(EXIT_FAILURE);
	}

	// Init the wrm structure
	memset(&st_wrm, 0, sizeof(ST_WRM));

	if ((fd = open(DEVICE_FILE, O_RDWR | O_CLOEXEC, 0)) == -1) {
		fprintf(stderr, "%s: device file - %s - open failed! (Is the driver module 'devmem_rw.ko' not loaded?)",
			argv[0], DEVICE_FILE);
		perror("device file open failed");
		exit(EXIT_FAILURE);
	}

	st_wrm.flag = !USE_IOBASE;
	errno = 0;
	if ((argc == 4) && (!strncmp(argv[1], "-o", 2))) {	// address specified as an Offset
		st_wrm.flag = USE_IOBASE;
		// Have to use strtoull (for 64 bit) as strtol() overflows...
		st_wrm.addr = strtoull(argv[2], 0, 16);
	} else {
		st_wrm.addr = strtoull(argv[1], 0, 16);
	}
	if ((errno == ERANGE
	     && (st_wrm.addr == ULONG_MAX || (long long)st_wrm.addr == LLONG_MIN))
	    || (errno != 0 && st_wrm.addr == 0)) {
		perror("strtoll addr");
		exit(EXIT_FAILURE);
	}
	MSG("addr/offset = %p\n", (void *)st_wrm.addr);

	errno = 0;
	if (st_wrm.flag == USE_IOBASE)
		st_wrm.val = strtoll(argv[3], 0, 16);
	else
		st_wrm.val = strtoll(argv[2], 0, 16);
	if ((errno == ERANGE
	     && (st_wrm.val == ULONG_MAX || (long long)st_wrm.val == LLONG_MIN))
	    || (errno != 0 && st_wrm.val == 0)) {
		perror("strtoll val");
		exit(EXIT_FAILURE);
	}

	if (st_wrm.flag != USE_IOBASE) { // we've been passed an absolute (user/kernel virtual) address
		/* Let's verify it before attempting to use it in the kernel driver;
		 * if it's a userspace addr, check it's validity, else we simply assume it's a valid kernel va
		 */
		if (is_user_address(st_wrm.addr)) { 
			if (uaddr_valid(st_wrm.addr) == -1) {
				fprintf(stderr,
				"%s: the (usermode virtual) address passed (%p) seems to be invalid. Aborting...\n"
				"%s\n",
				argv[0], (void *)st_wrm.addr, rdwrmem_tips_msg);
				close(fd);
				exit(EXIT_FAILURE);
			}
		}
	}

	MSG("addr: %p val=0x%x\n",
	    (void *)st_wrm.addr, (unsigned int)st_wrm.val);
	if (ioctl(fd, IOCTL_RWMEMDRV_IOCSMEM, &st_wrm) == -1) {
		perror("ioctl");
		close(fd);
		exit(EXIT_FAILURE);
	}
#ifdef DEBUG
	//void hex_dump(char *data, unsigned int size, char *caption, int verbose)
	hex_dump((unsigned char *)st_wrm.addr, 4, "Write Test MemDump", 1);
#endif

	close(fd);
	exit(EXIT_SUCCESS);
}
