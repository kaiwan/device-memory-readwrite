/*
 * wrmem.c
 * Utility to write to [I/O] memory (4 bytes).
 *
 * Project home: 
 * http://code.google.com/p/device-memory-readwrite/
 *
 * Pl see detailed usage Wiki page here:
 * http://code.google.com/p/device-memory-readwrite/wiki/UsageWithExamples
 *
 * License: GPL v2.
 *
 * Author: Kaiwan N Billimoria.
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

	if (argc < 3) {
		fprintf (stderr, "\
Usage: %s [-o] <address/offset> <value>\n\
[-o]: optional parameter:\n\
 : '-o' present implies the next parameter is an OFFSET and NOT an absolute address [HEX]\n\
 (this is the typical usage for writing to hardware registers that are offset from an IO base..)\n\
 : absence of '-o' implies that the next parameter is an ADDRESS [HEX]\n\
offset -or- address : required parameter:\n\
 memory offset or address to write to (HEX).\n\
\n\
value: required parameter:\n\
 data to write to above address/offset (4 bytes) (HEX).\n", argv[0]);
		exit (1);
	}

	// Init the wrm structure
	memset (&st_wrm, 0, sizeof (ST_WRM));

	if((fd = open (DEVICE_FILE, O_RDWR, 0)) == -1) {
		perror("device file open failed. Driver 'rwmem' not loaded?");
		exit(1); 
	}

	st_wrm.flag = !USE_IOBASE;
	errno=0;
	if ((argc == 4) && (!strncmp(argv[1], "-o", 2))) {	// address specified as an Offset
		st_wrm.flag = USE_IOBASE;
		// Have to use strtoll as strtol() overflows...
		st_wrm.addr = strtoll (argv[2], 0, 16);
	} else {
		st_wrm.addr = strtoll (argv[1], 0, 16);
	}
	if ((errno == ERANGE && (st_wrm.addr == ULONG_MAX || st_wrm.addr == LLONG_MIN))
        || (errno != 0 && st_wrm.addr == 0)) {
		perror("strtoll addr");
 		exit(EXIT_FAILURE);
	}
	MSG ("addr/offset = 0x%08x\n", (unsigned int)st_wrm.addr);

	errno=0;
	if (st_wrm.flag == USE_IOBASE)
		st_wrm.val = strtoll (argv[3], 0, 16);
	else
		st_wrm.val = strtoll (argv[2], 0, 16);
	if ((errno == ERANGE && (st_wrm.val == ULONG_MAX || st_wrm.val == LLONG_MIN))
        || (errno != 0 && st_wrm.val == 0)) {
		perror("strtoll val");
 		exit(EXIT_FAILURE);
	}

	MSG ("addr: 0x%x val=0x%x\n",
         (unsigned int)st_wrm.addr, (unsigned int)st_wrm.val);
	if (ioctl (fd, IOCTL_RWMEMDRV_IOCSMEM, &st_wrm) == -1) {
		perror("ioctl");
		close (fd);
		exit (1);
	}

	close (fd);
	return 0;
}

