/*
 * rdmem.c
 * Utility to read [I/O] memory and display it.
 *
 * Project home: 
 * http://code.google.com/p/device-memory-readwrite/
 *
 * Pl see detailed usage Wiki page here:
 * http://code.google.com/p/device-memory-readwrite/wiki/UsageWithExamples
 * 
 * License: GPL v2.
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

/* 
 * Compute the next highest power of 2 of 32-bit v
 * Credit: http://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
 */
unsigned int roundup_powerof2(unsigned int v)
{
	v--;
	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	v++;
	return v;
}

static void usage(char *name)
{
	fprintf (stderr, "\
Usage: %s [-o] <address/offset> [len]\n\
[-o]: optional parameter:\n\
 : '-o' present implies the next parameter is an OFFSET and NOT an absolute address [HEX]\n\
 (this is the typical usage for looking at hardware registers that are offset from an IO base..)\n\
 : absence of '-o' implies that the next parameter is an ADDRESS [HEX]\n\
offset -or- address : required parameter:\n\
 start offset or address to read memory from (HEX).\n\
\n\
len: optional parameter:\n\
 length : number of items to read. Default = 4 bytes (HEX)\n"
 " Restrictions: length must be in the range [%d-%d] and\n"
 " a power of 2 (if not, it will be auto rounded-up to the next ^2).\n", 
    name, MIN_LEN, MAX_LEN);
}

int main(int argc, char **argv)
{
	int fd;
	ST_RDM st_rdm;
	unsigned long orig_addr=0;

	if (argc < 2) {
		usage (argv[0]);
		exit (1);
	}

// TODO- clean up the bloody mess with args processing!
	if ((!strncmp(argv[1], "-o", 2)) && argc == 2) {	// address specified as an Offset
		fprintf (stderr, "%s: you're expected to pass the offset as a _separate_ parameter.\n"
		"Eg. you want to read 4 bytes from offset 8 onward:\n" 
		"%s -o8  <-- WRONG\n"
		"%s -o 8  <-- RIGHT\n\n", 
			argv[0], argv[0], argv[0]);
		usage (argv[0]);
		exit (1);
	}

	// Init the rdm structure
	memset (&st_rdm, 0, sizeof (ST_RDM));

	if((fd = open (DEVICE_FILE, O_RDONLY, 0)) == -1) {
		perror("device file open failed. Driver 'rwmem' not loaded?");
		exit(1); 
	}

	st_rdm.flag = !USE_IOBASE;
	errno=0;
	if (!strncmp(argv[1], "-o", 2)) {	// address specified as an Offset
		st_rdm.flag = USE_IOBASE;
		// Have to use strtoll as strtol() overflows...
		st_rdm.addr = strtoll (argv[2], 0, 16);
	}
	else {
		st_rdm.addr = strtoll (argv[1], 0, 16);
	}

	if ((errno == ERANGE && (st_rdm.addr == ULONG_MAX || st_rdm.addr == LLONG_MIN))
        || (errno != 0 && st_rdm.addr == 0)) {
strtol_err:
		perror("strtoll");
		 if (st_rdm.addr == ULONG_MAX)
			printf ("Ulong max\n");
		 if (st_rdm.addr == LLONG_MIN)
			printf ("long min\n");
 		exit(EXIT_FAILURE);
	}
	orig_addr = st_rdm.addr;
	MSG("1 st_rdm.addr=0x%x\n", (unsigned int)st_rdm.addr);

	/* Length is number of "items" to read of size "date_type" each.
	   Restrictions:
	   - should be in the range [MIN_LEN to MAX_LEN] [curr 4 - 131072]
	   - should be a power of 2. If not, it will be rounded up to the next power of 2.
	 */
	st_rdm.len = sizeof(int);
	errno=0;
	if (argc == 3) {	// either: (addr and length specified) OR ('-o' and offset) specified
		if (st_rdm.flag != USE_IOBASE)	// '-o' NOT passed and length specified
			st_rdm.len = strtol (argv[2], 0, 16);
	}
	else if (argc == 4) {	// -o passed and length specified
		st_rdm.len = strtol (argv[3], 0, 16);
	}
	if ((errno == ERANGE && (st_rdm.addr == ULONG_MAX || st_rdm.addr == LLONG_MIN))
   	  || (errno != 0 && st_rdm.addr == 0))
		goto strtol_err;

    MSG("len = 0x%x (%d) bytes\n", st_rdm.len, st_rdm.len);
    if ((st_rdm.len < MIN_LEN) || (st_rdm.len > MAX_LEN)) {
        fprintf (stderr, "%s: Invalid length (valid range: [%d-%d]).\n", 
			argv[0], MIN_LEN, MAX_LEN);
        exit (1);
    }
	st_rdm.len=roundup_powerof2(st_rdm.len);
	MSG("final: len=%d\n", st_rdm.len);


	st_rdm.buf = (unsigned char *)calloc (st_rdm.len, sizeof (unsigned char));
	if (!st_rdm.buf) {
		fprintf (stderr, "Out of memory!\n");
		exit (1);
	}

	MSG ("addr: 0x%x buf=0x%x len=0x%x flag=%d\n",
         (unsigned int)st_rdm.addr, (unsigned int)st_rdm.buf, (unsigned int)st_rdm.len, st_rdm.flag);
	if (ioctl (fd, IOCTL_RWMEMDRV_IOCGMEM, &st_rdm) == -1) {
		perror("ioctl");
		free (st_rdm.buf);
		close (fd);
		exit (1);
	}
#if 0
	for (i=0; i<st_rdm.len; i++)
		printf ("[0x%08x] 0x%02x\n", (unsigned int)&st_rdm.buf[i], (unsigned int)st_rdm.buf[i]);
	MSG ("\naddr: 0x%x buf=0x%x len=0x%x data_type=%d\n",
         (unsigned int)orig_addr, (unsigned int)st_rdm.buf, st_rdm.len, data_type);
#endif

	//void hex_dump(char *data, int size, char *caption, int verbose)
	hex_dump(st_rdm.buf, st_rdm.len, "MemDump", 0);
	free (st_rdm.buf);
	close (fd);
	return 0;
}

