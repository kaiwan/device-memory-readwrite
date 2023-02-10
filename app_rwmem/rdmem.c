/*
 * rdmem.c
 *
 * Part of the DEVMEM-RW opensource project - a simple 
 * utility to read / write [I/O] memory and display it.
 * This is the 'read' functionality app.
 * We assume the corresponding device driver is loaded when you run this...
 *
 * Project home: 
 * https://github.com/kaiwan/device-memory-readwrite
 *
 * Pl see detailed overview and usage PDF doc here:
 * https://github.com/kaiwan/device-memory-readwrite/blob/master/Devmem_HOWTO.pdf
 * 
 * License: MIT
 * Author: Kaiwan N Billimoria
 *         kaiwanTECH.
 */
#include "../common.h"
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

static void usage(char *name)
{
	fprintf(stderr, "\
Usage: %s [-o] <address/offset> [len]\n\
[-o]: optional parameter:\n\
 : '-o' present implies the next parameter is an OFFSET and NOT an absolute address [HEX]\n\
 (this is the typical usage for looking at hardware registers that are offset from an IO base..)\n\
 : absence of '-o' implies that the next parameter is an ADDRESS [HEX]\n\
offset -or- address : required parameter:\n\
 start offset or address to read memory from (HEX).\n\
\n\
len: optional parameter:\n\
 length : number of items to read. Default = 4 bytes\n"
 " Restrictions: length must be in the range [%d-%d] and\n"
 " a power of 2 (if not, it will be auto rounded-up to the next ^2).\n"
 "\n%s\n",
	name, MIN_LEN, MAX_LEN, usage_warning_msg);
}

int main(int argc, char **argv)
{
	int fd;
	ST_RDM st_rdm;

	if (syscheck() == -1) {
		fprintf(stderr, "%s: System check failed, aborting..\n"
			"(As of now, this implies you do not have udev support\n"
			"This project requires the kernel and userspace to support udev).\n",
			argv[0]);
		exit(1);
	}
	if (0 != geteuid()) {
		fprintf(stderr, "%s: This app requires root access.\n",
			argv[0]);
		exit(1);
	}
	if (argc < 2) {
		usage(argv[0]);
		exit(1);
	}

// TODO- clean up the bloody mess with args processing!
	if ((!strncmp(argv[1], "-o", 2)) && argc == 2) {	// address specified as an Offset
		fprintf(stderr,
			"%s: you're expected to pass the offset as a _separate_ parameter.\n"
			"Eg. you want to read 4 bytes from offset 8 onward:\n"
			"%s -o8  <-- WRONG\n" "%s -o 8  <-- RIGHT\n\n", argv[0],
			argv[0], argv[0]);
		usage(argv[0]);
		exit(1);
	}

	// Init the rdm structure
	memset(&st_rdm, 0, sizeof(ST_RDM));

	if ((fd = open(DEVICE_FILE, O_RDONLY | O_CLOEXEC, 0)) == -1) {
		perror
		    ("device file open failed. Driver 'devmem_rw' not loaded?");
		exit(1);
	}

	st_rdm.flag = !USE_IOBASE;
	errno = 0;
	if (!strncmp(argv[1], "-o", 2)) {	// address specified as an Offset
		st_rdm.flag = USE_IOBASE;
		// Have to use strtoull as strtol() overflows...
		st_rdm.addr = strtoull(argv[2], 0, 16);
	} else {
		st_rdm.addr = strtoull(argv[1], 0, 16);
	}

	// check that the conversion via strtoull()'s fine
	if ((errno == ERANGE
	     && (st_rdm.addr == ULONG_MAX || (long long int)st_rdm.addr == LLONG_MIN))
	    || (errno != 0 && st_rdm.addr == 0)) {
 strtol_err:
		perror("strtoll");
		if (st_rdm.addr == ULONG_MAX)
			printf("Ulong max\n");
		if ((long long int)st_rdm.addr == LLONG_MIN)
			printf("long min\n");
		close(fd);
		exit(EXIT_FAILURE);
	}
	MSG("1 offset? %s; st_rdm.addr=%p\n",
	    (st_rdm.flag == USE_IOBASE ? "yes" : "no"), (void *)st_rdm.addr);

	if (st_rdm.flag != USE_IOBASE) { // we've been passed an absolute (user/kernel virtual) address
		/* Let's verify it before attempting to use it in the kernel driver;
		 * if it's a userspace addr, check it's validity, else we simply assume it's a valid kernel va
		 */
		if (is_user_address(st_rdm.addr)) {
			if (uaddr_valid(st_rdm.addr) == -1) {
				fprintf(stderr,
			"%s: the (usermode virtual) address passed (%p) seems to be invalid. Aborting...\n",
				argv[0], (void *)st_rdm.addr);
				close(fd);
				exit(1);
			}
			MSG("addr is a valid user-mode addr\n");
		} else
			MSG("addr is Not a user-mode addr\n");
	}
	MSG("2 offset? %s; st_rdm.addr=%p\n",
	    (st_rdm.flag == USE_IOBASE ? "yes" : "no"), (void *)st_rdm.addr);

	/* Length is number of "items" to read of size "date_type" each.
	   Restrictions:
	   - should be in the range [MIN_LEN to MAX_LEN] [curr 4 - 16M]
	//	   - should be a power of 2. If not, it will be rounded up to the next power of 2.
	 */
	st_rdm.len = sizeof(unsigned int);
	errno = 0;
	if (argc == 3) {	// either: (addr and length specified) OR ('-o' and offset) specified
		if (st_rdm.flag != USE_IOBASE)	// '-o' NOT passed and length specified
			st_rdm.len = strtol(argv[2], 0, 0);
	} else if (argc == 4) {	// -o passed and length specified
		st_rdm.len = strtol(argv[3], 0, 0);
	}
	if ((errno == ERANGE
	     && (st_rdm.addr == ULONG_MAX || (long long int)st_rdm.addr == LLONG_MIN))
	    || (errno != 0 && st_rdm.addr == 0))
		goto strtol_err;

	if ((st_rdm.len < MIN_LEN) || (st_rdm.len > MAX_LEN)) {
		fprintf(stderr, "%s: Invalid length (valid range: [%d-%d]).\n",
			argv[0], MIN_LEN, MAX_LEN);
		close(fd);
		exit(1);
	}
//	st_rdm.len = roundup_powerof2(st_rdm.len);
	MSG("final: len=%d\n", st_rdm.len);

	st_rdm.buf = (unsigned char *)calloc(st_rdm.len, sizeof(unsigned char));
	if (!st_rdm.buf) {
		fprintf(stderr, "Out of memory!\n");
		close(fd);
		exit(1);
	}

	MSG("addr: %p buf=%p len=0x%x flag=%d\n",
	    (void *)st_rdm.addr, st_rdm.buf, (unsigned int)st_rdm.len,
	    st_rdm.flag);
	if (ioctl(fd, IOCTL_RWMEMDRV_IOCGMEM, &st_rdm) == -1) {
		perror("ioctl");
		free(st_rdm.buf);
		close(fd);
		exit(1);
	}

	//void hex_dump(char *data, unsigned int size, char *caption, int verbose)
	hex_dump(st_rdm.buf, st_rdm.len, "MemDump", 0);
	free(st_rdm.buf);
	close(fd);
	return 0;
}
