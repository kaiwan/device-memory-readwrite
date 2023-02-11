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


static void usage_x86_64(char *name)
{
	fprintf(stderr, "\
Usage:\n\
Read RAM memory or MMIO address range:\n\
   %s [-o] <address/offset> [len]\n\
 [-o]: optional parameter:\n\
 : '-o' present implies the next parameter is an OFFSET and NOT an absolute address [HEX]\n\
 (this is the typical usage for peeking hardware registers that are offset from an IO base..)\n\
 : absence of '-o' implies that the next parameter is an ADDRESS [HEX]\n\
offset -or- address : required parameter:\n\
 start offset or address to read memory (RAM or MMIO) from (HEX).\n\
\n\
 -OR-\n\
\n\
Read IO port (PIO) address range:\n\
   %s -p <-b|-w|-l> <ioport_address> [len]\n\
Based on the port width, pass the appropriate number of items to read (len).\n\
F.e.: the typical timer0 IO port registers on x86 systems are:\n\
 0040-0043 : timer0     (i.e. ioport locations 0x40, 0x41, 0x42, 0x43)\n\
So, reading it with different widths:\n\
  byte-width: sudo ./rdmem -p -b 0x40 4     # reads 4 items of 1 byte\n\
  word-width: sudo ./rdmem -p -w 0x40 2     # reads 2 items of 2 bytes\n\
  long-width: sudo ./rdmem -p -l 0x40 1     # reads 1 item of 4 bytes\n\
\n\
len (length): common optional parameter:\n\
 Number of items to read. Default = 4 bytes for MMIO, 1 item for PIO\n"
 " Must be in the range [%d-%d] bytes.\n"
 "\n%s\n"
 "\n%s\n",
	name, name, MIN_LEN, MAX_LEN, usage_warning_msg, rdwrmem_tips_msg);
}

static void usage_other(char *name)
{
	fprintf(stderr, "\
Usage:\n\
Read RAM memory or MMIO address range:\n\
   %s [-o] <address/offset> [len]\n\
 [-o]: optional parameter:\n\
 : '-o' present implies the next parameter is an OFFSET and NOT an absolute address [HEX]\n\
 (this is the typical usage for peeking hardware registers that are offset from an IO base..)\n\
 : absence of '-o' implies that the next parameter is an ADDRESS [HEX]\n\
offset -or- address : required parameter:\n\
 start offset or address to read memory (RAM or MMIO) from (HEX).\n\
\n\
len (length): common optional parameter:\n\
 Number of items to read. Default = 4 bytes\n"
 " Must be in the range [%d-%d] bytes.\n"
 "\n%s\n"
 "\n%s\n",
	name, MIN_LEN, MAX_LEN, usage_warning_msg, rdwrmem_tips_msg);
}

static void usage(char *name)
{
#ifdef __x86_64__
	usage_x86_64(name);
#else
	usage_other(name);
#endif
}

//----------------- IO Ports Reading (PIO) ----------------------------
#ifdef __x86_64__
#include <sys/io.h>   // ioports
/*
 * do_ioport_read()
 * Read and display IO port (registers) upto @ioport_len bytes from the IO
 * port starting at @ioport
 */
static int do_ioport_read(unsigned short ioport, unsigned short ioport_width, unsigned long ioport_len)
{
	unsigned char *buf = NULL;

	if (ioperm(0x0, 0xffff, 1) < 0) {
		perror("ioperm failed to allow access to IO port addr space [0-0xffff] (TIP: run as root)");
		return -1;
	}
	MSG("Can access all IO ports; ioport = 0x%x (%u)\n", ioport, ioport);
	printf("Value currently at IO port 0x%x (%u), width %u bits, for %lu bytes:\n",
		ioport, ioport, ioport_width, ioport_len);

	// void ins{b|w|l}(unsigned short port, void *addr,
        //        unsigned long count);
	if (ioport_width == 8) { // byte-wide '-b'
		buf = calloc(ioport_len, sizeof(unsigned char));
		if (!buf)
			goto out_memfail;
		insb(ioport, buf, ioport_len);
	} else if (ioport_width == 16) { // word-wide '-w'
		ioport_len *= 2;
		buf = calloc(ioport_len, sizeof(unsigned char));
		if (!buf)
			goto out_memfail;
		insw(ioport, buf, ioport_len);
	} else if (ioport_width == 32) { // long-wide '-l'
		ioport_len *= 4;
		buf = calloc(ioport_len, sizeof(unsigned char));
		if (!buf)
			goto out_memfail;
		insl(ioport, buf, ioport_len);
	}

	//void hex_dump(unsigned char *data, unsigned int size, char *caption, int verbose)
	hex_dump(buf, ioport_len, "IO port content", 1);
	free(buf);
	return 0;
out_memfail:
	fprintf(stderr, "Out of memory!\n");
	return -2;
}

static void ioport_read(int argc, char **argv)
{
	unsigned short ioport = 0, ioport_width = 8;
	unsigned long ioport_len = 1;

	if (argc < 4) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}
	// arg 2 : get IOport read width
	if (strlen(argv[2]) > 2) {
		fprintf(stderr, "%s: Invalid IO port width (valid values are -b or -w or -l).\n",
			argv[0]);
		exit(EXIT_FAILURE);
	}
	if (!strncmp(argv[2], "-b", 2))
		ioport_width = 8;
	else if (!strncmp(argv[2], "-w", 2))
		ioport_width = 16;
	else if (!strncmp(argv[2], "-l", 2))
		ioport_width = 32;
	else {
		fprintf(stderr, "%s: Invalid IO port width (valid values are -b or -w or -l).\n",
			argv[0]);
		exit(EXIT_FAILURE);
	}

	// arg 3 : get IOport number
	errno = 0;
	ioport = strtoul(argv[3], 0, 0);
	if (errno) {
		fprintf(stderr, "%s:%s(): strtoul(): range error, aborting...\n", argv[0], __func__);
		exit(EXIT_FAILURE);
	}
	if (argc == 5) {
		// arg 4 : get IOport length to read
		errno = 0;
		ioport_len = strtoul(argv[4], 0, 0);
		if (errno) {
			fprintf(stderr, "%s:%s(): strtoul(): range error, aborting...\n", argv[0], __func__);
			exit(EXIT_FAILURE);
		}
		if ((ioport_len < MIN_LEN_IOPORT) || (ioport_len > MAX_LEN_IOPORT)) {
			fprintf(stderr, "%s: Invalid IO port length (valid range: [%d-%d]).\n",
				argv[0], MIN_LEN_IOPORT, MAX_LEN_IOPORT);
			exit(EXIT_FAILURE);
		}
	}
	// whew
	if (do_ioport_read(ioport, ioport_width, ioport_len) < 0)
		exit(EXIT_FAILURE);
	exit(EXIT_SUCCESS);
}
#endif


int main(int argc, char **argv)
{
	int fd;
	ST_RDM st_rdm;

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

	if (argc < 2) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}
#ifdef __x86_64__
	if (!strncmp(argv[1], "-p", 2)) //===== IO port address specified
		ioport_read(argc, argv);
#endif

// TODO- clean up the bloody mess with args processing!
	if ((!strncmp(argv[1], "-o", 2)) && argc == 2) {	// address specified as an Offset
		fprintf(stderr,
			"%s: you're expected to pass the offset as a _separate_ parameter.\n"
			"Eg. you want to read 4 bytes from offset 8 onward:\n"
			"%s -o8  <-- WRONG\n" "%s -o 8  <-- RIGHT\n\n", argv[0],
			argv[0], argv[0]);
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	// Init the rdm structure
	memset(&st_rdm, 0, sizeof(ST_RDM));

	if ((fd = open(DEVICE_FILE, O_RDONLY | O_CLOEXEC, 0)) == -1) {
		perror
		    ("device file open failed. Driver 'devmem_rw' not loaded?");
		exit(EXIT_FAILURE);
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
 strtox_err:
		perror("strto[u]l[l]() failed");
		if (st_rdm.addr == ULONG_MAX)
			printf("Ulong max\n");
		if ((long long int)st_rdm.addr == LLONG_MIN)
			printf("long min\n");
		//close(fd);
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
			"%s: the (usermode virtual) address passed (%p) seems to be invalid. Aborting...\n"
			"%s\n",
				argv[0], (void *)st_rdm.addr, rdwrmem_tips_msg);
				close(fd);
				exit(EXIT_FAILURE);
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
		st_rdm.len = strtoul(argv[3], 0, 0);
	}
	if ((errno == ERANGE
	     && (st_rdm.addr == ULONG_MAX || (long long int)st_rdm.addr == LLONG_MIN))
	    || (errno != 0 && st_rdm.addr == 0))
		goto strtox_err;

	if ((st_rdm.len < MIN_LEN) || (st_rdm.len > MAX_LEN)) {
		fprintf(stderr, "%s: Invalid length (valid range: [%d-%d]).\n",
			argv[0], MIN_LEN, MAX_LEN);
		close(fd);
		exit(EXIT_FAILURE);
	}
//	st_rdm.len = roundup_powerof2(st_rdm.len);
	MSG("final: len=%u\n", st_rdm.len);

	st_rdm.buf = (unsigned char *)calloc(st_rdm.len, sizeof(unsigned char));
	if (!st_rdm.buf) {
		fprintf(stderr, "Out of memory!\n");
		close(fd);
		exit(EXIT_FAILURE);
	}

	MSG("addr: %p buf=%p len=0x%x (%u) bytes flag=%d\n",
	    (void *)st_rdm.addr, st_rdm.buf,
	    (unsigned int)st_rdm.len, (unsigned int)st_rdm.len,
	    st_rdm.flag);
	if (ioctl(fd, IOCTL_RWMEMDRV_IOCGMEM, &st_rdm) == -1) {
		perror("ioctl");
		free(st_rdm.buf);
		close(fd);
		exit(EXIT_FAILURE);
	}

	//void hex_dump(unsigned char *data, unsigned int size, char *caption, int verbose)
	hex_dump(st_rdm.buf, st_rdm.len, "MemDump", 0);
	free(st_rdm.buf);
	close(fd);
	return 0;
}
