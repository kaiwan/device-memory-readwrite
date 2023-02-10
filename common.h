/*
 * common.h
 *
 * Project home: 
 * http://github.com/kaiwan/device-memory-readwrite/
 *
 * Pl see detailed usage doc here:
 * https://github.com/kaiwan/device-memory-readwrite/blob/master/Devmem_HOWTO.pdf
 *
 * For rdmem/wrmem utility.
 */
#ifndef _RDWR_MEM_COMMON
#define _RDWR_MEM_COMMON

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#define APPNAME		"rdm_wrm_app"
#define	DRVNAME		"devmem_rw"

#ifndef __KERNEL__
#ifdef DEBUG_PRINT
 #define MSG(string, args...) \
	fprintf (stderr, "[%s]%s:%d: " string,		\
		APPNAME, __FUNCTION__, __LINE__, ##args)
#else
 #define MSG(string, args...)
#endif
#endif

#define DEVICE_FILE		"/dev/devmem_rw.0"

// "poison value" to init alloced mem to
#ifdef CONFIG_X86_64
#define POISONVAL		0xfe
#else
#define POISONVAL		0xff
#endif

#define MIN_LEN 		4
#define MAX_LEN			16*1024*1024

#define RW_MINOR_START     0
#define RW_COUNT           1
#define RW_NAME           DEVICE_FILE

//----------------ioctl stuff--------------
#define IOCTL_RWMEMDRV_MAGIC		0xbb
#define IOCTL_RWMEMDRV_IOCGMEM		_IOW(IOCTL_RWMEMDRV_MAGIC, 1, int)
#define IOCTL_RWMEMDRV_IOCSMEM		_IOR(IOCTL_RWMEMDRV_MAGIC, 2, int)
#define	IOCTL_RWMEMDRV_MAXIOCTL		2

#define USE_IOBASE	1	// for 'flag'
typedef struct _ST_RDM {
	volatile unsigned long addr;
	unsigned char *buf;
	unsigned int len; // [0-4G] range
	int flag;
} ST_RDM, *PST_RDM;

typedef struct _ST_WRM {
	volatile unsigned long addr;
	unsigned long val;
	int flag;
} ST_WRM, *PST_WRM;

#ifdef __KERNEL__
/*------------------------ PRINT_CTX ---------------------------------*/
/*
 * An interesting way to print the context info; we mimic the kernel
 * Ftrace 'latency-format' :
 *                       _-----=> irqs-off          [d]
 *                      / _----=> need-resched      [N]
 *                     | / _---=> hardirq/softirq   [H|h|s] [1]
 *                     || / _--=> preempt-depth     [#]
 *                     ||| /
 * CPU  TASK/PID       ||||  DURATION                  FUNCTION CALLS
 * |     |    |        ||||   |   |                     |   |   |   |
 *
 * [1] 'h' = hard irq is running ; 'H' = hard irq occurred inside a softirq]
 *
 * Sample output (via 'normal' printk method; in this comment, we make / * into \* ...)
 *  CPU)  task_name:PID  | irqs,need-resched,hard/softirq,preempt-depth  \* func_name() *\
 *  001)  rdwr_drv_secret -4857   |  ...0   \* read_miscdrv_rdwr() *\
 *
 * (of course, above, we don't display the 'Duration' and 'Function Calls' fields)
 */
#include <linux/sched.h>
#include <linux/interrupt.h>

#define PRINT_CTX() do {                                                      \
	int PRINTCTX_SHOWHDR = 0;                                                 \
	char intr = '.';                                                          \
	if (!in_task()) {                                                         \
		if (in_irq() && in_softirq())                                         \
			intr = 'H'; /* hardirq occurred inside a softirq */               \
		else if (in_irq())                                                    \
			intr = 'h'; /* hardirq is running */                              \
		else if (in_softirq())                                                \
			intr = 's';                                                       \
	}                                                                         \
	else                                                                      \
		intr = '.';                                                           \
										                                      \
	if (PRINTCTX_SHOWHDR == 1)                                                \
		pr_debug("CPU)  task_name:PID  | irqs,need-resched,hard/softirq,preempt-depth  /* func_name() */\n"); \
	pr_debug(                                                                    \
	"%03d) %c%s%c:%d   |  "                                                      \
	"%c%c%c%u   "                                                                \
	"/* %s() */\n"                                                               \
	, raw_smp_processor_id(),                                                    \
	(!current->mm?'[':' '), current->comm, (!current->mm?']':' '), current->pid, \
	(irqs_disabled()?'d':'.'),                                                   \
	(need_resched()?'N':'.'),                                                    \
	intr,                                                                        \
	(preempt_count() && 0xff),                                                   \
	__func__                                                                     \
	);                                                                           \
} while (0)
#endif

/*
 * Interesting:
 * Above, I had to change the smp_processor_id() to raw_smp_processor_id(); else,
 * on a DEBUG kernel (configured with many debug config options), the foll warnings
 * would ensue:
Oct 04 12:19:53 dbg-LKD kernel: BUG: using smp_processor_id() in preemptible [00000000] code: rdmem/12133
Oct 04 12:19:53 dbg-LKD kernel: caller is debug_smp_processor_id+0x17/0x20
Oct 04 12:19:53 dbg-LKD kernel: CPU: 0 PID: 12133 Comm: rdmem Tainted: G      D    O      5.10.60-dbg01 #1
Oct 04 12:19:53 dbg-LKD kernel: Hardware name: innotek GmbH VirtualBox/VirtualBox, BIOS VirtualBox 12/01/2006
Oct 04 12:19:53 dbg-LKD kernel: Call Trace:
Oct 04 12:19:53 dbg-LKD kernel:  dump_stack+0xbd/0xfa
...
 * This is caught due to the fact that, on a debug kernel, when the kernel config
 * CONFIG_DEBUG_PREEMPT is enabled, it catches the possibility that functions
 * like smp_processor_id() are called in an atomic context where sleeping / preemption
 * is disallowed! With the 'raw' version it works without issues (just as Ftrace does).
 */

/*------------------ Usermode functions--------------------------------*/
#ifndef __KERNEL__
#include <assert.h>

#define NON_FATAL    0

#define WARN(warnmsg, args...) do {                           \
	handle_err(NON_FATAL, "!WARNING! %s:%s:%d: " warnmsg, \
	   __FILE__, __FUNCTION__, __LINE__, ##args);         \
} while(0)
#define FATAL(errmsg, args...) do {                           \
	handle_err(EXIT_FAILURE, "FATAL:%s:%s:%d: " errmsg,   \
	   __FILE__, __FUNCTION__, __LINE__, ##args);         \
} while(0)

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>

int handle_err(int fatal, const char *fmt, ...)
{
#define ERRSTRMAX 512
	char *err_str;
	va_list argp;

	err_str = malloc(ERRSTRMAX);
	if (err_str == NULL)
		return -1;

	va_start(argp, fmt);
	vsnprintf(err_str, ERRSTRMAX-1, fmt, argp);
	va_end(argp);

	fprintf(stderr, "%s", err_str);
	if (errno) {
		fprintf(stderr, "  ");
		perror("kernel says");
	}

	free(err_str);
	if (!fatal)
		return 0;
	exit(fatal);
}

int syscheck(void)
{
	FILE *fp;
#define SZ  128
	char res[SZ];

	/* BUG #20181128.2
	Require dynamic device node kernel support. (Bug- Else the /dev/rwmem.0
	device file does not get created). Simple way... execute the command
	'ps -e|grep udev'; if it succeeds, udev support is available, else not.
	*/
	memset(res, 0, SZ);
	fp = popen("ps -e|grep udev", "r");
	if (!fp) {
		WARN("popen failed\n");
		return -1;
	}
	if (!fgets(res, SZ-1, fp)) {
		WARN("fgets failed\n");
		pclose(fp);
		return -1;
	}
	pclose(fp);
	//MSG("res = %s\n", res);

	if (res[0] == '\0')
		return -1;

	/* On a busybox based ps (or even other), the 'res' variable may contain:
	   "   816 0         0:00 sh -c ps -e|grep udev"
	   So, we check for this "grep udev" wrong case as well... Bah.
	   IOW, for success, the 'res' string should contain 'udev', or
	   something like 'systemd-udev' and NOT contain 'grep udev'.
	 */
	if (strstr(res, "udev")) {
		if (strstr(res, "grep udev"))
			return -1;
	}
	return 0;
}

// Ref: http://stackoverflow.com/questions/7134590/how-to-test-if-an-address-is-readable-in-linux-userspace-app
int uaddr_valid(volatile unsigned long addr)
{
	int fd[2];

	if (pipe(fd) == -1) {
		perror("pipe");
		return -2;
	}
	if (write(fd[1], (void *)addr, sizeof(unsigned long)) == -1) {
		//printf("errno=%d\n", errno);
		//perror("pipe write");
		close(fd[0]);
		close(fd[1]);
		return -1;
	}
	close(fd[0]);
	close(fd[1]);
	return 0;
}

/*
 * Using the value PAGE_OFFSET to determine the start of kernel VA is ONLY valid
 * on 32-bit... On 64-bit, the kernel VAS can begin before PAGE_OFFSET (use the
 * procmap util to verify this).
 * So, let's base this routine on /proc/pid/maps; take the highest valid UVA there
 * and check against it...
 * Ret: 1 => it is a (seemingly) valid user addr
 *      0 => it's not a valid user addr
 *     -1 => this routine failed
 */
int is_user_address(volatile unsigned long long addr)
{
	// get the high uva
	char *cmd = "head -n -1 /proc/self/maps|tail -n1|awk '{print $1}'|cut -d'-' -f2";
	FILE *fp;
#define SZ2  20
	char res[SZ2];
	unsigned long long high_uva;

	memset(res, 0, SZ2);
	fp = popen(cmd, "r");
	if (!fp) {
		WARN("popen failed\n");
		return -1;
	}
	if (!fgets(res, SZ2-1, fp)) {
		WARN("fgets failed\n");
		pclose(fp);
		return -1;
	}
	pclose(fp);
	MSG("res = %s\n", res);

	if (res[0] == '\0')
		return -1;
	high_uva = strtoull(res, 0, 16);
	MSG("high_uva = 0x%016llx, addr=0x%016llx\n", high_uva, addr);
	if (addr <= high_uva)
		return 1;
	else
		return 0;
}

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

#include <string.h>
/*--------------- Sourced from:
http://www.alexonlinux.com/hex-dump-functions
All rights rest with original author(s).----------------------

Added a 'verbose' parameter..(kaiwan).
*/
void hex_dump(unsigned char *data, unsigned int size, char *caption, int verbose)
{
	unsigned int i;		// index in data...
	int j;			// index in line...
	char temp[10];
	char buffer[80];
	char *ascii;

	memset(buffer, 0, 80);
	memset(buffer, 0, 10);

	if (verbose && caption)
		printf("---------> %s <--------- (%d bytes from %p)\n", caption,
		       size, data);

	// Printing the ruler...
	printf
	    ("         +0          +4          +8          +c               0   4   8   c   \n");

	/* Hex portion of the line is 11 (the padding, as 11 chars used for the '+offset ' portion)
	 *  + 3 * 16 = 59 chars long
	 * We add another four bytes padding (so 63) and place the corresponding ASCII chars...
	 */
	ascii = buffer + 62;
	memset(buffer, ' ', 62 + 16);
	buffer[62 + 16] = '\n';
	buffer[62 + 17] = '\0';
	buffer[0] = '0';
	buffer[1] = '0';
	buffer[2] = '0';
	buffer[3] = '0';
	buffer[4] = '0';
	buffer[5] = '0';
	buffer[6] = '0';
	buffer[7] = '0';
	for (i = 0, j = 0; i < size; i++, j++) {
		if (j == 16) {
			printf("%s", buffer);
			memset(buffer, ' ', 62 + 15);

			sprintf(temp, "%08u", i);
			//sprintf(temp, "+%04x", i);
			memcpy(buffer, temp, 8);

			j = 0;
		}

		sprintf(temp, "%02x", 0xff & data[i]);
		memcpy(buffer + 9 + (j * 3), temp, 2);
		if ((data[i] > 31) && (data[i] < 127)) // valid ASCII char (space to '~')
			ascii[j] = data[i];
		else
			ascii[j] = '.';
	}

	if (j != 0)
		printf("%s", buffer);
}

const char usage_warning_msg[] = "NOTE: You MUST realize that providing an invalid address, or \
even, a valid address that's within a sparse (empty) region of virtual address space \
WILL cause bugs. Be warned!";

const char rdwrmem_tips_msg[] = "\
[TIP: 1. Realize that usermode va's are Always wrt *this* process only\n\
 TIP: 2. Disabling user ASLR (Address Space Layout Randomization) can help\n\
         To do so: sudo sh -c \"echo 0 > /proc/sys/kernel/randomize_va_space\"\n\
 TIP: 3. Can test reading/writing userspace by disabling ASLR, running the DEBUG binary app,\n\
         seeing and using the uva of a 5k buffer (init to 0xea)]\n\
 TIP: 4. F.e.: to test wrmem: first disable ASLR, then do:\n\
         $ sudo ./wrmem_dbg\n\
         *** For Testing usermode va's (uva's) rd/wr ***\n\
         gbuf @ 0x55555555ca80    <---\\\n\
         [ ... ]                       |\n\
         [ ... ]                       |\n\
	 Now run wrmem_dbg with the uva| displayed above\n\
	 $ sudo ./wrmem_dbg 0x55555555ca80 0x112233ee\n\
         [ ... ]\n\
         ---------> Write Test MemDump <--------- (4 bytes from 0x55555555ca80)\n\
                  +0          +4          +8          +c               0   4   8   c\n\
         00000000 ee 33 22 11                                          .3\".\n\
	 *** Notice how, on little-endian, the output bytes show up in the 'reverse' order ***\n\
	 *** Worry not, ASCII text shows up correctly (only integers show 'reversed')      ***\
";

static char gbuf[5120];
void memtest(void)
{
	memset(gbuf, 0xea, 5120);
	printf("*** For Testing usermode va's (uva's) rd/wr ***\ngbuf @ %p\n", gbuf);
}

#endif
#endif
