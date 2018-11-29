/*
 * common.h
 *
 * Project home: 
 * http://code.google.com/p/device-memory-readwrite/
 *
 * Pl see detailed usage Wiki page here:
 * http://code.google.com/p/device-memory-readwrite/wiki/UsageWithExamples
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

#ifdef __KERNEL__
#ifdef DEBUG_PRINT
#define MSG(string, args...)				\
	pr_info("[%s]%s:%d: " string,			\
		DRVNAME, __FUNCTION__, __LINE__, ##args)
#define QP MSG("\n");
#else
#define MSG(string, args...)
#define QP
#endif
#else				// userspace
#ifdef DEBUG_PRINT
#define MSG(string, args...) \
	fprintf (stderr, "[%s]%s:%d: " string,		\
		APPNAME, __FUNCTION__, __LINE__, ##args)
#else
#define MSG(string, args...)
#define QP
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
#define MAX_LEN			128*1024 // 128Kb (arbit)..

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
	int len;
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
 An interesting way to print the context info:
 If USE_FTRACE_PRINT is On, it implies we'll use trace_printk(), else the vanilla
 printk(). 
 If we are using trace_printk(), we will automatically get output in the ftrace 
 latency format (see below):

 * The Ftrace 'latency-format' :
                       _-----=> irqs-off          [d]
                      / _----=> need-resched      [N]
                     | / _---=> hardirq/softirq   [H|h|s]   H=>both h && s
                     || / _--=> preempt-depth     [#]
                     ||| /                      
 CPU  TASK/PID       ||||  DURATION                  FUNCTION CALLS 
 |     |    |        ||||   |   |                     |   |   |   | 

 However, if we're _not_ using ftrace trace_printk(), then we'll _emulate_ the same
 with the printk() !
 (Of course, without the 'Duration' and 'Function Calls' fields).
 */
#include <linux/sched.h>
#include <linux/interrupt.h>

#ifndef USE_FTRACE_PRINT	// 'normal' printk(), lets emulate ftrace latency format
#define PRINT_CTX() do {                                                                     \
	char sep='|', intr='.';                                                              \
	                                                                                     \
   if (in_interrupt()) {                                                                     \
      if (in_irq() && in_softirq())                                                          \
	    intr='H';                                                                        \
	  else if (in_irq())                                                                 \
	    intr='h';                                                                        \
	  else if (in_softirq())                                                             \
	    intr='s';                                                                        \
	}                                                                                    \
   else                                                                                      \
	intr='.';                                                                            \
	                                                                                     \
	MSG(                                                                            \
	"PRINT_CTX:: [%03d]%c%s%c:%d   %c "                                                  \
	"%c%c%c%u "                                                                          \
	"\n"                                                                                 \
	, smp_processor_id(),                                                                \
    (!current->mm?'[':' '), current->comm, (!current->mm?']':' '), current->pid, sep,        \
	(irqs_disabled()?'d':'.'),                                                           \
	(need_resched()?'N':'.'),                                                            \
	intr,                                                                                \
	(preempt_count() && 0xff)                                                            \
	);                                                                                   \
} while (0)
#else				// using ftrace trace_prink() internally
#define PRINT_CTX() do {                                                                          \
	MSG("PRINT_CTX:: [cpu %02d]%s:%d\n", smp_processor_id(), __func__, current->pid);         \
	if (!in_interrupt()) {                                                                    \
  		MSG(" in process context:%c%s%c:%d\n",                                            \
		    (!current->mm?'[':' '), current->comm, (!current->mm?']':' '), current->pid); \
	} else {                                                                                  \
        MSG(" in interrupt context: in_interrupt:%3s. in_irq:%3s. in_softirq:%3s. "               \
		"in_serving_softirq:%3s. preempt_count=0x%x\n",                                   \
          (in_interrupt()?"yes":"no"), (in_irq()?"yes":"no"), (in_softirq()?"yes":"no"),          \
          (in_serving_softirq()?"yes":"no"), (preempt_count() && 0xff));                          \
	}                                                                                         \
} while (0)
#endif
#endif

#ifndef __KERNEL__
#include <assert.h>
/*------------------Functions---------------------------------*/

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
		return -1;
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

#include <mntent.h>
char *find_debugfs_mountpt(void)
{
	/* Ref:
	 * http://stackoverflow.com/questions/9280759/linux-function-to-get-mount-points
	 */
	struct mntent *ent;
	FILE *fp;
	char *ret = NULL;

	fp = setmntent("/proc/mounts", "r");
	if (NULL == fp) {
		perror("setmntent");
		exit(1);
	}
	while (NULL != (ent = getmntent(fp))) {
		char *s1 = ent->mnt_fsname;
		if (0 == strncmp(s1, "debugfs", 7)) {
			ret = ent->mnt_dir;
			break;
		}
	}
	endmntent(fp);
	return ret;
}

/*
 * debugfs_get_page_offset_val()
 *
 * @outval : the value-result parameter (pass-by-ref) that will hold the 
 *           result value
 *
 * Query the 'devmem_rw' debugfs "file" (this has been setup by the devmem_rw
 * driver on init..).
 * Thus it's now arch and kernel ver independent!
 * Of course, implies DEBUGFS is enabled within the kernel (usually the case).
 */
int debugfs_get_page_offset_val(unsigned long long *outval)
{
	int fd, MAX2READ = 16;
	char *debugfs_mnt = find_debugfs_mountpt();
	char *dbgfs_file = malloc(PATH_MAX);
	char buf[MAX2READ + 1];

	if (!debugfs_mnt) {
		fprintf(stderr, "%s: fetching debugfs mount point failed, aborting...",
			__func__);
		free(dbgfs_file);
		return -1;
	}
	assert(dbgfs_file);
	snprintf(dbgfs_file, PATH_MAX, "%s/%s/get_page_offset", debugfs_mnt,
		 DRVNAME);
	MSG("dbgfs_file: %s\n", dbgfs_file);

	if ((fd = open(dbgfs_file, O_RDONLY)) == -1) {
		perror("rdmem: open dbgfs_file");
		free(dbgfs_file);
		return -1;
	}
	memset(buf, 0, MAX2READ + 1);
	if (read(fd, buf, MAX2READ) == -1) {
		perror("rdmem: read dbgfs_file");
		close(fd);
		free(dbgfs_file);
		return -1;
	}
	close(fd);

	*outval = strtoull(buf, 0, 16);

	free(dbgfs_file);
	return 0;
}

int is_user_address(volatile unsigned long addr)
{
	unsigned long long page_offset;
	int stat = debugfs_get_page_offset_val(&page_offset);
	assert(stat >= 0);
	//MSG("page_offset = 0x%16llx\n", page_offset);

	if (addr < page_offset)
		return 1;
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
void hex_dump(unsigned char *data, int size, char *caption, int verbose)
{
	int i;			// index in data...
	int j;			// index in line...
	char temp[10];
	char buffer[128];
	char *ascii;

	memset(buffer, 0, 128);

	if (verbose && caption)
		printf("---------> %s <--------- (%d bytes from %p)\n", caption,
		       size, data);

	// Printing the ruler...
	printf
	    ("        +0          +4          +8          +c            0   4   8   c   \n");

	// Hex portion of the line is 8 (the padding) + 3 * 16 = 52 chars long
	// We add another four bytes padding and place the ASCII version...
	ascii = buffer + 58;
	memset(buffer, ' ', 58 + 16);
	buffer[58 + 16] = '\n';
	buffer[58 + 17] = '\0';
	buffer[0] = '+';
	buffer[1] = '0';
	buffer[2] = '0';
	buffer[3] = '0';
	buffer[4] = '0';
	for (i = 0, j = 0; i < size; i++, j++) {
		if (j == 16) {
			printf("%s", buffer);
			memset(buffer, ' ', 58 + 16);

			sprintf(temp, "+%04x", i);
			memcpy(buffer, temp, 5);

			j = 0;
		}

		sprintf(temp, "%02x", 0xff & data[i]);
		memcpy(buffer + 8 + (j * 3), temp, 2);
		if ((data[i] > 31) && (data[i] < 127))
			ascii[j] = data[i];
		else
			ascii[j] = '.';
	}

	if (j != 0)
		printf("%s", buffer);
}
#endif

#endif
