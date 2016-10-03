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

#define APPNAME		"rdm_wrm_app"

#ifdef __KERNEL__
 #ifdef DEBUG_PRINT
  #define MSG(string, args...) \
	pr_alert ("[%s]%s:%d: " string, \
		DRVNAME, __FUNCTION__, __LINE__, ##args)
  #define QP MSG("\n");
 #else
 #define MSG(string, args...)
 #endif
#else // userspace
 #ifdef DEBUG_PRINT
 #define MSG(string, args...) \
	fprintf (stderr, "[%s]%s:%d: " string, \
		APPNAME, __FUNCTION__, __LINE__, ##args)
 #else
 #define MSG(string, args...)
 #define QP
 #endif
#endif

#define DEVICE_FILE		"/dev/rwmem.0"
#define POISONVAL		0xea		// "poison value" to init alloced mem to
#define MIN_LEN 		4
#define MAX_LEN			128*1024	// 128Kb (arbit)..

#define RW_MINOR_START     0
#define RW_COUNT           1
#define RW_NAME           DEVICE_FILE

//----------------ioctl stuff--------------
#define IOCTL_RWMEMDRV_MAGIC		0xbb
#define IOCTL_RWMEMDRV_IOCGMEM		_IOW(IOCTL_RWMEMDRV_MAGIC, 1, int)
#define IOCTL_RWMEMDRV_IOCSMEM		_IOR(IOCTL_RWMEMDRV_MAGIC, 2, int)
#define	IOCTL_RWMEMDRV_MAXIOCTL		2

#define USE_IOBASE	1 	// for 'flag'
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
#define PRINT_CTX() do {                                                                   \
	MSG("PRINT_CTX:: [cpu %02d]%s:%d\n", smp_processor_id(), __func__, current->pid); \
	if (!in_interrupt()) {                                                                 \
  		MSG(" in process context:%c%s%c:%d\n",                                        \
		    (!current->mm?'[':' '), current->comm, (!current->mm?']':' '), current->pid);  \
	} else {                                                                               \
        MSG(" in interrupt context: in_interrupt:%3s. in_irq:%3s. in_softirq:%3s. "   \
		"in_serving_softirq:%3s. preempt_count=0x%x\n",                                    \
          (in_interrupt()?"yes":"no"), (in_irq()?"yes":"no"), (in_softirq()?"yes":"no"),   \
          (in_serving_softirq()?"yes":"no"), (preempt_count() && 0xff));                   \
	}                                                                                      \
} while (0)
#endif
#endif

#ifndef __KERNEL__
/*------------------Functions---------------------------------*/

#include <string.h>
/*--------------- Sourced from:
http://www.alexonlinux.com/hex-dump-functions
All rights rest with original author(s).----------------------

Added a 'verbose' parameter..(kaiwan).
*/
void hex_dump(unsigned char *data, int size, char *caption, int verbose)
{
	int i; // index in data...
	int j; // index in line...
	char temp[8];
	char buffer[128];
	char *ascii;

	memset(buffer, 0, 128);

	if (verbose && caption)
		printf("---------> %s <--------- (%d bytes from %p)\n", caption, size, data);

	// Printing the ruler...
	printf("        +0          +4          +8          +c            0   4   8   c   \n");

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
	for (i = 0, j = 0; i < size; i++, j++)
	{
		if (j == 16)
		{
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
