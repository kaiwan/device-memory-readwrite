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
	printk (KERN_ALERT "[%s]%s:%d: " string, \
		DRVNAME, __FUNCTION__, __LINE__, ##args)
  #define QP MSG("\n");
 #else
 #define MSG(string, args...)
 #endif
#else // userspace
 #ifdef DEBUG_PRINT
 #define MSG(string, args...) \
	printf ("[%s]%s:%d: " string, \
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
#include <linux/interrupt.h>
#define PRINT_CTX() {        \
  if (printk_ratelimit()) { \
	  printk("PRINT_CTX:: in function %s on cpu #%2d\n", __func__, smp_processor_id()); \
      if (!in_interrupt()) \
	  	printk(" in process context: %s:%d\n", current->comm, current->pid); \
	  else \
        printk(" in interrupt context: in_interrupt:%3s in_irq:%3s in_softirq:%3s in_serving_softirq:%3s preempt_count=0x%x\n",  \
          (in_interrupt()?"yes":"no"), (in_irq()?"yes":"no"), (in_softirq()?"yes":"no"),        \
          (in_serving_softirq()?"yes":"no"), preempt_count());        \
  } \
}
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
