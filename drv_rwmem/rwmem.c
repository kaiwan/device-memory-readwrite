/*
 * rwmem.c
 * Read/Write [I/O] memory kernel driver.
 *
 * Project home: 
 * http://code.google.com/p/device-memory-readwrite/
 *
 * Pl see detailed usage Wiki page here:
 * http://code.google.com/p/device-memory-readwrite/wiki/UsageWithExamples
 *
 * License: GPL v2.
 * Author: Kaiwan N Billimoria
 * kaiwan -at- desigergraphix dot com
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/ioctl.h>
#include <asm/io.h>
#include <asm/byteorder.h>
#include <linux/mutex.h>
#include <linux/interrupt.h>
#include "../common.h"

#define	DRVNAME			"rwmem"
/*
 * From the 'OMAP35x Technical Refernce Manual' pg 205:
 * Table 2-4. L4-Wakeup Memory Space Mapping
 * Device Name   Start Address (Hex)    End Address (Hex)   Size (KB)    Description
 * L4-Wakeup        0x4830 0000           0x4833 FFFF           256
 * ...
 * These are physical addresses...
 */

dev_t rw_dev_number;
struct rw_dev {
		char name[10];
		struct cdev cdev;     /* Char device structure      */
} *rw_devp;
static void __iomem * iobase=NULL;

static DEFINE_MUTEX (mtx);

//-------------- Module params
static unsigned long iobase_start=0x0;
module_param(iobase_start, ulong, 0);
MODULE_PARM_DESC(iobase_start, "Start (physical) address of IO base memory (typically h/w registers mapped here by the processor)");

static int iobase_len=0;
module_param(iobase_len, uint, 0);
MODULE_PARM_DESC(iobase_len, "Length (in bytes) of IO base memory (typically h/w registers mapped here by the processor)");

static int force_rel=0;
module_param(force_rel, uint, 0);
MODULE_PARM_DESC(force_rel, "Set to 1 to Force releasing the IO base memory region, even if (esp if) already mapped.\n\
WARNING! Could be dangerous!");

static char *reg_name;
module_param(reg_name, charp, 0);
MODULE_PARM_DESC(reg_name, "Set to a string describing the IO base memory region being mapped by this driver.");

#if 0
const int e = 1;
#define is_bigendian() ( (*(char*)&e) == 0 )
#endif

/*
 * Reads and writes can be specified to be an *offset* from the IO base address.
 * In this case, pst_[r|w]dm->flag == 0 and the offset is what arrives from 
 * userspace in the pst_[r|w]dm->addr member.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
static long rwmem_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
#else
static int rwmem_ioctl(struct inode *ino, struct file *filp, unsigned int cmd, unsigned long arg)
#endif
{
	int i=0, err=0, retval=0;
	volatile PST_RDM pst_rdm=NULL;
	volatile PST_WRM pst_wrm=NULL;
	unsigned char *kbuf=NULL, *tmpbuf=NULL;
	unsigned long flags;

	if (mutex_lock_interruptible (&mtx)) {
		MSG("pid %d: mtx lock interrupted!\n", current->pid);
		return -ERESTARTSYS;
	}
	
	//MSG ("In ioctl method, cmd=%d type=%d\n", _IOC_NR(cmd), _IOC_TYPE(cmd));
	PRINT_CTX();

	/* Check arguments */
	if (_IOC_TYPE(cmd) != IOCTL_RWMEMDRV_MAGIC) {
		printk ("%s: ioctl fail 1\n", DRVNAME);
		mutex_unlock (&mtx);
		return -ENOTTY;
	}
	if (_IOC_NR(cmd) > IOCTL_RWMEMDRV_MAXIOCTL) {
		printk ("%s: ioctl fail 2\n", DRVNAME);
		mutex_unlock (&mtx);
		return -ENOTTY;
	}

	/* Verify direction */
	if (_IOC_DIR(cmd) & _IOC_READ)
		err = !access_ok (VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd));
	else if (_IOC_DIR(cmd) & _IOC_WRITE)
		err = !access_ok (VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd));
	if (err) {
		printk ("%s: ioctl direction check fail!\n", DRVNAME);
		mutex_unlock (&mtx);
		return -EFAULT;
	}

	switch (cmd) {
		case IOCTL_RWMEMDRV_IOCGMEM: /* 'rdmem' */
			if (!(pst_rdm = kzalloc (sizeof (ST_RDM), GFP_KERNEL))) {
				printk (KERN_ALERT "%s: out of memory!\n", DRVNAME);
				retval = -ENOMEM;
				goto rdm_out_unlock;
			}

			if (copy_from_user (pst_rdm, (PST_RDM)arg, sizeof (ST_RDM))) {
				printk (KERN_ALERT "[%s] !WARNING! copy_from_user failed\n", DRVNAME);
				retval = -EFAULT;
				goto rdm_out_kfree_1;
			}

			MSG ("pst_rdm=0x%p addr: 0x%p buf=0x%p len=%d flag=%d\n\n", 
				(void *)pst_rdm, (void *)pst_rdm->addr, (void *)pst_rdm->buf, 
				pst_rdm->len, pst_rdm->flag);

			kbuf = kmalloc (pst_rdm->len, GFP_KERNEL);
			if (!kbuf) {
				printk (KERN_ALERT "%s: out of memory! (kbuf)\n", DRVNAME);
				retval = -ENOMEM;
				goto rdm_out_kfree_1;
			}
			memset (kbuf, POISONVAL, sizeof (kbuf));
			//MSG ("kbuf=0x%x pst_rdm=0x%x\n", (unsigned int)kbuf, (unsigned int)pst_rdm);

			tmpbuf = kmalloc (pst_rdm->len, GFP_KERNEL);
			if (!tmpbuf) {
				printk (KERN_ALERT "%s: out of memory! (tmpbuf)\n", DRVNAME);
				retval = -ENOMEM;
				goto rdm_out_kfree_2;
			}
			memset (tmpbuf, POISONVAL, sizeof (tmpbuf));

			//---------Critical section BEGIN: save & turn off interrupts
			local_irq_save (flags);

#if 0  //------------- ioread32_rep does NOT seem to work! ioread32 does...(on ARM BB). WHY ???
			if (USE_IOBASE == pst_rdm->flag)
				ioread32_rep (tmpbuf, (void *)(iobase+pst_rdm->addr), pst_rdm->len);
			else
				ioread32_rep (kbuf, (void *)pst_rdm->addr, pst_rdm->len/sizeof(void *));
			print_hex_dump_bytes ("", DUMP_PREFIX_OFFSET, tmpbuf, pst_rdm->len);
#else
			if (USE_IOBASE == pst_rdm->flag) { // offset relative to iobase address passed
				MSG ("dest:tmpbuf=0x%08x src:(iobase+pst_rdm->addr)=0x%08x pst_rdm->len=%d\n", 
					(u32)tmpbuf, (u32)(iobase+pst_rdm->addr), pst_rdm->len);
				memcpy_fromio (tmpbuf, (iobase+pst_rdm->addr), pst_rdm->len);
			}
			else { // absolute (virtual) address passed
				memcpy_fromio (tmpbuf, (void *)pst_rdm->addr, pst_rdm->len);
			} 
			//print_hex_dump_bytes ("", DUMP_PREFIX_OFFSET, tmpbuf, pst_rdm->len);
#endif
			local_irq_restore (flags);
			//---------Critical section END: restored interrupt state

#ifndef __BIG_ENDIAN
			/* Word-swap necesary...*/
			MSG("Little-endian, doing word-swap..\n");
			for (i=0; i < pst_rdm->len; i+=4) {
				kbuf[i] = tmpbuf[i+3];
				kbuf[i+1] = tmpbuf[i+2];
				kbuf[i+2] = tmpbuf[i+1];
				kbuf[i+3] = tmpbuf[i];
			}
#else
			memcpy (kbuf, tmpbuf, pst_rdm->len);
#endif
#ifdef DEBUG_PRINT
			print_hex_dump_bytes ("", DUMP_PREFIX_OFFSET, kbuf, pst_rdm->len);
#endif

			mb();
			if (copy_to_user (pst_rdm->buf, kbuf, pst_rdm->len)) {
				printk (KERN_ALERT "[%s] !WARNING! copy_to_user failed\n", DRVNAME);
				retval = -EFAULT;
				goto rdm_out_kfree_3;
			}
			retval = pst_rdm->len;

rdm_out_kfree_3:
			kfree (tmpbuf);
rdm_out_kfree_2:
			kfree (kbuf);
rdm_out_kfree_1:
			kfree (pst_rdm);
rdm_out_unlock:
			mutex_unlock (&mtx);
			return retval;

			break; // never reached

		case IOCTL_RWMEMDRV_IOCSMEM: /* 'wrmem' */
			if (!capable (CAP_SYS_ADMIN)) {
				retval = -EPERM;
				goto wrm_out_unlock;
			}

			if (!(pst_wrm = kzalloc (sizeof (ST_WRM), GFP_KERNEL))) {
				printk (KERN_ALERT "%s: out of memory!\n", DRVNAME);
				retval = -ENOMEM;
				goto wrm_out_unlock;
			}
			if (copy_from_user (pst_wrm, (PST_WRM)arg, sizeof (ST_WRM))) {
				printk (KERN_ALERT "[%s] !WARNING! copy_from_user failed\n", DRVNAME);
				retval = -EFAULT;
				goto wrm_out_kfree_1;
			}
			MSG ("addr/offset: 0x%x val=0x%x\n", 
				(unsigned int)pst_wrm->addr, (unsigned int)pst_wrm->val);

			//---------Critical section BEGIN: save & turn off interrupts
			local_irq_save (flags);
			if (USE_IOBASE == pst_wrm->flag)
				iowrite32 ((u32)pst_wrm->val, pst_wrm->addr+iobase);
			else
				iowrite32 ((u32)pst_wrm->val, (void __iomem *)pst_wrm->addr);
			wmb();
			local_irq_restore (flags);
			//---------Critical section END: restored interrupt state

			retval = sizeof(u32);

wrm_out_kfree_1:
			kfree (pst_wrm);
wrm_out_unlock:
			mutex_unlock (&mtx);
			return retval;

			break; // never reached

		default:
			retval = -ENOTTY;
	}

	mutex_unlock (&mtx);
	return retval;
}


/* Minor-specific open routines */
static struct file_operations rwmem_fops = {
	.llseek        =	no_llseek,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
	.unlocked_ioctl  = 	rwmem_ioctl,
#else
	.ioctl  = 	rwmem_ioctl,
#endif
};

static int rwmem_open(struct inode * inode, struct file * filp)
{
	switch (iminor(inode)) {
		case 0:
			filp->f_op = &rwmem_fops;
			break;
		default:
			return -ENXIO;
	}

	if (filp->f_op && filp->f_op->open)
		return filp->f_op->open(inode,filp); 
	MSG("opened.\n");
	return 0;
}

static int rwmem_close(struct inode *ino, struct file *filp)
{
	MSG("closed.\n");
	return 0;
}


/* Major-wide open routine */
static struct file_operations rwmem_open_fops = {
	.open    =		rwmem_open, /* just a means to get at the real open */
	.release =      rwmem_close,
};


/*--- Dynamic Char Device Registration & device nodes creation---------*/
static dev_t chardrv_dev_number;
static struct chardrv_dev {
	char name[10];
	struct cdev cdev;
} *chardrv_devp;
static struct class *chardrv_class=NULL;

static int chardev_registration(void)
{
    int res=0,i=0;

	res = alloc_chrdev_region(&chardrv_dev_number, RW_MINOR_START, RW_COUNT, DEVICE_FILE);
	if (res) {
		printk(KERN_WARNING "%s: could not allocate device\n", DRVNAME);
		return res;
	} else {
		printk (KERN_INFO "%s: registered with major number %d\n", DRVNAME, MAJOR(chardrv_dev_number));
	}

	chardrv_devp = kmalloc(RW_COUNT * sizeof(struct chardrv_dev), GFP_KERNEL);
	if (NULL == chardrv_devp) {
		return -ENOMEM;
	}

	memset(chardrv_devp, 0, RW_COUNT * sizeof(struct chardrv_dev));
	for (i = 0 ; i < RW_COUNT; i++) {
		cdev_init (&chardrv_devp[i].cdev, &rwmem_open_fops);
		chardrv_devp[i].cdev.owner = THIS_MODULE;
		chardrv_devp[i].cdev.ops = &rwmem_open_fops;
		res = cdev_add (&chardrv_devp[i].cdev, MKDEV(MAJOR(chardrv_dev_number), MINOR(chardrv_dev_number)+i), 1);
		if (res) {
			printk(KERN_NOTICE "%s: Error on cdev_add for %d\n", DRVNAME, res);
			return res;
		} else {
			printk(KERN_INFO "%s: cdev %s.%d added\n", DRVNAME, DRVNAME, i);
		}
	}

	/* Create the devices.
	 * Note: APIs class_create, device_create, etc exported as EXPORT_SYMBOL_GPL(...); so will not
  	 * show up unless the module license is GPL.
	 */
	chardrv_class = class_create (THIS_MODULE, DRVNAME);
	for ( i = 0 ; i < RW_COUNT; i++) {
		if (!device_create(chardrv_class, NULL, MKDEV(MAJOR(chardrv_dev_number), 
			 MINOR(chardrv_dev_number)+i), NULL, "%s.%d", DRVNAME, i)) {
			printk(KERN_NOTICE "%s: Error creating device node /dev/%s.%d !\n", DRVNAME, DRVNAME, i);
			return res;
		}
		else {
			printk(KERN_INFO " %s: Device node /dev/%s.%d created.\n", DRVNAME, DRVNAME, i);
		}
	}
	return res;
}


static int __init rwmem_init_module(void)
{
	int res, first_time=1;
	struct resource *iores=NULL;

	res = chardev_registration();
	if (res)
		return res;

	// If no IO base start address specified, we're done for now
	if (!iobase_start || !iobase_len) {
		printk(KERN_WARNING 
		"%s: IO base address NOT specified (or len invalid) as module param; not performing ioremap...\n", 
			DRVNAME);
		return 0;
	}

get_region:
	iores = request_mem_region (iobase_start, iobase_len, reg_name);
	if (!iores) {
		if (force_rel && first_time) {
			release_mem_region (iobase_start, iobase_len);
			first_time=0;
			goto get_region;
		}
		printk("%s: Could not get IO resource, aborting...\n", DRVNAME);
		return PTR_ERR(iores);
	}

	iobase = ioremap (iobase_start, iobase_len);
	if (!iobase) {
		printk("%s: ioremap failed, aborting...\n", DRVNAME);
		release_mem_region (iobase_start, iobase_len);
		return PTR_ERR(iobase);
	}
	MSG("iobase = 0x%p\n", (void *)iobase);
	return 0;
}

static void __exit rwmem_cleanup_module(void)
{
    int i=0;

	if (iobase_start) {
		iounmap (iobase);
		release_mem_region (iobase_start, iobase_len);
	}

	/* Char driver unregister */
	for (i=0; i<RW_COUNT; i++) {
		cdev_del(&chardrv_devp[i].cdev);
		device_destroy(chardrv_class, MKDEV(MAJOR(chardrv_dev_number), MINOR(chardrv_dev_number)+i));
	}
	class_destroy(chardrv_class);
	kfree(chardrv_devp);
	unregister_chrdev_region(chardrv_dev_number, RW_COUNT);
	MSG("Unregistered.\n");
}

module_init(rwmem_init_module);
module_exit(rwmem_cleanup_module);

MODULE_AUTHOR("(c) Kaiwan N Billimoria");
MODULE_DESCRIPTION("Char driver to implement read/write (I/O) memory support.");
MODULE_LICENSE("GPL");
