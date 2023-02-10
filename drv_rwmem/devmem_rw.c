/*
 * dev_rwmem.c
 *
 * Part of the DEVMEM-RW opensource project - a simple
 * utility to read / write [I/O] memory and display it.
 * This is the kernel driver.
 *
 * Project home:
 * https://github.com/kaiwan/device-memory-readwrite
 *
 * Pl see detailed overview and usage PDF doc here:
 * https://github.com/kaiwan/device-memory-readwrite/blob/master/Devmem_HOWTO.pdf
 *
 * License: Dual MIT / GPL v2.
 * Author: Kaiwan N Billimoria
 *         kaiwanTECH.
 * kaiwan -at- kaiwantech dot com
 */
#define pr_fmt(fmt) "%s:%s(): " fmt, KBUILD_MODNAME, __func__
#include "../common.h"
#include <asm/byteorder.h>
#include <asm/io.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/ioctl.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>  // kvmalloc()

// copy_[to|from]_user()
#include <linux/version.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 11, 0)
#include <linux/uaccess.h>
#else
#include <asm/uaccess.h>
#endif

static void __iomem *iobase;
static DEFINE_MUTEX(mtx);

//-------------- Module params
static unsigned long iobase_start;
module_param(iobase_start, ulong, 0);
MODULE_PARM_DESC(iobase_start,
"Start (physical) address of IO base memory "
"(typically h/w registers mapped here by the processor)");

static int iobase_len;
module_param(iobase_len, uint, 0);
MODULE_PARM_DESC(iobase_len,
"Length (in bytes) of IO base memory (typically h/w registers mapped "
"here by the processor)");

static int force_rel;
module_param(force_rel, uint, 0);
MODULE_PARM_DESC(force_rel, "Set to 1 to Force releasing the IO base memory\n"
" region, even if (esp if) already mapped.\nWARNING! Could be dangerous!");

static char *reg_name;
module_param(reg_name, charp, 0);
MODULE_PARM_DESC(reg_name,
"Set to a string describing the IO base memory region being mapped by "
"this driver");

/*
 * Reads and writes can be specified to be an *offset* from the IO base address.
 * In this case, pst_[r|w]dm->flag == 0 and the offset is what arrives from
 * userspace in the pst_[r|w]dm->addr member.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
static long rwmem_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
#else
static int rwmem_ioctl(struct inode *ino, struct file *filp, unsigned int cmd,
		       unsigned long arg)
#endif
{
	int retval = 0;
	PST_RDM pst_rdm = NULL;
	PST_WRM pst_wrm = NULL;
	unsigned char *kbuf = NULL, *tmpbuf = NULL;
	unsigned long flags;

	if (mutex_lock_interruptible(&mtx)) {
		pr_info("pid %d: mtx lock interrupted!\n", current->pid);
		return -ERESTARTSYS;
	}
	// pr_debug ("In ioctl method, cmd=%d type=%d\n", _IOC_NR(cmd), _IOC_TYPE(cmd));
	PRINT_CTX();

	/* Check arguments */
	if (_IOC_TYPE(cmd) != IOCTL_RWMEMDRV_MAGIC) {
		pr_info("ioctl fail 1\n");
		mutex_unlock(&mtx);
		return -ENOTTY;
	}
	if (_IOC_NR(cmd) > IOCTL_RWMEMDRV_MAXIOCTL) {
		pr_info("ioctl fail 2\n");
		mutex_unlock(&mtx);
		return -ENOTTY;
	}

	switch (cmd) {
	case IOCTL_RWMEMDRV_IOCGMEM:	/* 'rdmem' */
		pst_rdm = kzalloc(sizeof(ST_RDM), GFP_KERNEL);
		if (!pst_rdm) {
			retval = -ENOMEM;
			goto rdm_out_unlock;
		}

		if (copy_from_user(pst_rdm, (PST_RDM)arg, sizeof(ST_RDM))) {
			pr_warn("copy_from_user failed\n");
			retval = -EFAULT;
			goto rdm_out_kfree_1;
		}

		pr_debug("pst_rdm=%px addr: %px buf=%px len=%u flag=%d\n\n",
			 (void *)pst_rdm, (void *)pst_rdm->addr,
			 (void *)pst_rdm->buf, pst_rdm->len, pst_rdm->flag);

		kbuf = kvzalloc(pst_rdm->len, GFP_KERNEL);
		if (!kbuf) {
			retval = -ENOMEM;
			goto rdm_out_kfree_1;
		}
		memset(kbuf, POISONVAL, pst_rdm->len);
		// pr_debug ("kbuf=0x%x pst_rdm=0x%x\n", (unsigned int)kbuf, (unsigned
		// int)pst_rdm);

		tmpbuf = kvzalloc(pst_rdm->len, GFP_KERNEL);
		if (!tmpbuf) {
			retval = -ENOMEM;
			goto rdm_out_kfree_2;
		}
		memset(tmpbuf, POISONVAL, pst_rdm->len);

		//---------Critical section BEGIN: save & turn off interrupts
		local_irq_save(flags);

#if 0		//------------- ioread32_rep does NOT seem to work! ioread32 does...(on
		//ARM BB). WHY ???
		if (USE_IOBASE == pst_rdm->flag)
			ioread32_rep(tmpbuf, (void *)(iobase + pst_rdm->addr), pst_rdm->len);
		else
			ioread32_rep(kbuf, (void *)pst_rdm->addr,
				     pst_rdm->len / sizeof(void *));
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET, tmpbuf, pst_rdm->len);
#else
		if (pst_rdm->flag == USE_IOBASE) {	// offset relative to iobase address passed
			pr_debug
			    ("dest:tmpbuf=%px src:(iobase+pst_rdm->addr)=%px pst_rdm->len=%u\n",
			     tmpbuf, (iobase + pst_rdm->addr), pst_rdm->len);
			memcpy_fromio(tmpbuf, (iobase + pst_rdm->addr), pst_rdm->len);
		} else	// absolute (virtual) address passed
			memcpy_fromio(tmpbuf, (void *)pst_rdm->addr, pst_rdm->len);
		// print_hex_dump_bytes ("", DUMP_PREFIX_OFFSET, tmpbuf, pst_rdm->len);
#endif
		local_irq_restore(flags);
		//---------Critical section END: restored interrupt state

		memcpy(kbuf, tmpbuf, pst_rdm->len);

#ifdef DEBUG
//		print_hex_dump_bytes("kbuf: ", DUMP_PREFIX_OFFSET, kbuf, pst_rdm->len);
#endif

	/* ARM* requires :
	 * - A memory write barrier before the first write to a peripheral
	 * - A memory read barrier after the last read of a peripheral
	 * So this isn't (yet) correct... TODO
	 */
		mb();
		if (copy_to_user(pst_rdm->buf, kbuf, pst_rdm->len)) {
			pr_warn("copy_to_user failed\n");
			retval = -EFAULT;
			goto rdm_out_kfree_3;
		}
		retval = pst_rdm->len;

 rdm_out_kfree_3:
		kvfree(tmpbuf);
 rdm_out_kfree_2:
		kvfree(kbuf);
 rdm_out_kfree_1:
		kfree(pst_rdm);
 rdm_out_unlock:
		mutex_unlock(&mtx);
		return retval;

		break;		// never reached

	case IOCTL_RWMEMDRV_IOCSMEM:	/* 'wrmem' */
		if (!capable(CAP_SYS_ADMIN)) {
			retval = -EPERM;
			goto wrm_out_unlock;
		}

		pst_wrm = kzalloc(sizeof(ST_WRM), GFP_KERNEL);
		if (!pst_wrm) {
			retval = -ENOMEM;
			goto wrm_out_unlock;
		}
		if (copy_from_user(pst_wrm, (PST_WRM) arg, sizeof(ST_WRM))) {
			pr_warn("copy_from_user failed\n");
			retval = -EFAULT;
			goto wrm_out_kfree_1;
		}
		pr_debug("addr/offset: 0x%lx val=0x%lx\n", pst_wrm->addr,
			 pst_wrm->val);

		//---------Critical section BEGIN: save & turn off interrupts
		local_irq_save(flags);
		if (pst_wrm->flag == USE_IOBASE)
			iowrite32((u32) pst_wrm->val, pst_wrm->addr + iobase);
		else
			iowrite32((u32) pst_wrm->val, (void __iomem *)pst_wrm->addr);
		wmb(); // (same as mb(); comment above
		local_irq_restore(flags);
		//---------Critical section END: restored interrupt state

		retval = sizeof(u32);

 wrm_out_kfree_1:
		kfree(pst_wrm);
 wrm_out_unlock:
		mutex_unlock(&mtx);
		return retval;

		break;		// never reached

	default:
		retval = -ENOTTY;
	}

	mutex_unlock(&mtx);
	return retval;
}

/* Minor-specific open routines */
static const struct file_operations rwmem_fops = {
	.llseek = no_llseek,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
	.unlocked_ioctl = rwmem_ioctl,
#else
	.ioctl = rwmem_ioctl,
#endif
};

static int rwmem_open(struct inode *inode, struct file *filp)
{
	switch (iminor(inode)) {
	case 0:
		filp->f_op = &rwmem_fops;
		break;
	default:
		return -ENXIO;
	}

	if (filp->f_op && filp->f_op->open)
		return filp->f_op->open(inode, filp);
	pr_debug("opened.\n");
	return 0;
}

static int rwmem_close(struct inode *ino, struct file *filp)
{
	pr_debug("closed.\n");
	return 0;
}

/* Major-wide open routine */
static const struct file_operations rwmem_open_fops = {
	.open = rwmem_open,	/* just a means to get at the real open */
	.release = rwmem_close,
};

/*--- Dynamic Char Device Registration & device nodes creation---------*/
static dev_t chardrv_dev_number;
static struct chardrv_dev {
	char name[10];
	struct cdev cdev;
} *chardrv_devp;
static struct class *chardrv_class;

static int chardev_registration(void)
{
	int res = 0, i = 0;

	res = alloc_chrdev_region(&chardrv_dev_number, RW_MINOR_START, RW_COUNT, DEVICE_FILE);
	if (res) {
		pr_warn("could not allocate device\n");
		return res;
	}
	pr_info("registered with major number %d\n", MAJOR(chardrv_dev_number));

	chardrv_devp = kmalloc_array(RW_COUNT, sizeof(struct chardrv_dev), GFP_KERNEL);
	if (!chardrv_devp)
		return -ENOMEM;

	memset(chardrv_devp, 0, RW_COUNT * sizeof(struct chardrv_dev));
	for (i = 0; i < RW_COUNT; i++) {
		cdev_init(&chardrv_devp[i].cdev, &rwmem_open_fops);
		chardrv_devp[i].cdev.owner = THIS_MODULE;
		chardrv_devp[i].cdev.ops = &rwmem_open_fops;
		res = cdev_add(&chardrv_devp[i].cdev,
			       MKDEV(MAJOR(chardrv_dev_number),
				     MINOR(chardrv_dev_number) + i), 1);
		if (res) {
			pr_info("Error on cdev_add: %d\n", res);
			return res;
		}
		pr_info("cdev %s.%d added\n", DRVNAME, i);
	}

	/* Create the devices.
	 * Note: APIs class_create, device_create, etc exported as
	 * EXPORT_SYMBOL_GPL(...); so will not show up unless the module license is
	 * GPL.
	 */
	chardrv_class = class_create(THIS_MODULE, DRVNAME);
	for (i = 0; i < RW_COUNT; i++) {
		if (!device_create(chardrv_class, NULL,
				   MKDEV(MAJOR(chardrv_dev_number),
					 MINOR(chardrv_dev_number) + i), NULL,
				   "%s.%d", DRVNAME, i)) {
			pr_notice("Error creating device node /dev/%s.%d !\n", DRVNAME, i);
			return res;
		}
		pr_info("Device node /dev/%s.%d created.\n", DRVNAME, i);
	}
	return res;
}

/* Char driver unregister */
static void chardev_unregister(void)
{
	int i;

	for (i = 0; i < RW_COUNT; i++) {
		cdev_del(&chardrv_devp[i].cdev);
		device_destroy(chardrv_class, MKDEV(MAJOR(chardrv_dev_number),
						    MINOR(chardrv_dev_number) + i));
	}
	class_destroy(chardrv_class);
	kfree(chardrv_devp);
	unregister_chrdev_region(chardrv_dev_number, RW_COUNT);
	pr_info("unregistered char driver\n");
}

static inline int perform_registration(void)
{
	return chardev_registration();
}

static int __init rwmem_init_module(void)
{
	int first_time = 1;
	struct resource *iores = NULL;

	// If no IO base start address specified, we're done for now
	if (!iobase_start || !iobase_len) {
		pr_info
	    ("Init done. IO base address NOT specified (or len invalid) as "
	     "module param; so, not performing any ioremap() ...\n");
		return perform_registration();
	}

 get_region:
	iores = request_mem_region(iobase_start, iobase_len, reg_name);
	if (!iores) {
		if (force_rel && first_time) {
			pr_debug("attempting to release mem region..\n");
			release_mem_region(iobase_start, iobase_len);
			first_time = 0;
			goto get_region;
		}
		pr_info("Could not get IO resource, aborting...\n");
		return -ENXIO;
	}

	iobase = ioremap(iobase_start, iobase_len);
	if (!iobase) {
		pr_info("ioremap failed, aborting...\n");
		release_mem_region(iobase_start, iobase_len);
		return -ENXIO;
	}
	pr_debug("iobase = %px\n", (void *)iobase);

	// All ok; register the driver
	return perform_registration();
}

static void __exit rwmem_cleanup_module(void)
{
	chardev_unregister();
	if (iobase_start) {
		iounmap(iobase);
		release_mem_region(iobase_start, iobase_len);
	}
	pr_info("unregistered.\n");
}

module_init(rwmem_init_module);
module_exit(rwmem_cleanup_module);

MODULE_AUTHOR("(c) Kaiwan N Billimoria, kaiwanTECH");
MODULE_DESCRIPTION("Char driver to implement read/write (I/O) memory support.");
MODULE_LICENSE("Dual MIT/GPL");
