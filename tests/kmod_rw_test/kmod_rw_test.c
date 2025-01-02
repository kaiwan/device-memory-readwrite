/*
 * kmod_rw_test.c
 * Part of the tests for the devmem_rw project.
 *
 * Brief Description:
 * Our very first kernel module, the 'Hello, world' of course! The
 * idea being to explain the essentials of the Linux kernel's LKM
 * framework.
 *
 */
#define pr_fmt(fmt) "%s:%s(): " fmt, KBUILD_MODNAME, __func__

#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>

MODULE_AUTHOR("Kaiwan NB");
MODULE_DESCRIPTION("Test case for reads/writes via the devmem_rw prj on kernel memory");
MODULE_LICENSE("Dual MIT/GPL");
MODULE_VERSION("0.1");

#define NUM	(PAGE_SIZE*2)
#define FILL_PATTERN   1

static char *kbuf;

static int __init kmod_rw_test_init(void)
{
	int i;

	kbuf = kmalloc(NUM, GFP_KERNEL);
	if (unlikely(!kbuf))
		return -ENOMEM;
	pr_info("allocated %zu bytes of RAM at kernel va 0x%px\n", NUM, kbuf);

#if (FILL_PATTERN == 1)
	/* lets fill it with 'deadface' ! */
	for (i = 0; i < NUM/4; i++) {
#ifndef __BIG_ENDIAN	 // little-endian
		kbuf[(i * 4) + 0] = 0xde;
		kbuf[(i * 4) + 1] = 0xad;
		kbuf[(i * 4) + 2] = 0xfa;
		kbuf[(i * 4) + 3] = 0xce;
#else	 // big-endian
		kbuf[(i * 4) + 0] = 0xce;
		kbuf[(i * 4) + 1] = 0xfa;
		kbuf[(i * 4) + 2] = 0xad;
		kbuf[(i * 4) + 3] = 0xde;
#endif
#endif
	}
	print_hex_dump_bytes(" ", DUMP_PREFIX_OFFSET, kbuf, NUM/4);

	return 0;		/* success */
}
static void __exit kmod_rw_test_exit(void)
{
	kfree(kbuf);
	pr_info("Goodbye\n");
}
module_init(kmod_rw_test_init);
module_exit(kmod_rw_test_exit);
