/*
 * debugfs_hooks.c
 *
 * Debugfs interface code for the 'DevMem RW' project.
 * Refer: Documentation/filesystems/debugfs.txt
 *
 * Part of the DEVMEM-RW opensource project - a simple
 * utility to read / write [I/O] memory and display it.
 *
 * Project home:
 * https://github.com/kaiwan/device-memory-readwrite
 *
 * Pl see detailed overview and usage PDF doc here:
 * https://github.com/kaiwan/device-memory-readwrite/blob/master/Devmem_HOWTO.pdf
 *
 * License: GPL v2.
 * Author: Kaiwan N Billimoria
 *         kaiwanTECH.
 * kaiwan -at- kaiwantech dot com
 */
#include "../common.h"
#include <linux/debugfs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>

#define DBGFS_CREATE_ERR(pDentry, str)                                         \
  do {                                                                         \
    printk("%s: failed.\n", str);                                              \
    if (PTR_ERR(pDentry) == -ENODEV)                                           \
      printk(" debugfs support not available?\n");                             \
    debugfs_remove_recursive(pDentry);                                         \
    return (pDentry);                                                          \
  } while (0)

/* Spit out the value of PAGE_OFFSET */
static ssize_t dbgfs_genread(struct file *filp, char __user * ubuf,
			     size_t count, loff_t * fpos)
{
	char kbuf[20];

	snprintf(kbuf, 18, "%16lx", PAGE_OFFSET);
	MSG("kbuf: %s\n", kbuf);

	/* simple_read_from_buffer - copy data from the buffer to user space:
	 * @to: the user space buffer to read to
	 * @count: the maximum number of bytes to read
	 * @ppos: the current position in the buffer
	 * @from: the buffer to read from
	 * @available: the size of the buffer
	 *
	 * The simple_read_from_buffer() function reads up to @count bytes from the
	 * buffer @from at offset @ppos into the user space address starting at @to.
	 *
	 * On success, the number of bytes read is returned and the offset @ppos is
	 * advanced by this number, or negative value is returned on error.

	 ssize_t simple_read_from_buffer(void __user *to, size_t count, loff_t *ppos,
	 const void *from, size_t available)
	 */
	return simple_read_from_buffer(ubuf, strlen(kbuf), fpos, kbuf,
				       strlen(kbuf));
}

static struct file_operations dbg_fops = {
	.read = dbgfs_genread,
};

struct dentry *setup_debugfs_entries(void)
{
	struct dentry *parent = NULL;

	parent = debugfs_create_dir(DRVNAME, NULL);
	if (!parent) {
		DBGFS_CREATE_ERR(parent, "debugfs_create_dir");
	}

	/* Generic debugfs file.
	   4th param is a generic void * ptr; here we're not passing anything..
	   The idea: to let the apps (rdmem|wrmem) read kernel variables that
	   aren't exposed via procfs. Like PAGE_OFFSET.
	 */
	if (!debugfs_create_file
	    ("get_page_offset", 0444, parent, NULL, &dbg_fops)) {
		DBGFS_CREATE_ERR(parent, "debugfs_create_file");
	}
	MSG("debugfs hooks created\n");

	return parent;
}
