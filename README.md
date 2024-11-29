

# device-memory-readwrite

  

Read and/or Write to pretty much _any_ memory location (RAM or hardware IO Memory) on a device; these hardware IO locations are often called Memory Mapped IO (MMIO) regions and often are used to access the hardware registers or RAM on a peripheral.

This project enables the user to read from and/or write to any generic memory location(s) on a device running the modern (>=3.x) Linux OS. This includes "regular" RAM as well as hardware IO Memory (MMIO) that's mapped into kernel virtual address space.

Given the hardware base address and length (as module parameters), the driver component will perform the mapping.

The read/write utility programs run in user-land and talk to the underlying kernel driver via the ioctl system call.

This project can be useful for driver authors, kernel developers, etc who want to peek/poke memory for prototyping purposes, learning, debug, testing, register lookups/writes and similar purposes.

To get started, please clone the git tree, read the 'Devmem HOWTO.pdf' PDF document, and get to it!

***TIP*** :
Use the [**procmap**](https://github.com/kaiwan/procmap) utility to see the entire virtual address space of any process alive, including that of the kernel. You can then provide such addresses as input, provided, of course, that they're valid (not within a sparse or empty region of address space).

*Sept 2024: v0.2:*
* devmem_rw driver refactored to be a 'misc' driver, simplifying the code quite a bit
* a few bugfixes: potential overflow fix, deregister the misc device as required
* test cases moved into a folder named `tests`; (hopefully) better test cases.
 
**Trying it out**

Here, we run the project on the Raspberry Pi Zero W.

    # uname -a
     Linux kai1rpi0w 6.6.51+rpt-rpi-v6 #1 Raspbian 1:6.6.51-1+rpt3 (2024-10-08) armv6l GNU/Linux
    
    # cat /proc/iomem
    ...
    20807000-208070ff : 20807000.pixelvalve pixelvalve@7e807000
    20808000-208080ff : 20902000.hdmi hd
    20902000-209025ff : 20902000.hdmi hdmi
    20980000-2098ffff : dwc_otg
    20c00000-20c00fff : 20c00000.v3d v3d@7ec00000
    # 

Lets select the
`20808000-208080ff : 20902000.hdmi hd`
line for our experiment (as we aren't using HDMI now, we're running in headless mode of course).

So the start addr here is `0x20808000` and the length is 256 bytes; we load the driver accordingly, passing parameters to convey this info to it:

$ sudo insmod ../drv_rwmem/devmem_rw.ko iobase_start=0x20808000 iobase_len=256 reg_name=rpi_hdmi force_rel=1

    # dmesg |tail
    ...
    [ 465.396769] devmem_rw: loading out-of-tree module taints kernel.
    [ 465.397511] devmem_rw:rwmem_init_module(): little-endian arch
    [ 465.397915] misc devmem_miscdrv: devmem misc driver (major # 10) registered, minor# = 123, dev node is /dev/devmem_miscdrv
    [ 465.397954] devmem_rw:rwmem_init_module(): attempting to _force release_ the specified mem region..
    [ 465.397999] devmem_rw:rwmem_init_module(): iobase = 0xdc8ef000
    #
The driver has loaded successfully, ioremap'ping the specified h/w memory region into the kernel VAS! Our *rdmem* app now goes to work, issuing an ioctl() to the driver to extract memory content from the specified offset, which it then neatly dumps as both hex and ASCII:

    # ../app_rwmem/rdmem -o 0 256
    Offset +0 +4 +8 +c 0 4 8 c
    00000000 68 64 6d 69 68 64 6d 69 68 64 6d 69 68 64 6d 69 hdmihdmihdmihdmi
    00000016 68 64 6d 69 68 64 6d 69 68 64 6d 69 68 64 6d 69 hdmihdmihdmihdmi
    00000032 68 64 6d 69 68 64 6d 69 68 64 6d 69 68 64 6d 69 hdmihdmihdmihdmi
    00000048 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
    00000064 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
    00000080 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
    00000096 68 64 6d 69 68 64 6d 69 68 64 6d 69 68 64 6d 69 hdmihdmihdmihdmi
    00000112 68 64 6d 69 68 64 6d 69 68 64 6d 69 68 64 6d 69 hdmihdmihdmihdmi
    00000128 68 64 6d 69 68 64 6d 69 68 64 6d 69 68 64 6d 69 hdmihdmihdmihdmi
    00000144 68 64 6d 69 68 64 6d 69 68 64 6d 69 68 64 6d 69 hdmihdmihdmihdmi
    00000160 68 64 6d 69 68 64 6d 69 68 64 6d 69 68 64 6d 69 hdmihdmihdmihdmi
    00000176 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
    00000192 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
    00000208 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
    00000224 68 64 6d 69 68 64 6d 69 68 64 6d 69 68 64 6d 69 hdmihdmihdmihdmi
    00000240 68 64 6d 69 68 64 6d 69 68 64 6d 69 68 64 6d 69 hdmihdmihdmihdmi
    #
Done.
> Written with [StackEdit](https://stackedit.io/).




