# device-memory-readwrite

Read and/or Write to pretty much _any_ memory location (RAM or hardware IO Memory) on a device; these hardware IO locations are often called Memory Mapped IO (MMIO) regions and often are used to access the hardware registers or RAM on a peripheral.

This project enables the user to read from and/or write to any generic memory location(s) on a device running the modern (>=3.x) Linux OS. This includes "regular" RAM as well as hardware IO Memory (MMIO) that's mapped into kernel virtual address space.
Given the hardware base address and length (as module parameters), the driver component will perform the mapping.

The read/write utility programs run in user-land and talk to the underlying kernel driver via the ioctl system call.

This project can be useful for driver authors, kernel developers, etc who want to peek/poke memory for prototyping purposes, learning, debug, testing, register lookups/writes and similar purposes.

To get started, please clone the git tree, read the 'Devmem HOWTO.pdf' PDF document, and get to it!

***TIP*** :
Use the *procmap* utility to see the entire virtual address space of any process alive, including that of the kernel. You can then provide such addresses as input, provided, of course, that they're valid
(not within a sparse or empty region of address space). The [procmap](https://github.com/kaiwan/procmap) utility link.

*Sept 2024: v0.2:*

  * devmem_rw driver refactored to be a 'misc' driver, simplifying the code quite a bit
  * a few bugfixes: potential overflow fix, deregister the misc device as required
  * test cases moved into a folder named *tests*; (hopefully) better test cases.
