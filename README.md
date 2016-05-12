# device-memory-readwrite
Automatically exported from code.google.com/p/device-memory-readwrite

Read and/or Write to any memory location (RAM or H/W IO Memory) on a device.

This project enables the user to read from and/or write to any generic memory location(s) on a 
device running the 2.6 / 3.x Linux OS. This includes "regular" RAM as well as hardware IO Memory 
that's mapped into the kernel virtual address space. In fact, the driver will perform the mapping, 
given the hardware base address and length.

The read/write utility programs run in user-land and talk to the underlying kernel driver via the 
ioctl system call.

This could be extremely useful for driver authors, kernel developers, etc who want to peek/poke memory 
for learning, debug, testing, register lookups/writes and similar purposes.

To get started, read the Wiki page (Wiki menu) and clone the git tree (from the Source menu).
