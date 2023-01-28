# device-memory-readwrite

Read and/or Write to pretty much _any_ memory location (RAM or H/W IO Memory) on a device.

This project enables the user to read from and/or write to any generic memory location(s) on a 
device running the modern (>=3.x) Linux OS. This includes "regular" RAM as well as hardware IO Memory 
that's mapped into kernel virtual address space. 
Given the hardware base address and length (as module parameters), the driver component will perform the mapping.

The read/write utility programs run in user-land and talk to the underlying kernel driver via the 
ioctl system call.

This project can be useful for driver authors, kernel developers, etc who want to peek/poke memory 
for prototyping purposes, learning, debug, testing, register lookups/writes and similar purposes.

To get started, please clone the git tree, read the 'Devmem HOWTO.pdf' PDF document, and get to it!
TIP:
Use the procmap utility to see the entire virtual address space of any process alive, including that
of the kernel! You can then provide such addresses as input, provided, of course, that they're valid
(not within a sparse or empty region of VAS).
procmap: https://github.com/kaiwan/procmap .
