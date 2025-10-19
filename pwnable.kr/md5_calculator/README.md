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
Note: The code for the rest of the functions is not neccecry for the solution of the challnge, we just need to know what they do.

## Analysis

The canary is set in these lines:
```asm
.text:08048EDF                 mov     eax, large gs:14h
.text:08048EE5                 mov     [ebp+var_C], eax
```

### maim

### process_hash

The function get input from the user until he use enter. Than it copies 1024 bytes (chars) from `stdin` to the address `0x804b0e0`, and than it sets the first 512 bytes of `0x804b0e0` to `0`.

## Exploit Code

```python

```


