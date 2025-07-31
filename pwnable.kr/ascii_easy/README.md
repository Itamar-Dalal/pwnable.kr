# Pwnable.kr ascii_easy CTF Writeup

## Problem Description  
The code provided for the challenge is as follows:

```c
```

## Analysis  

```asm
pop eax ; ret       → eax = 5 (sys_open)
pop ebx ; ret       → ebx = "filename"
pop ecx ; ret       → ecx = O_RDONLY
int 0x80; rer       → syscall
```
## Exploit Code
