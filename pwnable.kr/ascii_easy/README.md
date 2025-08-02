# Pwnable.kr ascii_easy CTF Writeup

## Problem Description  
The code provided for the challenge is as follows:

```c
```

## Analysis  

```asm
0x00074040 : xor eax, eax ; ret
0x00098430 : add eax, 8 ; ret
0x00147060 : add eax, 3 ; ret
0x00109177 : int 0x80
```
## Exploit Code
