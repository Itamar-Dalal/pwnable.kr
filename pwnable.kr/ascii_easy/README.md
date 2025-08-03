# Pwnable.kr ascii_easy CTF Writeup

## Problem Description  
The code provided for the challenge is as follows:

```c
```

## Analysis  

```asm
0x00b8a40 : execvp
0x000973c : 63 00 (c /0)

export PATH="$PATH:/home/itamar/bin"
```
## Exploit Code
