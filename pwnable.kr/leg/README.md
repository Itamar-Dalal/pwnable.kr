# Pwnable.kr leg CTF writeup
```c
int main(){
	int key=0;
	printf("Daddy has very strong arm! : ");
	scanf("%d", &key);
	if( (key1()+key2()+key3()) == key ){
		printf("Congratz!\n");
		int fd = open("flag", O_RDONLY);
		char buf[100];
		int r = read(fd, buf, 100);
		write(0, buf, r);
	}
	else{
		printf("I have strong leg :P\n");
	}
	return 0;
}
```
The code receives an input (number), and if it is equal to the combined result of the three function returns, it will print the flag. We just need to look at the ARM assembly code to check what each function returns.
## key1
```asm
(gdb) disass key1
Dump of assembler code for function key1:
   0x00008cd4 <+0>:	push	{r11}		; (str r11, [sp, #-4]!)
   0x00008cd8 <+4>:	add	r11, sp, #0
   0x00008cdc <+8>:	mov	r3, pc
   0x00008ce0 <+12>:	mov	r0, r3
   0x00008ce4 <+16>:	sub	sp, r11, #0
   0x00008ce8 <+20>:	pop	{r11}		; (ldr r11, [sp], #4)
   0x00008cec <+24>:	bx	lr
End of assembler dump.
```
What's important for us is these lines:
```asm
   0x00008cdc <+8>:	mov	r3, pc
   0x00008ce0 <+12>:	mov	r0, r3
```
The `pc` is a register that holds the address of the current instruction, plus 8 (in ARM). So the register `r3` is equal to `0x00008cdc + 0x8 = 0x00008ce4`. After that, the value in `r3` moves to `r0`, which is the returned value.
## key2
```asm
(gdb) disass key2
Dump of assembler code for function key2:
   0x00008cf0 <+0>:	push	{r11}		; (str r11, [sp, #-4]!)
   0x00008cf4 <+4>:	add	r11, sp, #0
   0x00008cf8 <+8>:	push	{r6}		; (str r6, [sp, #-4]!)
   0x00008cfc <+12>:	add	r6, pc, #1
   0x00008d00 <+16>:	bx	r6
   0x00008d04 <+20>:	mov	r3, pc
   0x00008d06 <+22>:	adds	r3, #4
   0x00008d08 <+24>:	push	{r3}
   0x00008d0a <+26>:	pop	{pc}
   0x00008d0c <+28>:	pop	{r6}		; (ldr r6, [sp], #4)
   0x00008d10 <+32>:	mov	r0, r3
   0x00008d14 <+36>:	sub	sp, r11, #0
   0x00008d18 <+40>:	pop	{r11}		; (ldr r11, [sp], #4)
   0x00008d1c <+44>:	bx	lr
End of assembler dump.
```
Before I explain the code, we need to understand how ARM processors work. ARM processors can switch between ARM and Thumb modes based on the address of the instructions being executed:
#### Even Address (ARM Mode): If the address of an instruction is even, the processor is in ARM mode.
#### Odd Address (Thumb Mode): If the address of an instruction is odd, the processor is in Thumb mode.
When the processor is in Thumb mode, the pc register is equal to the current address plus 4 (not 8).
```asm
   0x00008cfc <+12>:	add	r6, pc, #1
   0x00008d00 <+16>:	bx	r6
```
In these lines, the program adds 1 to the `pc` register (thus making the processor run in Thumb mode) and jumps to the following lines:
```asm
   0x00008d04 <+20>:	mov	r3, pc
   0x00008d06 <+22>:	adds	r3, #4
   0x00008d10 <+32>:	mov	r0, r3
```
The value in `pc` (`0x00008d04`) moves to `r3`, plus 4 (Thumb mode). After that, the program adds `4` to the value of `r3` and moves it to `r0`. The result is: `r0 = 0x00008d04 + 0x4 + 0x4 = 0x00008d0c`.
## key3
```asm
(gdb) disass key3
Dump of assembler code for function key3:
   0x00008d20 <+0>:	push	{r11}		; (str r11, [sp, #-4]!)
   0x00008d24 <+4>:	add	r11, sp, #0
   0x00008d28 <+8>:	mov	r3, lr
   0x00008d2c <+12>:	mov	r0, r3
   0x00008d30 <+16>:	sub	sp, r11, #0
   0x00008d34 <+20>:	pop	{r11}		; (ldr r11, [sp], #4)
   0x00008d38 <+24>:	bx	lr
End of assembler dump.
(gdb)
```
What we care about are these lines:
```asm
   0x00008d28 <+8>:	mov	r3, lr
   0x00008d2c <+12>:	mov	r0, r3
```
The `lr` register holds the return address after the function executes. We need to look for this address in the main function:
```asm
   0x00008d7c <+64>:	bl	0x8d20 <key3>
   0x00008d80 <+68>:	mov	r3, r0
```
So the return address is `0x00008d80`. That value moves to `r3` and then to `r0`.
## solution
Now we just need to add the values we got: `0x00008ce4 + 0x00008d0c + 0x00008d80 = 0x0001A770`.
The program receives the input as decimal, so we need to convert it to decimal: `0x0001A770 = 108400`. <br/>
When running, we get this:
```
Daddy has very strong arm! : 108400
Congratz!
My daddy has a lot of ARMv5te muscle!
```
