#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("M");

#define SYS_open 5

static int __init my_init(void)
{
    __asm__ __volatile__(
        "cli;"
        "mov %cr0, %eax;"
        "and $0xFFFEFFFF, %eax;"
        "mov %eax, %cr0;"
    );

    void **syscall_table = (void **)0xC15FA020;
    void *sys_open_hooked = syscall_table[SYS_open];
    void *rootkit_base    = (char *)sys_open_hooked - 0x250;
    void *rootkit_sys_open = (char *)rootkit_base + 0x73C;
    syscall_table[SYS_open] = *(void **)rootkit_sys_open;

    __asm__ __volatile__(
        "mov %cr0, %eax;"
        "or $0x10000, %eax;"
        "mov %eax, %cr0;"
        "sti;"
    );
    return 0;
}

static void __exit my_exit(void)
{
    return;
}

module_init(my_init);
module_exit(my_exit);