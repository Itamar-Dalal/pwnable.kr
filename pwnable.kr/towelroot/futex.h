// futex.h
#ifndef FUTEX_H
#define FUTEX_H

#include <stdint.h>

// Kernel ABI values (match linux/futex.h on the target)
#define FUTEX_WAIT             0
#define FUTEX_WAKE             1
#define FUTEX_LOCK_PI          6
#define FUTEX_UNLOCK_PI        7
#define FUTEX_WAIT_REQUEUE_PI  11
#define FUTEX_CMP_REQUEUE_PI   12

// Generic futex syscall wrapper
int futex(int *uaddr, int futex_op, int val, uint32_t val2, int *uaddr2, int val3);

// Convenience wrappers
int futex_wait(int *uaddr, int val);
int futex_wake(int *uaddr, int nr_wake);
int futex_lock_pi(int *uaddr);
int futex_unlock_pi(int *uaddr);
int futex_wait_requeue_pi(int *uaddr1, int *uaddr2, int val);
int futex_cmp_requeue_pi(int *uaddr1, int *uaddr2, int nr_requeue, int cmpval);

// ---- Kernel structures (must match your target kernel exactly) ----

struct list_head_k {
    struct list_head_k *next, *prev;
};

struct plist_node {
    int prio;
    struct list_head_k prio_list;
    struct list_head_k node_list;
};

struct rt_mutex_waiter {
    struct plist_node list_entry;
    struct plist_node pi_list_entry;
    void *task;
    void *lock;
};

#endif