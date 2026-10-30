#define _GNU_SOURCE
#include "futex.h"

#include <unistd.h>
#include <sys/syscall.h>

int futex(int *uaddr, int futex_op, int val, uint32_t val2, int *uaddr2, int val3)
{
    return syscall(SYS_futex, uaddr, futex_op, val, val2, uaddr2, val3);
}

int futex_wait(int *uaddr, int val)
{
    return futex(uaddr, FUTEX_WAIT, val, 0, NULL, 0);
}

int futex_wake(int *uaddr, int nr_wake)
{
    return futex(uaddr, FUTEX_WAKE, nr_wake, 0, NULL, 0);
}

int futex_lock_pi(int *uaddr)
{
    return futex(uaddr, FUTEX_LOCK_PI, 0, 0, NULL, 0);
}

int futex_unlock_pi(int *uaddr)
{
    return futex(uaddr, FUTEX_UNLOCK_PI, 0, 0, NULL, 0);
}

int futex_wait_requeue_pi(int *uaddr1, int *uaddr2, int val)
{
    // val2 is the timeout slot; NULL timeout is passed as 0
    return futex(uaddr1, FUTEX_WAIT_REQUEUE_PI, val, 0, uaddr2, 0);
}

int futex_cmp_requeue_pi(int *uaddr1, int *uaddr2, int nr_requeue, int cmpval)
{
    // val = nr_wake, val2 = nr_requeue, val3 = cmpval
    return futex(uaddr1, FUTEX_CMP_REQUEUE_PI, 1, (uint32_t)nr_requeue, uaddr2, cmpval);
}