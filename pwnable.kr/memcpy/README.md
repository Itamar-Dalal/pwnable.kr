```c
memcpy@ubuntu:~$ cat memcpy.c
// gcc -o memcpy memcpy.c -m32 -lm
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <math.h>

unsigned long long rdtsc(){
        asm("rdtsc");
}

char* slow_memcpy(char* dest, const char* src, size_t len){
        int i;
        for (i=0; i<len; i++) {
                dest[i] = src[i];
        }
        return dest;
}

char* fast_memcpy(char* dest, const char* src, size_t len){
        size_t i;
        // 64-byte block fast copy
        if(len >= 64){
                i = len / 64;
                len &= (64-1);
                while(i-- > 0){
                        __asm__ __volatile__ (
                        "movdqa (%0), %%xmm0\n"
                        "movdqa 16(%0), %%xmm1\n"
                        "movdqa 32(%0), %%xmm2\n"
                        "movdqa 48(%0), %%xmm3\n"
                        "movntps %%xmm0, (%1)\n"
                        "movntps %%xmm1, 16(%1)\n"
                        "movntps %%xmm2, 32(%1)\n"
                        "movntps %%xmm3, 48(%1)\n"
                        ::"r"(src),"r"(dest):"memory");
                        dest += 64;
                        src += 64;
                }
        }

        // byte-to-byte slow copy
        if(len) slow_memcpy(dest, src, len);
        return dest;
}

int main(void){

        setvbuf(stdout, 0, _IONBF, 0);
        setvbuf(stdin, 0, _IOLBF, 0);

        printf("Hey, I have a boring assignment for CS class.. :(\n");
        printf("The assignment is simple.\n");

        printf("-----------------------------------------------------\n");
        printf("- What is the best implementation of memcpy?        -\n");
        printf("- 1. implement your own slow/fast version of memcpy -\n");
        printf("- 2. compare them with various size of data         -\n");
        printf("- 3. conclude your experiment and submit report     -\n");
        printf("-----------------------------------------------------\n");

        printf("This time, just help me out with my experiment and get flag\n");
        printf("No fancy hacking, I promise :D\n");

        unsigned long long t1, t2;
        int e;
        char* src;
        char* dest;
        unsigned int low, high;
        unsigned int size;
        // allocate memory
        char* cache1 = mmap(0, 0x4000, 7, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        char* cache2 = mmap(0, 0x4000, 7, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        src = mmap(0, 0x2000, 7, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

        size_t sizes[10];
        int i=0;

        // setup experiment parameters
        for(e=4; e<14; e++){    // 2^13 = 8K
                low = pow(2,e-1);
                high = pow(2,e);
                printf("specify the memcpy amount between %d ~ %d : ", low, high);
                scanf("%d", &size);
                if( size < low || size > high ){
                        printf("don't mess with the experiment.\n");
                        exit(0);
                }
                sizes[i++] = size;
        }

        sleep(1);
        printf("ok, lets run the experiment with your configuration\n");
        sleep(1);

        // run experiment
        for(i=0; i<10; i++){
                size = sizes[i];
                printf("experiment %d : memcpy with buffer size %d\n", i+1, size);
                dest = malloc( size );

                memcpy(cache1, cache2, 0x4000);         // to eliminate cache effect
                t1 = rdtsc();
                slow_memcpy(dest, src, size);           // byte-to-byte memcpy
                t2 = rdtsc();
                printf("ellapsed CPU cycles for slow_memcpy : %llu\n", t2-t1);

                memcpy(cache1, cache2, 0x4000);         // to eliminate cache effect
                t1 = rdtsc();
                fast_memcpy(dest, src, size);           // block-to-block memcpy
                t2 = rdtsc();
                printf("ellapsed CPU cycles for fast_memcpy : %llu\n", t2-t1);
                printf("\n");
        }

        printf("thanks for helping my experiment!\n");
        printf("flag : [erased here. get it from server]\n");
        return 0;
}

memcpy@ubuntu:~$ nc 0 9022
Hey, I have a boring assignment for CS class.. :(
The assignment is simple.
-----------------------------------------------------
- What is the best implementation of memcpy?        -
- 1. implement your own slow/fast version of memcpy -
- 2. compare them with various size of data         -
- 3. conclude your experiment and submit report     -
-----------------------------------------------------
This time, just help me out with my experiment and get flag
No fancy hacking, I promise :D
specify the memcpy amount between 8 ~ 16 : 16
specify the memcpy amount between 16 ~ 32 : 32
specify the memcpy amount between 32 ~ 64 : 40
specify the memcpy amount between 64 ~ 128 : 120
specify the memcpy amount between 128 ~ 256 : 248
specify the memcpy amount between 256 ~ 512 : 504
specify the memcpy amount between 512 ~ 1024 : 1016
specify the memcpy amount between 1024 ~ 2048 : 2040
specify the memcpy amount between 2048 ~ 4096 : 4088
specify the memcpy amount between 4096 ~ 8192 : 8184
ok, lets run the experiment with your configuration
experiment 1 : memcpy with buffer size 16
ellapsed CPU cycles for slow_memcpy : 5624
ellapsed CPU cycles for fast_memcpy : 1106

experiment 2 : memcpy with buffer size 32
ellapsed CPU cycles for slow_memcpy : 1596
ellapsed CPU cycles for fast_memcpy : 1604

experiment 3 : memcpy with buffer size 40
ellapsed CPU cycles for slow_memcpy : 1798
ellapsed CPU cycles for fast_memcpy : 1940

experiment 4 : memcpy with buffer size 120
ellapsed CPU cycles for slow_memcpy : 4898
ellapsed CPU cycles for fast_memcpy : 2644

experiment 5 : memcpy with buffer size 248
ellapsed CPU cycles for slow_memcpy : 9848
ellapsed CPU cycles for fast_memcpy : 2678

experiment 6 : memcpy with buffer size 504
ellapsed CPU cycles for slow_memcpy : 19778
ellapsed CPU cycles for fast_memcpy : 2958

experiment 7 : memcpy with buffer size 1016
ellapsed CPU cycles for slow_memcpy : 39316
ellapsed CPU cycles for fast_memcpy : 3228

experiment 8 : memcpy with buffer size 2040
ellapsed CPU cycles for slow_memcpy : 79154
ellapsed CPU cycles for fast_memcpy : 3562

experiment 9 : memcpy with buffer size 4088
ellapsed CPU cycles for slow_memcpy : 157698
ellapsed CPU cycles for fast_memcpy : 4812

experiment 10 : memcpy with buffer size 8184
ellapsed CPU cycles for slow_memcpy : 327922
ellapsed CPU cycles for fast_memcpy : 7492

thanks for helping my experiment!
flag : b0thers0m3_m3m0ry_4lignment
```
<h2><u>Explanation:</u></h2>

The implementation of the fast `memcpy` uses the `MOVNTPS` and `MOVDQA` instructions. These instructions require addresses that are aligned to 16 bytes. The problem is that the program uses `malloc` to allocate these addresses, and `malloc` returns 8-byte aligned addresses, not 16-byte aligned ones. This misalignment causes the execution to fail.

When we run the program, it only crashes after experiment 3, because until the length exceeds 64 bytes, the program uses the slow memcpy. To make the program work despite this bug, we need to provide values that result in `malloc` returning 16-byte aligned addresses. Once this is done, the flag should be printed as expected.
