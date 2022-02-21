/*
 * kernel_hooks.c
 *
 * An xnuspy program that hooks and logs
 *      - kernel_memory_allocate
 *      - kmem_free
 *
 * Experimental. Expect inconsistencies.
 *
 * (c) 2022 PARS Defense (parsdefense.com)
 */

#include <errno.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "kernel_hooks.h"
#include "xnuspy_ctl.h"

#include <mach/kmod.h>
#include <stdbool.h>
#include <stdint.h>

/*****************************************************
 * REPLACE THESE OFFSETS WITH THE ONES OBTAINED FROM *
 * YOUR DEVICE'S KERNELCACHE, OTHERWISE DON'T EXPECT *
 * THIS PROGRAM TO WORK                              *
 *****************************************************/

/* iPhone X, 14.6 */
#define ADDROF_KERNEL_MEMORY_ALLOCATE   0xFFFFFFF007B2666C /* iPhone 8, 14.6 0xfffffff007b2e66c, iPhone SE (2016), 14.7 0xfffffff0071f1384 */
#define ADDROF_KMEM_FREE                0xFFFFFFF007B28478

/* replace offsets below if you want to see the map where allocation is performed */
/* ret addr from kmem_alloc_flags(alloc_map, ...)*/
#define ADDROF_KALLOC_MAP_INDICATOR     0XFFFFFFF007A92174
/* ret addr from kmem_alloc_flags called by "falling back to kernel_map" */
#define ADDROF_KALLOC_MAP_IS_FULL_INDICATOR 0XFFFFFFF007A921C4

uint64_t kernel_slide = 0;
uint64_t kernel_map;
uint64_t kalloc_map;

static pid_t caller_pid(void){
    return proc_pid(current_proc());
}

/* DON'T CALL ANY FUNCTION OUTSIDE THE .TEXT OF THIS BINARY; E.G PRINTF (USE KPRINTF) */
kern_return_t _kernel_memory_allocate(void *map, uint64_t *addrp,
        uint64_t size, uint64_t mask, uint64_t flags, uint32_t tag){
    uint64_t caller = (uint64_t)__builtin_return_address(0) - kernel_slide;

    kern_return_t kret = kernel_memory_allocate(map, addrp, size, mask,
            flags, tag);

    ///////////////////////////////////////////////////////////////
    pid_t pid = caller_pid();
    char caller_name[MAXCOMLEN + 1] = {0}; 
    proc_name(pid, caller_name, MAXCOMLEN + 1);
    ///////////////////////////////////////////////////////////////

    char *msg = "", *map_name = "";

    /* ret addr from kmem_alloc_flags(alloc_map, ...)*/
    if (caller == ADDROF_KALLOC_MAP_INDICATOR) {
        /* set kalloc_map everytime b/c we're not sure what 
         * alloc_map = kalloc_map_for_size(size) will return
         */
        kalloc_map = (uint64_t)map;
        map_name = "(KALLOC_MAP)";
    }
    /* kernel_map is found by PF */
    else if ((uint64_t)map == kernel_map)
        map_name = "(KERNEL_MAP)";

    /* ret addr from kmem_alloc_flags called by "falling back to kernel_map" */
    if (caller == ADDROF_KALLOC_MAP_IS_FULL_INDICATOR)
        msg = "KALLOC_MAP is full!";


    kprintf("%20s | %20s | caller: 0x%016llx | %d = kernel_memory_allocate(*map = %p %12s, *addrp = 0x%016llx, size = 0x%016llx, mask = 0x%016llx, flags = 0x%016llx, tag = 0x%016x);\n",
            msg, caller_name, caller, kret, map, map_name, *addrp, size, mask, flags, tag);

    return kret;
}

void _kmem_free(void *map, uint64_t *addr, uint64_t size)
{
    uint64_t caller = (uint64_t)__builtin_return_address(0) - kernel_slide;

    char *map_name = "";

    ///////////////////////////////////////////////////////////////
    pid_t pid = caller_pid();
    char caller_name[MAXCOMLEN + 1] = {0}; 
    proc_name(pid, caller_name, MAXCOMLEN + 1);
    ///////////////////////////////////////////////////////////////

    if ((uint64_t)map == kernel_map)
        map_name = "(KERNEL_MAP)";
    else if ((uint64_t)map == kalloc_map)
        map_name = "(KALLOC_MAP)";

    kprintf("                     | %20s | caller: 0x%016llx |                  kmem_free(*map = %p %12s, *addr  = 0x%016llx, size = 0x%016llx);\n",
            caller_name, caller, map, map_name, addr, size);

    /* printf's first; kmem_free last. Otherwise crashes
     * possibly due to addr goes away after calling kmem_free
     */
    kmem_free(map, addr, size);
}

static long SYS_xnuspy_ctl = 0;

static bool setup_xnuspy()
{
    size_t oldlen = sizeof(long);
    int ret = sysctlbyname("kern.xnuspy_ctl_callnum", &SYS_xnuspy_ctl,
            &oldlen, NULL, 0);

    if(ret == -1){
        printf("sysctlbyname with kern.xnuspy_ctl_callnum failed: %s\n",
                strerror(errno));
        return false;
    }

    ret = syscall(SYS_xnuspy_ctl, XNUSPY_CHECK_IF_PATCHED, 0, 0, 0);

    if(ret != 999){
        printf("xnuspy_ctl isn't present?\n");
        return false;
    }

    extern uint64_t kernel_slide;
    ret = syscall(SYS_xnuspy_ctl, XNUSPY_CACHE_READ, KERNEL_SLIDE,
            &kernel_slide, 0, 0);

    if(ret){
        printf("failed reading kernel slide from xnuspy cache\n");
        return false;
    }

    return true;
}

static bool install_kernel_hooks(void){
    printf("[*] Installing kernel_memory_allocate hook\n");
    if(syscall(SYS_xnuspy_ctl, XNUSPY_INSTALL_HOOK,
            ADDROF_KERNEL_MEMORY_ALLOCATE, _kernel_memory_allocate, &kernel_memory_allocate))
        return false;

    printf("[*] Installing kmem_free hook\n");
    if(syscall(SYS_xnuspy_ctl, XNUSPY_INSTALL_HOOK,
            ADDROF_KMEM_FREE, _kmem_free, &kmem_free))
        return false;

    printf("[*] Done\n");
    return true;
}

static int gather_kernel_offsets(void){
    int ret;
#define GET(a, b) \
    do { \
        ret = syscall(SYS_xnuspy_ctl, XNUSPY_CACHE_READ, a, b, 0); \
        if(ret){ \
            printf("%s: failed getting %s\n", __func__, #a); \
            return ret; \
        } \
    } while (0)

    GET(KPRINTF, &kprintf);
    GET(KERNEL_MAP, &kernel_map);
    kernel_map |= 0xfffffff000000000;
    GET(PROC_NAME, &proc_name);
    GET(PROC_PID, &proc_pid);
    GET(CURRENT_PROC, &current_proc);

    return 0;
}

int main(int argc, char **argv){
    if(setup_xnuspy() == false) {
        printf("Error setting up xnuspy: %s\n", strerror(errno));
        return 1;
    }
    
    int ret = gather_kernel_offsets();
    if(ret){
        printf("Could not hook function(s): %s\n", strerror(errno));
        return 1;
    }

    if(!install_kernel_hooks())
        return false;

    for(;;);

    return true;
}
