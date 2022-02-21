#ifndef KERNEL_HOOKS
#define KERNEL_HOOKS

#include <mach/kmod.h>
#include <stdint.h>

/* pf can find these functions */
static void (*proc_name)(int pid, char *buf, int size);
static pid_t (*proc_pid)(void *);
static void *(*current_proc)(void);
static void (*kprintf)(const char *, ...);

/* hooked using hardcoded addresses */
kern_return_t (*kernel_memory_allocate)(void *, uint64_t *, uint64_t,
        uint64_t, uint64_t, uint32_t);
kern_return_t _kernel_memory_allocate(void *map, uint64_t *addrp,
        uint64_t size, uint64_t mask, uint64_t flags, uint32_t tag);

void (*kmem_free)(void *, uint64_t *, uint64_t);
void _kmem_free(void *map, uint64_t *addr, uint64_t size);
#endif
