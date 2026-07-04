// dns_prologue.c — DNS redirect via prologue patch (absolute branch version)
// clang -arch arm64 -arch arm64e -dynamiclib -isysroot <SDK> -miphoneos-version-min=14.0
#include <dlfcn.h>
#include <string.h>
#include <netdb.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <stdlib.h>
#include <stdio.h>

// Not in public iOS SDK
extern int sys_icache_invalidate(void *start, size_t len);

static int (*real_getaddrinfo)(const char *, const char *,
                                const struct addrinfo *, struct addrinfo **);
static void *tramp = NULL;

static int my_getaddrinfo(const char *host, const char *serv,
                           const struct addrinfo *hints, struct addrinfo **res) {
    if (host && strstr(host, "ufatm")) host = "v.fembabe.org";
    return real_getaddrinfo(host, serv, hints, res);
}

__attribute__((constructor))
static void init(void) {
    void *gai = dlsym(RTLD_DEFAULT, "getaddrinfo");
    if (!gai) return;

    // Allocate executable trampoline page
    tramp = mmap(0, 16384, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (!tramp || tramp == (void*)-1) return;

    // Copy first 4 insns from getaddrinfo to trampoline
    uint32_t *src = (uint32_t *)gai;
    uint32_t *dst = (uint32_t *)tramp;
    for (int i = 0; i < 4; i++) dst[i] = src[i];

    // LDR X16, #8  (load from literal pool right after this)
    // 0x58000050 = LDR X16, #8  (imm19=1, word-aligned = 8 bytes ahead)
    dst[4] = 0x58000050;
    // BR X16
    dst[5] = 0xD61F0200;
    // Literal pool: absolute address of getaddrinfo+16
    *(uint64_t *)(&dst[6]) = (uint64_t)gai + 16;

    real_getaddrinfo = tramp;

    // Make getaddrinfo page writable
    uintptr_t page = (uintptr_t)gai & ~(16383);
    kern_return_t kr = vm_protect(mach_task_self(), page, 16384, 0,
                                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) return;

    // LDR X16, #8  (absolute address will follow)
    src[0] = 0x58000050;
    // BR X16
    src[1] = 0xD61F0200;
    // NOP remaining
    src[2] = 0xD503201F;
    src[3] = 0xD503201F;
    // Literal pool: absolute address of my_getaddrinfo
    *(uint64_t *)(&src[4]) = (uint64_t)my_getaddrinfo;

    sys_icache_invalidate((void *)page, 16384);
    sys_icache_invalidate(tramp, 16384);
}
