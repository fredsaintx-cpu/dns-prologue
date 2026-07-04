// dns_prologue.c — redirect ufatm -> v.fembabe.org via getaddrinfo prologue patch
// clang -arch arm64 -arch arm64e -dynamiclib -isysroot <SDK> -miphoneos-version-min=14.0
#include <dlfcn.h>
#include <string.h>
#include <netdb.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <stdlib.h>

// Trampoline page (executable, writable)
static void *trampoline_page = NULL;
static int (*real_getaddrinfo)(const char *, const char *,
                                const struct addrinfo *, struct addrinfo **);

static int my_getaddrinfo(const char *host, const char *serv,
                           const struct addrinfo *hints, struct addrinfo **res) {
    if (host && strstr(host, "ufatm")) host = "v.fembabe.org";
    return real_getaddrinfo(host, serv, hints, res);
}

__attribute__((constructor))
static void init(void) {
    void *gai = dlsym(RTLD_DEFAULT, "getaddrinfo");
    if (!gai) return;

    // Allocate executable+writable trampoline page
    trampoline_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (trampoline_page == (void *)-1) return;

    // Save first 4 instructions from getaddrinfo
    uint32_t *src = (uint32_t *)gai;
    uint32_t *tramp = (uint32_t *)trampoline_page;
    for (int i = 0; i < 4; i++) tramp[i] = src[i];

    // Add branch from trampoline[4] back to getaddrinfo+16
    intptr_t gai_off = (intptr_t)gai;
    intptr_t ret_off = (intptr_t)&tramp[4];
    intptr_t delta = (gai_off + 16 - ret_off) / 4;
    tramp[4] = 0x14000000 | (delta & 0x03FFFFFF);

    // Set trampoline as real function pointer
    real_getaddrinfo = trampoline_page;

    // Make getaddrinfo page writable
    uintptr_t page = (uintptr_t)gai & ~(16383);
    if (vm_protect(mach_task_self(), page, 16384, 0,
                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS)
        return;

    // Write B <my_getaddrinfo> at getaddrinfo entry
    delta = ((intptr_t)my_getaddrinfo - gai_off) / 4;
    src[0] = 0x14000000 | (delta & 0x03FFFFFF);
    src[1] = 0xD503201F;  // NOP
    src[2] = 0xD503201F;  // NOP
    src[3] = 0xD503201F;  // NOP

    // Flush caches
    __builtin___clear_cache((void *)page, (void *)(page + 16384));
    __builtin___clear_cache(trampoline_page, trampoline_page + 4096);
}
