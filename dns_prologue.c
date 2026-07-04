// dns_prologue.c — prologue-patch getaddrinfo to redirect ufatm -> v.fembabe.org
// No GOT, no PAC, no __DATA_CONST. Overwrites first instructions of getaddrinfo.
// clang -arch arm64 -arch arm64e -dynamiclib -isysroot <SDK> -miphoneos-version-min=14.0

#include <dlfcn.h>
#include <string.h>
#include <netdb.h>
#include <sys/mman.h>
#include <mach/mach.h>
<parameter name="new_string" string="true">#include <unistd.h>

// iOS doesn't expose sys_icache_invalidate in public SDK
extern int sys_icache_invalidate(void *start, size_t len);

static int (*real_getaddrinfo)(const char *, const char *,
                                const struct addrinfo *, struct addrinfo **);

// Trampoline: saved instructions + branch back
static uint32_t trampoline[8];
static volatile int trampoline_ready = 0;
static void *target_addr = NULL;

static int my_getaddrinfo(const char *host, const char *serv,
                           const struct addrinfo *hints, struct addrinfo **res) {
    if (host && strstr(host, "ufatm"))
        host = "v.fembabe.org";
    return real_getaddrinfo(host, serv, hints, res);
}

__attribute__((constructor))
static void init(void) {
    // Find getaddrinfo
    void *gai = dlsym(RTLD_DEFAULT, "getaddrinfo");
    if (!gai) return;
    target_addr = gai;

    // Make the TEXT page writable (iOS arm64 page = 16KB)
    uintptr_t page = (uintptr_t)gai & ~(16383);
    vm_protect(mach_task_self(), page, 16384, 0,
               VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);

    // Save first 4 instructions to the trampoline
    uint32_t *src = (uint32_t *)gai;
    for (int i = 0; i < 4; i++)
        trampoline[i] = src[i];

    // Add a branch from trampoline back to getaddrinfo+16
    // B <offset>: offset = (target - PC) / 4
    intptr_t offset = ((uintptr_t)gai + 16 - (uintptr_t)&trampoline[4]) / 4;
    trampoline[4] = 0x14000000 | (offset & 0x03FFFFFF);

    // Set the trampoline as the "real" function
    real_getaddrinfo = (void *)trampoline;
    trampoline_ready = 1;

    // Write branch to my_getaddrinfo at getaddrinfo entry
    offset = ((uintptr_t)my_getaddrinfo - (uintptr_t)gai) / 4;
    src[0] = 0x14000000 | (offset & 0x03FFFFFF);  // B <offset>
    // NOP the rest
    src[1] = 0xD503201F;  // NOP
    src[2] = 0xD503201F;  // NOP
    src[3] = 0xD503201F;  // NOP

    // Flush instruction cache
    sys_icache_invalidate((void *)page, 16384);
    sys_icache_invalidate(trampoline, sizeof(trampoline));
}
