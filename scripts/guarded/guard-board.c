// Guard for test runs in this private copy only. A request for the general
// pasteboard gets a private named board, and one line with the stack goes to
// the log. It changes nothing else: named boards pass through untouched.
#include <CoreFoundation/CoreFoundation.h>
#include <execinfo.h>
#include <fcntl.h>
#include <objc/message.h>
#include <objc/runtime.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define GENERAL "Apple CFPasteboard general"

extern CFTypeRef CFPasteboardCreate(CFAllocatorRef, CFStringRef);

static void note(const char *what, int stack) {
    const char *path = getenv("LARSAL_GUARD_LOG");
    if (!path) return;
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) return;
    dprintf(fd, "%ld pid %d %s\n", (long)time(NULL), getpid(), what);
    if (stack) {
        void *frames[32];
        backtrace_symbols_fd(frames, backtrace(frames, 32), fd);
    }
    close(fd);
}

static CFStringRef private_name(void) {
    return CFStringCreateWithFormat(NULL, NULL, CFSTR("larsal-guard-general-%d"), getpid());
}

static int is_general(const void *name) {
    return name && CFStringCompare((CFStringRef)name, CFSTR(GENERAL), 0) == kCFCompareEqualTo;
}

static CFTypeRef guard_create(CFAllocatorRef allocator, CFStringRef name) {
    if (is_general(name)) {
        note("CFPasteboardCreate general", 1);
        name = private_name();
    }
    return CFPasteboardCreate(allocator, name);
}
__attribute__((used)) static const struct {
    const void *replacement;
    const void *replaced;
} interposers[] __attribute__((section("__DATA,__interpose"))) = {{(const void *)guard_create, (const void *)CFPasteboardCreate}};

static id (*real_named)(id, SEL, id);

static id guard_named(id self, SEL cmd, id name) {
    if (is_general(name)) {
        note("+pasteboardWithName: general", 1);
        name = (id)private_name();
    }
    return real_named(self, cmd, name);
}

static id guard_general(id self, SEL cmd) {
    note("+generalPasteboard", 1);
    return real_named(self, sel_registerName("pasteboardWithName:"), (id)private_name());
}

__attribute__((constructor)) static void start(void) {
    Class board = objc_getClass("NSPasteboard");
    Method named = board ? class_getClassMethod(board, sel_registerName("pasteboardWithName:")) : NULL;
    Method general = board ? class_getClassMethod(board, sel_registerName("generalPasteboard")) : NULL;
    if (named && general) {
        real_named = (id(*)(id, SEL, id))method_setImplementation(named, (IMP)guard_named);
        method_setImplementation(general, (IMP)guard_general);
        note("loaded, both methods replaced", 0);
    } else {
        note("loaded, methods NOT found", 0);
    }
}

