/* The manifest route an earlier run proved: same installed compiler, same argv, three private temp variables. No receipts: the earlier run proved its behaviour. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static const char compiler[] = "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/swiftc";
static const char private_tmp[] = PRIVATE_TMP;

int main(int argc, char **argv) {
    (void)argc;
    if (setenv("TMPDIR", private_tmp, 1) || setenv("TMP", private_tmp, 1) || setenv("TEMP", private_tmp, 1)) return 125;
    execv(compiler, argv);
    perror("compiler exec");
    return 126;
}
