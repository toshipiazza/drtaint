#include <sys/utsname.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syscall.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

void assert_write(void *a, int len)
{
    int ret = write(1, a, len);
    assert(ret != -1);
}

int main(int argc, char **argv)
{
    /* test uname */
    struct utsname a;
    uname(&a);
    assert_write(&a, sizeof(a));

    /* test lstat glibc wrapper */
    struct stat b;
    lstat(argv[0], &b);
    assert_write(&b, sizeof(b));

    /* test clock_gettime */
    struct timespec c;
    clock_gettime(CLOCK_REALTIME, &c);
    assert_write(&c, sizeof(c));

    return 0;
}
