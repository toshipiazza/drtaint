#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>

void write_assert_fail(void *p)
{
    assert(write(1, p, 4) == -1);
}

int main(int argc, char **argv)
{
    if (argc == 2) {
        /* meant to facilitate code leaks */
        unsigned int addr = strtoul(argv[1], NULL, 16);
        write_assert_fail((void*)addr);
        return 0;
    }

    /* leak fastbin freelist next pointer, which is a heap leak */
    unsigned int *a = malloc(10);
    unsigned int *b = malloc(10);
    unsigned int *c = malloc(10);
    free(a);
    free(c);
    write_assert_fail(c);

    /* leak heap address from the stack */
    write_assert_fail(c);

    /* leak stack address from the stack */
    unsigned int **d = &c;
    write_assert_fail(d);

    /* leak stack address from environ */
    extern char **environ;
    write_assert_fail(environ);

    /* leak a libc address provided by the loader */
    write_assert_fail(&stdout);

    return 0;
}
