#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    if (argc == 2) {
        /* meant to facilitate code leaks */
        unsigned int addr = strtoul(argv[1], NULL, 16);
        fwrite((void *)addr, 4, 1, stdout);
        return 0;
    }

    /* leak fastbin freelist next pointer, which is a heap leak */
    unsigned int *a = malloc(10);
    unsigned int *b = malloc(10);
    unsigned int *c = malloc(10);
    free(a);
    free(c);
    fwrite(c,  4, 1, stdout);

    /* leak heap address from the stack */
    fwrite(&c, 4, 1, stdout);

    /* leak stack address from the stack */
    unsigned int **d = &c;
    fwrite(&d, 4, 1, stdout);

    /* leak stack address from environ */
    extern char **environ;
    fwrite(environ, 4, 1, stdout);

    /* leak a libc address provided by the loader */
    fwrite(&stdout, 4, 1, stdout);

    return 0;
}
