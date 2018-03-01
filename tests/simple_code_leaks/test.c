#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>

static int global;

int main(void)
{
    /* leaking the address of a global variable */
    int *i = &global;
    fwrite(&i, 4, 1, stdout);
    return 0;
}
