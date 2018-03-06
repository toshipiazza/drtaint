#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>

static int global1;
int        global2;
static void foo1() { }
void        foo2() { }

int main(void)
{
    /* leaking the address of a global variable */
    int *i = &global1;
    fwrite(&i, 4, 1, stdout);
    i = &global2;
    fwrite(&i, 4, 1, stdout);
    i = &foo1;
    fwrite(&i, 4, 1, stdout);
    i = &foo2;
    fwrite(&i, 4, 1, stdout);
    return 0;
}
