#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>

static int global1;
int        global2;
static void foo1() { }
void        foo2() { }

int main(void)
{
    /* leaking the address of a global variable */
    int *i = (int *)&global1;
    fwrite(&i, 4, 1, stdout);
    i = (int *)&global2;
    fwrite(&i, 4, 1, stdout);
    i = (int *)&foo1;
    fwrite(&i, 4, 1, stdout);
    i = (int *)&foo2;
    fwrite(&i, 4, 1, stdout);

    return 0;
}
