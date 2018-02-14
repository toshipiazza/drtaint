#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

int bar(int a, int b, int c, int d)
{
    a = 1;
    b = 2;
    c = 3;
    d = 4;
}

int foo(int a, int b, int c, int d)
{
    bar(a, b, c, d);
    return a + b + c + d;
}

int _start(void)
{
    char j[100] = "Hello world from the stack!\n";
    foo(0xdead, 0xbeef, 0xcafe, 0xbabe);
    char *k = &j;
    write(1, &k, 4);
    char *i = malloc(100);
    strcpy(i, "Hello world from the heap!\n");
    write(1, &i, 4);
    _exit(0);
}
