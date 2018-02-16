#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

void print_hash(unsigned int i)
{
    int hash = 0x41424344;
    for (int j = 0; j < 100; ++j)
        hash = (hash ^ i) + 0x41424344;
    write(1, &hash, 4);
}

int main(void)
{
    int *s = alloca(100);
    int *h = malloc(100);
    printf("Printing leaks with write()\n");
    write(1, &s, 4);
    write(1, &h, 4);
    printf("Printing leaks with fwrite()\n");
    fwrite(&s, 4, 1, stdout);
    fwrite(&h, 4, 1, stdout);
    printf("Printing obfuscated leaks\n");
    print_hash((unsigned int)s);
    print_hash((unsigned int)h);
    return 0;
}
