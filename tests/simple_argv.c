#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

int main(int argc, char **argv, char **envp)
{
    int i;
    /* test argv taint status */
    for (i = 0; i < argc; ++i)
        printf("%s\n", argv[i]);
    for (i = 0; envp[i]; ++i)
        printf("%s\n", envp[i]);
    /* test envp taint status */
    for (; *envp; ++envp)              assert(write(1, &envp, 4) == -1);
    for (i = 0; i < argc; ++i, ++argv) assert(write(1, &argv, 4) == -1);
}
