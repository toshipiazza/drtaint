CFLAGS=-march=armv7 -mfloat-abi=soft -Wl,--rpath=/opt/glibc-arm-gnueabi/lib/libc.so.6 -Wl,--dynamic-linker=/opt/glibc-arm-gnueabi/lib/ld-linux.so.3

all:
	gcc $(CFLAGS) ./simple/simple.s -o ./simple/simple -nostartfiles -static
	gcc $(CFLAGS) ./simple/simple_thumb.s -o ./simple/simple_thumb -nostartfiles -static
	gcc $(CFLAGS) ./simple_leaks/test.c -o ./simple_leaks/test
	gcc $(CFLAGS) ./simple_argv/test.c -o ./simple_argv/test
