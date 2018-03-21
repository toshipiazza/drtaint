CFLAGS=-march=armv7 -mfloat-abi=soft -Wl,--rpath=/opt/glibc-arm-gnueabi/lib/libc.so.6 -Wl,--dynamic-linker=/opt/glibc-arm-gnueabi/lib/ld-linux.so.3

all:
	gcc $(CFLAGS) ./simple_argv.c -o simple_argv
	gcc $(CFLAGS) ./simple_leaks.c -o ./simple_leaks
	gcc $(CFLAGS) -fPIC -fPIE -pie ./simple_code_leaks.c -o ./simple_code_leaks
