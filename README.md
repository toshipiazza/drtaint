# Dr. Taint

A *very* WIP DynamoRIO module built on the Dr. Memory Framework to implement taint
analysis on ARM. Core functionality is still unfinished. Very raw, still has hardcoded
paths to my hard drive in CMakeLists.txt, etc.

# Limitations

Currently, taint propagation remains unimplemented for Neon and fpu instructions. glibc
must be compiled without fp support. The following worked for me (cross compiled on x86):

```bash
export CC="arm-linux-gnueabi-gcc"
export AR="arm-linux-gnueabi-ar"
export RANLIB="arm-linux-gnueabi-ranlib"
export CFLAGS="-march=armv7 -mthumb -mfloat-abi=soft"
export LDFLAGS="-march=armv7 -mthumb -mfloat-abi=soft"

# in glibc directory
./configure --without-fp --host="arm-linux-gnueabi"
```

Now, when compiling a userland application, use the following parameters:

```
LDFLAGS=-march=armv7 -mfloat-abi=soft -Wl,--rpath=/path/to/new/libc.so.6 -Wl,--dynamic-linker=/path/to/new/ld-linux.so.3
CFLAGS=-march=armv7 -mfloat-abi=soft
```

For some reason, this doesn't get rid of *all* fpu/neon instructions (to my knowledge) but
gets rid of almost all of them.
