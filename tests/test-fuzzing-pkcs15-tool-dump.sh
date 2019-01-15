#!/bin/bash

if [ ! -d x41-smartcard-fuzzing ];
then
    git clone https://github.com/x41sec/x41-smartcard-fuzzing
fi

gcc -shared -fPIC -o x41-smartcard-fuzzing/scard_override/libsccard_override.so x41-smartcard-fuzzing/scard_override/scard_override.c -ldl -I/usr/include/PCSC/

if [ ! -f configure ];
then
    autoreconf -vis
fi

if [ ! -f Makefile ];
then
    make clean
fi

#export AFL_USE_ASAN=1
./configure CC=afl-gcc CFLAGS="-O0" LDFLAGS="-ldl" --disable-shared --disable-notify --with-pcsc-provider=$PWD/x41-smartcard-fuzzing/scard_override/libsccard_override.so
make

if [ ! -d tests/fuzzing-testcases ]
then
    mkdir -p tests/fuzzing-testcases
    echo -ne "$(printf '\\x90\\x00')" > tests/fuzzing-testcases/9000
    IN=tests/fuzzing-testcases
else
    IN=-
fi

FUZZ_FILE=input.apdu  afl-fuzz -i $IN -o out -f input.apdu src/tools/pkcs15-tool -D
