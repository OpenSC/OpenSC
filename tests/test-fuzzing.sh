#!/bin/bash

set -ex

case "$1" in
    "pkcs11-tool")
        CMD="src/tools/pkcs11-tool --test --login --pin 123456"
        ;;
    "pkcs15-tool")
        CMD="src/tools/pkcs15-tool --dump"
        ;;
    "eidenv")
        CMD="src/tools/eidenv"
        ;;
    *)
        echo "Unknown fuzzing target"
        exit 1
        ;;
esac

IN=tests/fuzzing-testcases
if [ ! -d "$IN" ]
then
    mkdir -p "$IN"
    echo -ne "$(printf '\\x90\\x00')" > "$IN"/9000
fi

# reuse output directory if possible
OUT="out-$1"
if [ -d "$OUT" ]
then
    IN=-
fi

if [ ! -d x41-smartcard-fuzzing ];
then
    git clone https://github.com/x41sec/x41-smartcard-fuzzing
fi

gcc -shared -fPIC -o x41-smartcard-fuzzing/scard_override/libsccard_override.so x41-smartcard-fuzzing/scard_override/scard_override.c -ldl -I/usr/include/PCSC/

if [ ! -f configure ];
then
    autoreconf -vis
fi

#export AFL_USE_ASAN=1
./configure CC=afl-gcc CFLAGS="-O0" --disable-shared --disable-notify --with-pcsc-provider=$PWD/x41-smartcard-fuzzing/scard_override/libsccard_override.so
make

FUZZ_FILE=input.apdu  afl-fuzz -i "$IN" -o "$OUT" -f input.apdu $CMD
