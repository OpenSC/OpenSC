#!/bin/bash

BUILDPATH=${PWD}
PREFIX=/Library/OpenSC
export MACOSX_DEPLOYMENT_TARGET="10.13"

# parse arguments: options -b/--buildpath and -p/--prefix
while [ $# -gt 0 ]; do
    case "$1" in
        -b|--buildpath)
            BUILDPATH="$2"
            shift 2
            ;;
        -p|--prefix)
            PREFIX="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1" >&2
            echo "Usage: $0 [-b|--buildpath <path>] [-p|--prefix <path>]" >&2
            exit 1
            ;;
    esac
done

pushd $BUILDPATH
if ! test -e openssl; then
    git clone --depth=1 https://github.com/openssl/openssl.git -b openssl-3.5
    sed -ie 's!my @disablables = (!my @disablables = (\n    "apps",!' openssl/Configure
fi

pushd openssl
./Configure darwin64-x86_64 no-shared no-apps --prefix=$PREFIX enable-ec_nistp_64_gcc_128
make clean
make -j 4
make DESTDIR=$BUILDPATH/openssl_bin install_sw
make clean

./Configure darwin64-arm64 no-shared no-apps --prefix=$PREFIX enable-ec_nistp_64_gcc_128
make -j 4
make DESTDIR=$BUILDPATH/openssl_arm64 install_sw

lipo -create $BUILDPATH/openssl_arm64/$PREFIX/lib/libcrypto.a $BUILDPATH/openssl_bin/$PREFIX/lib/libcrypto.a -output libcrypto.a
lipo -create $BUILDPATH/openssl_arm64/$PREFIX/lib/libssl.a $BUILDPATH/openssl_bin/$PREFIX/lib/libssl.a -output libssl.a
mv libcrypto.a $BUILDPATH/openssl_bin/$PREFIX/lib/libcrypto.a
mv libssl.a $BUILDPATH/openssl_bin/$PREFIX/lib/libssl.a

popd
popd