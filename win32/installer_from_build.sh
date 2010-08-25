#!/bin/bash
set -ex
build_dir=$1
# use mingw to generate binaries
(cd ${build_dir}; CHOST=i586-mingw32msvc CBUILD=i686-pc-linux-gnu ./build)
# Copy files
cp ${build_dir}/image/opensc/etc/opensc.conf win32

mkdir -p win32/opensc
cp ${build_dir}/image/opensc/bin/*.dll ${build_dir}/image/opensc/bin/*.exe win32/opensc
cp ${build_dir}/image/opensc/share/opensc/*.profile win32/opensc
mkdir -p win32/engine_pkcs11
cp ${build_dir}/image/engine_pkcs11/bin/libp11-1.dll ${build_dir}/image/engine_pkcs11/lib/engines/engine_pkcs11.dll win32/engine_pkcs11

# Build installer
wine ~/.wine/drive_c/Program\ Files/Inno\ Setup\ 5/ISCC.exe win32/OpenSC.iss
