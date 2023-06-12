#!/bin/bash

set -ex -o xtrace

meson setup builddir

meson configure builddir --pkg-config-path /usr/local/lib/pkgconfig; --prefix /

meson compile

DESTDIR=$PWD/build meson install
