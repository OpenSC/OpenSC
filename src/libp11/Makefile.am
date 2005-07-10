# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in
DISTCLEANFILES= libp11.pc
EXTRA_DIST = Makefile.mak

lib_LTLIBRARIES = libp11.la

libp11_la_SOURCES = p11_attr.c p11_cert.c p11_err.c p11_key.c \
	p11_load.c p11_misc.c p11_rsa.c p11_slot.c libp11.h

libp11_la_CFLAGS = -I$(srcdir)
libp11_la_LDFLAGS = -version-info @OPENSC_LT_CURRENT@:@OPENSC_LT_REVISION@:@OPENSC_LT_AGE@
libp11_la_LIBADD = @LIBSCCONF@ ../scdl/libscdl.la @LIBDL@ @LIBCRYPTO@

pkgconfigdir = @libdir@/pkgconfig
pkgconfig_DATA = libp11.pc

