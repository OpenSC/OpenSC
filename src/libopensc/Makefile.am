# Process this file with automake to create Makefile.in

includedir = @includedir@/opensc

MAINTAINERCLEANFILES = Makefile.in

EXTRA_DIST = Makefile.mak libopensc.pc.in

INCLUDES = @CPPFLAGS@ @OPENCT_CFLAGS@ @CFLAGS_PCSC@
LDFLAGS = @LDFLAGS@ @OPENCT_LDFLAGS@

bin_SCRIPTS = opensc-config

lib_LTLIBRARIES = libopensc.la
libopensc_la_SOURCES = \
	sc.c ctx.c log.c errors.c portability.c module.c \
	asn1.c base64.c sec.c card.c iso7816.c dir.c padding.c \
	\
	pkcs15.c pkcs15-cert.c pkcs15-data.c pkcs15-pin.c \
	pkcs15-prkey.c pkcs15-pubkey.c pkcs15-sec.c \
	pkcs15-wrap.c pkcs15-algo.c pkcs15-cache.c \
	\
	emv.c \
	\
	ctbcs.c reader-ctapi.c reader-pcsc.c \
	reader-openct.c reader-usbtoken.c \
	\
	card-setcos.c card-miocos.c card-flex.c card-gpk.c \
	card-etoken.c card-tcos.c card-emv.c card-default.c \
	card-mcrd.c card-starcos.c
libopensc_la_LDFLAGS = -version-info @OPENSC_LT_CURRENT@:@OPENSC_LT_REVISION@:@OPENSC_LT_AGE@
libopensc_la_LIBADD = @LIBSCCONF@ ../scdl/libscdl.la @LIBDL@ @LIBCRYPTO@ @OPENCT_LIBS@ @LIBPCSC@

include_HEADERS = \
	opensc.h pkcs15.h emv.h \
	errors.h types.h \
	cardctl.h asn1.h log.h

noinst_HEADERS = ctbcs.h internal.h

pkgconfigdir = @libdir@/pkgconfig
pkgconfig_DATA = libopensc.pc
