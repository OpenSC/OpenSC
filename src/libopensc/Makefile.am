# Process this file with automake to create Makefile.in

includedir = @includedir@/opensc

MAINTAINERCLEANFILES = Makefile.in

EXTRA_DIST = Makefile.mak libopensc.pc.in libpkcs15init.pc.in libscconf.pc.in 

INCLUDES = $(CPPFLAGS) $(OPENSSL_CFLAGS) $(OPENCT_CFLAGS) $(PCSC_CFLAGS)
AM_LDFLAGS = 

bin_SCRIPTS = opensc-config

lib_LTLIBRARIES = libopensc.la
libopensc_la_SOURCES = \
	sc.c ctx.c ui.c log.c errors.c \
	asn1.c base64.c sec.c card.c iso7816.c dir.c padding.c apdu.c \
	\
	pkcs15.c pkcs15-cert.c pkcs15-data.c pkcs15-pin.c \
	pkcs15-prkey.c pkcs15-pubkey.c pkcs15-sec.c \
	pkcs15-wrap.c pkcs15-algo.c pkcs15-cache.c pkcs15-syn.c \
	\
	emv.c \
	\
	ctbcs.c reader-ctapi.c reader-pcsc.c reader-openct.c \
	\
	card-setcos.c card-miocos.c card-flex.c card-gpk.c \
	card-cardos.c card-tcos.c card-emv.c card-default.c \
	card-mcrd.c card-starcos.c card-openpgp.c card-jcop.c \
	card-oberthur.c card-belpic.c card-atrust-acos.c \
	card-incrypto34.c card-piv.c \
	\
	pkcs15-openpgp.c pkcs15-infocamere.c pkcs15-starcert.c \
	pkcs15-tcos.c pkcs15-esteid.c pkcs15-postecert.c pkcs15-gemsafe.c \
	pkcs15-actalis.c pkcs15-atrust-acos.c pkcs15-tccardos.c pkcs15-piv.c
libopensc_la_LDFLAGS = -version-info @OPENSC_LT_CURRENT@:@OPENSC_LT_REVISION@:@OPENSC_LT_AGE@
libopensc_la_LIBADD = @LIBSCCONF@ $(OPENSSL_LIBS) $(OPENCT_LIBS) $(PCSC_LIBS) $(LTLIBLTDL)

include_HEADERS = \
	opensc.h pkcs15.h emv.h \
	cardctl.h asn1.h log.h ui.h \
	errors.h types.h

noinst_HEADERS = cards.h ctbcs.h internal.h esteid.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libopensc.pc libpkcs15init.pc libscconf.pc
