## Makefile.am -- Process this file with automake to produce Makefile.in

includedir = ${prefix}/include/opensc

MAINTAINERCLEANFILES = Makefile.in

EXTRA_DIST = Makefile.mak opensc-config.in

if HAVE_SSL
SSL_LIB = @LIBCRYPTO@
endif

if HAVE_PCSCLITE
PCSC_SRC = reader-pcsc.c
PCSC_FLAGS = @CFLAGS_PCSC@
PCSC_LIB = @LIBPCSC@
endif

INCLUDES = $(PCSC_FLAGS)

bin_SCRIPTS = opensc-config

lib_LTLIBRARIES		= libopensc.la
libopensc_la_SOURCES	= sc.c ctx.c module.c asn1.c log.c base64.c \
			  errors.c sec.c card.c iso7816.c dir.c \
			  portability.c \
			  pkcs15.c pkcs15-cert.c pkcs15-data.c pkcs15-pin.c \
			  pkcs15-prkey.c pkcs15-pubkey.c pkcs15-sec.c \
			  pkcs15-wrap.c pkcs15-algo.c \
			  pkcs15-cache.c $(PCSC_SRC) reader-ctapi.c ctbcs.c \
			  card-setcos.c card-miocos.c card-flex.c card-gpk.c \
			  card-etoken.c card-tcos.c card-emv.c card-default.c \
			  card-mcrd.c

libopensc_la_LDFLAGS	= -version-info 0:6:0
libopensc_la_LIBADD	= @LIBDL@ $(PCSC_LIB) $(SSL_LIB) $(LIBSCCONF)

include_HEADERS		= opensc.h pkcs15.h emv.h \
			  errors.h types.h \
			  cardctl.h asn1.h log.h
noinst_HEADERS		= ctbcs.h internal.h
