## Makefile.am -- Process this file with automake to produce Makefile.in

EXTRA_DIST = opensc-config.in

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
libopensc_la_SOURCES	= asn1.c base64.c sec.c log.c sc.c card.c iso7816.c \
			  dir.c pkcs15.c pkcs15-cert.c pkcs15-pin.c \
			  pkcs15-prkey.c pkcs15-sec.c pkcs15-cache.c \
			  $(PCSC_SRC) \
			  card-setec.c card-miocos.c card-flex.c card-gpk.c \
			  card-tcos.c card-emv.c card-default.c
libopensc_la_LDFLAGS	= -version-info 0:6:0
libopensc_la_LIBADD	= $(PCSC_LIB) $(SSL_LIB)

include_HEADERS		= opensc.h opensc-pkcs15.h opensc-emv.h \
		   	  cardctl.h
noinst_HEADERS		= sc-asn1.h sc-log.h sc-internal.h
