## Makefile.am -- Process this file with automake to produce Makefile.in

EXTRA_DIST = opensc-config.in

INCLUDES = @CFLAGS_PCSC@

bin_SCRIPTS = opensc-config

lib_LTLIBRARIES		= libopensc.la
libopensc_la_SOURCES	= asn1.c base64.c sec.c log.c sc.c card.c iso7816.c \
			  pkcs15.c pkcs15-cert.c pkcs15-pin.c \
			  pkcs15-prkey.c pkcs15-sec.c pkcs15-cache.c \
			  card-setec.c card-flex.c card-gpk.c \
			  card-emv.c card-default.c
libopensc_la_LDFLAGS	= -version-info 0:5:0

if HAVE_SSL
libopensc_la_LIBADD	= @LIBPCSC@ @LIBCRYPTO@
else
libopensc_la_LIBADD	= @LIBPCSC@
endif

include_HEADERS		= opensc.h opensc-pkcs15.h opensc-emv.h
noinst_HEADERS		= sc-asn1.h sc-log.h sc-internal.h
