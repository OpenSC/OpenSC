## Makefile.am -- Process this file with automake to produce Makefile.in

lib_LTLIBRARIES		= libopensc.la
libopensc_la_SOURCES	= sc-asn1.c sc-base64.c sc-defaults.c \
			  sc-sec.c sc-log.c sc.c sc-card.c sc-iso7816.c\
			  sc-pkcs15.c sc-pkcs15-cert.c \
			  sc-pkcs15-pin.c sc-pkcs15-prkey.c \
			  sc-pkcs15-defaults.c sc-pkcs15-sec.c \
			  sc-card-setec.c sc-card-multiflex.c
libopensc_la_LDFLAGS	= -version-info 0:4:0
libopensc_la_LIBADD	= @LIBPCSCLITE@
libopensc_la_CFLAGS     = $(AM_CFLAGS) -Werror

include_HEADERS		= opensc.h opensc-pkcs15.h
noinst_HEADERS		= sc-asn1.h sc-log.h
