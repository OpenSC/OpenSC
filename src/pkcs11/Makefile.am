# Process this file with automake to create Makefile.in

SUBDIRS = . rsaref

libdir = ${prefix}/lib/pkcs11

INCLUDES = @CFLAGS_PCSC@ @CFLAGS_OPENSC@

LDFLAGS = @LDFLAGS@ @LIBDL@ @LIBOPENSC@

SRC = pkcs11-global.c pkcs11-session.c pkcs11-object.c misc.c slot.c \
	framework-pkcs15.c
INC = sc-pkcs11.h

lib_LTLIBRARIES = opensc-pkcs11.la

opensc_pkcs11_la_SOURCES = $(SRC) $(INC)
opensc_pkcs11_la_LDFLAGS = -module -avoid-version
