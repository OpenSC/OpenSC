# Process this file with automake to create Makefile.in

SUBDIRS = . pkcs11

libdir = ${prefix}/lib/pkcs11

INCLUDES = @CFLAGS_PCSC@ @CFLAGS_OPENSC@

LDFLAGS = @LDFLAGS@ @LIBDL@ @LIBOPENSC@

SRC = function_table.c generic.c session.c object.c \
	endecrypt.c digestsign.c verify.c misc.c slot.c
INC = sc-pkcs11.h

lib_LTLIBRARIES = opensc-pkcs11.la

opensc_pkcs11_la_SOURCES = $(SRC) $(INC)
opensc_pkcs11_la_LDFLAGS = -module -avoid-version
