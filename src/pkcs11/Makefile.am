# Process this file with automake to create Makefile.in

SUBDIRS = . pkcs11

libdir = ${prefix}/lib/pkcs11

INCLUDES = -I../libopensc

LDFLAGS = @LDFLAGS@ @LIBDL@ \
	../libopensc/libopensc.la

SRC = function_table.c generic.c session.c object.c \
	endecrypt.c digestsign.c verify.c misc.c slot.c
INC = sc-pkcs11.h

lib_LTLIBRARIES = opensc-pkcs11.la

opensc_pkcs11_la_SOURCES = $(SRC) $(INC)
opensc_pkcs11_la_LDFLAGS = -module -avoid-version
